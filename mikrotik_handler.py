import logging
import threading

import routeros_api


DEBUG = True


class MikroTikManager:
    """Connection and firewall rule manager for MikroTik via RouterOS API."""

    def __init__(self, host, username, password, port=8728):
        self.host = self._normalize_ip(host)
        self.user = (username or "").strip() or None
        self.password = None if password is None else str(password)
        self.port = int(port or 8728)

        self.connection = None
        self.api = None
        self.connected = False
        self.lock = threading.RLock()
        self.protected_ips = set()
        self.protected_macs = set()
        self.blocked_rules = {}

    def _normalize_ip(self, ip_address):
        if ip_address is None:
            return None
        value = str(ip_address).strip()
        return value or None

    def _normalize_mac(self, mac_address):
        if mac_address is None:
            return None
        value = str(mac_address).strip().lower()
        return value or None

    def set_protected_hosts(self, ips=None, macs=None):
        self.protected_ips = {self._normalize_ip(ip) for ip in (ips or []) if self._normalize_ip(ip)}
        self.protected_macs = {self._normalize_mac(mac) for mac in (macs or []) if self._normalize_mac(mac)}

    def connect(self):
        with self.lock:
            if not self.host or not self.user:
                self.connected = False
                logging.error("[MIKROTIK] Connection failed: incomplete configuration")
                return False

            self.disconnect()

            try:
                logging.info(
                    "[DEBUG] MikroTik config -> host=%s, user=%s, password=%s",
                    self.host,
                    self.user,
                    "EMPTY" if self.password in {None, ""} else "SET",
                )
                logging.info("[MIKROTIK] Connecting to %s:%s", self.host, self.port)
                self.connection = routeros_api.RouterOsApiPool(
                    self.host,
                    username=self.user,
                    password=self.password if self.password is not None else "",
                    port=self.port,
                    plaintext_login=True,
                )
                self.api = self.connection.get_api()
                self.api.get_resource("/system/identity").get()
                self.connected = True
                logging.info("[MIKROTIK] Connected successfully")
                return True
            except Exception as error:
                self.connected = False
                self.api = None
                self.connection = None
                logging.error("[MIKROTIK] Connection failed: %s", error)
                return False

    def disconnect(self):
        if self.connection:
            try:
                self.connection.disconnect()
            except Exception:
                pass
        self.connection = None
        self.api = None
        self.connected = False

    def is_connected(self):
        return hasattr(self, "connected") and self.connected is True

    def _get_rule_id(self, rule):
        return rule.get("id") or rule.get(".id")

    def _run_with_retry(self, fn):
        try:
            if not self.is_connected() and not self.connect():
                logging.error("MikroTik connection failed or not initialized")
                return None
            return fn()
        except Exception as first_error:
            logging.error("[MIKROTIK] Operation failed: %s", first_error)
            self.disconnect()
            if not self.connect():
                logging.error("MikroTik connection failed or not initialized")
                return None
            try:
                return fn()
            except Exception as second_error:
                logging.error("[MIKROTIK] Operation failed after retry: %s", second_error)
                return None

    def _tracked_comments_for_ip(self, ip_address):
        return [
            f"AUTO_BLOCK_{ip_address}_SRC",
            f"AUTO_BLOCK_{ip_address}_DST",
            f"AUTO_BLOCK_{ip_address}_INPUT",
        ]

    def _find_rule_by_comment(self, resource, comment):
        for rule in resource.get():
            if rule.get("comment", "") == comment:
                return rule
        return None

    def _extract_added_rule_id(self, add_result):
        if isinstance(add_result, str):
            return add_result
        if isinstance(add_result, dict):
            return self._get_rule_id(add_result)
        if isinstance(add_result, (list, tuple)) and add_result:
            first_item = add_result[0]
            if isinstance(first_item, dict):
                return self._get_rule_id(first_item)
            if isinstance(first_item, str):
                return first_item
        return None

    def _add_rule_at_top(self, resource, params, rule_label):
        rules = resource.get()
        first_rule_id = self._get_rule_id(rules[0]) if rules else None

        if DEBUG:
            logging.info("[DEBUG] Adding MikroTik rule %s first_rule_id=%s params=%s", rule_label, first_rule_id, params)

        if first_rule_id:
            try:
                return resource.add(**params, **{"place-before": first_rule_id})
            except Exception as error:
                logging.warning("[MIKROTIK] Could not place %s at top: %s", rule_label, error)

        return resource.add(**params)

    def block_ip(self, ip_address, mac_address=None):
        normalized_ip = self._normalize_ip(ip_address)
        normalized_mac = self._normalize_mac(mac_address)
        if not normalized_ip:
            logging.error("[MIKROTIK] Block request missing attacker IP")
            return False

        if normalized_ip in self.protected_ips:
            logging.warning("[MIKROTIK] Skipping protected IP: %s", normalized_ip)
            return False

        if normalized_mac and normalized_mac in self.protected_macs:
            logging.warning("[MIKROTIK] Skipping protected MAC: %s", normalized_mac)
            return False

        tracked_comments = self._tracked_comments_for_ip(normalized_ip)

        def _block():
            firewall = self.api.get_resource("/ip/firewall/filter")
            planned_rules = [
                (
                    tracked_comments[0],
                    {
                        "chain": "forward",
                        "src-address": normalized_ip,
                        "action": "drop",
                        "comment": tracked_comments[0],
                    },
                    f"firewall source rule for {normalized_ip}",
                ),
                (
                    tracked_comments[1],
                    {
                        "chain": "forward",
                        "dst-address": normalized_ip,
                        "action": "drop",
                        "comment": tracked_comments[1],
                    },
                    f"firewall destination rule for {normalized_ip}",
                ),
                (
                    tracked_comments[2],
                    {
                        "chain": "input",
                        "src-address": normalized_ip,
                        "action": "drop",
                        "comment": tracked_comments[2],
                    },
                    f"firewall input rule for {normalized_ip}",
                ),
            ]

            tracked_rule_ids = []
            for comment, params, rule_label in planned_rules:
                existing_rule = self._find_rule_by_comment(firewall, comment)
                if existing_rule:
                    rule_id = self._get_rule_id(existing_rule)
                    if rule_id:
                        tracked_rule_ids.append(rule_id)
                    logging.info("[MIKROTIK] %s already exists", rule_label)
                    continue

                add_result = self._add_rule_at_top(firewall, params, rule_label)
                rule_id = self._extract_added_rule_id(add_result)
                if not rule_id:
                    created_rule = self._find_rule_by_comment(firewall, comment)
                    rule_id = self._get_rule_id(created_rule) if created_rule else None
                if rule_id:
                    tracked_rule_ids.append(rule_id)
                logging.info("[MIKROTIK] Added %s", rule_label)

            self.blocked_rules[normalized_ip] = {
                "ids": tracked_rule_ids,
                "comments": tracked_comments,
                "mac": normalized_mac,
            }

            logging.info(
                "[MIKROTIK] Attacker blocked successfully with isolated IP rules: ip=%s mac=%s",
                normalized_ip,
                normalized_mac,
            )
            return True

        with self.lock:
            result = self._run_with_retry(_block)
            return bool(result)

    def unblock_ip(self, ip_address, mac_address=None):
        normalized_ip = self._normalize_ip(ip_address)
        normalized_mac = self._normalize_mac(mac_address)
        if not normalized_ip and not normalized_mac:
            return False

        def _remove_rules_by_comments(firewall, ip_value):
            tracked_state = self.blocked_rules.get(ip_value, {})
            tracked_ids = set(tracked_state.get("ids", []))
            tracked_comments = set(tracked_state.get("comments", []))
            if ip_value:
                tracked_comments.update(self._tracked_comments_for_ip(ip_value))

            removed = 0
            for rule in firewall.get():
                comment = rule.get("comment", "")
                rule_id = self._get_rule_id(rule)
                if not rule_id:
                    continue
                if rule_id in tracked_ids or comment in tracked_comments:
                    firewall.remove(id=rule_id)
                    removed += 1

            logging.info(
                "[MIKROTIK] Rule cleanup for ip=%s removed=%s comments=%s",
                ip_value or "unknown",
                removed,
                sorted(tracked_comments),
            )
            self.blocked_rules.pop(ip_value, None)
            return removed

        def _unblock():
            firewall = self.api.get_resource("/ip/firewall/filter")
            removed = _remove_rules_by_comments(firewall, normalized_ip)
            logging.info("[INFO] Unblocked attacker IP: %s removed_rules=%s", normalized_ip or "unknown", removed)
            return True

        with self.lock:
            result = self._run_with_retry(_unblock)
            return bool(result)

    def clear_connections(self, ip_address):
        normalized_ip = self._normalize_ip(ip_address)
        if not normalized_ip:
            return False

        def _clear():
            connections = self.api.get_resource("/ip/firewall/connection")
            removed = 0

            for connection in connections.get():
                src_address = str(connection.get("src-address", "")).strip()
                base_src_ip = src_address.split(":")[0] if src_address else ""
                connection_id = self._get_rule_id(connection)
                if not connection_id or base_src_ip != normalized_ip:
                    continue

                connections.remove(id=connection_id)
                removed += 1

            logging.info("[MIKROTIK CLEAN] ip=%s removed_connections=%s", normalized_ip, removed)
            return True

        with self.lock:
            result = self._run_with_retry(_clear)
            return bool(result)

    def block_attacker(self, ip_address, mac_address=None, attack_type="Unknown"):
        _ = mac_address, attack_type
        return self.block_ip(ip_address, mac_address)

    def unblock_attacker(self, ip_address, mac_address=None):
        return self.unblock_ip(ip_address, mac_address)


MikrotikManager = MikroTikManager
