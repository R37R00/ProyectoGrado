import logging
import threading

import routeros_api


DEBUG = False


class MikroTikManager:
    """Connection and multi-layer firewall rule manager for MikroTik via RouterOS API."""

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
                if DEBUG:
                    logging.info(
                        "[MIKROTIK] Config host=%s user=%s password=%s",
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
        return self.connected is True

    def _get_rule_id(self, rule):
        return rule.get("id") or rule.get(".id")

    def _run_with_retry(self, fn):
        try:
            if not self.is_connected() and not self.connect():
                logging.error("[MIKROTIK] Connection failed or not initialized")
                return None
            return fn()
        except Exception as first_error:
            logging.error("[MIKROTIK] Operation failed: %s", first_error)
            self.disconnect()
            if not self.connect():
                logging.error("[MIKROTIK] Connection failed or not initialized")
                return None
            try:
                return fn()
            except Exception as second_error:
                logging.error("[MIKROTIK] Operation failed after retry: %s", second_error)
                return None

    def _comment_map(self, ip_address):
        return {
            "raw_src": f"AUTO_BLOCK_{ip_address}_RAW_SRC",
            "raw_dst": f"AUTO_BLOCK_{ip_address}_RAW_DST",
            "filter_src": f"AUTO_BLOCK_{ip_address}_FILTER_SRC",
            "filter_dst": f"AUTO_BLOCK_{ip_address}_FILTER_DST",
            "filter_input": f"AUTO_BLOCK_{ip_address}_FILTER_INPUT",
            "filter_output": f"AUTO_BLOCK_{ip_address}_FILTER_OUTPUT",
            "bridge_src": f"AUTO_BLOCK_{ip_address}_BRIDGE_SRC",
        }

    def _flatten_comments(self, comment_map):
        return list(comment_map.values())

    def is_ip_blocked_in_router(self, ip_address):
        normalized_ip = self._normalize_ip(ip_address)
        if not normalized_ip:
            return False

        comments = self._comment_map(normalized_ip)

        def _check():
            resources = self._resource_bundle()
            raw_comments = {comments["raw_src"], comments["raw_dst"]}
            filter_comments = {
                comments["filter_src"],
                comments["filter_dst"],
                comments["filter_input"],
                comments["filter_output"],
            }

            existing_raw = {
                rule.get("comment", "")
                for rule in resources["raw"].get()
                if rule.get("comment", "") in raw_comments
            }
            existing_filter = {
                rule.get("comment", "")
                for rule in resources["filter"].get()
                if rule.get("comment", "") in filter_comments
            }

            return existing_raw == raw_comments and existing_filter == filter_comments

        with self.lock:
            result = self._run_with_retry(_check)
            return bool(result)

    def _resource_bundle(self):
        return {
            "raw": self.api.get_resource("/ip/firewall/raw"),
            "filter": self.api.get_resource("/ip/firewall/filter"),
            "bridge": self.api.get_resource("/interface/bridge/filter"),
            "connections": self.api.get_resource("/ip/firewall/connection"),
        }

    def _find_rule_by_comment(self, resource, comment, cached_rules=None):
        rules = cached_rules if cached_rules is not None else resource.get()
        for rule in rules:
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

    def _add_rule_at_top(self, resource, params, resource_rules=None):
        first_rule_id = self._get_rule_id(resource_rules[0]) if resource_rules else None
        if first_rule_id:
            try:
                return resource.add(**params, **{"place-before": first_rule_id})
            except Exception as error:
                logging.warning("[MIKROTIK] Could not place rule at top: %s", error)
        return resource.add(**params)

    def _ensure_rule(self, resource, resource_rules, tracker_bucket, comment, params, rule_label):
        existing_rule = self._find_rule_by_comment(resource, comment, cached_rules=resource_rules)
        if existing_rule:
            rule_id = self._get_rule_id(existing_rule)
            if rule_id:
                tracker_bucket.append(rule_id)
            logging.info("[MIKROTIK] %s already exists", rule_label)
            return

        add_result = self._add_rule_at_top(resource, params, resource_rules=resource_rules)
        rule_id = self._extract_added_rule_id(add_result)
        if not rule_id:
            created_rule = self._find_rule_by_comment(resource, comment)
            rule_id = self._get_rule_id(created_rule) if created_rule else None
        if rule_id:
            tracker_bucket.append(rule_id)
        logging.info("[MIKROTIK] Added %s", rule_label)

    def _block_raw(self, resources, normalized_ip, comments, tracker):
        raw_rules = resources["raw"].get()
        planned_rules = [
            (
                comments["raw_src"],
                {
                    "chain": "prerouting",
                    "src-address": normalized_ip,
                    "action": "drop",
                    "comment": comments["raw_src"],
                },
                f"raw source rule for {normalized_ip}",
            ),
            (
                comments["raw_dst"],
                {
                    "chain": "prerouting",
                    "dst-address": normalized_ip,
                    "action": "drop",
                    "comment": comments["raw_dst"],
                },
                f"raw destination rule for {normalized_ip}",
            ),
        ]

        for comment, params, label in planned_rules:
            self._ensure_rule(resources["raw"], raw_rules, tracker["raw_rule_ids"], comment, params, label)

    def _block_filter(self, resources, normalized_ip, comments, tracker):
        filter_rules = resources["filter"].get()
        planned_rules = [
            (
                comments["filter_src"],
                {
                    "chain": "forward",
                    "src-address": normalized_ip,
                    "action": "drop",
                    "comment": comments["filter_src"],
                },
                f"filter source rule for {normalized_ip}",
            ),
            (
                comments["filter_dst"],
                {
                    "chain": "forward",
                    "dst-address": normalized_ip,
                    "action": "drop",
                    "comment": comments["filter_dst"],
                },
                f"filter destination rule for {normalized_ip}",
            ),
            (
                comments["filter_input"],
                {
                    "chain": "input",
                    "src-address": normalized_ip,
                    "action": "drop",
                    "comment": comments["filter_input"],
                },
                f"filter input rule for {normalized_ip}",
            ),
            (
                comments["filter_output"],
                {
                    "chain": "output",
                    "dst-address": normalized_ip,
                    "action": "drop",
                    "comment": comments["filter_output"],
                },
                f"filter output rule for {normalized_ip}",
            ),
        ]

        for comment, params, label in planned_rules:
            self._ensure_rule(resources["filter"], filter_rules, tracker["filter_rule_ids"], comment, params, label)

    def _block_bridge(self, resources, normalized_mac, comments, tracker):
        if not normalized_mac:
            return

        bridge_rules = resources["bridge"].get()
        params = {
            "chain": "forward",
            "src-mac-address": normalized_mac,
            "action": "drop",
            "comment": comments["bridge_src"],
        }
        self._ensure_rule(
            resources["bridge"],
            bridge_rules,
            tracker["bridge_rule_ids"],
            comments["bridge_src"],
            params,
            f"bridge source rule for {normalized_mac}",
        )

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

        comments = self._comment_map(normalized_ip)

        def _block():
            resources = self._resource_bundle()
            already_blocked = self.is_ip_blocked_in_router(normalized_ip)
            tracker = {
                "filter_rule_ids": [],
                "raw_rule_ids": [],
                "bridge_rule_ids": [],
                "mac": normalized_mac,
                "comments": self._flatten_comments(comments),
            }

            self._block_raw(resources, normalized_ip, comments, tracker)
            self._block_filter(resources, normalized_ip, comments, tracker)
            self._block_bridge(resources, normalized_mac, comments, tracker)
            self.clear_connections(normalized_ip, resource_bundle=resources)

            self.blocked_rules[normalized_ip] = tracker
            if already_blocked:
                logging.info(
                    "[MIKROTIK] Block rules already existed; validated and refreshed ip=%s mac=%s",
                    normalized_ip,
                    normalized_mac or "unknown",
                )
            else:
                logging.info(
                    "[MIKROTIK] Attacker blocked successfully with layered rules: ip=%s mac=%s",
                    normalized_ip,
                    normalized_mac or "unknown",
                )
            return True

        with self.lock:
            result = self._run_with_retry(_block)
            return bool(result)

    def _remove_rules_by_comments(self, resource, comments, tracked_ids=None):
        tracked_ids = set(tracked_ids or [])
        removed = 0
        for rule in resource.get():
            comment = rule.get("comment", "")
            rule_id = self._get_rule_id(rule)
            if not rule_id:
                continue
            if rule_id in tracked_ids or comment in comments:
                resource.remove(id=rule_id)
                removed += 1
        return removed

    def unblock_ip(self, ip_address, mac_address=None):
        normalized_ip = self._normalize_ip(ip_address)
        normalized_mac = self._normalize_mac(mac_address)
        if not normalized_ip and not normalized_mac:
            return False

        def _unblock():
            resources = self._resource_bundle()
            tracked_state = self.blocked_rules.get(normalized_ip, {})
            comments = set(tracked_state.get("comments", []))
            if normalized_ip:
                comments.update(self._flatten_comments(self._comment_map(normalized_ip)))

            removed = 0
            removed += self._remove_rules_by_comments(
                resources["raw"],
                comments,
                tracked_ids=tracked_state.get("raw_rule_ids", []),
            )
            removed += self._remove_rules_by_comments(
                resources["filter"],
                comments,
                tracked_ids=tracked_state.get("filter_rule_ids", []),
            )
            removed += self._remove_rules_by_comments(
                resources["bridge"],
                comments,
                tracked_ids=tracked_state.get("bridge_rule_ids", []),
            )

            self.blocked_rules.pop(normalized_ip, None)
            logging.info("[MIKROTIK] Unblocked attacker ip=%s removed_rules=%s", normalized_ip or "unknown", removed)
            return True

        with self.lock:
            result = self._run_with_retry(_unblock)
            return bool(result)

    def clear_connections(self, ip_address, resource_bundle=None):
        normalized_ip = self._normalize_ip(ip_address)
        if not normalized_ip:
            return False

        def _clear():
            connections = (resource_bundle or self._resource_bundle())["connections"]
            removed = 0

            for connection in connections.get():
                src_address = str(connection.get("src-address", "")).strip()
                dst_address = str(connection.get("dst-address", "")).strip()
                base_src_ip = src_address.split(":")[0] if src_address else ""
                base_dst_ip = dst_address.split(":")[0] if dst_address else ""
                connection_id = self._get_rule_id(connection)
                if not connection_id or normalized_ip not in {base_src_ip, base_dst_ip}:
                    continue

                connections.remove(id=connection_id)
                removed += 1

            logging.info("[MIKROTIK CLEAN] ip=%s removed_connections=%s", normalized_ip, removed)
            return True

        with self.lock:
            result = _clear() if resource_bundle is not None else self._run_with_retry(_clear)
            return bool(result)

    def block_attacker(self, ip_address, mac_address=None, attack_type="Unknown"):
        _ = attack_type
        return self.block_ip(ip_address, mac_address)

    def unblock_attacker(self, ip_address, mac_address=None):
        return self.unblock_ip(ip_address, mac_address)


MikrotikManager = MikroTikManager
