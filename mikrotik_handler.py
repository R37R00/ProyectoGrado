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

    def _find_existing_rules(self, firewall, ip_address):
        existing_rules = []
        for rule in firewall.get():
            if rule.get("src-address") == ip_address or f"AUTO_BLOCK_{ip_address}" in rule.get("comment", ""):
                existing_rules.append(rule)
        return existing_rules

    def _find_existing_mac_rules(self, firewall, mac_address):
        existing_rules = []
        for rule in firewall.get():
            comment = rule.get("comment", "")
            if (
                rule.get("src-mac-address") == mac_address
                or rule.get("dst-mac-address") == mac_address
                or f"AUTO_BLOCK_MAC_{mac_address}" in comment
                or f"AUTO_BLOCK_MAC_DST_{mac_address}" in comment
            ):
                existing_rules.append(rule)
        return existing_rules

    def _add_rule_at_top(self, firewall, chain, ip_address, comment):
        rules = firewall.get()
        first_rule_id = self._get_rule_id(rules[0]) if rules else None

        add_params = {
            "chain": chain,
            "src_address": ip_address,
            "action": "drop",
            "comment": comment,
        }

        if DEBUG:
            logging.info("[DEBUG] Adding MikroTik rule chain=%s ip=%s first_rule_id=%s", chain, ip_address, first_rule_id)

        if first_rule_id:
            try:
                firewall.add(place_before=first_rule_id, **add_params)
                return True
            except Exception as error:
                logging.warning(
                    "[MIKROTIK] Could not place rule at top for %s in chain %s: %s",
                    ip_address,
                    chain,
                    error,
                )

        firewall.add(**add_params)
        return True

    def block_ip(self, ip_address, mac_address=None):
        normalized_ip = self._normalize_ip(ip_address)
        normalized_mac = self._normalize_mac(mac_address)
        if not normalized_ip:
            logging.error("[MIKROTIK] Block request missing attacker IP")
            return False

        if not normalized_mac:
            logging.error("[MIKROTIK] Block request missing attacker MAC")
            return False

        if normalized_ip in self.protected_ips:
            logging.warning("[MIKROTIK] Skipping protected IP: %s", normalized_ip)
            return False

        if normalized_mac in self.protected_macs:
            logging.warning("[MIKROTIK] Skipping protected MAC: %s", normalized_mac)
            return False

        firewall_src_comment = f"AUTO_BLOCK_SRC_{normalized_ip}"
        firewall_dst_comment = f"AUTO_BLOCK_DST_{normalized_ip}"
        firewall_input_comment = f"AUTO_BLOCK_INPUT_{normalized_ip}"
        bridge_src_comment = f"BRIDGE_BLOCK_SRC_{normalized_mac}"
        bridge_dst_comment = f"BRIDGE_BLOCK_DST_{normalized_mac}"

        def _rule_exists_by_comment(resource, comment):
            for rule in resource.get():
                if rule.get("comment", "") == comment:
                    return True
            return False

        def _add_rule_at_top(resource, params, rule_label):
            rules = resource.get()
            first_rule_id = self._get_rule_id(rules[0]) if rules else None

            if first_rule_id:
                try:
                    resource.add(**params, **{"place-before": first_rule_id})
                    logging.info("[MIKROTIK] Added %s at top", rule_label)
                    return True
                except Exception as error:
                    logging.warning(
                        "[MIKROTIK] Could not place %s at top: %s",
                        rule_label,
                        error,
                    )

            resource.add(**params)
            logging.info("[MIKROTIK] Added %s", rule_label)
            return True

        def _ensure_bridge_ip_firewall():
            settings = self.api.get_resource("/interface/bridge/settings")
            try:
                current = settings.get()
            except Exception as error:
                logging.warning("[MIKROTIK] Could not read bridge settings: %s", error)
                current = []

            if current:
                setting = current[0]
                current_value = str(
                    setting.get("use-ip-firewall")
                    or setting.get("use_ip_firewall")
                    or ""
                ).lower()
                if current_value in {"yes", "true"}:
                    logging.info("[MIKROTIK] Bridge setting use-ip-firewall already enabled")
                    return True

                setting_id = self._get_rule_id(setting)
                try:
                    if setting_id:
                        settings.set(**{"id": setting_id, "use-ip-firewall": "yes"})
                    else:
                        settings.set(**{"use-ip-firewall": "yes"})
                    logging.info("[MIKROTIK] Bridge setting use-ip-firewall enabled")
                    return True
                except Exception as error:
                    logging.warning("[MIKROTIK] Could not enable use-ip-firewall via settings.set: %s", error)

            try:
                settings.set(**{"use-ip-firewall": "yes"})
                logging.info("[MIKROTIK] Bridge setting use-ip-firewall enabled")
                return True
            except Exception as error:
                logging.error("[MIKROTIK] Failed to configure bridge setting use-ip-firewall=yes: %s", error)
                return False

        def _block():
            firewall = self.api.get_resource("/ip/firewall/filter")
            bridge = self.api.get_resource("/interface/bridge/filter")

            _ensure_bridge_ip_firewall()

            if _rule_exists_by_comment(firewall, firewall_src_comment):
                logging.info("[MIKROTIK] Firewall source rule already exists for %s", normalized_ip)
            else:
                _add_rule_at_top(
                    firewall,
                    {
                        "chain": "forward",
                        "src-address": normalized_ip,
                        "action": "drop",
                        "comment": firewall_src_comment,
                    },
                    f"firewall source rule for {normalized_ip}",
                )

            if _rule_exists_by_comment(firewall, firewall_dst_comment):
                logging.info("[MIKROTIK] Firewall destination rule already exists for %s", normalized_ip)
            else:
                _add_rule_at_top(
                    firewall,
                    {
                        "chain": "forward",
                        "dst-address": normalized_ip,
                        "action": "drop",
                        "comment": firewall_dst_comment,
                    },
                    f"firewall destination rule for {normalized_ip}",
                )

            if _rule_exists_by_comment(firewall, firewall_input_comment):
                logging.info("[MIKROTIK] Firewall input rule already exists for %s", normalized_ip)
            else:
                _add_rule_at_top(
                    firewall,
                    {
                        "chain": "input",
                        "src-address": normalized_ip,
                        "action": "drop",
                        "comment": firewall_input_comment,
                    },
                    f"firewall input rule for {normalized_ip}",
                )

            if _rule_exists_by_comment(bridge, bridge_src_comment):
                logging.info("[MIKROTIK] Bridge source MAC rule already exists for %s", normalized_mac)
            else:
                _add_rule_at_top(
                    bridge,
                    {
                        "chain": "forward",
                        "src-mac-address": normalized_mac,
                        "action": "drop",
                        "comment": bridge_src_comment,
                    },
                    f"bridge source rule for {normalized_mac}",
                )

            if _rule_exists_by_comment(bridge, bridge_dst_comment):
                logging.info("[MIKROTIK] Bridge destination MAC rule already exists for %s", normalized_mac)
            else:
                _add_rule_at_top(
                    bridge,
                    {
                        "chain": "forward",
                        "dst-mac-address": normalized_mac,
                        "action": "drop",
                        "comment": bridge_dst_comment,
                    },
                    f"bridge destination rule for {normalized_mac}",
                )

            logging.info(
                "[MIKROTIK] Attacker blocked successfully: ip=%s mac=%s",
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

        def _unblock():
            firewall = self.api.get_resource("/ip/firewall/filter")
            removed = False
            for rule in firewall.get():
                comment = rule.get("comment", "")
                if (
                    (normalized_mac and (f"AUTO_BLOCK_MAC_{normalized_mac}" in comment or f"AUTO_BLOCK_MAC_DST_{normalized_mac}" in comment))
                    or (normalized_ip and f"AUTO_BLOCK_{normalized_ip}" in comment)
                ):
                    rule_id = self._get_rule_id(rule)
                    if rule_id:
                        firewall.remove(id=rule_id)
                        removed = True

            if normalized_mac:
                try:
                    bridge = self.api.get_resource("/interface/bridge/filter")
                    for rule in bridge.get():
                        if f"BRIDGE_BLOCK_{normalized_mac}" in rule.get("comment", ""):
                            rule_id = self._get_rule_id(rule)
                            if rule_id:
                                bridge.remove(id=rule_id)
                                removed = True
                except Exception:
                    pass

            if removed:
                logging.info("[INFO] Unblocked MAC/IP: %s / %s", normalized_mac or "unknown", normalized_ip or "unknown")
            return removed

        with self.lock:
            result = self._run_with_retry(_unblock)
            return bool(result)

    def block_attacker(self, ip_address, mac_address=None, attack_type="Unknown"):
        _ = mac_address, attack_type
        return self.block_ip(ip_address, mac_address)

    def unblock_attacker(self, ip_address, mac_address=None):
        return self.unblock_ip(ip_address, mac_address)


MikrotikManager = MikroTikManager
