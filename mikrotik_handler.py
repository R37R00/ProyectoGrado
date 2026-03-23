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

    def block_ip(self, ip_address):
        normalized_ip = self._normalize_ip(ip_address)
        if not normalized_ip:
            logging.error("[MIKROTIK] Block request missing attacker IP")
            return False

        if normalized_ip in self.protected_ips:
            logging.warning("[MIKROTIK] Skipping protected IP: %s", normalized_ip)
            return False

        logging.info("[INFO] Blocking attacker IP: %s", normalized_ip)

        def _block():
            firewall = self.api.get_resource("/ip/firewall/filter")
            existing_rules = self._find_existing_rules(firewall, normalized_ip)
            if existing_rules:
                logging.info("[MIKROTIK] Rule already exists for %s", normalized_ip)
                return True

            comment = f"AUTO_BLOCK_{normalized_ip}"
            self._add_rule_at_top(firewall, "forward", normalized_ip, comment)
            self._add_rule_at_top(firewall, "input", normalized_ip, comment)
            return True

        with self.lock:
            result = self._run_with_retry(_block)
            return bool(result)

    def unblock_ip(self, ip_address):
        normalized_ip = self._normalize_ip(ip_address)
        if not normalized_ip:
            return False

        def _unblock():
            firewall = self.api.get_resource("/ip/firewall/filter")
            removed = False
            for rule in firewall.get():
                if f"AUTO_BLOCK_{normalized_ip}" in rule.get("comment", ""):
                    rule_id = self._get_rule_id(rule)
                    if rule_id:
                        firewall.remove(id=rule_id)
                        removed = True
            if removed:
                logging.info("[INFO] Unblocked IP: %s", normalized_ip)
            return removed

        with self.lock:
            result = self._run_with_retry(_unblock)
            return bool(result)

    def block_attacker(self, ip_address, mac_address=None, attack_type="Unknown"):
        _ = mac_address, attack_type
        return self.block_ip(ip_address)

    def unblock_attacker(self, ip_address, mac_address=None):
        _ = mac_address
        return self.unblock_ip(ip_address)


MikrotikManager = MikroTikManager
