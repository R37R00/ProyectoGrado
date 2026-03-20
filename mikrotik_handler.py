import logging
import threading
from datetime import datetime

from routeros_api import RouterOsApiPool


class MikrotikManager:
    """Gestor de bloqueo IP en MikroTik usando RouterOS API."""

    def __init__(
        self,
        host,
        username,
        password,
        port=8728,
        use_ssl=False,
        address_list_name="blacklist",
        default_unblock_seconds=300,
    ):
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.use_ssl = use_ssl
        self.address_list_name = address_list_name
        self.default_unblock_seconds = default_unblock_seconds

        self.pool = None
        self.api = None
        self.lock = threading.Lock()
        self.unblock_timers = {}

    def connect(self):
        """Abre conexión con el router; reconecta si ya había sesión."""
        self.disconnect()
        self.pool = RouterOsApiPool(
            host=self.host,
            username=self.username,
            password=self.password,
            port=self.port,
            use_ssl=self.use_ssl,
            plaintext_login=True,
        )
        self.api = self.pool.get_api()
        self.ensure_blacklist_drop_rule()

    def disconnect(self):
        if self.pool:
            try:
                self.pool.disconnect()
            except Exception:
                pass
        self.pool = None
        self.api = None

    def _api(self):
        if self.api is None:
            self.connect()
        return self.api

    def _run_with_reconnect(self, fn):
        """Ejecuta operación API y reintenta una vez ante error."""
        try:
            return fn(self._api())
        except Exception as first_error:
            logging.warning("Error MikroTik, reintentando conexión: %s", first_error)
            try:
                self.connect()
                return fn(self._api())
            except Exception as second_error:
                logging.error("Fallo definitivo MikroTik: %s", second_error)
                return None

    def ensure_blacklist_drop_rule(self):
        """Asegura regla: chain=forward src-address-list=blacklist action=drop."""

        def _ensure(api):
            rules = api.get_resource("/ip/firewall/filter")
            current = rules.get(
                chain="forward",
                **{"src-address-list": self.address_list_name},
                action="drop",
            )
            if current:
                return True
            rules.add(
                chain="forward",
                **{"src-address-list": self.address_list_name},
                action="drop",
                comment="Drop blacklist by IDS",
            )
            logging.info("Regla de firewall MikroTik creada para blacklist")
            return True

        return bool(self._run_with_reconnect(_ensure))

    def is_ip_blocked(self, ip_address):
        def _check(api):
            resource = api.get_resource("/ip/firewall/address-list")
            entries = resource.get(
                list=self.address_list_name,
                address=ip_address,
            )
            return len(entries) > 0

        result = self._run_with_reconnect(_check)
        return bool(result)

    def block_ip(self, ip_address, attack_type="Unknown", unblock_seconds=None):
        """Bloquea IP en blacklist y programa desbloqueo automático."""
        if not ip_address:
            return False

        with self.lock:
            self.ensure_blacklist_drop_rule()
            if self.is_ip_blocked(ip_address):
                logging.info("IP %s ya estaba bloqueada, no se duplica", ip_address)
                return True

            def _add(api):
                resource = api.get_resource("/ip/firewall/address-list")
                resource.add(
                    list=self.address_list_name,
                    address=ip_address,
                    comment="Blocked by IDS",
                )
                return True

            added = self._run_with_reconnect(_add)
            if not added:
                return False

            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            logging.warning(
                "[%s] IP bloqueada en MikroTik: %s | Tipo de ataque: %s",
                timestamp,
                ip_address,
                attack_type,
            )

            delay = unblock_seconds if unblock_seconds is not None else self.default_unblock_seconds
            timer = threading.Timer(delay, self.unblock_ip, args=(ip_address,))
            timer.daemon = True
            timer.start()
            self.unblock_timers[ip_address] = timer
            return True

    def unblock_ip(self, ip_address):
        """Elimina IP de blacklist."""
        with self.lock:
            def _remove(api):
                resource = api.get_resource("/ip/firewall/address-list")
                entries = resource.get(
                    list=self.address_list_name,
                    address=ip_address,
                )
                for entry in entries:
                    resource.remove(id=entry["id"])
                return True

            removed = self._run_with_reconnect(_remove)
            if removed:
                logging.info("IP desbloqueada automáticamente: %s", ip_address)

            timer = self.unblock_timers.pop(ip_address, None)
            if timer:
                timer.cancel()
