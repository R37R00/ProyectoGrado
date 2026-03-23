import getpass
import logging
import os
from dataclasses import dataclass

import routeros_api
from scapy.all import conf


DEBUG = True
_ACTIVE_MIKROTIK_CONFIG = None


@dataclass
class MikroTikConfig:
    host: str | None = None
    username: str | None = None
    password: str | None = None
    port: int = 8728

    def normalized(self):
        return MikroTikConfig(
            host=(self.host or "").strip() or None,
            username=(self.username or "").strip() or None,
            password=None if self.password is None else str(self.password),
            port=int(self.port or 8728),
        )


def set_active_mikrotik_config(config):
    global _ACTIVE_MIKROTIK_CONFIG
    _ACTIVE_MIKROTIK_CONFIG = (config or MikroTikConfig()).normalized() if config else None
    return _ACTIVE_MIKROTIK_CONFIG


def get_active_mikrotik_config():
    return _ACTIVE_MIKROTIK_CONFIG


def load_mikrotik_config_from_env():
    port_value = os.getenv("MIKROTIK_PORT", "8728").strip() or "8728"
    try:
        port = int(port_value)
    except ValueError:
        logging.warning("Invalid MIKROTIK_PORT value '%s'. Using 8728.", port_value)
        port = 8728

    config = MikroTikConfig(
        host=os.getenv("MIKROTIK_HOST"),
        username=os.getenv("MIKROTIK_USER"),
        password=os.getenv("MIKROTIK_PASSWORD"),
        port=port,
    ).normalized()

    logging.info(
        "[MIKROTIK] Loaded environment config host=%s user=%s port=%s password=%s",
        config.host or "missing",
        config.username or "missing",
        config.port,
        "EMPTY" if config.password == "" else ("SET" if config.password is not None else "NONE"),
    )
    return config


def validate_mikrotik_config(config):
    normalized = (config or MikroTikConfig()).normalized()
    missing = []
    if not normalized.host:
        missing.append("MIKROTIK_HOST")
    if not normalized.username:
        missing.append("MIKROTIK_USER")
    return len(missing) == 0, missing


def get_selected_interface_gateway(selected_interface=None):
    try:
        route = conf.route.route("0.0.0.0")
        route_interface = route[0] if len(route) > 0 else None
        gateway_ip = route[2] if len(route) > 2 else None

        if DEBUG:
            logging.info(
                "[DEBUG] Selected interface=%s route_interface=%s gateway=%s",
                selected_interface or "unknown",
                route_interface or "unknown",
                gateway_ip or "unknown",
            )

        if gateway_ip and gateway_ip != "0.0.0.0":
            return gateway_ip
    except Exception as error:
        logging.warning("Failed to resolve default gateway for MikroTik detection: %s", error)

    return None


def detect_mikrotik_host(selected_interface=None, username=None, password=None, port=8728):
    gateway_ip = get_selected_interface_gateway(selected_interface)
    logging.info("[MIKROTIK] Attempting automatic detection via gateway %s", gateway_ip or "unavailable")

    if not gateway_ip:
        logging.warning("[MIKROTIK] Automatic detection failed: no default gateway found")
        return None

    if not username:
        logging.warning("[MIKROTIK] Automatic detection requires a username before testing gateway")
        return None

    connection = None
    try:
        connection = routeros_api.RouterOsApiPool(
            gateway_ip,
            username=username,
            password=password,
            port=port,
            plaintext_login=True,
        )
        api = connection.get_api()
        api.get_resource("/system/identity").get()
        logging.info("[MIKROTIK] Automatic detection succeeded at %s", gateway_ip)
        return gateway_ip
    except Exception as error:
        logging.error("[MIKROTIK] Automatic detection failed for gateway %s: %s", gateway_ip, error)
        return None
    finally:
        if connection:
            try:
                connection.disconnect()
            except Exception:
                pass


def _prompt_with_gui(parent=None, defaults=None):
    defaults = (defaults or MikroTikConfig()).normalized()

    try:
        from PyQt5.QtWidgets import QInputDialog, QLineEdit
    except Exception:
        return None

    host, ok = QInputDialog.getText(
        parent,
        "MikroTik configuration",
        "MikroTik host or IP:",
        text=defaults.host or "",
    )
    if not ok:
        return None

    username, ok = QInputDialog.getText(
        parent,
        "MikroTik configuration",
        "Username:",
        text=defaults.username or "",
    )
    if not ok:
        return None

    password, ok = QInputDialog.getText(
        parent,
        "MikroTik configuration",
        "Password (leave empty if none):",
        QLineEdit.Password,
        "" if defaults.password is None else defaults.password,
    )
    if not ok:
        return None
    if password == "":
        logging.warning("[MIKROTIK] Using empty password (default configuration)")

    port_text, ok = QInputDialog.getText(
        parent,
        "MikroTik configuration",
        "API port:",
        text=str(defaults.port or 8728),
    )
    if not ok:
        return None

    try:
        port = int((port_text or "").strip() or "8728")
    except ValueError:
        port = 8728

    return MikroTikConfig(host=host, username=username, password=password, port=port).normalized()


def _prompt_with_cli(defaults=None):
    defaults = (defaults or MikroTikConfig()).normalized()

    host = input(f"MikroTik host or IP [{defaults.host or ''}]: ").strip() or defaults.host
    username = input(f"MikroTik username [{defaults.username or ''}]: ").strip() or defaults.username
    password = getpass.getpass("MikroTik Password (leave empty if none): ")
    if password == "":
        logging.warning("[MIKROTIK] Using empty password (default configuration)")
    port_text = input(f"MikroTik API port [{defaults.port or 8728}]: ").strip() or str(defaults.port or 8728)

    try:
        port = int(port_text)
    except ValueError:
        port = 8728

    return MikroTikConfig(host=host, username=username, password=password, port=port).normalized()


def prompt_mikrotik_config(parent=None, defaults=None):
    logging.info("[MIKROTIK] Falling back to manual configuration")

    try:
        from PyQt5.QtWidgets import QApplication

        if QApplication.instance() is not None:
            return _prompt_with_gui(parent=parent, defaults=defaults)
    except Exception:
        pass

    return _prompt_with_cli(defaults=defaults)


def resolve_mikrotik_config(selected_interface=None, parent=None):
    existing_config = get_active_mikrotik_config()
    if existing_config:
        valid, _missing = validate_mikrotik_config(existing_config)
        if valid:
            logging.info("[MIKROTIK] Reusing previously provided configuration")
            return existing_config

    env_config = load_mikrotik_config_from_env()
    working_config = env_config

    if not working_config.username:
        logging.info("[MIKROTIK] Username missing from environment, requesting manual input")
        manual_credentials = prompt_mikrotik_config(parent=parent, defaults=working_config)
        if manual_credentials:
            working_config = manual_credentials

    if not working_config.host:
        detected_host = detect_mikrotik_host(
            selected_interface=selected_interface,
            username=working_config.username,
            password=working_config.password,
            port=working_config.port,
        )
        if detected_host:
            working_config = MikroTikConfig(
                host=detected_host,
                username=working_config.username,
                password=working_config.password,
                port=working_config.port,
            ).normalized()
        else:
            logging.info("[MIKROTIK] Automatic detection did not resolve a host, requesting manual input")
            manual_config = prompt_mikrotik_config(parent=parent, defaults=working_config)
            if manual_config:
                working_config = manual_config

    valid, missing = validate_mikrotik_config(working_config)
    if not valid:
        logging.error("[MIKROTIK] Configuration incomplete. Missing: %s", ", ".join(missing))
        return None

    persisted_config = set_active_mikrotik_config(working_config)
    logging.info(
        "[MIKROTIK] Configuration ready host=%s user=%s port=%s",
        persisted_config.host,
        persisted_config.username,
        persisted_config.port,
    )
    return persisted_config
