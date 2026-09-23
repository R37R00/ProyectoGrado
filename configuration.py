import json
from pathlib import Path


CONFIG_PATH = Path(__file__).resolve().parent / "config" / "ids_config.json"

DEFAULT_IDS_CONFIG = {
    "arp": {
        "suspicion_window_s": 2,
        "suspicion_threshold": 1,
    },
    "port_scan": {
        "window_s": 4,
        "threshold": 6,
    },
    "dos": {
        "window_s": 3,
        "alert_cooldown_s": 1,
        "min_suspicious_events": 2,
        "event_reset_s": 2,
        "profiles": {
            "icmp_flood": {
                "alert_pps": 4,
                "block_pps": 8,
                "block_bps": 12000,
            },
            "syn_flood": {
                "alert_pps": 4,
                "block_pps": 7,
                "block_bps": 12000,
            },
        },
    },
    "arp_mitigation": {
        "enabled": True,
        "periodic_enabled": False,
        "lock_gateway_enabled": False,
        "aggressive_mode": False,
    },
}

def load_ids_config():
    if not CONFIG_PATH.exists():
        raise FileNotFoundError(
            f"No se encontró el archivo de configuración: {CONFIG_PATH}"
        )

    with CONFIG_PATH.open("r", encoding="utf-8") as file:
        return json.load(file)


def get_ids_config_path():
    return CONFIG_PATH

def save_ids_config(config):
    with CONFIG_PATH.open("w", encoding="utf-8") as file:
        json.dump(config, file, indent=4, ensure_ascii=False)
