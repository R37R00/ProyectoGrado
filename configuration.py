import json
from pathlib import Path


CONFIG_PATH = Path(__file__).resolve().parent / "config" / "ids_config.json"


def load_ids_config():
    if not CONFIG_PATH.exists():
        raise FileNotFoundError(
            f"No se encontró el archivo de configuración: {CONFIG_PATH}"
        )

    with CONFIG_PATH.open("r", encoding="utf-8") as file:
        return json.load(file)


def get_ids_config_path():
    return CONFIG_PATH
