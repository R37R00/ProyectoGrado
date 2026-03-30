DEBUG_MODE = True

_gui_event_callback = None


def set_gui_event_callback(callback):
    global _gui_event_callback
    _gui_event_callback = callback


def log_debug(message):
    if DEBUG_MODE:
        print(f"[DEBUG] {message}")


def log_event(message, level="info"):
    if _gui_event_callback:
        prefix = f"[{level.upper()}] " if level else ""
        _gui_event_callback(f"{prefix}{message}")
