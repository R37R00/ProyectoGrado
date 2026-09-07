import ipaddress
import logging
import queue
import threading
import tkinter as tk
import time
from collections import deque
from datetime import datetime
from tkinter import messagebox, ttk

from scapy.all import ARP, Ether, IP

from core.capture import CaptureService, format_packet_record, list_available_interfaces
from core.detection import DetectionService
from event_logger import set_gui_event_callback
from mikrotik_config import (
    MikroTikConfig,
    get_active_mikrotik_config,
    load_mikrotik_config_from_env,
    set_active_mikrotik_config,
)
from mikrotik_handler import MikroTikManager
from ui.interface_selection import InterfaceSelectionView
from ui.packet_view import PacketView
from ui.router_config import RouterConfigView


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)


class AppController:
    CONNECTION_TIMEOUT_MS = 8000
    ATTACK_RESOLVE_TIMEOUT_S = 30

    def __init__(self, root):
        self.root = root
        self.root.title("Sistema IDS - Monitor de Tráfico")
        self.root.geometry("1360x820")
        self.root.minsize(1180, 720)
        self.root.configure(bg="#ffffff")

        self.ui_queue = queue.Queue()
        self.packet_pipeline_queue = queue.Queue(maxsize=2000)
        self.mikrotik_action_queue = queue.Queue()
        self.services_lock = threading.RLock()
        self.capture_service = None
        self.detection_service = None
        self.mikrotik_manager = None
        self.current_view = None
        self.interface_view = None
        self.router_view = None
        self.packet_view = None
        self.selected_interface = None
        self.packet_counter = 0
        self.packet_counter_lock = threading.Lock()
        self.packet_buffer = []
        self.packet_buffer_lock = threading.Lock()
        self.packet_flush_limit = 250
        self.packet_buffer_max = 1500
        self.hosts = {}
        self.host_lock = threading.RLock()
        self.host_update_pending = False
        self.security_event_lock = threading.RLock()
        self.active_attacks = {}
        self.event_history = deque(maxlen=1000)
        self.security_update_pending = False
        self.startup_in_progress = False
        self.deferred_events = []
        self.startup_token = 0
        self.connection_timeout_job = None
        self.worker_stop_event = threading.Event()
        self.queue_drop_notice_at = 0.0

        self._configure_style()
        self.root.protocol("WM_DELETE_WINDOW", self.shutdown)
        set_gui_event_callback(self.handle_alert)

        self.container = ttk.Frame(self.root, style="App.TFrame", padding=18)
        self.container.pack(fill="both", expand=True)

        self.packet_pipeline_thread = threading.Thread(target=self._packet_pipeline_worker, daemon=True)
        self.packet_pipeline_thread.start()
        self.mikrotik_worker_thread = threading.Thread(target=self._mikrotik_action_worker, daemon=True)
        self.mikrotik_worker_thread.start()

        self.show_interface_selection()
        self.process_ui_queue()

    def _configure_style(self):
        style = ttk.Style(self.root)
        style.theme_use("clam")

        style.configure("App.TFrame", background="#ffffff")
        style.configure("Card.TFrame", background="#ffffff", relief="flat")
        style.configure("Panel.TFrame", background="#f8fafc", relief="flat")
        style.configure("SectionTitle.TLabel", background="#ffffff", foreground="#0f172a", font=("Segoe UI", 18, "bold"))
        style.configure("Muted.TLabel", background="#ffffff", foreground="#64748b", font=("Segoe UI", 10))
        style.configure("Body.TLabel", background="#f8fafc", foreground="#1e293b", font=("Segoe UI", 11))
        style.configure("StatusValue.TLabel", background="#f8fafc", foreground="#0f172a", font=("Segoe UI", 12, "bold"))
        style.configure("Primary.TButton", font=("Segoe UI", 10, "bold"), padding=(16, 10), background="#2563eb", foreground="#ffffff")
        style.map(
            "Primary.TButton",
            background=[("active", "#1d4ed8"), ("disabled", "#cbd5e1")],
            foreground=[("disabled", "#64748b")],
        )
        style.configure("Secondary.TButton", font=("Segoe UI", 10), padding=(14, 10), background="#e2e8f0", foreground="#0f172a")
        style.map(
            "Secondary.TButton",
            background=[("active", "#cbd5e1"), ("disabled", "#f1f5f9")],
            foreground=[("disabled", "#94a3b8")],
        )
        style.configure("Card.TLabelframe", background="#ffffff", foreground="#0f172a", borderwidth=1)
        style.configure("Card.TLabelframe.Label", background="#ffffff", foreground="#0f172a", font=("Segoe UI", 10, "bold"))
        style.configure("TEntry", fieldbackground="#ffffff", foreground="#0f172a", insertcolor="#0f172a", borderwidth=1)
        style.configure("TNotebook", background="#ffffff", borderwidth=0)
        style.configure("TNotebook.Tab", background="#f1f5f9", foreground="#334155", padding=(14, 8))
        style.map(
            "TNotebook.Tab",
            background=[("selected", "#ffffff"), ("active", "#e2e8f0")],
            foreground=[("selected", "#0f172a"), ("active", "#0f172a")],
        )
        style.configure("Treeview", background="#ffffff", fieldbackground="#ffffff", foreground="#0f172a", rowheight=28, borderwidth=0)
        style.map("Treeview", background=[("selected", "#1d4ed8")], foreground=[("selected", "#ffffff")])
        style.configure("Treeview.Heading", background="#e2e8f0", foreground="#0f172a", font=("Segoe UI", 10, "bold"), relief="flat")
        style.map("Treeview.Heading", background=[("active", "#cbd5e1")])

    def _set_view(self, widget):
        if self.current_view is not None:
            self.current_view.destroy()
        self.current_view = widget
        self.current_view.pack(fill="both", expand=True)

    def _cancel_connection_timeout(self):
        if self.connection_timeout_job is not None:
            try:
                self.root.after_cancel(self.connection_timeout_job)
            except tk.TclError:
                pass
            self.connection_timeout_job = None

    def _reset_runtime_services(self):
        with self.services_lock:
            self.capture_service = None
            self.detection_service = None
            self.mikrotik_manager = None

    def _cleanup_services(self, capture_service=None, mikrotik_manager=None):
        if capture_service is not None:
            try:
                capture_service.stop()
            except Exception as error:
                logging.debug("Error stopping capture during cleanup: %s", error)
        if mikrotik_manager is not None:
            try:
                mikrotik_manager.disconnect()
            except Exception as error:
                logging.debug("Error disconnecting MikroTik during cleanup: %s", error)

    def show_interface_selection(self):
        interfaces = list_available_interfaces()
        self.interface_view = InterfaceSelectionView(
            self.container,
            on_continue=self._handle_interface_selected,
            on_refresh=self.show_interface_selection,
        )
        self.interface_view.populate_interfaces(interfaces)
        self._set_view(self.interface_view)

    def _handle_interface_selected(self, interface_info):
        self.selected_interface = interface_info
        defaults = get_active_mikrotik_config() or load_mikrotik_config_from_env()
        self.router_view = RouterConfigView(
            self.container,
            interface_info=interface_info,
            defaults=defaults,
            on_accept=self._begin_startup,
            on_cancel=self._cancel_startup,
        )
        self._set_view(self.router_view)

    def _validate_router_config(self, values):
        host_value = (values.get("host") or "").strip()
        username = (values.get("username") or "").strip()
        password = values.get("password")
        port_text = (values.get("port") or "").strip()

        if not host_value:
            raise ValueError("La IP de MikroTik es obligatoria.")
        try:
            ipaddress.IPv4Address(host_value)
        except ValueError as error:
            raise ValueError("La IP de MikroTik debe ser una dirección IPv4 válida.") from error

        if not username:
            raise ValueError("El usuario es obligatorio.")

        if not port_text:
            raise ValueError("El puerto API es obligatorio.")
        if not port_text.isdigit():
            raise ValueError("El puerto API debe contener sólo números.")

        port_value = int(port_text)
        if port_value < 1 or port_value > 65535:
            raise ValueError("El puerto API debe estar entre 1 y 65535.")

        return MikroTikConfig(
            host=host_value,
            username=username,
            password=password,
            port=port_value,
        ).normalized()

    def _begin_startup(self, form_values):
        if self.startup_in_progress:
            return
        if not self.selected_interface:
            messagebox.showerror("Interfaz", "Selecciona una interfaz de red antes de continuar.")
            self.show_interface_selection()
            return

        try:
            config = self._validate_router_config(form_values)
        except ValueError as error:
            self.router_view.set_message(str(error), is_error=True)
            return

        self.startup_token += 1
        startup_token = self.startup_token
        self.startup_in_progress = True
        self._reset_runtime_services()

        logging.info("[UI] Starting MikroTik connection thread")
        self.router_view.set_busy(True, "Conectando con MikroTik...", keep_cancel_enabled=True)
        self._cancel_connection_timeout()
        self.connection_timeout_job = self.root.after(
            self.CONNECTION_TIMEOUT_MS,
            lambda token=startup_token: self._handle_connection_timeout(token),
        )

        worker = threading.Thread(
            target=self._connect_mikrotik_worker,
            args=(startup_token, self.selected_interface, config),
            daemon=True,
        )
        worker.start()

    def _connect_mikrotik_worker(self, startup_token, interface_info, config):
        mikrotik_manager = None
        try:
            mikrotik_manager = MikroTikManager(
                host=config.host,
                username=config.username,
                password=config.password,
                port=config.port,
            )
            success = mikrotik_manager.connect()
            if startup_token != self.startup_token:
                self._cleanup_services(mikrotik_manager=mikrotik_manager)
                return

            if success:
                self.root.after(
                    0,
                    lambda: self.on_connection_success(
                        startup_token,
                        interface_info,
                        config,
                        mikrotik_manager,
                    ),
                )
                return

            raise RuntimeError("No se pudo conectar con el router MikroTik. Revisa la IP, las credenciales y el puerto API.")
        except Exception as error:
            self._cleanup_services(mikrotik_manager=mikrotik_manager)
            self.root.after(0, lambda: self.on_connection_failed(startup_token, str(error)))

    def _handle_connection_timeout(self, startup_token):
        if startup_token != self.startup_token or not self.startup_in_progress:
            return

        logging.error("[UI] MikroTik connection timeout")
        self.startup_in_progress = False
        self.startup_token += 1
        self.connection_timeout_job = None
        if self.router_view is not None:
            self.router_view.set_busy(False, "Tiempo de conexión agotado.", keep_cancel_enabled=True)
            self.router_view.set_message("La conexión con MikroTik no respondió a tiempo.", is_error=True)
        messagebox.showerror("Tiempo de conexión agotado", "La conexión con MikroTik no respondió a tiempo.")
        self.show_interface_selection()

    def on_connection_success(self, startup_token, interface_info, config, mikrotik_manager):
        if startup_token != self.startup_token or not self.startup_in_progress:
            self._cleanup_services(mikrotik_manager=mikrotik_manager)
            return

        self._cancel_connection_timeout()
        logging.info("[UI] MikroTik connection successful")
        logging.info("[UI] Switching to capture screen")

        if self.router_view is not None:
            self.router_view.set_busy(False, "Conexión exitosa. Preparando captura...", keep_cancel_enabled=False)

        self._show_packet_view(
            {
                "interface": interface_info,
                "config": config,
                "interface_ip": interface_info.ip_address or "N/D",
                "interface_network": "Inicializando...",
            }
        )
        self.packet_view.set_mikrotik_status("Conexión exitosa", connected=True)
        self.packet_view.set_capture_status("Inicializando...")
        self.packet_view.append_log("[UI] Conexión con MikroTik exitosa", level="info")
        self.packet_view.append_log("[UI] Cambiando a la pantalla de captura", level="info")
        self.start_packet_capture(startup_token, interface_info, config, mikrotik_manager)

    def on_connection_failed(self, startup_token, error_message):
        if startup_token != self.startup_token:
            return

        self._cancel_connection_timeout()
        self.startup_in_progress = False
        logging.error("[UI] MikroTik connection failed: %s", error_message)
        if self.router_view is not None:
            self.router_view.set_busy(False, "", keep_cancel_enabled=True)
            self.router_view.set_message(error_message, is_error=True)
        messagebox.showerror("Error de conexión", error_message)
        self.show_interface_selection()

    def _initialize_capture_worker(self, startup_token, interface_info, config, mikrotik_manager):
        capture_service = None
        detection_service = None
        try:
            capture_service = CaptureService(packet_callback=self.handle_packet)
            interface_ip = capture_service.get_interface_ip(interface_info.identifier)
            interface_network = capture_service.get_interface_network(interface_info.identifier)

            detection_service = DetectionService(
                alert_callback=self.handle_alert,
                block_callback=self.block_attacker_connection,
            )
            protection = detection_service.configure_for_capture(
                interface_name=interface_info.identifier,
                interface_ip=interface_ip,
                interface_network=interface_network,
                mikrotik_ip=config.host,
            )
            mikrotik_manager.set_protected_hosts(protection.protected_ips, protection.protected_macs)

            with self.services_lock:
                if startup_token != self.startup_token:
                    self._cleanup_services(capture_service=capture_service, mikrotik_manager=mikrotik_manager)
                    return
                self.capture_service = capture_service
                self.detection_service = detection_service
                self.mikrotik_manager = mikrotik_manager

            if not capture_service.start(interface_info.identifier):
                raise RuntimeError("No se pudo iniciar la captura de paquetes en la interfaz seleccionada.")

            self.root.after(
                0,
                lambda: self._finalize_capture_startup(
                    startup_token,
                    {
                        "interface": interface_info,
                        "config": config,
                        "interface_ip": interface_ip or "N/D",
                        "interface_network": str(interface_network) if interface_network else "N/D",
                    },
                ),
            )

            detection_service.build_baseline(interface_network=interface_network)
            self.root.after(
                0,
                lambda: self._append_runtime_log(
                    f"[IDS] Línea base lista en {interface_info.identifier}",
                    level="info",
                ),
            )
        except Exception as error:
            self._cleanup_services(capture_service=capture_service, mikrotik_manager=mikrotik_manager)
            self._reset_runtime_services()
            self.root.after(0, lambda: self._handle_capture_startup_failure(startup_token, str(error)))

    def start_packet_capture(self, startup_token, interface_info, config, mikrotik_manager):
        logging.info("[CAPTURE] Scheduling packet capture startup for interface: %s", interface_info.identifier)
        if self.packet_view is not None:
            self.packet_view.set_capture_status("Iniciando captura...")
            self.packet_view.append_log(
                f"[CAPTURA] Iniciando captura en la interfaz: {interface_info.identifier}",
                level="info",
            )

        worker = threading.Thread(
            target=self._initialize_capture_worker,
            args=(startup_token, interface_info, config, mikrotik_manager),
            daemon=True,
        )
        worker.start()

    def _finalize_capture_startup(self, startup_token, startup_data):
        if startup_token != self.startup_token:
            return

        self.startup_in_progress = False
        self.packet_view.set_interface(startup_data["interface"].name, startup_data["interface_ip"])
        self.packet_view.set_mikrotik_status(
            f"Conectado a {startup_data['config'].host}:{startup_data['config'].port}",
            connected=True,
        )
        self.packet_view.set_capture_status("En ejecución")
        self.packet_view.append_log(
            f"Captura iniciada en {startup_data['interface'].name} ({startup_data['interface'].identifier}) | Red {startup_data['interface_network']}",
            level="info",
        )

    def _append_runtime_log(self, message, level="info"):
        if self.packet_view is not None:
            self.packet_view.append_log(message, level=level)
        else:
            self.ui_queue.put({"type": "log", "data": {"message": message, "level": level}})

    def _rate_limited_warning(self, key, message, interval_s=5.0):
        now = time.time()
        if now - self.queue_drop_notice_at < interval_s:
            return
        self.queue_drop_notice_at = now
        logging.warning("%s", message)

    def _packet_pipeline_worker(self):
        while not self.worker_stop_event.is_set():
            try:
                packet = self.packet_pipeline_queue.get(timeout=0.2)
            except queue.Empty:
                continue

            try:
                self._track_packet_hosts(packet)

                with self.packet_counter_lock:
                    self.packet_counter += 1
                    packet_number = self.packet_counter

                with self.services_lock:
                    detection_service = self.detection_service

                if detection_service is not None:
                    detection_service.process_packet(packet)

                packet_record = format_packet_record(packet, packet_number)
                with self.packet_buffer_lock:
                    self.packet_buffer.append(packet_record)
                    if len(self.packet_buffer) > self.packet_buffer_max:
                        overflow = len(self.packet_buffer) - self.packet_buffer_max
                        if overflow > 0:
                            del self.packet_buffer[:overflow]
            except Exception as error:
                logging.error("[PIPELINE] Error processing packet: %s", error)
            finally:
                self.packet_pipeline_queue.task_done()

    def _run_mikrotik_action(self, action, **payload):
        request = {
            "action": action,
            "payload": payload,
            "event": threading.Event(),
            "result": False,
        }
        self.mikrotik_action_queue.put(request)
        request["event"].wait(timeout=2.5)
        return bool(request.get("result"))

    def _queue_mikrotik_action(self, action, **payload):
        self.mikrotik_action_queue.put(
            {
                "action": action,
                "payload": payload,
                "event": None,
                "result": None,
            }
        )

    def _mikrotik_action_worker(self):
        while not self.worker_stop_event.is_set():
            try:
                request = self.mikrotik_action_queue.get(timeout=0.2)
            except queue.Empty:
                continue

            result = False
            try:
                action = request.get("action")
                payload = request.get("payload", {})
                if action == "block":
                    result = self._execute_block_request(**payload)
                elif action == "unblock":
                    result = self._execute_unblock_request(**payload)
            except Exception as error:
                logging.error("[MIKROTIK] Worker action failed: %s", error)
            finally:
                request["result"] = result
                if request.get("event") is not None:
                    request["event"].set()
                self.mikrotik_action_queue.task_done()

    def _execute_block_request(self, ip_address, mac_address=None, attack_type="Unknown"):
        with self.services_lock:
            mikrotik_manager = self.mikrotik_manager
            detection_service = self.detection_service
        if mikrotik_manager is None:
            return False
        if not mikrotik_manager.is_connected() and not mikrotik_manager.connect():
            self.ui_queue.put({"type": "status", "data": {"text": "Desconectado", "connected": False}})
            self._set_host_status(ip_address, "suspicious", attack_type=attack_type, clear_block=True)
            self._append_runtime_log(f"No se pudo bloquear {ip_address} ({self._translate_attack_type_for_ui(attack_type)}).", level="error")
            return False
        self.ui_queue.put({"type": "status", "data": {"text": "Conectado", "connected": True}})
        attack_context = detection_service.get_attack_context(ip_address, mac_address) if detection_service is not None else None
        victim_ip = attack_context.get("victim_ip") if attack_context else None
        victim_mac = attack_context.get("victim_mac") if attack_context else None
        if not victim_ip:
            with self.security_event_lock:
                for attack in self.active_attacks.values():
                    if attack.get("attacker") == ip_address:
                        victim_ip = attack.get("victim")
                        victim_mac = victim_mac or attack.get("victim_mac")
                        break

        block_result = bool(mikrotik_manager.block_attacker(ip_address, mac_address, attack_type=attack_type))
        router_has_rules = False
        try:
            router_has_rules = bool(mikrotik_manager.is_ip_blocked_in_router(ip_address))
        except Exception as error:
            logging.error("[MIKROTIK] Could not validate block rules for %s: %s", ip_address, error)

        blocked = block_result or router_has_rules
        if blocked:
            self._set_host_status(ip_address, "blocked", attack_type=attack_type)
            self._upsert_attack_event(
                attack_type,
                attacker_ip=ip_address,
                victim_ip=victim_ip,
                status="blocked",
                attacker_mac=mac_address,
                victim_mac=victim_mac,
            )
            self._append_runtime_log(
                f"Bloqueado atacante={ip_address} víctima={victim_ip or 'desconocida'} mac_víctima={victim_mac or 'desconocida'} ataque={self._translate_attack_type_for_ui(attack_type)}.",
                level="alert",
            )
            if detection_service is not None and attack_context:
                threading.Thread(
                    target=self._activate_post_block_mitigation,
                    args=(detection_service, attack_context, attack_type, ip_address, victim_ip),
                    daemon=True,
                ).start()
        else:
            self._set_host_status(ip_address, "suspicious", attack_type=attack_type, clear_block=True)
            self._upsert_attack_event(
                attack_type,
                attacker_ip=ip_address,
                victim_ip=victim_ip,
                status="block failed",
                attacker_mac=mac_address,
                victim_mac=victim_mac,
            )
            self._append_runtime_log(
                f"No se pudo bloquear atacante={ip_address} víctima={victim_ip or 'desconocida'} ataque={self._translate_attack_type_for_ui(attack_type)}; no se encontraron reglas en el router.",
                level="error",
            )
        return blocked

    def _activate_post_block_mitigation(self, detection_service, attack_context, attack_type, attacker_ip, victim_ip):
        mitigated = detection_service.activate_post_block_mitigation(attack_context)
        if mitigated:
            self._upsert_attack_event(
                attack_type,
                attacker_ip=attacker_ip,
                victim_ip=victim_ip,
                status="mitigated",
                attacker_mac=attack_context.get("attacker_mac"),
                victim_mac=attack_context.get("victim_mac"),
            )
            self.ui_queue.put(
                {
                    "type": "log",
                    "data": {
                        "message": f"Mitigación aplicada atacante={attacker_ip} víctima={victim_ip or 'desconocida'} ataque={self._translate_attack_type_for_ui(attack_type)}.",
                        "level": "alert",
                    },
                }
            )

    def _execute_unblock_request(self, ip_address, mac_address=None):
        with self.services_lock:
            mikrotik_manager = self.mikrotik_manager
        if mikrotik_manager is None:
            return False
        if not mikrotik_manager.is_connected() and not mikrotik_manager.connect():
            self.ui_queue.put({"type": "status", "data": {"text": "Desconectado", "connected": False}})
            return False
        self.ui_queue.put({"type": "status", "data": {"text": "Conectado", "connected": True}})
        return bool(mikrotik_manager.unblock_attacker(ip_address, mac_address))

    def _format_last_seen(self, timestamp_value):
        if not timestamp_value:
            return "-"
        return datetime.fromtimestamp(float(timestamp_value)).strftime("%H:%M:%S")

    def _serialize_hosts(self):
        with self.host_lock:
            serialized = []
            for ip_address in sorted(self.hosts):
                host = dict(self.hosts[ip_address])
                serialized.append(
                    {
                        "ip": host.get("ip", ip_address),
                        "mac": host.get("mac") or "unknown",
                        "status": host.get("status", "active"),
                        "is_blocked": bool(host.get("is_blocked", False)),
                        "block_type": host.get("block_type"),
                        "attack_type": host.get("attack_type"),
                        "display_status": self._format_host_status_label(host),
                        "last_seen": self._format_last_seen(host.get("last_seen")),
                    }
                )
            return serialized

    def _refresh_hosts_table(self):
        self.host_update_pending = False
        if self.packet_view is not None:
            self.packet_view.update_hosts(self._serialize_hosts())

    def _schedule_hosts_refresh(self):
        if self.host_update_pending:
            return
        self.host_update_pending = True
        try:
            self.root.after(200, self._refresh_hosts_table)
        except tk.TclError:
            self.host_update_pending = False

    def _format_event_timestamp(self, timestamp_value=None, include_date=True):
        timestamp_value = timestamp_value or time.time()
        pattern = "%Y-%m-%d %H:%M:%S" if include_date else "%H:%M:%S"
        return datetime.fromtimestamp(float(timestamp_value)).strftime(pattern)

    def _normalize_attack_type(self, attack_type):
        value = str(attack_type or "Unknown").strip()
        upper_value = value.upper().replace("_", " ")
        if "ARP" in upper_value:
            return "ARP Spoofing"
        if "PORT" in upper_value or "SCAN" in upper_value:
            return "Port Scan"
        if "DOS" in upper_value or "FLOOD" in upper_value:
            return "DoS"
        if value.lower() == "manual":
            return "Manual"
        return value or "Unknown"

    def _translate_attack_type_for_ui(self, attack_type):
        value = str(attack_type or "").strip()
        normalized = value.upper().replace("_", " ")
        if not value or normalized == "UNKNOWN":
            return "desconocido"
        if "ARP" in normalized:
            return "suplantación ARP"
        if "PORT" in normalized or "SCAN" in normalized:
            return "escaneo de puertos"
        if "DOS" in normalized:
            return "denegación de servicio"
        if "ICMP" in normalized and "FLOOD" in normalized:
            return "inundación ICMP"
        if "SYN" in normalized and "FLOOD" in normalized:
            return "inundación SYN"
        if normalized == "MANUAL":
            return "manual"
        return value

    def _severity_for_attack(self, attack_type):
        normalized = self._normalize_attack_type(attack_type).lower()
        if "arp" in normalized or "dos" in normalized:
            return "critical"
        if "scan" in normalized:
            return "warning"
        return "suspicious"

    def _get_host_mac(self, ip_address):
        normalized_ip = str(ip_address).strip() if ip_address else None
        if not normalized_ip:
            return None
        with self.host_lock:
            mac_address = self.hosts.get(normalized_ip, {}).get("mac")
        if not mac_address or mac_address == "unknown":
            return None
        return mac_address

    def _attack_key(self, attack_type, attacker_ip, victim_ip=None):
        return (
            self._normalize_attack_type(attack_type),
            str(attacker_ip or "unknown").strip(),
            str(victim_ip or "unknown").strip(),
        )

    def _serialize_active_attacks(self):
        with self.security_event_lock:
            attacks = sorted(
                (dict(attack) for attack in self.active_attacks.values()),
                key=lambda item: item.get("last_seen", 0),
                reverse=True,
            )

        serialized = []
        for attack in attacks:
            serialized.append(
                {
                    "timestamp": self._format_event_timestamp(attack.get("last_seen"), include_date=False),
                    "type": attack.get("type", "Unknown"),
                    "attacker": attack.get("attacker", "unknown"),
                    "victim": attack.get("victim", "unknown"),
                    "attacker_mac": attack.get("attacker_mac") or "unknown",
                    "victim_mac": attack.get("victim_mac") or "unknown",
                    "severity": attack.get("severity", "suspicious"),
                    "status": attack.get("status", "active"),
                    "count": attack.get("count", 1),
                }
            )
        return serialized

    def _serialize_event_history(self):
        with self.security_event_lock:
            events = list(self.event_history)

        serialized = []
        for event in reversed(events):
            serialized.append(
                {
                    "timestamp": self._format_event_timestamp(event.get("timestamp")),
                    "type": event.get("type", "Unknown"),
                    "attacker": event.get("attacker", "unknown"),
                    "victim": event.get("victim", "unknown"),
                    "status": event.get("status", "unknown"),
                }
            )
        return serialized

    def _refresh_security_tables(self):
        self.security_update_pending = False
        if self.packet_view is not None:
            self.packet_view.update_active_alerts(self._serialize_active_attacks())
            self.packet_view.update_event_history(self._serialize_event_history())

    def _schedule_security_refresh(self):
        if self.security_update_pending:
            return
        self.security_update_pending = True
        try:
            self.root.after(200, self._refresh_security_tables)
        except tk.TclError:
            self.security_update_pending = False

    def _record_event_history(self, attack_type, attacker_ip=None, victim_ip=None, status="Detected"):
        with self.security_event_lock:
            self.event_history.append(
                {
                    "timestamp": time.time(),
                    "type": self._normalize_attack_type(attack_type),
                    "attacker": str(attacker_ip or "unknown").strip(),
                    "victim": str(victim_ip or "unknown").strip(),
                    "status": status,
                }
            )

    def _upsert_attack_event(
        self,
        attack_type,
        attacker_ip=None,
        victim_ip=None,
        status="active",
        attacker_mac=None,
        victim_mac=None,
        add_history=True,
    ):
        normalized_attack = self._normalize_attack_type(attack_type)
        normalized_attacker = str(attacker_ip or "unknown").strip()
        normalized_victim = str(victim_ip or "unknown").strip()
        if normalized_attacker == "unknown" and normalized_victim == "unknown":
            return

        now = time.time()
        key = self._attack_key(normalized_attack, normalized_attacker, normalized_victim)
        attacker_mac = attacker_mac or self._get_host_mac(normalized_attacker)
        victim_mac = victim_mac or self._get_host_mac(normalized_victim)

        with self.security_event_lock:
            existing = self.active_attacks.get(key)
            if existing is None:
                for existing_key, candidate in self.active_attacks.items():
                    same_attacker = candidate.get("attacker") == normalized_attacker
                    same_type = candidate.get("type") == normalized_attack
                    candidate_victim = str(candidate.get("victim") or "unknown").strip()
                    victim_matches = candidate_victim in {"unknown", normalized_victim} or normalized_victim == "unknown"
                    if same_attacker and same_type and victim_matches:
                        key = existing_key
                        existing = candidate
                        if candidate_victim == "unknown" and normalized_victim != "unknown":
                            existing["victim"] = normalized_victim
                        break
            previous_status = existing.get("status") if existing else None
            if existing is None:
                self.active_attacks[key] = {
                    "type": normalized_attack,
                    "attacker": normalized_attacker,
                    "victim": normalized_victim,
                    "attacker_mac": attacker_mac,
                    "victim_mac": victim_mac,
                    "severity": self._severity_for_attack(normalized_attack),
                    "status": status,
                    "first_seen": now,
                    "last_seen": now,
                    "count": 1,
                }
            else:
                existing["last_seen"] = now
                existing["status"] = status
                existing["count"] = int(existing.get("count", 1)) + 1
                existing["attacker_mac"] = attacker_mac or existing.get("attacker_mac")
                existing["victim_mac"] = victim_mac or existing.get("victim_mac")

            if add_history and (existing is None or previous_status != status):
                self._record_event_history(normalized_attack, normalized_attacker, normalized_victim, status.title())

        self._schedule_security_refresh()

    def _mark_attack_resolved(self, attacker_ip, status="Resolved"):
        normalized_ip = str(attacker_ip).strip() if attacker_ip else None
        if not normalized_ip:
            return

        with self.security_event_lock:
            for attack in self.active_attacks.values():
                if attack.get("attacker") == normalized_ip:
                    attack["status"] = status.lower()
                    attack["last_seen"] = time.time()
                    self._record_event_history(attack.get("type"), normalized_ip, attack.get("victim"), status)

        self._schedule_security_refresh()

    def _expire_inactive_attacks(self):
        now = time.time()
        changed = False
        with self.security_event_lock:
            for attack in self.active_attacks.values():
                status = str(attack.get("status", "")).lower()
                if status in {"resolved", "unblocked", "block failed"}:
                    continue
                if now - float(attack.get("last_seen", now)) < self.ATTACK_RESOLVE_TIMEOUT_S:
                    continue
                attack["status"] = "resolved"
                attack["last_seen"] = now
                self._record_event_history(attack.get("type"), attack.get("attacker"), attack.get("victim"), "Resolved")
                changed = True

        if changed:
            self._schedule_security_refresh()

    def _format_host_status_label(self, host):
        status = str(host.get("status", "active")).strip().lower()
        if bool(host.get("is_blocked", False)):
            block_type = str(host.get("block_type") or "").strip().lower()
            attack_type = str(host.get("attack_type") or "").strip()
            if block_type == "manual":
                return "Bloqueado (Manual)"
            if attack_type:
                return f"Bloqueado ({self._translate_attack_type_for_ui(attack_type)})"
            return "Bloqueado"
        if status == "suspicious":
            return "Sospechoso"
        return "Activo"

    def _resolve_host_state(self, existing=None, status=None, attack_type=None, clear_block=False):
        existing = existing or {}
        existing_status = str(existing.get("status", "active")).strip().lower() or "active"
        existing_attack_type = existing.get("attack_type")
        existing_is_blocked = bool(existing.get("is_blocked", False))
        existing_block_type = existing.get("block_type")

        next_status = str(status or existing_status or "active").strip().lower()
        next_attack_type = attack_type if attack_type is not None else existing_attack_type

        if clear_block:
            return next_status, next_attack_type, False, None

        if next_status == "blocked":
            next_is_blocked = True
            next_block_type = "manual" if str(next_attack_type or "").strip().lower() == "manual" else "auto"
            return next_status, next_attack_type, next_is_blocked, next_block_type

        if existing_is_blocked and next_status in {"active", "suspicious"}:
            preserved_attack_type = next_attack_type if next_attack_type is not None else existing_attack_type
            preserved_block_type = existing_block_type or (
                "manual" if str(preserved_attack_type or "").strip().lower() == "manual" else "auto"
            )
            return "blocked", preserved_attack_type, True, preserved_block_type

        if next_status == "active" and attack_type is None:
            next_attack_type = None

        return next_status, next_attack_type, False, None

    def _upsert_host(self, ip_address, mac_address=None, status=None, attack_type=None):
        normalized_ip = str(ip_address).strip() if ip_address else None
        if not normalized_ip:
            return

        normalized_mac = str(mac_address).strip().lower() if mac_address else None
        now = time.time()

        with self.host_lock:
            existing = self.hosts.get(normalized_ip)
            if existing is None:
                next_status, next_attack_type, next_is_blocked, next_block_type = self._resolve_host_state(
                    None,
                    status=status,
                    attack_type=attack_type,
                )
                self.hosts[normalized_ip] = {
                    "ip": normalized_ip,
                    "mac": normalized_mac or "unknown",
                    "status": next_status,
                    "is_blocked": next_is_blocked,
                    "block_type": next_block_type,
                    "attack_type": next_attack_type,
                    "last_seen": now,
                }
                logging.info("[HOST] New host detected: %s", normalized_ip)
            else:
                next_status, next_attack_type, next_is_blocked, next_block_type = self._resolve_host_state(
                    existing,
                    status=status,
                    attack_type=attack_type,
                )
                existing["mac"] = normalized_mac or existing.get("mac") or "unknown"
                existing["status"] = next_status
                existing["is_blocked"] = next_is_blocked
                existing["block_type"] = next_block_type
                existing["attack_type"] = next_attack_type
                existing["last_seen"] = now
                logging.info("[HOST] Updated host: %s status=%s", normalized_ip, existing["status"])

        self._schedule_hosts_refresh()

    def _set_host_status(self, ip_address, status, attack_type=None, clear_block=False):
        normalized_ip = str(ip_address).strip() if ip_address else None
        if not normalized_ip:
            return

        with self.host_lock:
            existing = self.hosts.get(normalized_ip)
            if existing is None:
                next_status, next_attack_type, next_is_blocked, next_block_type = self._resolve_host_state(
                    None,
                    status=status,
                    attack_type=attack_type,
                    clear_block=clear_block,
                )
                self.hosts[normalized_ip] = {
                    "ip": normalized_ip,
                    "mac": "unknown",
                    "status": next_status,
                    "is_blocked": next_is_blocked,
                    "block_type": next_block_type,
                    "attack_type": next_attack_type,
                    "last_seen": time.time(),
                }
                logging.info("[HOST] New host detected: %s", normalized_ip)
            else:
                next_status, next_attack_type, next_is_blocked, next_block_type = self._resolve_host_state(
                    existing,
                    status=status,
                    attack_type=attack_type,
                    clear_block=clear_block,
                )
                existing["status"] = next_status
                existing["is_blocked"] = next_is_blocked
                existing["block_type"] = next_block_type
                existing["attack_type"] = next_attack_type
                existing["last_seen"] = time.time()
                logging.info("[HOST] Updated host: %s status=%s blocked=%s", normalized_ip, next_status, next_is_blocked)

        self._schedule_hosts_refresh()

    def _parse_alert_message(self, message):
        details = self._parse_alert_details(message)
        return details.get("attack_type"), details.get("attacker_ip"), details.get("victim_ip")

    def _parse_alert_details(self, message):
        attack_type = None
        attacker_ip = None
        victim_ip = None
        spoofed_ip = None
        attacker_mac = None
        victim_mac = None

        lines = [line.strip() for line in str(message).splitlines() if line.strip()]
        upper_message = str(message).upper()
        if "ARP SPOOFING DETECTED" in upper_message:
            attack_type = "ARP"
        elif "PORT SCAN" in upper_message:
            attack_type = "PORT_SCAN"
        elif "DOS" in upper_message:
            attack_type = "DoS"

        for line in lines:
            upper_line = line.upper()
            if upper_line.startswith("ATTACKER IP:"):
                attacker_ip = line.split(":", 1)[1].strip()
            elif upper_line.startswith("VICTIM IP:"):
                victim_ip = line.split(":", 1)[1].strip()
            elif upper_line.startswith("TARGET IP:") and not victim_ip:
                victim_ip = line.split(":", 1)[1].strip()
            elif upper_line.startswith("SPOOFED IP:"):
                spoofed_ip = line.split(":", 1)[1].strip()
            elif upper_line.startswith("IP ATACANTE POSIBLE:") and not attacker_ip:
                attacker_ip = line.split(":", 1)[1].strip()
            elif upper_line.startswith("ATTACKER MAC:"):
                attacker_mac = line.split(":", 1)[1].strip()
            elif upper_line.startswith("VICTIM MAC:"):
                victim_mac = line.split(":", 1)[1].strip()
            elif upper_line.startswith("ATTACK TYPE:") and not attack_type:
                attack_type = line.split(":", 1)[1].strip()

        if attack_type == "ARP" and not attacker_ip:
            attacker_ip = spoofed_ip

        return {
            "attack_type": attack_type,
            "attacker_ip": attacker_ip,
            "victim_ip": victim_ip,
            "attacker_mac": attacker_mac,
            "victim_mac": victim_mac,
        }

    def _is_invalid_host_ip(self, ip_address):
        try:
            candidate = ipaddress.ip_address(str(ip_address).strip())
        except ValueError:
            return True

        if candidate.version != 4:
            return True
        if any(
            [
                candidate.is_loopback,
                candidate.is_multicast,
                candidate.is_unspecified,
                candidate.is_reserved,
                candidate == ipaddress.IPv4Address("255.255.255.255"),
            ]
        ):
            return True

        with self.services_lock:
            detection_service = self.detection_service
        if detection_service is None:
            return False

        for network in getattr(detection_service.engine, "local_networks", []) or []:
            if candidate == network.network_address or candidate == network.broadcast_address:
                return True

        return False

    def _handle_capture_startup_failure(self, startup_token, error_message):
        if startup_token != self.startup_token:
            return

        self.startup_in_progress = False
        logging.error("[UI] Capture startup failed: %s", error_message)
        messagebox.showerror("Error al iniciar la captura", error_message)
        self.show_interface_selection()

    def _cancel_startup(self):
        if not self.startup_in_progress:
            self.show_interface_selection()
            return

        logging.info("[UI] Startup cancelled by user")
        self._cancel_connection_timeout()
        self.startup_in_progress = False
        self.startup_token += 1
        self._reset_runtime_services()
        if self.router_view is not None:
            self.router_view.set_busy(False, "", keep_cancel_enabled=True)
        self.show_interface_selection()

    def _show_packet_view(self, startup_data):
        interface_info = startup_data["interface"]
        config = startup_data["config"]
        set_active_mikrotik_config(config)

        self.packet_view = PacketView(
            self.container,
            on_pause=self.pause_capture,
            on_resume=self.resume_capture,
            on_stop=self.stop_capture,
            on_unblock_host=self.unblock_host,
            on_block_host=self.block_host,
        )
        self.packet_view.set_interface(interface_info.name, startup_data["interface_ip"])
        self.packet_view.set_mikrotik_status("Conectando...", connected=False)
        self.packet_view.set_capture_status("Inicializando...")
        self.packet_view.append_log(
            f"Preparando captura en {interface_info.name} ({interface_info.identifier})...",
            level="info",
        )
        self.packet_view.update_hosts(self._serialize_hosts())
        self.packet_view.update_active_alerts(self._serialize_active_attacks())
        self.packet_view.update_event_history(self._serialize_event_history())
        self._set_view(self.packet_view)

    def handle_packet(self, packet):
        try:
            self.packet_pipeline_queue.put_nowait(packet)
        except queue.Full:
            self._rate_limited_warning("packet_queue_full", "[PIPELINE] Cola de paquetes llena; se descartan paquetes para conservar la respuesta en tiempo real")

    def _track_packet_hosts(self, packet):
        if packet.haslayer(ARP):
            arp_ip = str(packet[ARP].psrc).strip() if getattr(packet[ARP], "psrc", None) else None
            if arp_ip and not self._is_invalid_host_ip(arp_ip):
                self._upsert_host(arp_ip, packet[ARP].hwsrc, status="active", attack_type=None)
            return

        if packet.haslayer(IP) and packet.haslayer(Ether):
            src_ip = str(packet[IP].src).strip() if getattr(packet[IP], "src", None) else None
            if src_ip and not self._is_invalid_host_ip(src_ip):
                self._upsert_host(src_ip, packet[Ether].src, status="active", attack_type=None)

    def handle_alert(self, message):
        if not message:
            return
        upper_message = str(message).upper()
        if "ARP SPOOFING DETECTED" in upper_message:
            logging.warning("[IDS] ARP attack detected")
        elif "DOS" in upper_message:
            logging.warning("[IDS] DoS detected")
        elif "PORT SCAN" in upper_message:
            logging.warning("[IDS] Port scan detected")
        alert_details = self._parse_alert_details(message)
        attack_type = alert_details.get("attack_type")
        attacker_ip = alert_details.get("attacker_ip")
        victim_ip = alert_details.get("victim_ip")
        attacker_mac = alert_details.get("attacker_mac")
        victim_mac = alert_details.get("victim_mac")
        if attacker_ip and attack_type:
            self._set_host_status(attacker_ip, "suspicious", attack_type=attack_type)
            self._upsert_attack_event(
                attack_type,
                attacker_ip=attacker_ip,
                victim_ip=victim_ip,
                status="active",
                attacker_mac=attacker_mac,
                victim_mac=victim_mac,
            )
        if victim_ip:
            self._set_host_status(victim_ip, "active", attack_type=None)
        if attacker_ip or victim_ip:
            log_message = (
                f"Alerta detectada: {self._translate_attack_type_for_ui(attack_type)}\n"
                f"Atacante: {attacker_ip or 'desconocido'}\n"
                f"Víctima: {victim_ip or 'desconocida'}\n"
                f"MAC víctima: {victim_mac or self._get_host_mac(victim_ip) or 'desconocida'}"
            )
        else:
            log_message = message
        self.ui_queue.put({"type": "log", "data": {"message": log_message, "level": self._infer_log_level(message)}})

    def _infer_log_level(self, message):
        upper_message = str(message).upper()
        if "[BLOCK" in upper_message or "[ALERT" in upper_message:
            return "alert"
        if "[WARNING" in upper_message:
            return "warning"
        if "[ERROR" in upper_message:
            return "error"
        return "info"

    def block_attacker_connection(self, attacker_ip, attacker_mac=None, attack_type="Unknown"):
        normalized_ip = str(attacker_ip).strip() if attacker_ip else None
        if not normalized_ip:
            return False

        normalized_mac = str(attacker_mac).strip().lower() if attacker_mac else None
        if not normalized_mac:
            with self.host_lock:
                normalized_mac = self.hosts.get(normalized_ip, {}).get("mac")

        with self.services_lock:
            mikrotik_manager = self.mikrotik_manager

        if mikrotik_manager is None:
            self.ui_queue.put(
                {
                    "type": "log",
                    "data": {
                        "message": f"La conexión con el router no está disponible. No se pudo bloquear {normalized_ip}.",
                        "level": "error",
                    },
                }
            )
            return False

        logging.warning("[BLOCK] Blocking attacker %s", normalized_ip)
        self._set_host_status(normalized_ip, "suspicious", attack_type=attack_type)
        self._upsert_attack_event(
            attack_type,
            attacker_ip=normalized_ip,
            victim_ip=None,
            status="queued",
            attacker_mac=normalized_mac,
        )
        self._queue_mikrotik_action(
            "block",
            ip_address=normalized_ip,
            mac_address=normalized_mac,
            attack_type=attack_type,
        )
        return True

    def block_host(self, ip_address):
        normalized_ip = str(ip_address).strip() if ip_address else None
        if not normalized_ip:
            return False

        with self.services_lock:
            mikrotik_manager = self.mikrotik_manager

        if mikrotik_manager is None:
            self._append_runtime_log(f"No se pudo bloquear {normalized_ip}: el router no está conectado.", level="error")
            return False

        with self.host_lock:
            host_entry = dict(self.hosts.get(normalized_ip, {}))
        host_mac = host_entry.get("mac")
        if host_mac == "unknown":
            host_mac = None

        self._set_host_status(normalized_ip, "blocked", attack_type="manual")
        self._upsert_attack_event(
            "Manual",
            attacker_ip=normalized_ip,
            victim_ip=None,
            status="queued",
            attacker_mac=host_mac,
        )
        self._queue_mikrotik_action(
            "block",
            ip_address=normalized_ip,
            mac_address=host_mac,
            attack_type="manual",
        )
        self._append_runtime_log(f"Bloqueo manual en cola para {normalized_ip}.", level="warning")
        return True

    def pause_capture(self):
        with self.services_lock:
            capture_service = self.capture_service
        if capture_service is not None:
            capture_service.pause()
            if self.packet_view is not None:
                self.packet_view.set_capture_state(paused=True, stopped=False)
                self.packet_view.append_log("Captura pausada.", level="warning")

    def resume_capture(self):
        with self.services_lock:
            capture_service = self.capture_service
        if capture_service is not None:
            capture_service.resume()
            if self.packet_view is not None:
                self.packet_view.set_capture_state(paused=False, stopped=False)
                self.packet_view.append_log("Captura reanudada.", level="info")

    def stop_capture(self):
        with self.services_lock:
            capture_service = self.capture_service
        if capture_service is not None:
            capture_service.stop()
        if self.packet_view is not None:
            self.packet_view.set_capture_state(paused=False, stopped=True)
            self.packet_view.append_log("Captura detenida de forma segura.", level="warning")

    def unblock_host(self, ip_address):
        normalized_ip = str(ip_address).strip() if ip_address else None
        if not normalized_ip:
            return False

        with self.services_lock:
            mikrotik_manager = self.mikrotik_manager
            detection_service = self.detection_service

        if mikrotik_manager is None or not mikrotik_manager.is_connected():
            self._append_runtime_log(f"No se pudo desbloquear {normalized_ip}: el router no está conectado.", level="error")
            return False

        with self.host_lock:
            host_entry = dict(self.hosts.get(normalized_ip, {}))
        host_mac = host_entry.get("mac")
        if host_mac == "unknown":
            host_mac = None

        unblocked = self._run_mikrotik_action(
            "unblock",
            ip_address=normalized_ip,
            mac_address=host_mac,
        )
        if not unblocked:
            self._append_runtime_log(f"No se pudo desbloquear {normalized_ip}.", level="error")
            return False

        if detection_service is not None:
            detection_service.clear_attack_state(normalized_ip)
            detection_service.reset_host_state(normalized_ip)

        self._set_host_status(normalized_ip, "active", attack_type=None, clear_block=True)
        self._mark_attack_resolved(normalized_ip, status="Unblocked")
        self._record_event_history("Manual", normalized_ip, None, "Unblocked")
        self._schedule_security_refresh()
        self._append_runtime_log(f"El equipo {normalized_ip} fue desbloqueado manualmente.", level="info")
        return True

    def process_ui_queue(self):
        self._expire_inactive_attacks()
        packet_batch = []
        with self.packet_buffer_lock:
            if self.packet_buffer:
                packet_batch = self.packet_buffer[: self.packet_flush_limit]
                del self.packet_buffer[: self.packet_flush_limit]

        if self.packet_view is not None and packet_batch:
            for packet_record in packet_batch:
                self.packet_view.add_packet(packet_record)

        try:
            while True:
                task = self.ui_queue.get_nowait()
                task_type = task.get("type")
                task_data = task.get("data")

                if task_type == "log" and self.packet_view is not None:
                    self.packet_view.append_log(task_data["message"], level=task_data.get("level", "info"))
                elif task_type == "log":
                    self.deferred_events.append(task)
                elif task_type == "status" and self.packet_view is not None:
                    text = task_data.get("text", "Desconectado")
                    self.packet_view.set_mikrotik_status(text, connected=bool(task_data.get("connected")))
                elif task_type == "status":
                    self.deferred_events.append(task)
        except queue.Empty:
            pass

        if self.packet_view is not None and self.deferred_events:
            for deferred_task in self.deferred_events:
                self.ui_queue.put(deferred_task)
            self.deferred_events.clear()

        try:
            if self.root.winfo_exists():
                self.root.after(200, self.process_ui_queue)
        except tk.TclError:
            return

    def shutdown(self):
        self._cancel_connection_timeout()
        self.worker_stop_event.set()
        with self.services_lock:
            capture_service = self.capture_service
            mikrotik_manager = self.mikrotik_manager

        self._cleanup_services(capture_service=capture_service, mikrotik_manager=mikrotik_manager)
        self.root.destroy()


def main():
    root = tk.Tk()
    AppController(root)
    root.mainloop()


if __name__ == "__main__":
    main()
