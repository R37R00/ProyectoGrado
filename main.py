import logging
import os
import queue
import socket
import sys

from PyQt5.QtCore import QTimer
from PyQt5.QtWidgets import QApplication, QInputDialog, QMessageBox
from scapy.all import conf

from detection_engine import DetectionEngine
from interfaz_grafica import MainWindow
from mikrotik_handler import MikrotikManager
from network_capture import NetworkCaptureScanner


logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
)


def get_friendly_interfaces():
    interfaces = []
    try:
        for iface in conf.ifaces.values():
            real_name = getattr(iface, "name", None)
            if not real_name:
                continue

            friendly_name = getattr(iface, "description", "") or real_name
            interfaces.append((friendly_name, real_name))
    except Exception as error:
        logging.error("Error al obtener interfaces amigables: %s", error)

    unique = {}
    for friendly_name, real_name in interfaces:
        if real_name not in unique:
            unique[real_name] = friendly_name

    return [(friendly_name, real_name) for real_name, friendly_name in unique.items()]


class AppController:
    def __init__(self):
        conf.verb = 1

        self.window = MainWindow()
        self.detection_engine = DetectionEngine()
        self.packet_event_queue = queue.Queue()

        self.window.packet_text_edit.document().setMaximumBlockCount(200)
        self.mikrotik_manager = self._build_mikrotik_manager()

        self.packet_flush_timer = QTimer()
        self.packet_flush_timer.setInterval(300)
        self.packet_flush_timer.timeout.connect(self.flush_packet_events)

        self.friendly_interfaces = get_friendly_interfaces()
        self.window.set_capture_interfaces(self.friendly_interfaces)

        selected_interface = self.window.get_selected_capture_interface()
        self.network_capture = NetworkCaptureScanner(
            packet_callback=self.handle_packet,
            hosts_callback=self.window.hosts_found_signal.emit,
            interface=selected_interface,
        )

        self.detection_engine.set_alert_callback(self.handle_alert)
        self.detection_engine.set_block_callback(self.block_attacker_connection)
        self.detection_engine.set_capture_interface(selected_interface)
        self.detection_engine.configure_mitigation(**self.window.get_mitigation_options())
        self.detection_engine.set_whitelist(self._build_block_whitelist())
        self.window.bind_actions(
            pause_callback=self.pause_capture,
            continue_callback=self.continue_capture,
            stop_callback=self.stop_capture,
            find_hosts_callback=self.network_capture.find_hosts,
            block_host_callback=self.block_attacker_connection,
        )

    def _build_mikrotik_manager(self):
        host = os.getenv("MIKROTIK_HOST")
        username = os.getenv("MIKROTIK_USER")
        password = os.getenv("MIKROTIK_PASSWORD")
        port = int(os.getenv("MIKROTIK_PORT", "8728"))
        unblock_seconds = int(os.getenv("MIKROTIK_UNBLOCK_SECONDS", "300"))

        if not host or not username or not password:
            logging.warning("MikroTik no configurado (faltan variables de entorno)")
            return None

        manager = MikrotikManager(
            host=host,
            username=username,
            password=password,
            port=port,
            address_list_name="blacklist",
            default_unblock_seconds=unblock_seconds,
        )
        manager.connect()
        return manager

    def _build_block_whitelist(self):
        whitelist = set()
        router_ip = os.getenv("MIKROTIK_HOST")
        if router_ip:
            whitelist.add(router_ip)

        try:
            local_ip = socket.gethostbyname(socket.gethostname())
            if local_ip:
                whitelist.add(local_ip)
        except Exception:
            pass

        try:
            route = conf.route.route("0.0.0.0")
            gateway_ip = route[2] if len(route) > 2 else None
            if gateway_ip and gateway_ip != "0.0.0.0":
                whitelist.add(gateway_ip)
        except Exception:
            pass

        return whitelist

    def handle_packet(self, packet):
        self.window.packet_count += 1
        self.detection_engine.process_packet(packet)

        self.packet_event_queue.put(packet.summary())

    def flush_packet_events(self):
        displayed = 0
        while displayed < 30:
            try:
                summary = self.packet_event_queue.get_nowait()
            except queue.Empty:
                break
            self.window.packet_received_signal.emit(summary)
            displayed += 1


    def handle_alert(self, message):
        self.window.anomaly_detected_signal.emit(message)

    def pause_capture(self):
        self.network_capture.pause_capture()

    def continue_capture(self):
        self.network_capture.resume_capture()

    def stop_capture(self):
        self.network_capture.stop_capture()

    def block_attacker_connection(self, attacker_ip):
        if not attacker_ip:
            return

        blocked = False
        if self.mikrotik_manager:
            blocked = self.mikrotik_manager.block_ip(attacker_ip, attack_type="ARP Spoofing")
        else:
            logging.warning("Solicitud de bloqueo sin MikroTik configurado: %s", attacker_ip)

        if blocked:
            existing = self.window.hosts.get(attacker_ip, {})
            mac = existing.get("mac", "unknown")
            self.window.update_hosts(
                attacker_ip,
                mac,
                status="Blocked",
                host_type=existing.get("type", "Host"),
                activity="ARP Spoofing",
            )
            self.window.anomaly_detected_signal.emit(f"[BLOCKED] IP bloqueada: {attacker_ip}")

    def ask_user_interface_if_needed(self):
        if len(self.friendly_interfaces) <= 1:
            return

        friendly_names = [friendly for friendly, _real in self.friendly_interfaces]
        selected_name, accepted = QInputDialog.getItem(
            self.window,
            "Seleccionar interfaz de red",
            "Se detectaron múltiples interfaces. Elige cuál deseas usar:",
            friendly_names,
            editable=False,
        )

        if not accepted or not selected_name:
            return

        selected_real = next(
            (real for friendly, real in self.friendly_interfaces if friendly == selected_name),
            None,
        )
        if selected_real:
            self.window.set_selected_capture_interface(selected_real)

    def run(self):
        self.ask_user_interface_if_needed()

        selected_interface = self.window.get_selected_capture_interface()
        self.network_capture.interface = selected_interface
        self.detection_engine.set_capture_interface(selected_interface)
        self.detection_engine.configure_mitigation(**self.window.get_mitigation_options())
        self.detection_engine.build_arp_baseline()

        if selected_interface is None:
            QMessageBox.warning(
                self.window,
                "Interfaz de red",
                "No se pudo determinar una interfaz de captura. Se usará la interfaz por defecto de Scapy.",
            )

        self.packet_flush_timer.start()
        self.window.show()
        self.network_capture.start_capture_thread()


def main():
    app = QApplication(sys.argv)
    controller = AppController()
    controller.run()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
