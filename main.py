import logging
import queue
import sys

from PyQt5.QtCore import QTimer
from PyQt5.QtWidgets import QApplication, QInputDialog, QMessageBox
from scapy.all import conf
from scapy.layers.l2 import ARP

from detection_engine import DetectionEngine
from interfaz_grafica import MainWindow
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
        self.window.bind_actions(
            pause_callback=self.pause_capture,
            continue_callback=self.continue_capture,
            stop_callback=self.stop_capture,
            find_hosts_callback=self.network_capture.find_hosts,
            block_host_callback=self.block_attacker_connection,
        )

    def should_display_packet(self, packet):
        return ARP in packet

    def handle_packet(self, packet):
        if self.window.capture_paused:
            return

        self.window.packet_count += 1
        self.detection_engine.process_packet(packet)

        if self.should_display_packet(packet):
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
        pass

    def continue_capture(self):
        pass

    def stop_capture(self):
        self.network_capture.stop_capture()

    def block_attacker_connection(self, attacker_ip):
        print(f"Bloqueo solicitado para: {attacker_ip}")

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
