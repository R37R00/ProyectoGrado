import re
import sys

import psutil
from PyQt5.QtWidgets import QApplication, QInputDialog, QMessageBox
from scapy.all import conf, get_if_list

from detection_engine import DetectionEngine
from interfaz_grafica import MainWindow
from network_capture import NetworkCaptureScanner


def get_friendly_interfaces():
    interfaces = []
    try:
        scapy_interfaces = get_if_list()
        os_interfaces = list(psutil.net_if_addrs().keys())

        for npf_name in scapy_interfaces:
            if not npf_name:
                continue

            friendly_name = npf_name
            guid_match = re.search(r"\{[0-9A-Fa-f\-]+\}", npf_name)

            if guid_match:
                guid = guid_match.group(0).strip("{}").lower()
                mapped_name = next(
                    (
                        name
                        for name in os_interfaces
                        if guid in name.lower()
                    ),
                    None,
                )
                if mapped_name:
                    friendly_name = mapped_name
                else:
                    friendly_name = f"Interfaz ({guid_match.group(0)})"

            interfaces.append((friendly_name, npf_name))

    except Exception as error:
        print("Error al obtener interfaces amigables:", error)

    # Evitar duplicados preservando el identificador real (npf)
    unique = {}
    for friendly_name, npf_name in interfaces:
        unique[npf_name] = friendly_name

    return [(friendly_name, npf_name) for npf_name, friendly_name in unique.items()]


class AppController:
    def __init__(self):
        conf.verb = 1

        self.window = MainWindow()
        self.detection_engine = DetectionEngine()

        self.friendly_interfaces = get_friendly_interfaces()
        self.window.set_capture_interfaces(self.friendly_interfaces)

        selected_interface = self.window.get_selected_capture_interface()
        self.network_capture = NetworkCaptureScanner(
            packet_callback=self.handle_packet,
            hosts_callback=self.window.hosts_found_signal.emit,
            interface=selected_interface,
        )

        self.detection_engine.set_alert_callback(self.window.handle_alert)
        self.window.bind_actions(
            pause_callback=self.pause_capture,
            continue_callback=self.continue_capture,
            stop_callback=self.stop_capture,
            find_hosts_callback=self.network_capture.find_hosts,
            block_host_callback=self.block_attacker_connection,
        )

    def handle_packet(self, packet):
        if self.window.capture_paused:
            return
        self.window.packet_count += 1
        self.window.packet_received_signal.emit(packet.summary())
        self.detection_engine.process_packet(packet)

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

        self.window.show()
        self.network_capture.start_capture_thread()


def main():
    app = QApplication(sys.argv)
    controller = AppController()
    controller.run()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
