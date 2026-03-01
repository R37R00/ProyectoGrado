import sys

from PyQt5.QtWidgets import QApplication
from scapy.all import conf

from detection_engine import DetectionEngine
from interfaz_grafica import MainWindow
from network_capture import NetworkCaptureScanner


class AppController:
    def __init__(self):
        conf.verb = 1

        self.window = MainWindow()
        self.detection_engine = DetectionEngine()
        self.network_capture = NetworkCaptureScanner(
            packet_callback=self.handle_packet,
            hosts_callback=self.window.hosts_found_signal.emit,
            interface="Qualcomm Atheros AR956x Wireless Network Adapter",
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

    def run(self):
        self.window.show()
        self.network_capture.start_capture_thread()


def main():
    app = QApplication(sys.argv)
    controller = AppController()
    controller.run()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
