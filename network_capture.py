import ipaddress
import socket
import threading
import logging

from scapy.all import sniff, ARP, Ether, srp
from scapy.layers.inet import IP


class NetworkCaptureScanner:
    def __init__(self, packet_callback, hosts_callback, interface=None):
        self.packet_callback = packet_callback
        self.hosts_callback = hosts_callback
        self.interface = interface
        self.capture_stopped = False
        self.capture_thread = None

    def start_capture_thread(self):
        self.capture_stopped = False
        self.capture_thread = threading.Thread(target=self.start_capture, daemon=True)
        self.capture_thread.start()

    def stop_capture(self):
        self.capture_stopped = True
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=3)

    def should_stop(self, _packet):
        return self.capture_stopped

    def start_capture(self):
        try:
            logging.info("Iniciando captura en interfaz real: %s", self.interface)
            sniff(iface=self.interface, prn=self._handle_packet, stop_filter=self.should_stop)
        except Exception as error:
            print("Error en la captura de paquetes:", error)

    def _handle_packet(self, packet):
        try:
            if IP in packet:
                self.packet_callback(packet)
        except Exception as error:
            print("Error al manejar el paquete:", error)

    def find_hosts(self):
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            network = ipaddress.IPv4Network(local_ip + "/24", strict=False)

            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))
            result = srp(arp_request, timeout=3, verbose=False)[0]
            hosts = [{"ip": received.psrc, "mac": received.hwsrc} for _sent, received in result]
            self.hosts_callback(hosts)
        except Exception as error:
            print("Error al buscar hosts en la red:", error)
