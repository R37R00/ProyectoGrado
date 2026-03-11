import ipaddress
import logging
import socket

from scapy.all import AsyncSniffer, ARP, Ether, srp


class NetworkCaptureScanner:
    def __init__(self, packet_callback, hosts_callback, interface=None):
        self.packet_callback = packet_callback
        self.hosts_callback = hosts_callback
        self.interface = interface

        self.capture_running = False
        self.capture_paused = False
        self.sniffer = None

    def start_capture_thread(self):
        self.capture_running = True
        self.capture_paused = False
        self.start_capture()

    def stop_capture(self):
        self.capture_running = False
        if self.sniffer:
            try:
                self.sniffer.stop()
            except Exception as error:
                logging.error("Error al detener captura: %s", error)
            finally:
                self.sniffer = None

    def pause_capture(self):
        self.capture_paused = True

    def resume_capture(self):
        self.capture_paused = False

    def start_capture(self):
        try:
            logging.info("Iniciando captura en interfaz real: %s", self.interface)
            self.sniffer = AsyncSniffer(
                iface=self.interface,
                prn=self._handle_packet,
                store=False,
            )
            self.sniffer.start()
        except Exception as error:
            logging.error("Error en la captura de paquetes: %s", error)

    def _handle_packet(self, packet):
        try:
            if not self.capture_running or packet is None or self.capture_paused:
                return

            self.packet_callback(packet)

        except Exception as error:
            logging.error("Error al manejar el paquete: %s", error)

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
