import ipaddress
import logging
import socket

import psutil
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

    def get_interface_ip(self, interface_name):
        if not interface_name:
            return None

        interfaces = psutil.net_if_addrs()
        interface_name_lower = interface_name.lower()

        for iface, addr_list in interfaces.items():
            if interface_name_lower in iface.lower():
                for addr in addr_list:
                    if addr.family == socket.AF_INET:
                        return addr.address

        return None

    def find_hosts(self):
        try:
            local_ip = self.get_interface_ip(self.interface)
            if not local_ip:
                logging.error("No se encontró una IP IPv4 para la interfaz seleccionada: %s", self.interface)
                return

            network = ipaddress.IPv4Network(local_ip + "/24", strict=False)
            logging.info(f"Interfaz seleccionada: {self.interface}")
            logging.info(f"IP detectada: {local_ip}")
            logging.info(f"Red escaneada: {network}")

            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))
            result = srp(arp_request, timeout=3, verbose=False, iface=self.interface)[0]
            hosts = [{"ip": received.psrc, "mac": received.hwsrc} for _sent, received in result]
            self.hosts_callback(hosts)
        except Exception as error:
            logging.error("Error al buscar hosts en la red: %s", error)