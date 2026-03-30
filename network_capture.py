import ipaddress
import logging
import socket
import threading

import psutil
from scapy.all import ARP, Ether, sniff, srp

from event_logger import log_debug


DEBUG = True


class NetworkCaptureScanner:
    def __init__(self, packet_callback, hosts_callback, interface=None):
        self.packet_callback = packet_callback
        self.hosts_callback = hosts_callback
        self.interfaces = []
        self.interface = None

        self.capture_running = False
        self.capture_paused = False
        self.capture_threads = []
        self.stop_event = threading.Event()

        self.set_interfaces(interface)

    def set_interfaces(self, interfaces):
        if interfaces is None:
            normalized = []
        elif isinstance(interfaces, (list, tuple)):
            normalized = [iface for iface in interfaces if iface]
        else:
            normalized = [interfaces] if interfaces else []

        self.interfaces = normalized[:2]
        self.interface = self.interfaces[0] if self.interfaces else None

    def start_capture_thread(self, interfaces=None):
        if interfaces is not None:
            self.set_interfaces(interfaces)

        if not self.interfaces:
            logging.error("No hay interfaces configuradas para captura")
            return False

        self.stop_capture()

        self.capture_running = True
        self.capture_paused = False
        self.stop_event.clear()
        self.capture_threads = []

        for iface in self.interfaces:
            thread = threading.Thread(
                target=self._capture_loop,
                args=(iface,),
                daemon=True,
            )
            thread.start()
            self.capture_threads.append(thread)

        return True

    def _capture_loop(self, interface_name):
        try:
            logging.info("Iniciando captura en interfaz real: %s", interface_name)
            if DEBUG:
                log_debug(f"Selected interface for capture: {interface_name}")

            while self.capture_running and not self.stop_event.is_set():
                sniff(
                    iface=interface_name,
                    prn=self._handle_packet,
                    store=False,
                    filter=None,
                    timeout=1,
                )
        except Exception as error:
            logging.error("Error en la captura de paquetes sobre %s: %s", interface_name, error)

    def stop_capture(self):
        self.capture_running = False
        self.capture_paused = False
        self.stop_event.set()

        for thread in self.capture_threads:
            if thread.is_alive():
                thread.join(timeout=2)

        self.capture_threads = []

    def resume_capture(self):
        self.capture_paused = False

    def pause_capture(self):
        self.capture_paused = True

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
            active_interface = self.interface or (self.interfaces[0] if self.interfaces else None)
            local_ip = self.get_interface_ip(active_interface)
            if not local_ip:
                logging.error("No se encontro una IP IPv4 para la interfaz seleccionada: %s", active_interface)
                return

            network = ipaddress.IPv4Network(local_ip + "/24", strict=False)
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))
            result = srp(arp_request, timeout=3, verbose=False, iface=active_interface)[0]
            hosts = [{"ip": received.psrc, "mac": received.hwsrc} for _sent, received in result]

            self.hosts_callback(hosts)
        except Exception as error:
            logging.error("Error al buscar hosts en la red: %s", error)
