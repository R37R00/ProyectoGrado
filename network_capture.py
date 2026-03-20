import ipaddress
import logging

from scapy.all import AsyncSniffer, ARP, Ether, srp
import netifaces
import psutil

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

    def get_interface_ip(self, interface_name):
        if not interface_name:
            logging.error("No se definió interfaz para resolver IP")
            return None

        target = interface_name.lower().strip()

        try:
            for iface in netifaces.interfaces():
                iface_lower = iface.lower()
                if target == iface_lower or target in iface_lower or iface_lower in target:
                    addresses = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])
                    for addr_data in addresses:
                        ip_addr = addr_data.get("addr")
                        if ip_addr:
                            return ip_addr
        except Exception as error:
            logging.warning("Fallo netifaces al resolver interfaz '%s': %s", interface_name, error)

        try:
            for iface, addrs in psutil.net_if_addrs().items():
                iface_lower = iface.lower()
                if target == iface_lower or target in iface_lower or iface_lower in target:
                    for addr in addrs:
                        if getattr(addr, "family", None) == 2 and addr.address:
                            return addr.address
        except Exception as error:
            logging.warning("Fallo psutil al resolver interfaz '%s': %s", interface_name, error)

        logging.error("No se pudo obtener IP para la interfaz seleccionada: %s", interface_name)
        return None

    def find_hosts(self, network_cidr=None):
        try:
            if network_cidr:
                network = ipaddress.IPv4Network(network_cidr, strict=False)
                logging.info("Escaneando red (override): %s", network)
            else:
                local_ip = self.get_interface_ip(self.interface)
                if not local_ip:
                    logging.error("No se ejecuta escaneo: no se pudo resolver IP de interfaz")
                    return
                network = ipaddress.IPv4Network(local_ip + "/24", strict=False)
                logging.info("Usando interfaz: %s con IP: %s", self.interface, local_ip)
                logging.info("Escaneando red: %s", network)

            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))
            result = srp(arp_request, timeout=3, verbose=False, iface=self.interface)[0]
            hosts = [{"ip": received.psrc, "mac": received.hwsrc} for _sent, received in result]
            self.hosts_callback(hosts)
        except Exception as error:
            logging.error("Error al buscar hosts en la red: %s", error)
