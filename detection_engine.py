import logging

from scapy.all import ARP, sr1
from scapy.layers.inet import IP, ICMP, TCP


class DetectionEngine:
    def __init__(self):
        self.packet_counter = 0
        self.syn_counter = 0
        self.ip_packet_count = {}
        self.arp_table = {}
        self.mac_table = {}
        self.alert_callback = None

    def set_alert_callback(self, callback):
        self.alert_callback = callback

    def process_packet(self, packet):
        try:
            if IP in packet:
                src_ip = packet[IP].src
                self.packet_counter += 1
                self.ip_packet_count[src_ip] = self.ip_packet_count.get(src_ip, 0) + 1

                if TCP in packet and packet[TCP].flags & 0x02:
                    self.syn_counter += 1

                if ICMP in packet and packet[ICMP].type == 8:
                    self.trigger_alert(f"Actividad ICMP sospechosa desde {src_ip}")

            if packet.haslayer(ARP):
                self.detect_arp_spoofing(packet)

        except Exception as error:
            logging.error("Error en process_packet: %s", error)

    def active_arp_verification(self, ip, expected_mac):
        try:
            logging.debug("Verificación ARP activa para IP %s con MAC esperada %s", ip, expected_mac)
            response = sr1(ARP(op=1, pdst=ip), timeout=2, verbose=False)
            if response and response.haslayer(ARP):
                verified_mac = response[ARP].hwsrc
                logging.debug("Respuesta verificada para IP %s: MAC %s", ip, verified_mac)
                return verified_mac.lower() == expected_mac.lower()
        except Exception as error:
            logging.error("Error en verificación ARP activa para %s: %s", ip, error)
        return False

    def _update_mac_table(self, ip, new_mac, old_mac=None):
        if old_mac:
            old_ips = self.mac_table.get(old_mac, set())
            old_ips.discard(ip)
            if not old_ips and old_mac in self.mac_table:
                del self.mac_table[old_mac]

        ips_for_mac = self.mac_table.setdefault(new_mac, set())
        ips_for_mac.add(ip)

    def _find_possible_attacker_ip(self, suspicious_mac, spoofed_ip):
        known_ips = self.mac_table.get(suspicious_mac, set())
        candidates = sorted(ip for ip in known_ips if ip != spoofed_ip)
        return candidates[0] if candidates else None

    def detect_arp_spoofing(self, packet):
        try:
            arp_layer = packet[ARP]
            src_ip = arp_layer.psrc
            src_mac = arp_layer.hwsrc

            if not src_ip or not src_mac:
                return

            known_mac = self.arp_table.get(src_ip)

            if known_mac is None:
                self.arp_table[src_ip] = src_mac
                self._update_mac_table(src_ip, src_mac)
                logging.debug("Nueva asociación IP-MAC registrada: %s -> %s", src_ip, src_mac)
                return

            if known_mac.lower() == src_mac.lower():
                self._update_mac_table(src_ip, src_mac)
                return

            logging.debug("Cambio detectado para IP %s: %s -> %s", src_ip, known_mac, src_mac)
            possible_attacker_ip = self._find_possible_attacker_ip(src_mac, src_ip)

            alert_lines = [
                "ARP SPOOFING DETECTED",
                f"Spoofed IP: {src_ip}",
                f"Original MAC: {known_mac}",
                f"Suspicious MAC (possible attacker): {src_mac}",
            ]
            if possible_attacker_ip:
                alert_lines.append(f"Possible attacker IP: {possible_attacker_ip}")

            self.trigger_alert("\n".join(alert_lines))

            if not self.active_arp_verification(src_ip, known_mac):
                self.trigger_alert(f"ARP Spoofing confirmado para IP {src_ip}")
            else:
                self.arp_table[src_ip] = src_mac
                self._update_mac_table(src_ip, src_mac, old_mac=known_mac)

            ips_for_mac = self.mac_table.setdefault(src_mac, set())
            ips_for_mac.add(src_ip)
            if len(ips_for_mac) > 1:
                ips_list = ", ".join(sorted(ips_for_mac))
                self.trigger_alert(f"Advertencia: MAC {src_mac} anuncia múltiples IP: {ips_list}")

        except Exception as error:
            logging.error("Error en detect_arp_spoofing: %s", error)

    def detect_arp_spoof(self, packet):
        self.detect_arp_spoofing(packet)

    def check_dos(self):
        for ip, count in self.ip_packet_count.items():
            if count > 500:
                self.trigger_alert(f"Posible DoS desde {ip}")

        self.packet_counter = 0
        self.syn_counter = 0
        self.ip_packet_count = {}

    def trigger_alert(self, message):
        if self.alert_callback:
            self.alert_callback(message)
