import logging
import time

from scapy.all import ARP, Ether, srp
from scapy.layers.inet import IP, ICMP, TCP


class DetectionEngine:
    def __init__(self):
        self.packet_counter = 0
        self.syn_counter = 0
        self.ip_packet_count = {}

        self.arp_table = {}
        self.mac_table = {}
        self.suspicious_arp_events = {}
        self.arp_suspicion_window_s = 5
        self.arp_suspicion_threshold = 3

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

    def active_arp_verification(self, ip, previous_mac, observed_mac):
        try:
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=ip)
            answered = srp(arp_request, timeout=2, verbose=False)[0]
            if not answered:
                return False

            verified_mac = answered[0][1][ARP].hwsrc
            logging.debug(
                "Verificación ARP para %s: previous=%s observed=%s verified=%s",
                ip,
                previous_mac,
                observed_mac,
                verified_mac,
            )
            return verified_mac.lower() != previous_mac.lower()
        except Exception as error:
            logging.error("Error en verificación ARP activa para %s: %s", ip, error)
            return False

    def _update_mac_table(self, ip, new_mac, old_mac=None):
        if old_mac:
            previous_ips = self.mac_table.get(old_mac, set())
            previous_ips.discard(ip)
            if not previous_ips and old_mac in self.mac_table:
                del self.mac_table[old_mac]

        self.mac_table.setdefault(new_mac, set()).add(ip)

    def _register_suspicious_event(self, ip):
        now = time.time()
        events = self.suspicious_arp_events.setdefault(ip, [])
        events.append(now)
        cutoff = now - self.arp_suspicion_window_s
        self.suspicious_arp_events[ip] = [event for event in events if event >= cutoff]
        return len(self.suspicious_arp_events[ip])

    def _get_possible_attacker_ip(self, suspicious_mac, spoofed_ip):
        possible_ips = [ip for ip in self.mac_table.get(suspicious_mac, set()) if ip != spoofed_ip]
        if not possible_ips:
            return None
        return sorted(possible_ips)[0]

    def detect_arp_spoofing(self, packet):
        try:
            arp_layer = packet[ARP]
            if arp_layer.op != 2:
                return

            sender_ip = arp_layer.psrc
            sender_mac = arp_layer.hwsrc
            attacker_mac = packet[Ether].src if packet.haslayer(Ether) else sender_mac
            if not sender_ip or not sender_mac or not attacker_mac:
                return

            known_mac = self.arp_table.get(sender_ip)
            if known_mac is None:
                self.arp_table[sender_ip] = sender_mac
                self._update_mac_table(sender_ip, sender_mac)
                logging.debug("Nueva asociación ARP: %s -> %s", sender_ip, sender_mac)
                return

            if known_mac.lower() == sender_mac.lower():
                self._update_mac_table(sender_ip, sender_mac)
                return

            suspicion_count = self._register_suspicious_event(sender_ip)
            logging.debug(
                "Cambio ARP sospechoso para %s (%s -> %s), attacker=%s, ocurrencias=%s",
                sender_ip,
                known_mac,
                sender_mac,
                attacker_mac,
                suspicion_count,
            )

            if suspicion_count < self.arp_suspicion_threshold:
                return

            if not self.active_arp_verification(sender_ip, known_mac, sender_mac):
                return

            possible_attacker_ip = self._get_possible_attacker_ip(attacker_mac, sender_ip)
            alert_lines = [
                "[ALERT] ARP Spoofing detected",
                f"Attacker MAC: {attacker_mac}",
                f"Spoofed IP: {sender_ip}",
                f"Previous MAC: {known_mac}",
                f"New MAC: {sender_mac}",
            ]
            if possible_attacker_ip:
                alert_lines.append(f"Possible attacker IP: {possible_attacker_ip}")

            self.trigger_alert("\n".join(alert_lines))

            self.arp_table[sender_ip] = sender_mac
            self._update_mac_table(sender_ip, sender_mac, old_mac=known_mac)

            suspicious_ips = self.mac_table.setdefault(attacker_mac, set())
            suspicious_ips.add(sender_ip)
            if len(suspicious_ips) > 1:
                ips_list = ", ".join(sorted(suspicious_ips))
                self.trigger_alert(f"Advertencia: MAC {attacker_mac} anuncia múltiples IP: {ips_list}")

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
