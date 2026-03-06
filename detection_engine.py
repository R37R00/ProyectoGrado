from scapy.all import Ether, srp
from scapy.layers.inet import IP, ICMP, TCP
from scapy.layers.l2 import ARP


class DetectionEngine:
    def __init__(self):
        self.packet_counter = 0
        self.syn_counter = 0
        self.ip_packet_count = {}
        self.arp_table = {}
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

            if ARP in packet and packet[ARP].op == 2:
                self.detect_arp_spoof(packet)

        except Exception as error:
            print("Error en process_packet:", error)

    def get_real_mac(self, ip):
        try:
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
            answered = srp(arp_request, timeout=2, verbose=False)[0]
            if answered:
                return answered[0][1].hwsrc
        except Exception as error:
            print(f"Error al obtener MAC real para {ip}:", error)
        return None

    def detect_arp_spoof(self, packet):
        try:
            if ARP not in packet or packet[ARP].op != 2:
                return

            ip = packet[ARP].psrc
            observed_mac = packet[ARP].hwsrc
            known_mac = self.arp_table.get(ip)

            if known_mac is None:
                self.arp_table[ip] = observed_mac
                return

            if known_mac == observed_mac:
                return

            real_mac = self.get_real_mac(ip)
            if real_mac is None:
                return

            if observed_mac != real_mac:
                self.trigger_alert(
                    f"Posible ARP Spoofing detectado desde {ip} (MAC observada: {observed_mac}, MAC real: {real_mac})"
                )
            else:
                self.arp_table[ip] = observed_mac

        except Exception as error:
            print("Error en detect_arp_spoof:", error)

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
