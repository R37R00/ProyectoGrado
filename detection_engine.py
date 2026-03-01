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

    def detect_arp_spoof(self, packet):
        ip = packet[ARP].psrc
        mac = packet[ARP].hwsrc

        if ip in self.arp_table and self.arp_table[ip] != mac:
            self.trigger_alert(f"Posible ARP Spoofing detectado desde {ip}")
        else:
            self.arp_table[ip] = mac

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
