import ipaddress
import logging
import platform
import socket
import subprocess
import threading
import time

from scapy.all import ARP, Ether, send, srp
from scapy.layers.inet import IP, ICMP, TCP


class ArpMitigationEngine:
    def __init__(self, detection_engine):
        self.detection_engine = detection_engine
        self.mitigation_enabled = True
        self.periodic_enabled = False
        self.lock_gateway_enabled = False
        self.aggressive_mode = False
        self.default_interval_s = 1.0
        self.aggressive_interval_s = 0.5
        self.min_interval_s = 0.3
        self.max_interval_s = 3.0

        self.last_attack_time = 0
        self.last_attack_info = None
        self.defense_thread = None
        self.stop_event = threading.Event()

    def configure(self, mitigation_enabled, periodic_enabled, lock_gateway_enabled, aggressive_mode):
        self.mitigation_enabled = mitigation_enabled
        self.periodic_enabled = periodic_enabled
        self.lock_gateway_enabled = lock_gateway_enabled
        self.aggressive_mode = aggressive_mode

    def _get_defense_interval(self):
        interval = self.aggressive_interval_s if self.aggressive_mode else self.default_interval_s
        return max(self.min_interval_s, min(self.max_interval_s, interval))

    def activate_attack_defense(self, attack_info):
        if not self.mitigation_enabled:
            return False

        self.last_attack_time = time.time()
        self.last_attack_info = attack_info

        restored = self._execute_bidirectional_restoration(attack_info)

        if self.lock_gateway_enabled:
            self.lock_gateway_arp(attack_info.get("gateway_ip"), attack_info.get("gateway_mac"))

        if self.periodic_enabled:
            self.start_defense_loop()

        self.detection_engine.trigger_alert(
            "[MITIGATION ACTIVE]\n"
            "Targeted ARP restoration running\n"
            "MITM attack mitigation in progress"
        )

        return restored

    def _execute_bidirectional_restoration(self, attack_info):
        victim_ip = attack_info.get("victim_ip")
        victim_mac = attack_info.get("victim_mac")
        gateway_ip = attack_info.get("gateway_ip")
        gateway_mac = attack_info.get("gateway_mac")

        if not victim_ip or not gateway_ip or not gateway_mac:
            return False

        ok_a = self.detection_engine.restore_arp(victim_ip, victim_mac, gateway_ip, gateway_mac)
        ok_b = False
        if victim_mac:
            ok_b = self.detection_engine.restore_arp(gateway_ip, gateway_mac, victim_ip, victim_mac)

        return ok_a or ok_b

    def start_defense_loop(self):
        if self.defense_thread and self.defense_thread.is_alive():
            return

        self.stop_event.clear()
        self.defense_thread = threading.Thread(target=self._defense_loop, daemon=True)
        self.defense_thread.start()

    def _defense_loop(self):
        while not self.stop_event.is_set():
            if not self.last_attack_info:
                break

            idle_time = time.time() - self.last_attack_time
            if idle_time > 60:
                break

            self._execute_bidirectional_restoration(self.last_attack_info)

            interval = self._get_defense_interval()
            self.stop_event.wait(interval)

    def stop_defense_loop(self):
        self.stop_event.set()

    def lock_gateway_arp(self, gateway_ip, gateway_mac):
        if not gateway_ip or not gateway_mac:
            return

        try:
            system = platform.system().lower()
            interface = self.detection_engine.capture_interface

            if "linux" in system and interface:
                cmd = [
                    "ip",
                    "neigh",
                    "replace",
                    gateway_ip,
                    "lladdr",
                    gateway_mac,
                    "nud",
                    "permanent",
                    "dev",
                    interface,
                ]
                subprocess.run(cmd, check=False, capture_output=True, text=True)

            elif "windows" in system:
                cmd = [
                    "netsh",
                    "interface",
                    "ipv4",
                    "add",
                    "neighbors",
                    "Ethernet",
                    gateway_ip,
                    gateway_mac,
                ]
                subprocess.run(cmd, check=False, capture_output=True, text=True)

        except Exception as error:
            logging.error("Error al fijar entrada ARP estática: %s", error)


class DetectionEngine:
    def __init__(self):
        self.packet_counter = 0
        self.syn_counter = 0
        self.ip_packet_count = {}

        self.arp_table = {}
        self.arp_baseline = {}
        self.mac_table = {}
        self.suspicious_arp_events = {}
        self.arp_suspicion_window_s = 5
        self.arp_suspicion_threshold = 3

        self.active_attacks = {}
        self.attack_expiration_s = 60

        self.capture_interface = None
        self.alert_callback = None
        self.block_callback = None
        self.block_whitelist = set()

        self.mitigation_engine = ArpMitigationEngine(self)

    def set_alert_callback(self, callback):
        self.alert_callback = callback

    def set_block_callback(self, callback):
        self.block_callback = callback

    def set_whitelist(self, whitelist_ips):
        self.block_whitelist = {ip for ip in (whitelist_ips or []) if ip}

    def set_capture_interface(self, interface):
        self.capture_interface = interface

    def configure_mitigation(self, mitigation_enabled, periodic_enabled, lock_gateway_enabled, aggressive_mode):
        self.mitigation_engine.configure(
            mitigation_enabled=mitigation_enabled,
            periodic_enabled=periodic_enabled,
            lock_gateway_enabled=lock_gateway_enabled,
            aggressive_mode=aggressive_mode,
        )

    def build_arp_baseline(self, network_cidr=None):
        try:
            if network_cidr is None:
                hostname = socket.gethostname()
                local_ip = socket.gethostbyname(hostname)
                network_cidr = f"{local_ip}/24"

            network = ipaddress.IPv4Network(network_cidr, strict=False)
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))
            answered = srp(
                arp_request,
                timeout=3,
                verbose=False,
                iface=self.capture_interface,
            )[0]

            self.arp_baseline.clear()
            for _sent, received in answered:
                ip = received.psrc
                mac = received.hwsrc
                self.arp_baseline[ip] = mac
                self.arp_table[ip] = mac
                self._update_mac_table(ip, mac)

            logging.info("Baseline ARP construida con %s hosts", len(self.arp_baseline))

        except Exception as error:
            logging.error("Error construyendo baseline ARP: %s", error)

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

    def verify_host(self, ip, expected_mac):
        try:
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=ip)
            answered = srp(
                arp_request,
                timeout=2,
                verbose=False,
                iface=self.capture_interface,
            )[0]
            if not answered:
                return False, None

            verified_mac = answered[0][1][ARP].hwsrc
            logging.debug(
                "Verificación host %s: esperado=%s verificado=%s",
                ip,
                expected_mac,
                verified_mac,
            )
            return verified_mac.lower() == expected_mac.lower(), verified_mac

        except Exception as error:
            logging.error("Error en verify_host para %s: %s", ip, error)
            return False, None

    def _update_mac_table(self, ip, new_mac, old_mac=None):
        if old_mac:
            previous_ips = self.mac_table.get(old_mac, set())
            previous_ips.discard(ip)
            if not previous_ips and old_mac in self.mac_table:
                del self.mac_table[old_mac]

        self.mac_table.setdefault(new_mac, set()).add(ip)

    def _resolve_attacker_ip(self, attacker_mac, spoofed_ip=None, victim_ip=None):
        if not attacker_mac:
            return None

        mac_ips = set(self.mac_table.get(attacker_mac, set()))
        table_ips = {ip for ip, mac in self.arp_table.items() if mac == attacker_mac}
        candidates = list(mac_ips.union(table_ips))
        excluded = {spoofed_ip, victim_ip}

        for candidate in candidates:
            if candidate and candidate not in excluded:
                return candidate

        if victim_ip and self.arp_table.get(victim_ip) == attacker_mac:
            return victim_ip

        return None

    def _is_whitelisted(self, ip_address):
        return bool(ip_address and ip_address in self.block_whitelist)

    def _register_suspicious_event(self, ip):
        now = time.time()
        events = self.suspicious_arp_events.setdefault(ip, [])
        events.append(now)
        cutoff = now - self.arp_suspicion_window_s
        self.suspicious_arp_events[ip] = [event for event in events if event >= cutoff]
        return len(self.suspicious_arp_events[ip])

    def _cleanup_active_attacks(self):
        now = time.time()
        self.active_attacks = {
            key: value
            for key, value in self.active_attacks.items()
            if now - value["timestamp"] < self.attack_expiration_s
        }

    def _is_attack_active(self, attack_key):
        self._cleanup_active_attacks()
        return attack_key in self.active_attacks

    def _mark_attack_active(self, attack_key, confirmed=False):
        self.active_attacks[attack_key] = {
            "timestamp": time.time(),
            "confirmed": confirmed,
        }

    def detect_arp_inconsistency(self, sender_ip, sender_mac, target_ip, attacker_mac):
        expected_mac = self.arp_baseline.get(sender_ip) or self.arp_table.get(sender_ip)

        if not expected_mac:
            self.arp_baseline[sender_ip] = sender_mac
            self.arp_table[sender_ip] = sender_mac
            self._update_mac_table(sender_ip, sender_mac)
            return

        ip_mac_changed = expected_mac.lower() != sender_mac.lower()
        mac_claims_multiple_ips = sender_mac in self.mac_table and sender_ip not in self.mac_table[sender_mac]

        logging.debug(
            "ARP packet observed: ip=%s mac=%s expected=%s changed=%s mac_multi_ip=%s",
            sender_ip,
            sender_mac,
            expected_mac,
            ip_mac_changed,
            mac_claims_multiple_ips,
        )

        if not ip_mac_changed and not mac_claims_multiple_ips:
            self.arp_table[sender_ip] = sender_mac
            self._update_mac_table(sender_ip, sender_mac)
            return

        logging.warning("ARP inconsistency detected for %s", sender_ip)

        attack_key = f"{sender_ip}-{attacker_mac}"
        suspicion_count = self._register_suspicious_event(sender_ip)

        if not self._is_attack_active(attack_key):
            self._mark_attack_active(attack_key, confirmed=False)
            warning_lines = [
                "[WARNING] ARP inconsistency detected",
                f"Victim IP: {target_ip or 'unknown'}",
                f"Spoofed IP: {sender_ip}",
                f"Expected MAC: {expected_mac}",
                f"Detected MAC: {sender_mac}",
                f"Attacker MAC: {attacker_mac}",
                f"Suspicion count: {suspicion_count}/{self.arp_suspicion_threshold}",
            ]
            self.trigger_alert("\n".join(warning_lines))

        if suspicion_count < self.arp_suspicion_threshold:
            return

        current_state = self.active_attacks.get(attack_key, {})
        if current_state.get("confirmed"):
            return

        is_consistent, verified_mac = self.verify_host(sender_ip, expected_mac)
        if is_consistent:
            logging.debug("Verificación activa descarta spoofing para %s", sender_ip)
            return

        victim_ip = target_ip or "desconocido"
        alert_lines = [
            "[ALERT] ARP Spoofing Detected",
            f"Victim IP: {victim_ip}",
            f"Spoofed IP: {sender_ip}",
            f"Expected MAC: {expected_mac}",
            f"Detected MAC: {sender_mac}",
            f"Attacker MAC: {attacker_mac}",
        ]
        if verified_mac:
            alert_lines.append(f"Active verification MAC: {verified_mac}")

        attack_info = {
            "victim_ip": target_ip,
            "victim_mac": self.arp_baseline.get(target_ip) if target_ip else None,
            "gateway_ip": sender_ip,
            "gateway_mac": expected_mac,
            "attacker_mac": attacker_mac,
        }
        mitigation_ok = self.mitigation_engine.activate_attack_defense(attack_info)
        alert_lines.append(
            "Mitigation: ARP restoration sent" if mitigation_ok else "Mitigation: inactive or failed"
        )

        self.trigger_alert("\n".join(alert_lines))
        self._mark_attack_active(attack_key, confirmed=True)
        self.arp_table[sender_ip] = expected_mac

        attacker_ip = self._resolve_attacker_ip(attacker_mac, spoofed_ip=sender_ip, victim_ip=target_ip)
        if attacker_ip:
            self.trigger_alert(f"IP atacante posible: {attacker_ip}")

        if attacker_ip and self._is_whitelisted(attacker_ip):
            logging.info("IP %s en whitelist: se omite bloqueo", attacker_ip)
            return

        if attacker_ip and self.block_callback:
            try:
                self.block_callback(attacker_ip)
            except Exception as error:
                logging.error("Error ejecutando callback de bloqueo para %s: %s", attacker_ip, error)

    def restore_arp(self, victim_ip, victim_mac, real_ip, real_mac):
        try:
            if not victim_ip or not real_ip or not real_mac:
                return False

            if not victim_mac:
                logging.warning("Restore ARP omitido para %s: victim_mac desconocida", victim_ip)
                return False

            send(
                ARP(op=2, psrc=real_ip, hwsrc=real_mac, pdst=victim_ip, hwdst=victim_mac),
                count=5,
                inter=0.2,
                verbose=False,
                iface=self.capture_interface,
            )

            if victim_mac:
                send(
                    ARP(op=2, psrc=victim_ip, hwsrc=victim_mac, pdst=real_ip, hwdst=real_mac),
                    count=5,
                    inter=0.2,
                    verbose=False,
                    iface=self.capture_interface,
                )

            return True
        except Exception as error:
            logging.error("Error en restore_arp: %s", error)
            return False

    def detect_arp_spoofing(self, packet):
        try:
            arp_layer = packet[ARP]
            if arp_layer.op != 2:
                return

            sender_ip = arp_layer.psrc
            sender_mac = arp_layer.hwsrc
            target_ip = arp_layer.pdst
            attacker_mac = arp_layer.hwsrc
            if not sender_ip or not sender_mac:
                logging.debug("Paquete ARP sin campos mínimos, ignorado")
                return

            previous_mac = self.arp_table.get(sender_ip)
            self.arp_table[sender_ip] = sender_mac
            self._update_mac_table(sender_ip, sender_mac, previous_mac)

            self.detect_arp_inconsistency(sender_ip, sender_mac, target_ip, attacker_mac)

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
