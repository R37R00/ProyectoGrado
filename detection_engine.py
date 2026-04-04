import ipaddress
import logging
import platform
import socket
import subprocess
import threading
import time

from scapy.all import ARP, Ether, sendp, srp
from scapy.layers.inet import ICMP, IP, TCP

from event_logger import log_debug, log_event


DEBUG = True


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
        interface = attack_info.get("interface") or self.detection_engine.capture_interface

        if not victim_ip or not gateway_ip or not gateway_mac or not interface:
            return False

        ok_a = self.detection_engine.restore_arp(
            victim_ip,
            victim_mac,
            gateway_ip,
            gateway_mac,
            interface,
        )
        ok_b = False
        if victim_mac:
            ok_b = self.detection_engine.restore_arp(
                gateway_ip,
                gateway_mac,
                victim_ip,
                victim_mac,
                interface,
            )

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
            logging.error("Error al fijar entrada ARP estatica: %s", error)


class DetectionEngine:
    def __init__(self):
        self.packet_counter = 0
        self.syn_counter = 0
        self.ip_packet_count = {}

        self.arp_table = {}
        self.arp_baseline = {}
        self.mac_table = {}
        self.mac_ip_map = {}
        self.suspicious_arp_events = {}
        self.arp_suspicion_window_s = 5
        self.arp_suspicion_threshold = 3

        self.active_attacks = {}
        self.attack_expiration_s = 60

        self.capture_interface = None
        self.alert_callback = None
        self.block_callback = None
        self.block_whitelist = set()
        self.block_mac_whitelist = set()
        self.local_networks = []
        self.detected_arp_attacks = set()
        self.blocked_hosts = set()
        self.attack_contexts = {}

        self.mitigation_engine = ArpMitigationEngine(self)

    def set_alert_callback(self, callback):
        self.alert_callback = callback

    def set_block_callback(self, callback):
        self.block_callback = callback

    def set_whitelist(self, whitelist_ips):
        self.block_whitelist = {ip for ip in (whitelist_ips or []) if ip}

    def set_mac_whitelist(self, whitelist_macs):
        self.block_mac_whitelist = {
            self._normalize_mac(mac)
            for mac in (whitelist_macs or [])
            if self._normalize_mac(mac)
        }

    def set_local_networks(self, networks):
        self.local_networks = []
        for network in networks or []:
            if not network:
                continue
            try:
                self.local_networks.append(ipaddress.ip_network(str(network), strict=False))
            except ValueError:
                continue

    def set_capture_interface(self, interface):
        self.capture_interface = interface

    def configure_mitigation(self, mitigation_enabled, periodic_enabled, lock_gateway_enabled, aggressive_mode):
        self.mitigation_engine.configure(
            mitigation_enabled=mitigation_enabled,
            periodic_enabled=periodic_enabled,
            lock_gateway_enabled=lock_gateway_enabled,
            aggressive_mode=aggressive_mode,
        )

    def _normalize_mac(self, mac_address):
        if mac_address is None:
            return None
        value = str(mac_address).strip().lower()
        return value or None

    def _attack_context_key(self, attacker_ip=None, attacker_mac=None):
        normalized_ip = str(attacker_ip).strip() if attacker_ip else "unknown"
        normalized_mac = self._normalize_mac(attacker_mac) or "unknown"
        return normalized_ip, normalized_mac

    def _store_attack_context(self, attack_info):
        if not attack_info:
            return

        key = self._attack_context_key(
            attack_info.get("attacker_ip"),
            attack_info.get("attacker_mac"),
        )
        stored = dict(attack_info)
        stored["attacker_mac"] = self._normalize_mac(stored.get("attacker_mac"))
        self.attack_contexts[key] = stored

    def get_attack_context(self, attacker_ip=None, attacker_mac=None):
        direct_key = self._attack_context_key(attacker_ip, attacker_mac)
        if direct_key in self.attack_contexts:
            return dict(self.attack_contexts[direct_key])

        normalized_ip = str(attacker_ip).strip() if attacker_ip else None
        normalized_mac = self._normalize_mac(attacker_mac)
        for _key, context in reversed(list(self.attack_contexts.items())):
            context_ip = context.get("attacker_ip")
            context_mac = self._normalize_mac(context.get("attacker_mac"))
            if normalized_mac and context_mac != normalized_mac:
                continue
            if normalized_ip and context_ip != normalized_ip:
                continue
            return dict(context)

        return None

    def activate_post_block_mitigation(self, attack_info):
        if not attack_info:
            return False

        self._store_attack_context(attack_info)
        return self.mitigation_engine.activate_attack_defense(attack_info)

    def _is_valid_mac(self, mac_address):
        normalized = self._normalize_mac(mac_address)
        if not normalized:
            return False

        parts = normalized.split(":")
        return len(parts) == 6 and all(len(part) == 2 for part in parts)

    def _is_ip_in_local_networks(self, ip_address):
        if not ip_address:
            return False

        try:
            candidate = ipaddress.ip_address(ip_address)
        except ValueError:
            return False

        if not self.local_networks:
            return candidate.is_private

        return any(candidate in network for network in self.local_networks)

    def _observe_real_ip_source(self, packet):
        if not (packet.haslayer(IP) and packet.haslayer(Ether)):
            return

        source_ip = str(packet[IP].src).strip() if packet[IP].src else None
        source_mac = self._normalize_mac(packet[Ether].src)
        if not source_ip or not source_mac or self._is_invalid_ip_candidate(source_ip):
            return

        if not self._is_ip_in_local_networks(source_ip):
            return

        self.mac_ip_map[source_mac] = source_ip

    def _resolve_attacker_ip_from_real_traffic(self, attacker_mac):
        normalized_mac = self._normalize_mac(attacker_mac)
        if not normalized_mac:
            return None

        attacker_ip = self.mac_ip_map.get(normalized_mac)
        if (
            not attacker_ip
            or self._is_invalid_ip_candidate(attacker_ip)
            or not self._is_ip_in_local_networks(attacker_ip)
        ):
            return None

        return attacker_ip

    def _resolve_context_mac(self, ip_address):
        normalized_ip = str(ip_address).strip() if ip_address else None
        if not normalized_ip:
            return None

        return self._normalize_mac(
            self.arp_baseline.get(normalized_ip) or self.arp_table.get(normalized_ip)
        )

    def _resolve_attacker_ip_from_context(self, attacker_mac, gateway_ip=None, victim_ip=None):
        resolved_ip = self._resolve_attacker_ip_from_real_traffic(attacker_mac)
        if resolved_ip:
            return resolved_ip

        normalized_mac = self._normalize_mac(attacker_mac)
        if not normalized_mac:
            return None

        excluded = {
            str(gateway_ip).strip() if gateway_ip else None,
            str(victim_ip).strip() if victim_ip else None,
        }

        for table in [self.arp_table, self.arp_baseline]:
            for candidate_ip, candidate_mac in table.items():
                normalized_candidate_ip = str(candidate_ip).strip() if candidate_ip else None
                if (
                    normalized_candidate_ip
                    and normalized_candidate_ip not in excluded
                    and self._normalize_mac(candidate_mac) == normalized_mac
                    and not self._is_invalid_ip_candidate(normalized_candidate_ip)
                    and self._is_ip_in_local_networks(normalized_candidate_ip)
                ):
                    return normalized_candidate_ip

        return None

    def _is_invalid_ip_candidate(self, ip_address):
        if not ip_address:
            return True
        if str(ip_address).strip() == "255.255.255.255":
            return True

        try:
            candidate = ipaddress.ip_address(ip_address)
        except ValueError:
            return True

        return any(
            [
                candidate.is_multicast,
                candidate.is_loopback,
                candidate.is_unspecified,
                candidate.is_link_local,
                candidate.is_reserved,
            ]
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
                mac = self._normalize_mac(received.hwsrc)
                self.arp_baseline[ip] = mac
                self.arp_table[ip] = mac
                self._update_mac_table(ip, mac)

            logging.info("Baseline ARP construida con %s hosts", len(self.arp_baseline))
            if DEBUG:
                for ip, mac in sorted(self.arp_baseline.items()):
                    logging.info("[DEBUG] Baseline host -> IP: %s, MAC: %s", ip, mac)

        except Exception as error:
            logging.error("Error construyendo baseline ARP: %s", error)

    def process_packet(self, packet):
        try:
            if IP in packet:
                src_ip = packet[IP].src
                self._observe_real_ip_source(packet)
                self.packet_counter += 1
                self.ip_packet_count[src_ip] = self.ip_packet_count.get(src_ip, 0) + 1

                if TCP in packet and packet[TCP].flags & 0x02:
                    self.syn_counter += 1

                if ICMP in packet and packet[ICMP].type == 8:
                    log_event(f"Actividad ICMP sospechosa desde {src_ip}", "warning")

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

            verified_mac = self._normalize_mac(answered[0][1][ARP].hwsrc)
            logging.debug(
                "Verificacion host %s: esperado=%s verificado=%s",
                ip,
                expected_mac,
                verified_mac,
            )
            return verified_mac == self._normalize_mac(expected_mac), verified_mac

        except Exception as error:
            logging.error("Error en verify_host para %s: %s", ip, error)
            return False, None

    def _update_mac_table(self, ip, new_mac, old_mac=None):
        new_mac = self._normalize_mac(new_mac)
        old_mac = self._normalize_mac(old_mac)

        if old_mac:
            previous_ips = self.mac_table.get(old_mac, set())
            previous_ips.discard(ip)
            if not previous_ips and old_mac in self.mac_table:
                del self.mac_table[old_mac]

        if new_mac:
            self.mac_table.setdefault(new_mac, set()).add(ip)

    def _build_attack_context(
        self,
        attacker_ip,
        attacker_mac,
        victim_ip,
        victim_mac,
        gateway_ip,
        gateway_mac,
        spoofed_ip=None,
        target_ip=None,
        interface_name=None,
    ):
        return {
            "attacker_ip": attacker_ip,
            "attacker_mac": self._normalize_mac(attacker_mac),
            "victim_ip": victim_ip,
            "victim_mac": self._normalize_mac(victim_mac),
            "gateway_ip": gateway_ip,
            "gateway_mac": self._normalize_mac(gateway_mac),
            "spoofed_ip": spoofed_ip or gateway_ip,
            "target_ip": target_ip or victim_ip,
            "interface": interface_name or self.capture_interface,
        }

    def _build_complete_attack_context(
        self,
        claimed_ip,
        target_ip,
        attacker_mac,
        interface_name=None,
        attacker_ip=None,
        expected_gateway_mac=None,
    ):
        gateway_ip = str(claimed_ip).strip() if claimed_ip else None
        victim_ip = str(target_ip).strip() if target_ip else None
        resolved_attacker_ip = (
            str(attacker_ip).strip()
            if attacker_ip
            else self._resolve_attacker_ip_from_context(attacker_mac, gateway_ip=gateway_ip, victim_ip=victim_ip)
        )
        gateway_mac = self._normalize_mac(expected_gateway_mac) or self._resolve_context_mac(gateway_ip)
        victim_mac = self._resolve_context_mac(victim_ip)

        if resolved_attacker_ip in {gateway_ip, victim_ip}:
            resolved_attacker_ip = None

        attack_context = self._build_attack_context(
            attacker_ip=resolved_attacker_ip,
            attacker_mac=attacker_mac,
            victim_ip=victim_ip,
            victim_mac=victim_mac,
            gateway_ip=gateway_ip,
            gateway_mac=gateway_mac,
            spoofed_ip=gateway_ip,
            target_ip=victim_ip,
            interface_name=interface_name,
        )
        logging.debug(
            "[ARP CONTEXT] attacker_ip=%s victim_ip=%s gateway_ip=%s victim_mac=%s gateway_mac=%s interface=%s",
            attack_context.get("attacker_ip"),
            attack_context.get("victim_ip"),
            attack_context.get("gateway_ip"),
            attack_context.get("victim_mac"),
            attack_context.get("gateway_mac"),
            attack_context.get("interface"),
        )
        return attack_context

    def handle_arp_attack(self, attacker_ip, attacker_mac, spoofed_ip=None, victim_ip=None, attack_context=None):
        normalized_mac = self._normalize_mac(attacker_mac)
        resolved_ip = str(attacker_ip).strip() if attacker_ip else None
        gateway_ip = None
        victim_target_ip = None

        if attack_context:
            self._store_attack_context(attack_context)
            gateway_ip = str(attack_context.get("gateway_ip")).strip() if attack_context.get("gateway_ip") else None
            victim_target_ip = str(attack_context.get("victim_ip")).strip() if attack_context.get("victim_ip") else None

        if not resolved_ip:
            logging.warning("Ataque ARP detectado pero sin IP atacante valida; se omite bloqueo automatico")
            return

        if self._is_invalid_ip_candidate(resolved_ip):
            logging.warning("IP atacante invalida detectada (%s); se omite bloqueo automatico", resolved_ip)
            return

        attack_key = (resolved_ip, normalized_mac or "unknown")
        if attack_key in self.detected_arp_attacks:
            return

        if gateway_ip and resolved_ip == gateway_ip:
            logging.warning("IP atacante coincide con gateway (%s); se omite bloqueo", resolved_ip)
            return

        if victim_target_ip and resolved_ip == victim_target_ip:
            logging.warning("IP atacante coincide con victima (%s); se omite bloqueo", resolved_ip)
            return

        self.detected_arp_attacks.add(attack_key)

        if self._is_whitelisted(resolved_ip):
            print("[WARNING] Skipping gateway, not attacker")
            logging.info("IP %s protegida/en whitelist: se omite bloqueo", resolved_ip)
            return

        if self._is_mac_whitelisted(normalized_mac):
            logging.info("MAC %s en whitelist: se omite bloqueo", normalized_mac)
            return

        if resolved_ip in self.blocked_hosts:
            logging.info("IP %s ya fue enviada a bloqueo automatico", resolved_ip)
            return

        print("[ALERT] Real attacker detected:", resolved_ip)
        if self.block_callback:
            try:
                self.blocked_hosts.add(resolved_ip)
                self.block_callback(resolved_ip, normalized_mac)
            except Exception as error:
                self.blocked_hosts.discard(resolved_ip)
                logging.error(
                    "Error ejecutando callback de bloqueo para ip=%s mac=%s: %s",
                    resolved_ip,
                    normalized_mac,
                    error,
                )

    def _is_whitelisted(self, ip_address):
        return bool(ip_address and ip_address in self.block_whitelist)

    def _is_mac_whitelisted(self, mac_address):
        normalized_mac = self._normalize_mac(mac_address)
        return bool(normalized_mac and normalized_mac in self.block_mac_whitelist)

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

    def detect_arp_inconsistency(self, sender_ip, sender_mac, target_ip, attacker_mac, interface_name=None):
        sender_mac = self._normalize_mac(sender_mac)
        attacker_mac = self._normalize_mac(attacker_mac)
        expected_mac = self._normalize_mac(self.arp_baseline.get(sender_ip) or self.arp_table.get(sender_ip))

        if not expected_mac:
            self.arp_baseline[sender_ip] = sender_mac
            self.arp_table[sender_ip] = sender_mac
            self._update_mac_table(sender_ip, sender_mac)
            return

        ip_mac_changed = expected_mac != sender_mac
        mac_claims_multiple_ips = sender_mac in self.mac_table and sender_ip not in self.mac_table[sender_mac]

        if DEBUG:
            log_debug(
                f"ARP mismatch detected: sender_ip={sender_ip} expected_mac={expected_mac} "
                f"detected_mac={sender_mac} target_ip={target_ip or 'unknown'}"
            )

        if not ip_mac_changed and not mac_claims_multiple_ips:
            self.arp_table[sender_ip] = sender_mac
            self._update_mac_table(sender_ip, sender_mac)
            return

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
            logging.debug("Verificacion activa descarta spoofing para %s", sender_ip)
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

        attack_info = self._build_complete_attack_context(
            claimed_ip=sender_ip,
            target_ip=target_ip,
            attacker_mac=attacker_mac,
            interface_name=interface_name,
            attacker_ip=self._resolve_attacker_ip_from_real_traffic(attacker_mac),
            expected_gateway_mac=expected_mac,
        )
        attacker_ip = attack_info.get("attacker_ip")
        self._store_attack_context(attack_info)

        alert_lines.append("Mitigation: queued for post-block ARP restoration")
        self.trigger_alert("\n".join(alert_lines))
        self._mark_attack_active(attack_key, confirmed=True)
        self.arp_table[sender_ip] = expected_mac

        print("[DEBUG] Spoof detected:")
        print("  Claimed IP:", sender_ip)
        print("  Real MAC:", attacker_mac)
        print("  Real attacker IP:", attacker_ip)

        if attacker_ip:
            self.trigger_alert(f"IP atacante posible: {attacker_ip}")
        else:
            logging.warning("No se pudo correlacionar MAC atacante %s con IP real", attacker_mac)

        if attacker_ip and self._is_whitelisted(attacker_ip):
            logging.info("IP %s en whitelist: se omite bloqueo", attacker_ip)
            return

        if attacker_ip and self._is_invalid_ip_candidate(attacker_ip):
            logging.info("IP %s invalida para bloqueo automatico", attacker_ip)
            return

        if self._is_mac_whitelisted(attacker_mac):
            logging.info("MAC %s en whitelist: se omite bloqueo", attacker_mac)
            return

        if attacker_ip and attacker_mac and self.block_callback:
            try:
                self.handle_arp_attack(
                    attacker_ip,
                    attacker_mac,
                    spoofed_ip=sender_ip,
                    victim_ip=target_ip,
                    attack_context=attack_info,
                )
            except Exception as error:
                logging.error(
                    "Error ejecutando callback de bloqueo para ip=%s mac=%s: %s",
                    attacker_ip,
                    attacker_mac,
                    error,
                )

    def restore_arp(self, victim_ip, victim_mac, real_ip, real_mac, interface=None, count=7):
        try:
            victim_ip = str(victim_ip).strip() if victim_ip else None
            real_ip = str(real_ip).strip() if real_ip else None
            victim_mac = self._normalize_mac(victim_mac)
            real_mac = self._normalize_mac(real_mac)
            interface = interface or self.capture_interface

            if not victim_ip or not real_ip or not real_mac or not interface:
                return False

            if not victim_mac:
                logging.warning("Restore ARP omitido para %s: victim_mac desconocida", victim_ip)
                return False

            if not self._is_valid_mac(victim_mac) or not self._is_valid_mac(real_mac):
                logging.warning("Restore ARP omitido por MAC invalida victim=%s real=%s", victim_mac, real_mac)
                return False

            logging.info("[ARP] Restoring ARP for victim %s", victim_ip)
            logging.info("[ARP] Sending correct mapping: %s -> %s", real_ip, real_mac)

            sendp(
                Ether(dst=victim_mac, src=real_mac) / ARP(
                    op=2,
                    psrc=real_ip,
                    hwsrc=real_mac,
                    pdst=victim_ip,
                    hwdst=victim_mac,
                ),
                count=count,
                inter=0.2,
                verbose=False,
                iface=interface,
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

            interface_name = getattr(packet, "capture_interface", None) or getattr(packet, "sniffed_on", None)
            sender_ip = arp_layer.psrc
            sender_mac = self._normalize_mac(arp_layer.hwsrc)
            target_ip = arp_layer.pdst
            attacker_mac = sender_mac
            if not sender_ip or not sender_mac:
                logging.debug("Paquete ARP sin campos minimos, ignorado")
                return

            previous_mac = self.arp_table.get(sender_ip)

            if previous_mac and self._normalize_mac(previous_mac) != sender_mac:
                log_debug(
                    f"ARP mismatch detected: {sender_ip} changed MAC "
                    f"{self._normalize_mac(previous_mac)} -> {sender_mac}"
                )
                log_event(f"ARP spoofing detected for {sender_ip}", "alert")
                attack_info = self._build_complete_attack_context(
                    claimed_ip=sender_ip,
                    target_ip=target_ip,
                    attacker_mac=sender_mac,
                    interface_name=interface_name,
                    attacker_ip=self._resolve_attacker_ip_from_real_traffic(sender_mac),
                    expected_gateway_mac=previous_mac,
                )
                attacker_ip = attack_info.get("attacker_ip")
                print("[DEBUG] Spoof detected:")
                print("  Claimed IP:", sender_ip)
                print("  Real MAC:", sender_mac)
                print("  Real attacker IP:", attacker_ip)
                self._store_attack_context(attack_info)
                if attacker_ip is None:
                    logging.warning("Spoof detectado pero sin IP real para MAC atacante %s", sender_mac)
                else:
                    self.handle_arp_attack(
                        attacker_ip,
                        sender_mac,
                        spoofed_ip=sender_ip,
                        victim_ip=target_ip,
                        attack_context=attack_info,
                    )

            self.arp_table[sender_ip] = sender_mac
            self._update_mac_table(sender_ip, sender_mac, previous_mac)

            self.detect_arp_inconsistency(sender_ip, sender_mac, target_ip, attacker_mac, interface_name=interface_name)

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
        else:
            log_event(message, "alert")
