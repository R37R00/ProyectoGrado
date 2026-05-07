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


DEBUG = False
traffic_stats = {}

DOS_WINDOW_SECONDS = 3
DOS_ALERT_COOLDOWN_SECONDS = 1
DOS_BLOCK_PERSISTENCE_SECONDS = 2.0
DOS_MIN_SUSPICIOUS_EVENTS = 2
DOS_EVENT_RESET_SECONDS = 2
DOS_SUSPICIOUS_CYCLE_SECONDS = 0.5
DOS_BLOCK_BPS_THRESHOLD = 12000
ATTACK_TIMEOUT_SECONDS = 10
DOS_PROFILES = {
    "icmp_flood": {
        "label": "ICMP Flood",
        "alert_pps": 4,
        "block_pps": 8,
        "block_bps": DOS_BLOCK_BPS_THRESHOLD,
    },
    "syn_flood": {
        "label": "SYN Flood",
        "alert_pps": 4,
        "block_pps": 7,
        "block_bps": DOS_BLOCK_BPS_THRESHOLD,
    },
}


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
        self.traffic_stats = traffic_stats
        self.target_traffic_stats = {}
        self.dos_state = {}
        self.suspicious_count = {}
        self.hosts = {}
        self.attack_state = {}
        self.dos_window_s = DOS_WINDOW_SECONDS
        self.dos_alert_cooldown_s = DOS_ALERT_COOLDOWN_SECONDS
        self.dos_block_persistence_s = DOS_BLOCK_PERSISTENCE_SECONDS
        self.dos_min_suspicious_events = DOS_MIN_SUSPICIOUS_EVENTS
        self.dos_event_reset_s = DOS_EVENT_RESET_SECONDS
        self.dos_suspicious_cycle_s = DOS_SUSPICIOUS_CYCLE_SECONDS
        self.dos_profiles = {
            attack_name: dict(profile)
            for attack_name, profile in DOS_PROFILES.items()
        }

        self.arp_table = {}
        self.arp_baseline = {}
        self.mac_table = {}
        self.mac_ip_map = {}
        self.suspicious_arp_events = {}
        self.arp_suspicion_window_s = 2
        self.arp_suspicion_threshold = 1

        self.active_attacks = {}
        self.attack_expiration_s = ATTACK_TIMEOUT_SECONDS
        self.attack_timeout_s = ATTACK_TIMEOUT_SECONDS

        self.capture_interface = None
        self.alert_callback = None
        self.block_callback = None
        self.block_whitelist = set()
        self.block_mac_whitelist = set()
        self.local_networks = []
        self.observed_ips = set()
        self.detected_arp_attacks = set()
        self.scan_tracker = {}
        self.scan_cleanup_interval_s = 2
        self.last_scan_cleanup_s = 0
        self.port_scan_tracker = {}
        self.port_scan_window_s = 4
        self.port_scan_threshold = 6
        self.detected_port_scanners = set()
        self.blocked_hosts = set()
        self.attack_contexts = {}
        self.state_lock = threading.RLock()

        self.mitigation_engine = ArpMitigationEngine(self)

    def set_alert_callback(self, callback):
        self.alert_callback = callback

    def set_block_callback(self, callback):
        self.block_callback = callback

    def block_attacker(self, ip_address, mac_address=None, attack_type="DoS"):
        if not self.block_callback:
            logging.critical("block_callback not defined attacker=%s attack=%s", ip_address, attack_type)
            return False
        return self.block_callback(ip_address, mac_address, attack_type)

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
                normalized_network = ipaddress.ip_network(str(network), strict=False)
                if normalized_network.version == 4:
                    self.local_networks.append(normalized_network)
            except ValueError:
                logging.warning("Red local invalida descartada: %s", network)
                continue
        logging.debug(
            "Local networks configuradas manualmente: %s",
            ", ".join(str(network) for network in self.local_networks) if self.local_networks else "none",
        )

    def update_local_networks(self, interfaces):
        if interfaces is None:
            normalized_interfaces = []
        elif isinstance(interfaces, (list, tuple, set)):
            normalized_interfaces = [str(interface).strip() for interface in interfaces if interface]
        else:
            normalized_interfaces = [str(interfaces).strip()] if interfaces else []

        discovered_networks = {}

        if not normalized_interfaces:
            self.local_networks = []
            logging.debug("update_local_networks sin interfaces validas; se activa fallback fail-open")
            return

        try:
            from network_capture import NetworkCaptureScanner

            scanner = NetworkCaptureScanner(lambda _packet: None, lambda _hosts: None)
        except Exception as error:
            self.local_networks = []
            logging.error("No se pudo inicializar NetworkCaptureScanner para descubrir redes locales: %s", error)
            return

        for interface_name in normalized_interfaces:
            try:
                network = scanner.get_interface_network(interface_name)
            except Exception as error:
                logging.warning("Error obteniendo red local para interfaz %s: %s", interface_name, error)
                continue

            if not network:
                logging.debug("No se detecto red IPv4 para interfaz %s", interface_name)
                continue

            try:
                ipv4_network = ipaddress.IPv4Network(str(network), strict=False)
            except ValueError:
                logging.warning("Red local invalida descartada para interfaz %s: %s", interface_name, network)
                continue

            discovered_networks[str(ipv4_network)] = ipv4_network

        self.local_networks = list(discovered_networks.values())
        logging.debug(
            "Local networks descubiertas dinamicamente: %s",
            ", ".join(str(network) for network in self.local_networks) if self.local_networks else "none",
        )

    def set_capture_interface(self, interface):
        self.capture_interface = interface
        self.update_local_networks(interface)

    def configure_mitigation(self, mitigation_enabled, periodic_enabled, lock_gateway_enabled, aggressive_mode):
        self.mitigation_engine.configure(
            mitigation_enabled=mitigation_enabled,
            periodic_enabled=periodic_enabled,
            lock_gateway_enabled=lock_gateway_enabled,
            aggressive_mode=aggressive_mode,
        )

    def configure_dos_thresholds(
        self,
        profiles=None,
        window_s=None,
        block_persistence_s=None,
        suspicious_events=None,
        suspicious_cycle_s=None,
        alert_cooldown_s=None,
        event_reset_s=None,
    ):
        if profiles:
            for attack_name, profile in profiles.items():
                if not isinstance(profile, dict):
                    continue
                current = dict(self.dos_profiles.get(attack_name, {}))
                current.update(profile)
                self.dos_profiles[attack_name] = current

        if window_s is not None and window_s > 0:
            self.dos_window_s = float(window_s)
        if block_persistence_s is not None and block_persistence_s > 0:
            self.dos_block_persistence_s = float(block_persistence_s)
        if suspicious_events is not None and suspicious_events > 0:
            self.dos_min_suspicious_events = int(suspicious_events)
        if suspicious_cycle_s is not None and suspicious_cycle_s > 0:
            self.dos_suspicious_cycle_s = float(suspicious_cycle_s)
        if alert_cooldown_s is not None and alert_cooldown_s >= 0:
            self.dos_alert_cooldown_s = float(alert_cooldown_s)
        if event_reset_s is not None and event_reset_s > 0:
            self.dos_event_reset_s = float(event_reset_s)

    def update_host(self, ip_address, mac_address=None, status=None):
        normalized_ip = str(ip_address).strip() if ip_address else None
        normalized_mac = self._normalize_mac(mac_address)
        if not normalized_ip or self._is_invalid_ip_candidate(normalized_ip):
            return None

        with self.state_lock:
            existing = self.hosts.get(normalized_ip, {})
            updated = {
                "mac": normalized_mac or existing.get("mac"),
                "status": status or existing.get("status") or "trusted",
                "last_seen": time.time(),
            }
            self.hosts[normalized_ip] = updated

        self._log_dos_debug(
            f"[DEBUG] Host updated: IP={normalized_ip} MAC={updated.get('mac') or 'unknown'}"
        )
        return dict(updated)

    def get_host(self, ip_address):
        normalized_ip = str(ip_address).strip() if ip_address else None
        if not normalized_ip:
            return {}
        with self.state_lock:
            return dict(self.hosts.get(normalized_ip, {}))

    def _update_hosts_from_packet(self, packet):
        if packet.haslayer(IP):
            src_ip = str(packet[IP].src).strip() if packet[IP].src else None
            dst_ip = str(packet[IP].dst).strip() if packet[IP].dst else None
            src_mac = self._normalize_mac(packet[Ether].src) if packet.haslayer(Ether) else None
            self.update_host(src_ip, src_mac)
            self.update_host(dst_ip)
            return

        if packet.haslayer(ARP):
            arp_layer = packet[ARP]
            self.update_host(arp_layer.psrc, arp_layer.hwsrc)
            self.update_host(arp_layer.pdst)

    def _cleanup_attack_state(self, current_time=None):
        now = current_time or time.time()
        with self.state_lock:
            self.attack_state = {
                ip_address: state
                for ip_address, state in self.attack_state.items()
                if state.get("active") and now - state.get("last_seen", 0) < self.attack_timeout_s
            }

    def update_attack_state(self, ip_address, attack_type, victim_ip=None):
        normalized_ip = str(ip_address).strip() if ip_address else None
        normalized_victim_ip = str(victim_ip).strip() if victim_ip else None
        if not normalized_ip:
            return 0

        now = time.time()
        self._cleanup_attack_state(now)

        with self.state_lock:
            existing = self.attack_state.get(normalized_ip, {})
            if (
                existing.get("type") == attack_type
                and existing.get("active")
                and now - existing.get("last_seen", 0) < self.attack_timeout_s
            ):
                count = int(existing.get("count", 0)) + 1
            else:
                count = 1

            self.attack_state[normalized_ip] = {
                "active": True,
                "type": attack_type,
                "last_seen": now,
                "count": count,
                "victim_ip": normalized_victim_ip or existing.get("victim_ip"),
            }

        self._log_dos_debug(f"[DEBUG] Attack classified as {attack_type}")
        self._log_dos_debug(f"[DEBUG] Attack persistence count={count}")
        return count

    def is_attack_active(self, ip_address):
        normalized_ip = str(ip_address).strip() if ip_address else None
        if not normalized_ip:
            return False

        now = time.time()
        self._cleanup_attack_state(now)

        with self.state_lock:
            attack_entry = self.attack_state.get(normalized_ip)
            return bool(
                attack_entry
                and attack_entry.get("active")
                and (now - attack_entry.get("last_seen", 0)) < self.attack_timeout_s
            )

    def clear_attack_state(self, ip_address):
        normalized_ip = str(ip_address).strip() if ip_address else None
        if not normalized_ip:
            return

        with self.state_lock:
            self.attack_state.pop(normalized_ip, None)

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
        normalized_ip = str(ip_address).strip() if ip_address else None
        if not normalized_ip:
            logging.debug("Validacion de red local omitida: IP vacia")
            return False

        try:
            candidate = ipaddress.ip_address(normalized_ip)
        except ValueError:
            logging.debug("Validacion de red local fallo: IP invalida %s", normalized_ip)
            return False

        if candidate.version != 4:
            logging.debug("Validacion de red local omitida para IP no IPv4 %s", normalized_ip)
            return False

        if not self.local_networks:
            logging.debug("No hay redes locales descubiertas; fail-open habilitado para %s", normalized_ip)
            return True

        in_local_networks = any(candidate in network for network in self.local_networks)
        logging.debug(
            "Evaluacion de red local ip=%s resultado=%s redes=%s",
            normalized_ip,
            in_local_networks,
            ", ".join(str(network) for network in self.local_networks),
        )
        return in_local_networks

    def _is_ip_trusted_context(self, ip):
        normalized_ip = str(ip).strip() if ip else None
        return bool(normalized_ip and normalized_ip in self.observed_ips)

    def _is_attacker_ip_allowed(self, attacker_ip, reason):
        normalized_ip = str(attacker_ip).strip() if attacker_ip else None
        if not normalized_ip:
            logging.debug("Evaluacion atacante sin IP (%s)", reason)
            return False

        if self._is_invalid_ip_candidate(normalized_ip):
            logging.debug("Evaluacion atacante rechazada por IP invalida ip=%s reason=%s", normalized_ip, reason)
            return False

        in_local_networks = self._is_ip_in_local_networks(normalized_ip)
        in_observed_context = self._is_ip_trusted_context(normalized_ip)
        allowed = in_local_networks or in_observed_context
        logging.debug(
            "Evaluacion atacante ip=%s reason=%s local=%s observed=%s allowed=%s",
            normalized_ip,
            reason,
            in_local_networks,
            in_observed_context,
            allowed,
        )
        return allowed

    def _observe_real_ip_source(self, packet):
        if not (packet.haslayer(IP) and packet.haslayer(Ether)):
            return

        source_ip = str(packet[IP].src).strip() if packet[IP].src else None
        source_mac = self._normalize_mac(packet[Ether].src)
        if not source_ip or not source_mac or self._is_invalid_ip_candidate(source_ip):
            return

        if not self._is_attacker_ip_allowed(source_ip, "observe_real_ip_source"):
            logging.debug("Fuente real descartada para correlacion MAC/IP: %s", source_ip)
            return

        self.mac_ip_map[source_mac] = source_ip

    def _resolve_attacker_ip_from_real_traffic(self, attacker_mac):
        normalized_mac = self._normalize_mac(attacker_mac)
        if not normalized_mac:
            return None

        attacker_ip = self.mac_ip_map.get(normalized_mac)
        if not attacker_ip:
            return None

        if not self._is_attacker_ip_allowed(attacker_ip, "resolve_real_traffic"):
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
                    and self._is_attacker_ip_allowed(normalized_candidate_ip, "resolve_context")
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

    def _cleanup_traffic_window(self, ip_address, current_time=None):
        normalized_ip = str(ip_address).strip() if ip_address else None
        if not normalized_ip:
            return None

        tracker = self.traffic_stats.get(normalized_ip)
        if not tracker:
            return None

        now = current_time or time.time()
        cutoff = now - self.dos_window_s
        timestamps = tracker.setdefault("timestamps", [])
        byte_sizes = tracker.setdefault("bytes", [])

        while timestamps and timestamps[0] < cutoff:
            timestamps.pop(0)
            if byte_sizes:
                byte_sizes.pop(0)

        if not timestamps:
            self.traffic_stats.pop(normalized_ip, None)
            return None

        return tracker

    def _cleanup_target_traffic_window(self, src_ip, dst_ip, current_time=None):
        normalized_src_ip = str(src_ip).strip() if src_ip else None
        normalized_dst_ip = str(dst_ip).strip() if dst_ip else None
        if not normalized_src_ip or not normalized_dst_ip:
            return None

        source_targets = self.target_traffic_stats.get(normalized_src_ip, {})
        tracker = source_targets.get(normalized_dst_ip)
        if not tracker:
            return None

        now = current_time or time.time()
        cutoff = now - self.dos_window_s
        timestamps = tracker.setdefault("timestamps", [])
        byte_sizes = tracker.setdefault("bytes", [])

        while timestamps and timestamps[0] < cutoff:
            timestamps.pop(0)
            if byte_sizes:
                byte_sizes.pop(0)

        if not timestamps:
            source_targets.pop(normalized_dst_ip, None)
            if not source_targets:
                self.target_traffic_stats.pop(normalized_src_ip, None)
            return None

        return tracker

    def update_traffic_stats(self, packet):
        if IP not in packet:
            return None, None, None

        src_ip = str(packet[IP].src).strip() if packet[IP].src else None
        dst_ip = str(packet[IP].dst).strip() if packet[IP].dst else None
        if not src_ip or self._is_invalid_ip_candidate(src_ip):
            return src_ip, None, None

        current_time = time.time()
        packet_size = len(packet)

        with self.state_lock:
            tracker = self.traffic_stats.setdefault(
                src_ip,
                {
                    "timestamps": [],
                    "bytes": [],
                },
            )
            tracker["timestamps"].append(current_time)
            tracker["bytes"].append(packet_size)
            self._cleanup_traffic_window(src_ip, current_time=current_time)

            if dst_ip and not self._is_invalid_ip_candidate(dst_ip):
                dst_tracker = self.target_traffic_stats.setdefault(src_ip, {}).setdefault(
                    dst_ip,
                    {
                        "timestamps": [],
                        "bytes": [],
                    },
                )
                dst_tracker["timestamps"].append(current_time)
                dst_tracker["bytes"].append(packet_size)
                self._cleanup_target_traffic_window(src_ip, dst_ip, current_time=current_time)

        return src_ip, packet_size, current_time

    def calculate_rates(self, ip_address, current_time=None):
        normalized_ip = str(ip_address).strip() if ip_address else None
        if not normalized_ip:
            return 0.0, 0.0

        with self.state_lock:
            tracker = self._cleanup_traffic_window(normalized_ip, current_time=current_time)
            if not tracker:
                return 0.0, 0.0

            timestamps = tracker.get("timestamps", [])
            byte_sizes = tracker.get("bytes", [])
            if not timestamps:
                return 0.0, 0.0

            now = current_time or time.time()
            observed_window_s = min(
                self.dos_window_s,
                max(1.0, now - timestamps[0]),
            )
            pps = len(timestamps) / float(observed_window_s)
            bps = sum(byte_sizes) / float(observed_window_s)

        return pps, bps

    def calculate_target_rates(self, src_ip, dst_ip, current_time=None):
        normalized_src_ip = str(src_ip).strip() if src_ip else None
        normalized_dst_ip = str(dst_ip).strip() if dst_ip else None
        if not normalized_src_ip or not normalized_dst_ip:
            return 0.0, 0.0

        with self.state_lock:
            tracker = self._cleanup_target_traffic_window(
                normalized_src_ip,
                normalized_dst_ip,
                current_time=current_time,
            )
            if not tracker:
                return 0.0, 0.0

            timestamps = tracker.get("timestamps", [])
            byte_sizes = tracker.get("bytes", [])
            if not timestamps:
                return 0.0, 0.0

            now = current_time or time.time()
            observed_window_s = min(
                self.dos_window_s,
                max(1.0, now - timestamps[0]),
            )
            pps = len(timestamps) / float(observed_window_s)
            bps = sum(byte_sizes) / float(observed_window_s)

        return pps, bps

    def _is_likely_port_scan(self, attacker_ip, target_ip):
        tracker_key = (attacker_ip, target_ip)
        entries = self.port_scan_tracker.get(tracker_key, [])
        if not entries:
            return False
        unique_ports = {port for port, _timestamp in entries}
        return len(unique_ports) >= self.port_scan_threshold

    def _resolve_mac_for_ip(self, ip_address):
        normalized_ip = str(ip_address).strip() if ip_address else None
        if not normalized_ip:
            return None

        return self._normalize_mac(
            self.arp_table.get(normalized_ip) or self.arp_baseline.get(normalized_ip)
        )

    def _get_dos_profile(self, packet):
        if ICMP in packet and packet[ICMP].type == 8:
            return "icmp_flood", self.dos_profiles["icmp_flood"]

        if TCP in packet:
            tcp_flags = int(packet[TCP].flags)
            if tcp_flags & 0x02 and not (tcp_flags & 0x10):
                return "syn_flood", self.dos_profiles["syn_flood"]

        return None, None

    def _clear_dos_state(self, ip_address, attack_key=None):
        normalized_ip = str(ip_address).strip() if ip_address else None
        if not normalized_ip:
            return

        ip_state = self.dos_state.get(normalized_ip)
        if not ip_state:
            return

        if attack_key:
            ip_state.pop(attack_key, None)
            if ip_state:
                return

        self.dos_state.pop(normalized_ip, None)

    def _log_dos_debug(self, message):
        if DEBUG:
            logging.debug(message)
            log_debug(message)

    def handle_attack(self, ip_address, mac_address, attack_type, victim_ip=None):
        normalized_ip = str(ip_address).strip() if ip_address else None
        normalized_mac = self._normalize_mac(mac_address)
        normalized_victim_ip = str(victim_ip).strip() if victim_ip else None
        if not normalized_ip:
            return False

        self.update_host(normalized_ip, normalized_mac, status="attacker")
        self.update_attack_state(normalized_ip, attack_type, victim_ip=normalized_victim_ip)

        if self._is_whitelisted(normalized_ip):
            self._log_dos_debug(f"[DEBUG] Skipping protected IP: {normalized_ip}")
            return False

        if self._is_mac_whitelisted(normalized_mac):
            return False

        logging.info(
            "[BLOCK QUEUE] Requesting block ip=%s mac=%s attack=%s victim=%s",
            normalized_ip,
            normalized_mac or "unknown",
            attack_type,
            normalized_victim_ip or "unknown",
        )
        result = self.block_attacker(normalized_ip, normalized_mac, attack_type)
        if result is True:
            with self.state_lock:
                self.blocked_hosts.add(normalized_ip)
                host_entry = self.hosts.setdefault(
                    normalized_ip,
                    {
                        "mac": normalized_mac,
                        "status": "trusted",
                        "last_seen": time.time(),
                    },
                )
                host_entry["mac"] = normalized_mac or host_entry.get("mac")
                host_entry["status"] = "blocked"
                host_entry["last_seen"] = time.time()
            return True

        return False

    def detect_dos(self, ip_address, packet, current_time=None, pps=None, bps=None):
        normalized_ip = str(ip_address).strip() if ip_address else None
        victim_ip = str(packet[IP].dst).strip() if packet.haslayer(IP) and packet[IP].dst else None
        attack_key, attack_profile = self._get_dos_profile(packet)
        if not normalized_ip or not attack_profile or not victim_ip:
            return

        if self._is_invalid_ip_candidate(normalized_ip):
            return

        if not self._is_attacker_ip_allowed(normalized_ip, "detect_dos"):
            return

        attacker_mac = self._normalize_mac(packet[Ether].src) if packet.haslayer(Ether) else None
        if self._is_whitelisted(normalized_ip):
            self._log_dos_debug(f"[DEBUG] Skipping protected IP: {normalized_ip}")
            return

        if self._is_mac_whitelisted(attacker_mac):
            return

        now = current_time or time.time()
        if pps is None or bps is None:
            calculated_pps, calculated_bps = self.calculate_rates(normalized_ip, current_time=now)
            if pps is None:
                pps = calculated_pps
            if bps is None:
                bps = calculated_bps

        target_pps, target_bps = self.calculate_target_rates(normalized_ip, victim_ip, current_time=now)
        if self._is_likely_port_scan(normalized_ip, victim_ip):
            self._log_dos_debug(
                f"[DEBUG] Attack classified as PORT_SCAN src={normalized_ip} dst={victim_ip}"
            )
            return

        alert_pps = float(attack_profile.get("alert_pps", 0))
        block_pps = float(attack_profile.get("block_pps", 0))
        block_bps = float(attack_profile.get("block_bps", DOS_BLOCK_BPS_THRESHOLD))

        alert_condition = target_pps > alert_pps or target_bps > block_bps
        block_condition = target_pps > block_pps or target_bps > block_bps
        if not alert_condition:
            with self.state_lock:
                current_count = self.suspicious_count.get(normalized_ip, 0)
                if current_count > 0:
                    self.suspicious_count[normalized_ip] = max(0, current_count - 1)
                if self.suspicious_count.get(normalized_ip, 0) == 0:
                    self.suspicious_count.pop(normalized_ip, None)
                    self._clear_dos_state(normalized_ip, attack_key)
                debug_count = self.suspicious_count.get(normalized_ip, 0)
            self._log_dos_debug(
                f"[DEBUG] PPS={target_pps:.2f}, BPS={target_bps:.2f}, suspicious_count={debug_count} ip={normalized_ip}"
            )
            return

        should_alert = False
        suspicious_count = 0
        with self.state_lock:
            ip_state = self.dos_state.setdefault(normalized_ip, {})
            attack_state = ip_state.get(attack_key)

            if not attack_state or now - attack_state.get("last_seen", 0) > self.dos_event_reset_s:
                attack_state = {
                    "last_seen": now,
                    "last_alert_at": 0,
                    "blocked": False,
                }
                ip_state[attack_key] = attack_state

            attack_state["last_seen"] = now

            attack_state["pps"] = target_pps
            attack_state["bps"] = target_bps
            attack_state["victim_ip"] = victim_ip

            if now - attack_state["last_alert_at"] >= self.dos_alert_cooldown_s:
                attack_state["last_alert_at"] = now
                should_alert = True

            if block_condition:
                self.suspicious_count[normalized_ip] = self.suspicious_count.get(normalized_ip, 0) + 1

            suspicious_count = self.suspicious_count.get(normalized_ip, 0)

        alert_message = (
            f"[ALERT] Possible DoS detected: {normalized_ip} PPS={target_pps:.2f} BPS={target_bps:.2f}\n"
            f"Attacker IP: {normalized_ip}\n"
            f"Victim IP: {victim_ip}\n"
            f"Attack Type: {attack_profile['label']}\n"
            f"PPS: {target_pps:.2f}\n"
            f"BPS: {target_bps:.2f}\n"
            f"Suspicious Cycles: {suspicious_count}/{self.dos_min_suspicious_events}\n"
            f"Window: up to {self.dos_window_s}s"
        )

        if should_alert:
            logging.warning(
                "[ALERT] Possible DoS detected: %s PPS=%.2f BPS=%.2f type=%s victim=%s",
                normalized_ip,
                target_pps,
                target_bps,
                attack_profile["label"],
                victim_ip,
            )
            self.update_host(normalized_ip, attacker_mac, status="attacker")
            self.update_host(victim_ip)
            self.update_attack_state(normalized_ip, "DOS", victim_ip=victim_ip)
            self.trigger_alert(alert_message)

        self._log_dos_debug(
            f"[DEBUG] PPS={target_pps:.2f}, BPS={target_bps:.2f}, suspicious_count={suspicious_count} ip={normalized_ip}"
        )

        if block_condition and suspicious_count >= self.dos_min_suspicious_events:
            self._log_dos_debug(f"[DEBUG] Blocking condition met for {normalized_ip}")
            self.handle_dos_attack(normalized_ip, packet, attack_key, attack_profile, target_pps, target_bps)

    def handle_dos_attack(self, ip_address, packet, attack_key, attack_profile, pps=None, bps=None):
        normalized_ip = str(ip_address).strip() if ip_address else None
        victim_ip = str(packet[IP].dst).strip() if packet.haslayer(IP) and packet[IP].dst else None
        if not normalized_ip:
            return False

        attacker_mac = self._normalize_mac(packet[Ether].src) if packet.haslayer(Ether) else None
        attacker_mac = attacker_mac or self._resolve_mac_for_ip(normalized_ip)

        if not self._is_attacker_ip_allowed(normalized_ip, "handle_dos_attack"):
            return False

        if self._is_whitelisted(normalized_ip):
            self._log_dos_debug(f"[DEBUG] Skipping protected IP: {normalized_ip}")
            logging.info("IP %s protegida/en whitelist: se omite bloqueo por DoS", normalized_ip)
            return False

        if self._is_mac_whitelisted(attacker_mac):
            logging.info("MAC %s en whitelist: se omite bloqueo por DoS", attacker_mac)
            return False

        try:
            if DEBUG:
                log_debug(f"[ATTACK TYPE] Detected {attack_profile['label']} from {normalized_ip}")

            result = self.handle_attack(
                normalized_ip,
                attacker_mac,
                attack_profile["label"],
                victim_ip=victim_ip,
            )
            if result is True:
                with self.state_lock:
                    self.suspicious_count.pop(normalized_ip, None)
                    ip_state = self.dos_state.setdefault(normalized_ip, {})
                    ip_state.setdefault(attack_key, {})["blocked"] = True

                logging.warning("[BLOCK] DoS attacker blocked: %s", normalized_ip)
                self.trigger_alert(
                    "\n".join(
                        [
                            f"[BLOCK] DoS attacker blocked: {normalized_ip}",
                            f"Attacker IP: {normalized_ip}",
                            f"Victim IP: {victim_ip or 'unknown'}",
                            f"Attacker MAC: {attacker_mac or 'unknown'}",
                            f"Attack Type: {attack_profile['label']}",
                            f"PPS: {pps:.2f}" if pps is not None else "PPS: unknown",
                            f"BPS: {bps:.2f}" if bps is not None else "BPS: unknown",
                        ]
                    )
                )
                return True
        except Exception as error:
            logging.error(
                "Error ejecutando callback de bloqueo DoS para ip=%s mac=%s tipo=%s: %s",
                normalized_ip,
                attacker_mac,
                attack_profile["label"],
                error,
            )

        return False

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

    def _classify_tcp_scan(self, tcp_flags):
        if tcp_flags == 0:
            return "NULL scan"
        if tcp_flags == 0x01:
            return "FIN scan"
        if tcp_flags == 0x29:
            return "XMAS scan"
        if tcp_flags == 0x02:
            return "SYN scan"
        return None

    def _cleanup_scan_tracker(self, current_time=None, source_ip=None):
        now = current_time or time.time()
        cutoff = now - self.port_scan_window_s

        with self.state_lock:
            tracked_ips = [source_ip] if source_ip else list(self.scan_tracker.keys())
            for tracked_ip in tracked_ips:
                if tracked_ip not in self.scan_tracker:
                    continue

                entry = self.scan_tracker.get(tracked_ip, {})
                timestamps = [
                    (timestamp, port)
                    for timestamp, port in entry.get("timestamps", [])
                    if timestamp >= cutoff
                ]
                if not timestamps:
                    self.scan_tracker.pop(tracked_ip, None)
                    continue

                entry["timestamps"] = timestamps
                entry["ports"] = {port for timestamp, port in timestamps}
                self.scan_tracker[tracked_ip] = entry

    def _track_behavioral_scan(self, src_ip, dst_ip, dst_port, tcp_flags):
        attacker_ip = str(src_ip).strip() if src_ip else None
        target_ip = str(dst_ip).strip() if dst_ip else None
        if not attacker_ip or dst_port is None or self._is_invalid_ip_candidate(attacker_ip):
            return

        now = time.time()
        if now - self.last_scan_cleanup_s >= self.scan_cleanup_interval_s:
            self._cleanup_scan_tracker(current_time=now)
            self.last_scan_cleanup_s = now

        with self.state_lock:
            tracker = self.scan_tracker.setdefault(
                attacker_ip,
                {
                    "ports": set(),
                    "timestamps": [],
                },
            )
            tracker["timestamps"].append((now, int(dst_port)))
            tracker["timestamps"] = [
                (timestamp, port)
                for timestamp, port in tracker["timestamps"]
                if timestamp >= now - self.port_scan_window_s
            ]
            tracker["ports"] = {port for timestamp, port in tracker["timestamps"]}
            ports_scanned = sorted(tracker["ports"])

        scan_type = self._classify_tcp_scan(tcp_flags)
        if DEBUG:
            log_debug(
                f"[SCAN DETECT] src_ip={attacker_ip} flags=0x{tcp_flags:02x} "
                f"ports_scanned={ports_scanned}"
            )

        if scan_type:
            self.trigger_alert(
                f"{scan_type} detected from {attacker_ip}"
                f"{f' to {target_ip}:{dst_port}' if target_ip else ''}"
            )

        if len(ports_scanned) >= self.port_scan_threshold:
            logging.warning(
                "[SCAN DETECT] src_ip=%s flags=0x%02x ports_scanned=%s",
                attacker_ip,
                tcp_flags,
                ports_scanned,
            )
            self.trigger_alert(
                f"Port scan detected from {attacker_ip} "
                f"({len(ports_scanned)} unique ports in {self.port_scan_window_s}s)"
            )
            self._handle_port_scan(attacker_ip, target_ip, ports_scanned)

    def reset_host_state(self, ip_address):
        normalized_ip = str(ip_address).strip() if ip_address else None
        if not normalized_ip:
            return

        with self.state_lock:
            self.scan_tracker.pop(normalized_ip, None)
            self.port_scan_tracker = {
                key: value
                for key, value in self.port_scan_tracker.items()
                if normalized_ip not in key
            }
            self.detected_port_scanners = {
                entry
                for entry in self.detected_port_scanners
                if not (
                    entry == normalized_ip
                    or (isinstance(entry, tuple) and normalized_ip in entry)
                )
            }
            self.detected_arp_attacks = {
                entry
                for entry in self.detected_arp_attacks
                if not (
                    isinstance(entry, tuple) and entry and entry[0] == normalized_ip
                )
            }
            self.traffic_stats.pop(normalized_ip, None)
            self.target_traffic_stats.pop(normalized_ip, None)
            for source_ip, targets in list(self.target_traffic_stats.items()):
                targets.pop(normalized_ip, None)
                if not targets:
                    self.target_traffic_stats.pop(source_ip, None)
            self.dos_state.pop(normalized_ip, None)
            self.suspicious_count.pop(normalized_ip, None)
            self.attack_state.pop(normalized_ip, None)
            self.blocked_hosts.discard(normalized_ip)
            self.observed_ips.discard(normalized_ip)
            self.suspicious_arp_events.pop(normalized_ip, None)
            self.ip_packet_count.pop(normalized_ip, None)
            host_entry = self.hosts.get(normalized_ip)
            if host_entry:
                host_entry["status"] = "trusted"
                host_entry["last_seen"] = time.time()
            self.attack_contexts = {
                key: context
                for key, context in self.attack_contexts.items()
                if normalized_ip
                not in {
                    str(context.get("attacker_ip")).strip() if context.get("attacker_ip") else None,
                    str(context.get("victim_ip")).strip() if context.get("victim_ip") else None,
                    str(context.get("gateway_ip")).strip() if context.get("gateway_ip") else None,
                    str(context.get("spoofed_ip")).strip() if context.get("spoofed_ip") else None,
                    str(context.get("target_ip")).strip() if context.get("target_ip") else None,
                }
            }
            self.active_attacks = {
                key: value
                for key, value in self.active_attacks.items()
                if normalized_ip not in str(key)
            }

        logging.info("[STATE RESET] ip=%s", normalized_ip)
        if DEBUG:
            log_debug(f"[STATE RESET] ip={normalized_ip}")

    def process_packet(self, packet):
        try:
            self._update_hosts_from_packet(packet)
            if IP in packet:
                src_ip, _packet_size, current_time = self.update_traffic_stats(packet)
                dst_ip = str(packet[IP].dst).strip() if packet[IP].dst else None
                if src_ip:
                    self.observed_ips.add(src_ip)
                self._observe_real_ip_source(packet)
                self.packet_counter += 1
                if src_ip:
                    self.ip_packet_count[src_ip] = self.ip_packet_count.get(src_ip, 0) + 1

                if TCP in packet:
                    tcp_layer = packet[TCP]
                    tcp_flags = int(tcp_layer.flags)
                    self._track_behavioral_scan(src_ip, dst_ip, tcp_layer.dport, tcp_flags)

                    if tcp_flags & 0x02:
                        self.syn_counter += 1

                        if not (tcp_flags & 0x10):
                            self._track_port_scan(src_ip, dst_ip, tcp_layer.dport)

                if src_ip:
                    pps, bps = self.calculate_rates(src_ip, current_time=current_time)
                    self.detect_dos(src_ip, packet, current_time=current_time, pps=pps, bps=bps)

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

        if not self._is_attacker_ip_allowed(resolved_ip, "handle_arp_attack"):
            logging.warning("Attacker validation failed - blocking cancelled ip=%s attack=arp", resolved_ip)
            return

        attack_key = (resolved_ip, normalized_mac or "unknown")

        if gateway_ip and resolved_ip == gateway_ip:
            logging.warning("IP atacante coincide con gateway (%s); se omite bloqueo", resolved_ip)
            return

        if victim_target_ip and resolved_ip == victim_target_ip:
            logging.warning("IP atacante coincide con victima (%s); se omite bloqueo", resolved_ip)
            return

        if self._is_whitelisted(resolved_ip):
            logging.warning("Skipping protected/gateway IP during ARP block evaluation: %s", resolved_ip)
            logging.info("IP %s protegida/en whitelist: se omite bloqueo", resolved_ip)
            return

        if self._is_mac_whitelisted(normalized_mac):
            logging.info("MAC %s en whitelist: se omite bloqueo", normalized_mac)
            return

        logging.warning("[ALERT] Real attacker detected: %s", resolved_ip)
        self.update_host(resolved_ip, normalized_mac, status="attacker")
        self.update_host(victim_target_ip)
        self.update_attack_state(resolved_ip, "ARP", victim_ip=victim_target_ip or spoofed_ip)

        try:
            if DEBUG:
                log_debug(f"[ATTACK TYPE] Detected ARP Spoofing from {resolved_ip}")
            result = self.handle_attack(
                resolved_ip,
                normalized_mac,
                "ARP Spoofing",
                victim_ip=victim_target_ip or spoofed_ip,
            )
        except Exception as error:
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

    def _track_port_scan(self, src_ip, dst_ip, dst_port):
        attacker_ip = str(src_ip).strip() if src_ip else None
        target_ip = str(dst_ip).strip() if dst_ip else None

        if not attacker_ip or not target_ip or dst_port is None:
            return

        if self._is_invalid_ip_candidate(attacker_ip):
            return

        tracker_key = (attacker_ip, target_ip)
        now = time.time()
        cutoff = now - self.port_scan_window_s
        recent_entries = [
            (port, timestamp)
            for port, timestamp in self.port_scan_tracker.get(tracker_key, [])
            if timestamp >= cutoff
        ]

        recent_entries.append((int(dst_port), now))
        self.port_scan_tracker[tracker_key] = recent_entries

        unique_ports = {port for port, _timestamp in recent_entries}
        if len(unique_ports) < self.port_scan_threshold:
            return

        logging.warning(
            "Posible port scan TCP SYN detectado src=%s dst=%s puertos_unicos=%s ventana=%ss",
            attacker_ip,
            target_ip,
            len(unique_ports),
            self.port_scan_window_s,
        )
        self._handle_port_scan(attacker_ip, target_ip, unique_ports)

    def _log_port_scan_debug(self, message):
        logging.debug(message)
        if DEBUG:
            log_debug(message)

    def _handle_port_scan(self, attacker_ip, target_ip, ports):
        attacker_ip = str(attacker_ip).strip() if attacker_ip else None
        target_ip = str(target_ip).strip() if target_ip else None
        detection_key = (attacker_ip, target_ip)
        sorted_ports = sorted({int(port) for port in ports if port is not None})

        self._log_port_scan_debug(
            f"[PORT SCAN] Handle start attacker={attacker_ip or 'unknown'} "
            f"target={target_ip or 'unknown'} ports={sorted_ports}"
        )

        if not attacker_ip:
            self._log_port_scan_debug("[PORT SCAN] Skipping block reason=missing_attacker_ip")
            logging.info("IP atacante invalida para port scan (%s); se omite bloqueo", attacker_ip)
            return

        if not self._is_attacker_ip_allowed(attacker_ip, "handle_port_scan"):
            self._log_port_scan_debug(
                f"[PORT SCAN] Skipping block reason=attacker_validation_failed attacker={attacker_ip}"
            )
            logging.warning("Attacker validation failed - blocking cancelled ip=%s attack=port_scan", attacker_ip)
            return

        if self._is_whitelisted(attacker_ip):
            self._log_port_scan_debug(
                f"[PORT SCAN] Skipping block reason=whitelisted attacker={attacker_ip}"
            )
            logging.info("IP %s en whitelist: se omite bloqueo por port scan", attacker_ip)
            return

        port_preview = ", ".join(str(port) for port in sorted_ports[:10])
        if len(sorted_ports) > 10:
            port_preview += ", ..."

        message = (
            "[ALERT] TCP SYN Port Scan Detected\n"
            f"Attacker IP: {attacker_ip}\n"
            f"Victim IP: {target_ip or 'unknown'}\n"
            f"Unique Ports: {len(sorted_ports)}\n"
            f"Observed Ports: {port_preview}\n"
            f"Window: {self.port_scan_window_s}s"
        )

        logging.warning(
            "Port scan confirmado src=%s dst=%s ports=%s",
            attacker_ip,
            target_ip,
            sorted_ports,
        )
        self.update_host(attacker_ip, status="attacker")
        self.update_host(target_ip)
        self.update_attack_state(attacker_ip, "SCAN", victim_ip=target_ip)
        self.trigger_alert(message)

        self._log_port_scan_debug(
            f"[PORT SCAN] Attempting block attacker={attacker_ip} target={target_ip or 'unknown'} "
            f"ports={sorted_ports}"
        )
        logging.info("Attempting to block attacker %s por port scan", attacker_ip)

        try:
            if DEBUG:
                log_debug(f"[ATTACK TYPE] Detected Port Scan from {attacker_ip}")
            result = self.handle_attack(attacker_ip, None, "Port Scan", victim_ip=target_ip)
            self._log_port_scan_debug(
                f"[PORT SCAN] block_callback result={result!r} attacker={attacker_ip}"
            )

            if result is True:
                with self.state_lock:
                    self.port_scan_tracker.pop(detection_key, None)
                logging.info("Bloqueo por port scan ejecutado correctamente para attacker=%s", attacker_ip)
                self._log_port_scan_debug(
                    f"[PORT SCAN] Block success attacker={attacker_ip} target={target_ip or 'unknown'}"
                )
                return

            logging.critical(
                "Bloqueo por port scan no confirmado attacker=%s result=%r",
                attacker_ip,
                result,
            )
            self._log_port_scan_debug(
                f"[PORT SCAN] Skipping block reason=callback_failed attacker={attacker_ip} result={result!r}"
            )
        except Exception as error:
            self._log_port_scan_debug(
                f"[PORT SCAN] Skipping block reason=callback_exception attacker={attacker_ip} error={error}"
            )
            logging.error(
                "Error ejecutando callback de bloqueo por port scan para ip=%s: %s",
                attacker_ip,
                error,
            )

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

        if not self._is_attack_active(attack_key) and not self.is_attack_active(sender_ip):
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
        tracked_arp_ip = attacker_ip or sender_ip
        if self.is_attack_active(tracked_arp_ip):
            self.update_attack_state(tracked_arp_ip, "ARP", victim_ip=victim_ip)
            self._mark_attack_active(attack_key, confirmed=True)
            self.arp_table[sender_ip] = expected_mac
            return

        if attacker_ip:
            alert_lines.insert(1, f"Attacker IP: {attacker_ip}")
            self.update_host(attacker_ip, attacker_mac, status="attacker")
            self.update_attack_state(attacker_ip, "ARP", victim_ip=victim_ip)
        self.update_host(victim_ip)

        alert_lines.append("Mitigation: queued for post-block ARP restoration")
        self.trigger_alert("\n".join(alert_lines))
        self._mark_attack_active(attack_key, confirmed=True)
        self.arp_table[sender_ip] = expected_mac

        if DEBUG:
            logging.debug(
                "Spoof detected claimed_ip=%s attacker_mac=%s attacker_ip=%s",
                sender_ip,
                attacker_mac,
                attacker_ip,
            )

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
                if DEBUG:
                    logging.debug(
                        "Spoof detected claimed_ip=%s sender_mac=%s attacker_ip=%s",
                        sender_ip,
                        sender_mac,
                        attacker_ip,
                    )
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
        tracked_ips = list(self.traffic_stats.keys())
        for ip in tracked_ips:
            self.calculate_rates(ip)

        self.packet_counter = 0
        self.syn_counter = 0
        self.ip_packet_count = {}

    def trigger_alert(self, message):
        if self.alert_callback:
            self.alert_callback(message)
        else:
            log_event(message, "alert")
