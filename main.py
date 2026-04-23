import logging
import ipaddress
import queue
import socket
import sys
import threading
import time
from datetime import datetime

from PyQt5.QtCore import QTimer
from PyQt5.QtWidgets import QApplication, QMessageBox
from scapy.all import ARP, Ether, IP, conf, get_if_hwaddr, getmacbyip

from detection_engine import DEBUG as DETECTION_DEBUG
from detection_engine import DetectionEngine
from event_logger import log_debug, log_event, set_gui_event_callback
from interfaz_grafica import MainWindow
from mikrotik_config import get_active_mikrotik_config, resolve_mikrotik_config
from mikrotik_handler import MikroTikManager
from network_capture import NetworkCaptureScanner


DEBUG = True


logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
)


def get_friendly_interfaces():
    interfaces = []
    try:
        for iface in conf.ifaces.values():
            real_name = getattr(iface, "name", None)
            if not real_name:
                continue

            friendly_name = getattr(iface, "description", "") or real_name
            interfaces.append((friendly_name, real_name))
    except Exception as error:
        logging.error("Error al obtener interfaces amigables: %s", error)

    unique = {}
    for friendly_name, real_name in interfaces:
        if real_name not in unique:
            unique[real_name] = friendly_name

    return [(friendly_name, real_name) for real_name, friendly_name in unique.items()]


class AppController:
    def __init__(self):
        conf.verb = 1

        self.window = MainWindow()
        self.detection_engine = DetectionEngine()
        self.packet_event_queue = queue.Queue()
        self.host_records = {}
        self.host_lock = threading.RLock()
        self.protected_ips = set()
        self.protected_macs = set()
        self.local_networks = []
        self.gateway_ips = set()
        self.gateway_ip = None
        self.local_interface_ips = set()
        self.own_host_ip = None
        self.own_host_mac = None
        self.mikrotik_ip = None
        self.mikrotik_config = get_active_mikrotik_config()
        self.mikrotik = None
        self.blocked_ips = set()
        self.blocked_macs = set()

        self.window.packet_text_edit.document().setMaximumBlockCount(200)
        set_gui_event_callback(self.handle_alert)

        self.ui_queue = queue.Queue()
        self.ui_poll_timer = QTimer()
        self.ui_poll_timer.setInterval(200)
        self.ui_poll_timer.timeout.connect(self.process_ui_queue)

        self.friendly_interfaces = get_friendly_interfaces()
        self.window.set_capture_interfaces(self.friendly_interfaces)

        selected_interfaces = self.window.get_selected_capture_interfaces()
        selected_interface = selected_interfaces[0] if selected_interfaces else None
        self.network_capture = NetworkCaptureScanner(
            packet_callback=self.handle_packet,
            hosts_callback=self.handle_hosts_found,
            interface=selected_interface,
        )

        self.detection_engine.set_alert_callback(self.handle_alert)
        self.detection_engine.set_block_callback(self.block_attacker_connection)
        self.detection_engine.set_capture_interface(selected_interface)
        self.detection_engine.configure_mitigation(**self.window.get_mitigation_options())

        self.window.bind_actions(
            start_callback=self.start_capture,
            pause_callback=self.pause_capture,
            continue_callback=self.continue_capture,
            stop_callback=self.stop_capture,
            find_hosts_callback=self.find_hosts,
            block_host_callback=self.block_attacker_connection,
            unblock_host_callback=self.unblock_attacker_connection,
        )

    def _get_primary_interface(self, selected_interfaces=None):
        if selected_interfaces:
            return selected_interfaces[0]
        return self.window.get_selected_capture_interface()

    def _normalize_status(self, status):
        return (status or "trusted").strip().lower()

    def _get_host_record(self, ip_address):
        with self.host_lock:
            record = self.host_records.get(ip_address, {})
            return dict(record)

    def _serialize_hosts(self):
        with self.host_lock:
            serialized = []
            for ip_address in sorted(self.host_records):
                data = self.host_records[ip_address]
                interfaces = sorted(data.get("interfaces", set()))
                serialized.append(
                    {
                        "ip": ip_address,
                        "mac": data.get("mac", "unknown"),
                        "interface": ", ".join(interfaces) if interfaces else "Unknown",
                        "status": self._normalize_status(data.get("status")),
                        "type": data.get("type", "Host"),
                        "activity": data.get("activity", "Normal"),
                        "attack_types": sorted(data.get("attack_types", set())),
                    }
                )
            return serialized

    def _emit_hosts_update(self):
        self._queue_ui_task("update_devices", self._serialize_hosts())

    def _queue_ui_task(self, task_type, data):
        self.ui_queue.put(
            {
                "type": task_type,
                "data": data,
            }
        )

    def _upsert_host_record(
        self,
        ip_address,
        mac_address=None,
        interface_name=None,
        status=None,
        activity=None,
        host_type=None,
        attack_type=None,
        emit=True,
    ):
        normalized_ip = self._normalize_ip(ip_address)
        normalized_mac = self._normalize_mac(mac_address)
        if not normalized_ip:
            return

        changed = False
        with self.host_lock:
            existing = self.host_records.get(normalized_ip, {})
            interfaces = set(existing.get("interfaces", set()))
            attack_types = set(existing.get("attack_types", set()))
            if interface_name:
                for value in str(interface_name).split(","):
                    value = value.strip()
                    if value:
                        interfaces.add(value)

            if attack_type:
                attack_types.add(str(attack_type).strip())

            updated_record = {
                "mac": normalized_mac or existing.get("mac", "unknown"),
                "status": self._normalize_status(status or existing.get("status") or "trusted"),
                "type": host_type or existing.get("type", "Host"),
                "activity": activity or existing.get("activity", "Normal"),
                "interfaces": interfaces,
                "attack_types": attack_types,
                "last_seen": time.time(),
            }
            previous_stable = {
                key: value
                for key, value in existing.items()
                if key != "last_seen"
            }
            updated_stable = {
                key: value
                for key, value in updated_record.items()
                if key != "last_seen"
            }
            changed = updated_stable != previous_stable
            self.host_records[normalized_ip] = updated_record

        if emit and changed:
            logging.debug(
                "[DEBUG] Host updated: IP=%s MAC=%s",
                normalized_ip,
                updated_record.get("mac", "unknown"),
            )
            self._emit_hosts_update()

    def _extract_host_from_packet(self, packet):
        interface_name = getattr(packet, "capture_interface", None) or getattr(packet, "sniffed_on", None)
        if packet.haslayer(ARP):
            arp_layer = packet[ARP]
            return arp_layer.psrc, self._normalize_mac(arp_layer.hwsrc), interface_name

        if packet.haslayer(IP) and packet.haslayer(Ether):
            ip_layer = packet[IP]
            ethernet_layer = packet[Ether]
            return ip_layer.src, self._normalize_mac(ethernet_layer.src), interface_name

        return None, None, interface_name

    def _register_packet_host(self, packet):
        ip_address, mac_address, interface_name = self._extract_host_from_packet(packet)
        if not ip_address or not mac_address:
            return
        self._upsert_host_record(
            ip_address,
            mac_address,
            interface_name=interface_name,
            emit=True,
        )

    def handle_hosts_found(self, hosts):
        if not hosts:
            return

        for host in hosts:
            self._upsert_host_record(
                host.get("ip"),
                host.get("mac"),
                interface_name=host.get("interface"),
                status=host.get("status", "trusted"),
                activity=host.get("activity", "Discovered"),
                host_type=host.get("type", "Host"),
                emit=False,
            )

        self._emit_hosts_update()

    def _initialize_mikrotik(self, selected_interface):
        config = resolve_mikrotik_config(selected_interface=selected_interface, parent=self.window)
        if not config:
            self.mikrotik_config = None
            self.mikrotik = None
            logging.error("MikroTik connection failed or not initialized")
            return

        self.mikrotik_config = config
        self.mikrotik = MikroTikManager(
            host=config.host,
            username=config.username,
            password=config.password,
            port=config.port,
        )
        self.mikrotik_ip = config.host
        self.mikrotik.connect()

        if not self.mikrotik.is_connected():
            logging.error("MikroTik connection failed or not initialized")

    def _normalize_ip(self, ip_address):
        if ip_address is None:
            return None
        value = str(ip_address).strip()
        return value or None

    def _normalize_mac(self, mac_address):
        if mac_address is None:
            return None
        value = str(mac_address).strip().lower()
        return value or None

    def _is_valid_mac(self, mac_address):
        normalized = self._normalize_mac(mac_address)
        if not normalized:
            return False
        parts = normalized.split(":")
        return len(parts) == 6 and all(len(part) == 2 for part in parts)

    def _get_gateway_ips(self, selected_interfaces=None):
        gateway_ips = set()

        for context in self.detection_engine.attack_contexts.values():
            for candidate in [context.get("gateway_ip"), context.get("spoofed_ip")]:
                normalized_candidate = self._normalize_ip(candidate)
                if not normalized_candidate:
                    continue
                if not self._is_in_local_networks(normalized_candidate):
                    continue
                if normalized_candidate not in self.detection_engine.arp_baseline:
                    continue
                gateway_ips.add(normalized_candidate)

        return gateway_ips

    def _resolve_local_ip(self, selected_interface):
        local_ip = None

        try:
            if self.network_capture and selected_interface:
                local_ip = self.network_capture.get_interface_ip(selected_interface)
        except Exception as error:
            logging.debug("No se pudo resolver IP local por interfaz: %s", error)

        if not local_ip:
            try:
                local_ip = socket.gethostbyname(socket.gethostname())
            except Exception:
                local_ip = None

        return local_ip

    def _resolve_local_mac(self, selected_interface):
        if not selected_interface:
            return None

        try:
            return self._normalize_mac(get_if_hwaddr(selected_interface))
        except Exception as error:
            logging.debug("No se pudo resolver MAC local de %s: %s", selected_interface, error)
            return None

    def _resolve_known_mac(self, ip_address):
        if not ip_address:
            return None

        host_record = self._get_host_record(ip_address)
        mac_address = self.detection_engine.arp_baseline.get(ip_address) or host_record.get("mac") or self.window.get_mac_for_ip(ip_address)
        mac_address = self._normalize_mac(mac_address)
        if mac_address:
            return mac_address

        try:
            return self._normalize_mac(getmacbyip(ip_address))
        except Exception as error:
            logging.debug("No se pudo resolver MAC para %s: %s", ip_address, error)
            return None

    def _resolve_interface_for_ip(self, ip_address, preferred_interface=None):
        if preferred_interface:
            return preferred_interface

        host_record = self._get_host_record(ip_address) if ip_address else {}
        interfaces = sorted(host_record.get("interfaces", set()))
        if interfaces:
            return interfaces[0]

        selected_interfaces = self.window.get_selected_capture_interfaces()
        if selected_interfaces:
            return selected_interfaces[0]

        return self.network_capture.interface

    def _build_restoration_context(self, attacker_ip, attacker_mac):
        attack_context = self.detection_engine.get_attack_context(attacker_ip, attacker_mac) or {}
        spoofed_ip = self._normalize_ip(attack_context.get("spoofed_ip"))
        target_ip = self._normalize_ip(attack_context.get("target_ip"))
        victim_ip = self._normalize_ip(attack_context.get("victim_ip"))
        gateway_ip = self._normalize_ip(attack_context.get("gateway_ip"))
        attacker_ip = self._normalize_ip(attacker_ip) or self._normalize_ip(attack_context.get("attacker_ip"))
        interface_name = attack_context.get("interface")

        gateway_candidates = [
            self._normalize_ip(candidate)
            for candidate in [gateway_ip, spoofed_ip]
            if self._normalize_ip(candidate)
        ]
        gateway_ip = next(
            (
                candidate
                for candidate in gateway_candidates
                if self._is_in_local_networks(candidate) and candidate in self.detection_engine.arp_baseline
            ),
            None,
        )
        if not gateway_ip and spoofed_ip and self._is_in_local_networks(spoofed_ip):
            gateway_ip = spoofed_ip

        victim_candidates = [
            self._normalize_ip(candidate)
            for candidate in [target_ip, victim_ip]
            if self._normalize_ip(candidate)
        ]
        victim_ip = next(
            (
                candidate
                for candidate in victim_candidates
                if (
                    self._is_in_local_networks(candidate)
                    and candidate in self.detection_engine.arp_baseline
                    and candidate != attacker_ip
                    and candidate != gateway_ip
                )
            ),
            None,
        )
        if not victim_ip and target_ip and self._is_in_local_networks(target_ip) and target_ip != attacker_ip:
            victim_ip = target_ip

        victim_record = self._get_host_record(victim_ip) if victim_ip else {}
        gateway_record = self._get_host_record(gateway_ip) if gateway_ip else {}

        victim_mac = (
            self._normalize_mac(self.detection_engine.arp_baseline.get(victim_ip))
            or self._normalize_mac(self.detection_engine.arp_table.get(victim_ip))
            or self._normalize_mac(victim_record.get("mac"))
        )
        gateway_mac = (
            self._normalize_mac(self.detection_engine.arp_baseline.get(gateway_ip))
            or self._normalize_mac(self.detection_engine.arp_table.get(gateway_ip))
            or self._normalize_mac(gateway_record.get("mac"))
        )

        if not interface_name:
            victim_interfaces = sorted(victim_record.get("interfaces", set()))
            gateway_interfaces = sorted(gateway_record.get("interfaces", set()))
            interface_name = victim_interfaces[0] if victim_interfaces else None
            if not interface_name and gateway_interfaces:
                interface_name = gateway_interfaces[0]
            if not interface_name:
                interface_name = self._resolve_interface_for_ip(victim_ip or gateway_ip)

        context = {
            "attacker_ip": attacker_ip or attack_context.get("attacker_ip"),
            "attacker_mac": self._normalize_mac(attacker_mac) or self._normalize_mac(attack_context.get("attacker_mac")),
            "victim_ip": victim_ip,
            "victim_mac": victim_mac,
            "gateway_ip": gateway_ip,
            "gateway_mac": gateway_mac,
            "spoofed_ip": spoofed_ip,
            "target_ip": target_ip,
            "interface": interface_name,
        }
        logging.debug(
            "[ARP CONTEXT] attacker_ip=%s victim_ip=%s gateway_ip=%s victim_mac=%s gateway_mac=%s interface=%s",
            context.get("attacker_ip"),
            context.get("victim_ip"),
            context.get("gateway_ip"),
            context.get("victim_mac"),
            context.get("gateway_mac"),
            context.get("interface"),
        )
        return context

    def _restore_victim_connectivity(self, attacker_ip, attacker_mac):
        attack_context = self._build_restoration_context(attacker_ip, attacker_mac)
        victim_ip = self._normalize_ip(attack_context.get("victim_ip"))
        victim_mac = self._normalize_mac(attack_context.get("victim_mac"))
        gateway_ip = self._normalize_ip(attack_context.get("gateway_ip"))
        gateway_mac = self._normalize_mac(attack_context.get("gateway_mac"))
        interface_name = attack_context.get("interface")
        attacker_ip = self._normalize_ip(attack_context.get("attacker_ip"))

        if not all([attacker_ip, victim_ip, gateway_ip, victim_mac, gateway_mac, interface_name]):
            missing_fields = [
                field_name
                for field_name, field_value in {
                    "attacker_ip": attacker_ip,
                    "victim_ip": victim_ip,
                    "gateway_ip": gateway_ip,
                    "victim_mac": victim_mac,
                    "gateway_mac": gateway_mac,
                    "interface": interface_name,
                }.items()
                if not field_value
            ]
            logging.warning(
                "ARP restoration skipped: incomplete context missing=%s context=%s",
                ",".join(missing_fields),
                attack_context,
            )
            return False

        if victim_ip == attacker_ip or victim_ip == gateway_ip or victim_ip in self.blocked_ips:
            logging.warning("ARP restoration skipped: invalid victim target %s", victim_ip)
            return False

        if not self._is_in_local_networks(victim_ip) or not self._is_in_local_networks(gateway_ip):
            logging.error(
                "ARP restoration skipped: cross-network context victim=%s gateway=%s attacker=%s",
                victim_ip,
                gateway_ip,
                attacker_ip,
            )
            return False

        if not self._share_local_network(victim_ip, gateway_ip, attacker_ip):
            logging.error(
                "ARP restoration skipped: no shared subnet victim=%s gateway=%s attacker=%s",
                victim_ip,
                gateway_ip,
                attacker_ip,
            )
            return False

        print("[DEBUG] Victim:", victim_ip)
        print("[DEBUG] Gateway:", gateway_ip)
        print("[DEBUG] Attacker:", attacker_ip)
        print("[DEBUG] Gateway MAC:", gateway_mac)
        print("[DEBUG] Victim MAC:", victim_mac)
        logging.debug("[ARP CONTEXT] attacker_ip=%s victim_ip=%s gateway_ip=%s", attacker_ip, victim_ip, gateway_ip)
        logging.debug(
            "[DEBUG] ARP restore: %s <- %s (%s)",
            victim_ip,
            gateway_ip,
            gateway_mac,
        )
        logging.debug(
            "[DEBUG] ARP restore: %s <- %s (%s)",
            gateway_ip,
            victim_ip,
            victim_mac,
        )

        logging.info(
            "[ARP] Restoring ARP for victim %s through %s on %s",
            victim_ip,
            gateway_ip,
            interface_name,
        )

        if not self._is_valid_mac(victim_mac) or not self._is_valid_mac(gateway_mac):
            logging.warning(
                "ARP restoration skipped due to invalid MACs victim=%s gateway=%s",
                victim_mac,
                gateway_mac,
            )
            return False

        restored = self.detection_engine.activate_post_block_mitigation(attack_context)
        if restored:
            log_event(f"ARP restored for victim {victim_ip}", "info")
        else:
            logging.warning("ARP restoration failed for victim %s", victim_ip)
        return restored

    def _refresh_protection_lists(self, selected_interfaces=None):
        selected_interfaces = [iface for iface in (selected_interfaces or self.window.get_selected_capture_interfaces()) if iface]
        primary_interface = selected_interfaces[0] if selected_interfaces else self.window.get_selected_capture_interface()
        self.local_networks = [
            network
            for network in (
                self.network_capture.get_interface_network(interface_name)
                for interface_name in selected_interfaces
            )
            if network
        ]

        self.gateway_ips = {
            self._normalize_ip(ip_address)
            for ip_address in self._get_gateway_ips(selected_interfaces)
            if self._normalize_ip(ip_address)
        }
        self.gateway_ip = sorted(self.gateway_ips)[0] if self.gateway_ips else None
        self.local_interface_ips = {
            self._normalize_ip(self._resolve_local_ip(interface_name))
            for interface_name in selected_interfaces
            if self._normalize_ip(self._resolve_local_ip(interface_name))
        }
        self.own_host_ip = self._normalize_ip(self._resolve_local_ip(primary_interface))
        self.own_host_mac = self._normalize_mac(self._resolve_local_mac(primary_interface))
        self.mikrotik_ip = self._normalize_ip(self.mikrotik.host if self.mikrotik else (self.mikrotik_config.host if self.mikrotik_config else None))

        protected_ips = {
            ip
            for ip in self.gateway_ips.union(self.local_interface_ips).union({self.mikrotik_ip})
            if ip
        }
        protected_macs = {
            mac
            for mac in {
                self.own_host_mac,
                *[self._resolve_known_mac(gateway_ip) for gateway_ip in self.gateway_ips],
                self._resolve_known_mac(self.mikrotik_ip),
            }
            if mac
        }

        self.protected_ips = protected_ips
        self.protected_macs = protected_macs

        self.detection_engine.set_whitelist(self.protected_ips)
        self.detection_engine.set_mac_whitelist(self.protected_macs)
        self.detection_engine.set_local_networks(self.local_networks)

        if self.mikrotik:
            self.mikrotik.set_protected_hosts(self.protected_ips, self.protected_macs)

        logging.info(
            "Proteccion actualizada: ips=%s macs=%s",
            sorted(self.protected_ips),
            sorted(self.protected_macs),
        )

        if DEBUG:
            log_debug(f"Selected interface: {', '.join(selected_interfaces) if selected_interfaces else 'default'}")
            log_debug(
                f"Local networks: {', '.join(str(network) for network in self.local_networks) if self.local_networks else 'unknown'}"
            )
            log_debug(f"Gateways: {', '.join(sorted(self.gateway_ips)) if self.gateway_ips else 'unknown'}")
            log_debug(f"Local interface IPs: {', '.join(sorted(self.local_interface_ips)) if self.local_interface_ips else 'unknown'}")
            log_debug(f"MikroTik IP: {self.mikrotik_ip or 'unknown'}")

    def _is_in_local_networks(self, ip_address):
        normalized_ip = self._normalize_ip(ip_address)
        if not normalized_ip:
            return False

        try:
            candidate = ipaddress.ip_address(normalized_ip)
        except ValueError:
            return False

        if not self.local_networks:
            return candidate.is_private

        return any(candidate in network for network in self.local_networks)

    def _share_local_network(self, *ip_addresses):
        normalized_values = [self._normalize_ip(value) for value in ip_addresses if self._normalize_ip(value)]
        if not normalized_values:
            return False

        try:
            candidates = [ipaddress.ip_address(value) for value in normalized_values]
        except ValueError:
            return False

        if not self.local_networks:
            return all(candidate.is_private for candidate in candidates)

        return any(all(candidate in network for candidate in candidates) for network in self.local_networks)

    def is_valid_attacker(self, ip_address, mac_address):
        normalized_ip = self._normalize_ip(ip_address)
        normalized_mac = self._normalize_mac(mac_address)

        if not normalized_ip:
            logging.warning("Skipping attacker validation with empty IP")
            return False

        if normalized_ip == "255.255.255.255":
            logging.warning("Skipping broadcast address candidate: %s", normalized_ip)
            return False

        if normalized_ip in self.gateway_ips:
            print("[WARNING] Skipping gateway, not attacker")
            logging.warning("Skipping gateway IP: %s", normalized_ip)
            return False

        if normalized_ip in self.protected_ips:
            logging.warning("Skipping protected host: %s", normalized_ip)
            return False

        try:
            candidate = ipaddress.ip_address(normalized_ip)
        except ValueError:
            logging.warning("Skipping invalid IP candidate: %s", normalized_ip)
            return False

        if not self._is_in_local_networks(normalized_ip):
            print("[DEBUG] Skipping external IP:", normalized_ip)
            logging.info("Skipping external IP outside local networks: %s", normalized_ip)
            return False

        if any(
            [
                candidate.is_multicast,
                candidate.is_loopback,
                candidate.is_unspecified,
                candidate.is_link_local,
                candidate.is_reserved,
            ]
        ):
            logging.warning("Skipping non-routable or reserved IP: %s", normalized_ip)
            return False

        if normalized_ip in self.blocked_ips:
            logging.info("Skipping already blocked IP: %s", normalized_ip)
            return False

        if normalized_mac and normalized_mac in self.protected_macs:
            logging.warning("Skipping protected MAC: %s", normalized_mac)
            return False

        return True

    def _resolve_attacker_identity(self, attacker_ip, attacker_mac):
        normalized_ip = self._normalize_ip(attacker_ip)
        normalized_mac = self._normalize_mac(attacker_mac)
        if self.is_valid_attacker(normalized_ip, normalized_mac):
            return normalized_ip, normalized_mac
        return None, normalized_mac

    def handle_packet(self, packet):
        self.window.packet_count += 1
        self._register_packet_host(packet)
        self.detection_engine.process_packet(packet)
        self._queue_ui_task("packet_summary", packet.summary())

    def handle_alert(self, message):
        self._queue_ui_task("alert", message)

    def remove_mikrotik_rules(self, ip_address, mac_address=None):
        normalized_ip = self._normalize_ip(ip_address)
        normalized_mac = self._normalize_mac(mac_address)
        if not normalized_ip:
            return False

        if not self.mikrotik or not self.mikrotik.is_connected():
            logging.error("MikroTik connection failed or not initialized")
            return False

        return bool(self.mikrotik.unblock_ip(normalized_ip, normalized_mac))

    def process_ui_queue(self):
        packet_summaries = []
        pending_hosts = None
        alerts = []
        cleared_alert_ips = []

        while not self.ui_queue.empty():
            try:
                task = self.ui_queue.get_nowait()
            except queue.Empty:
                break

            task_type = task.get("type")
            task_data = task.get("data")
            if task_type == "update_devices":
                pending_hosts = task_data
            elif task_type == "packet_summary":
                packet_summaries.append(task_data)
            elif task_type == "alert":
                alerts.append(task_data)
            elif task_type == "remove_alerts":
                cleared_alert_ips.append(task_data)

        for summary in packet_summaries[:30]:
            self.window.update_packet_display(summary)

        for ip_address in cleared_alert_ips:
            self.window.remove_alerts_for_ip(ip_address)

        for message in alerts:
            self.window.update_anomaly_display(message)

        if pending_hosts is not None:
            self.window.update_hosts_display(pending_hosts)

    def start_capture(self, selected_interfaces):
        if not selected_interfaces:
            logging.error("No hay interfaces seleccionadas para iniciar la captura")
            return False

        if len(selected_interfaces) > 2:
            logging.error("La captura dual admite como maximo dos interfaces")
            return False

        primary_interface = self._get_primary_interface(selected_interfaces)
        self.network_capture.set_interfaces(selected_interfaces)
        self.detection_engine.set_capture_interface(primary_interface)
        self.detection_engine.configure_mitigation(**self.window.get_mitigation_options())

        self._initialize_mikrotik(primary_interface)
        self._refresh_protection_lists(selected_interfaces)
        self.detection_engine.build_arp_baseline()

        started = self.network_capture.start_capture_thread(selected_interfaces)
        if started:
            logging.info("Captura iniciada en interfaces: %s", ", ".join(selected_interfaces))
        else:
            logging.error("No se pudo iniciar la captura en las interfaces seleccionadas")
        return started

    def pause_capture(self):
        self.network_capture.pause_capture()

    def continue_capture(self):
        self.network_capture.resume_capture()

    def stop_capture(self):
        self.network_capture.stop_capture()

    def find_hosts(self):
        selected_interfaces = self.window.get_selected_capture_interfaces()
        if selected_interfaces:
            self.network_capture.set_interfaces(selected_interfaces)
        self.network_capture.find_hosts()

    def block_attacker_connection(self, attacker_ip, attacker_mac=None, attack_type="Unknown"):
        normalized_ip = self._normalize_ip(attacker_ip)
        normalized_mac = self._normalize_mac(attacker_mac)
        attack_context = self.detection_engine.get_attack_context(normalized_ip or attacker_ip, attacker_mac) or {}

        log_debug(
            f"[BLOCK FLOW] Request to block attacker={normalized_ip or attacker_ip or 'unknown'} "
            f"mac={normalized_mac or 'unknown'} attack_type={attack_type}"
        )
        log_debug(
            f"[ATTACK TYPE] Blocking {normalized_ip or attacker_ip or 'unknown'} as {attack_type}"
        )

        if not normalized_ip:
            logging.error("[BLOCK] Invalid attacker IP received: %s", attacker_ip)
            return False

        host_record = self._get_host_record(normalized_ip)
        self._upsert_host_record(
            normalized_ip,
            normalized_mac or host_record.get("mac"),
            interface_name=", ".join(sorted(host_record.get("interfaces", set()))) if host_record else None,
            status="attacker",
            activity=attack_type,
            attack_type=attack_type,
        )

        if self.mikrotik and not self.mikrotik.is_connected():
            try:
                self.mikrotik.connect()
            except Exception as error:
                logging.error("[BLOCK] Exception while connecting MikroTik for %s: %s", normalized_ip, error)
                return False

        if not self.mikrotik or not self.mikrotik.is_connected():
            logging.error("[BLOCK] MikroTik connection failed or not initialized for %s", normalized_ip)
            return False

        try:
            result = self.mikrotik.block_attacker(normalized_ip, normalized_mac, attack_type=attack_type)
            log_debug(f"[BLOCK FLOW] MikroTik block result attacker={normalized_ip} result={result!r}")
        except TypeError:
            try:
                result = self.mikrotik.block_attacker(normalized_ip, normalized_mac)
                log_debug(f"[BLOCK FLOW] MikroTik block result attacker={normalized_ip} result={result!r}")
            except Exception as error:
                logging.error("[BLOCK] Exception while blocking %s: %s", normalized_ip, error)
                return False
        except Exception as error:
            logging.error("[BLOCK] Exception while blocking %s: %s", normalized_ip, error)
            return False

        if result:
            self.blocked_ips.add(normalized_ip)
            if normalized_mac:
                self.blocked_macs.add(normalized_mac)

            updated_record = self._get_host_record(normalized_ip)
            self._upsert_host_record(
                normalized_ip,
                normalized_mac or updated_record.get("mac", "unknown"),
                interface_name=", ".join(sorted(updated_record.get("interfaces", set()))) if updated_record else None,
                status="blocked",
                host_type=updated_record.get("type", "Host"),
                activity=attack_type,
                attack_type=attack_type,
            )

            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self._queue_ui_task(
                "alert",
                "\n".join(
                    [
                        "[BLOCKED] Attacker blocked",
                        f"Timestamp: {timestamp}",
                        f"Attacker IP: {normalized_ip}",
                        f"Attacker MAC: {normalized_mac or 'unknown'}",
                        f"Attack Type: {attack_type}",
                    ]
                ),
            )

            logging.info("[BLOCK] Attacker %s blocked successfully as %s", normalized_ip, attack_type)
            if attack_context:
                time.sleep(1)
                self._restore_victim_connectivity(normalized_ip, normalized_mac)
            return True

        logging.error("[BLOCK] MikroTik failed to block %s as %s", normalized_ip, attack_type)
        return False

    def _legacy_unblock_attacker_connection(self, attacker_ip, attacker_mac=None):
        resolved_ip, resolved_mac = self._resolve_attacker_identity(attacker_ip, attacker_mac)
        target_ip = resolved_ip or self._normalize_ip(attacker_ip)
        target_record = self._get_host_record(target_ip) if target_ip else {}
        target_mac = resolved_mac or self._normalize_mac(attacker_mac) or target_record.get("mac")

        if not target_ip:
            logging.warning("No attacker IP available for MikroTik unblock")
            return

        if self.detection_engine.is_attack_active(target_ip):
            answer = QMessageBox.question(
                self.window,
                "Ataque activo",
                "El dispositivo aún presenta un ataque en curso. ¿Desea continuar?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if answer != QMessageBox.Yes:
                return

        if self.mikrotik and not self.mikrotik.is_connected():
            self.mikrotik.connect()

        if self.mikrotik and self.mikrotik.is_connected():
            unblocked = self.mikrotik.unblock_ip(target_ip, target_mac)
        else:
            logging.error("MikroTik connection failed or not initialized")
            return

        if unblocked:
            logging.debug("[DEBUG] Unblocking attacker %s", target_ip)
            self.clear_mikrotik_connections(target_ip)
            self.blocked_ips.discard(target_ip)
            if target_mac:
                self.blocked_macs.discard(target_mac)
            self.detection_engine.reset_host_state(target_ip)
            self._upsert_host_record(
                target_ip,
                target_mac or target_record.get("mac", "unknown"),
                interface_name=", ".join(sorted(target_record.get("interfaces", set()))) if target_record else None,
                status="trusted",
                host_type=target_record.get("type", "Host"),
                activity="Manual Unblock",
            )

            self._queue_ui_task(
                "alert",
                "\n".join(
                    [
                        "[UNBLOCKED] Host allowed again",
                        f"Attacker IP: {target_ip}",
                        f"Attacker MAC: {target_mac or 'unknown'}",
                    ]
                ),
            )

    def unblock_attacker_connection(self, attacker_ip, attacker_mac=None):
        resolved_ip, resolved_mac = self._resolve_attacker_identity(attacker_ip, attacker_mac)
        target_ip = resolved_ip or self._normalize_ip(attacker_ip)
        target_record = self._get_host_record(target_ip) if target_ip else {}
        target_mac = resolved_mac or self._normalize_mac(attacker_mac) or target_record.get("mac")

        if not target_ip:
            logging.warning("No attacker IP available for MikroTik unblock")
            return

        if self.detection_engine.is_attack_active(target_ip):
            answer = QMessageBox.question(
                self.window,
                "Ataque activo",
                "El dispositivo aun presenta un ataque en curso. Desea continuar?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if answer != QMessageBox.Yes:
                return

        if self.mikrotik and not self.mikrotik.is_connected():
            self.mikrotik.connect()

        if not self.mikrotik or not self.mikrotik.is_connected():
            logging.error("MikroTik connection failed or not initialized")
            return

        if not self.remove_mikrotik_rules(target_ip, target_mac):
            return

        logging.debug("[DEBUG] Unblocking attacker %s", target_ip)
        self.clear_mikrotik_connections(target_ip)
        self.blocked_ips.discard(target_ip)
        if target_mac:
            self.blocked_macs.discard(target_mac)
        self.detection_engine.clear_attack_state(target_ip)
        self.detection_engine.reset_host_state(target_ip)
        self._upsert_host_record(
            target_ip,
            target_mac or target_record.get("mac", "unknown"),
            interface_name=", ".join(sorted(target_record.get("interfaces", set()))) if target_record else None,
            status="trusted",
            host_type=target_record.get("type", "Host"),
            activity="Manual Unblock",
        )

        self._queue_ui_task("remove_alerts", target_ip)
        self._queue_ui_task(
            "alert",
            "\n".join(
                [
                    "[UNBLOCKED] Host allowed again",
                    f"Attacker IP: {target_ip}",
                    f"Attacker MAC: {target_mac or 'unknown'}",
                ]
            ),
        )

    def clear_mikrotik_connections(self, ip_address):
        normalized_ip = self._normalize_ip(ip_address)
        if not normalized_ip:
            return False

        if not self.mikrotik or not self.mikrotik.is_connected():
            logging.warning("[MIKROTIK CLEAN] ip=%s skipped=no_connection", normalized_ip)
            return False

        try:
            cleaned = self.mikrotik.clear_connections(normalized_ip)
            logging.info("[MIKROTIK CLEAN] ip=%s cleaned=%s", normalized_ip, cleaned)
            if DEBUG:
                log_debug(f"[MIKROTIK CLEAN] ip={normalized_ip}")
            return bool(cleaned)
        except Exception as error:
            logging.error("[MIKROTIK CLEAN] ip=%s error=%s", normalized_ip, error)
            return False

    def run(self):
        self.detection_engine.configure_mitigation(**self.window.get_mitigation_options())
        self.ui_poll_timer.start()
        self.window.show()


def main():
    app = QApplication(sys.argv)
    controller = AppController()
    controller.run()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
