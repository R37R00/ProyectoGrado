import logging
import queue
import socket
import sys
from datetime import datetime

from PyQt5.QtCore import QTimer
from PyQt5.QtWidgets import QApplication, QInputDialog, QMessageBox
from scapy.all import conf, get_if_hwaddr, getmacbyip

from detection_engine import DEBUG as DETECTION_DEBUG
from detection_engine import DetectionEngine
from interfaz_grafica import MainWindow
from mikrotik_config import get_active_mikrotik_config, resolve_mikrotik_config
from mikrotik_handler import MikroTikManager
from network_capture import NetworkCaptureScanner


DEBUG = True
LAB_SUBNET_PREFIX = "10.0.0."


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
        self.protected_ips = set()
        self.protected_macs = set()
        self.gateway_ip = None
        self.own_host_ip = None
        self.own_host_mac = None
        self.mikrotik_ip = None
        self.mikrotik_config = get_active_mikrotik_config()
        self.mikrotik = None

        self.window.packet_text_edit.document().setMaximumBlockCount(200)

        self.packet_flush_timer = QTimer()
        self.packet_flush_timer.setInterval(300)
        self.packet_flush_timer.timeout.connect(self.flush_packet_events)

        self.friendly_interfaces = get_friendly_interfaces()
        self.window.set_capture_interfaces(self.friendly_interfaces)

        selected_interface = self.window.get_selected_capture_interface()
        self.network_capture = NetworkCaptureScanner(
            packet_callback=self.handle_packet,
            hosts_callback=self.window.hosts_found_signal.emit,
            interface=selected_interface,
        )

        self.detection_engine.set_alert_callback(self.handle_alert)
        self.detection_engine.set_block_callback(self.block_attacker_connection)
        self.detection_engine.set_capture_interface(selected_interface)
        self.detection_engine.configure_mitigation(**self.window.get_mitigation_options())

        self.window.bind_actions(
            pause_callback=self.pause_capture,
            continue_callback=self.continue_capture,
            stop_callback=self.stop_capture,
            find_hosts_callback=self.network_capture.find_hosts,
            block_host_callback=self.block_attacker_connection,
            unblock_host_callback=self.unblock_attacker_connection,
        )

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

    def _get_gateway_ip(self):
        try:
            route = conf.route.route("0.0.0.0")
            gateway_ip = route[2] if len(route) > 2 else None
            if gateway_ip and gateway_ip != "0.0.0.0":
                return gateway_ip
        except Exception as error:
            logging.debug("No se pudo resolver gateway por Scapy: %s", error)
        return None

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

        mac_address = self.detection_engine.arp_baseline.get(ip_address) or self.window.get_mac_for_ip(ip_address)
        mac_address = self._normalize_mac(mac_address)
        if mac_address:
            return mac_address

        try:
            return self._normalize_mac(getmacbyip(ip_address))
        except Exception as error:
            logging.debug("No se pudo resolver MAC para %s: %s", ip_address, error)
            return None

    def _refresh_protection_lists(self, selected_interface=None):
        selected_interface = selected_interface or self.window.get_selected_capture_interface()

        self.gateway_ip = self._normalize_ip(self._get_gateway_ip())
        self.own_host_ip = self._normalize_ip(self._resolve_local_ip(selected_interface))
        self.own_host_mac = self._normalize_mac(self._resolve_local_mac(selected_interface))
        self.mikrotik_ip = self._normalize_ip(self.mikrotik.host if self.mikrotik else (self.mikrotik_config.host if self.mikrotik_config else None))

        protected_ips = {ip for ip in {self.gateway_ip, self.own_host_ip, self.mikrotik_ip} if ip}
        protected_macs = {
            mac
            for mac in {
                self.own_host_mac,
                self._resolve_known_mac(self.gateway_ip),
                self._resolve_known_mac(self.mikrotik_ip),
            }
            if mac
        }

        self.protected_ips = protected_ips
        self.protected_macs = protected_macs

        self.detection_engine.set_whitelist(self.protected_ips)
        self.detection_engine.set_mac_whitelist(self.protected_macs)

        if self.mikrotik:
            self.mikrotik.set_protected_hosts(self.protected_ips, self.protected_macs)

        logging.info(
            "Proteccion actualizada: ips=%s macs=%s",
            sorted(self.protected_ips),
            sorted(self.protected_macs),
        )

        if DEBUG:
            logging.info("[DEBUG] Selected interface: %s", selected_interface or "default")
            logging.info("[DEBUG] Gateway: %s", self.gateway_ip or "unknown")
            logging.info("[DEBUG] Own host IP: %s", self.own_host_ip or "unknown")
            logging.info("[DEBUG] MikroTik IP: %s", self.mikrotik_ip or "unknown")

    def _candidate_ips_for_mac(self, mac_address):
        normalized_mac = self._normalize_mac(mac_address)
        candidates = []

        if not normalized_mac:
            return candidates

        for ip_address, data in self.window.hosts.items():
            if self._normalize_mac(data.get("mac")) == normalized_mac:
                candidates.append(ip_address)

        candidates.extend(self.detection_engine.get_candidate_ips_for_mac(normalized_mac))
        unique_candidates = []
        seen = set()
        for candidate in candidates:
            normalized_candidate = self._normalize_ip(candidate)
            if normalized_candidate and normalized_candidate not in seen:
                unique_candidates.append(normalized_candidate)
                seen.add(normalized_candidate)
        return unique_candidates

    def is_valid_attacker(self, ip_address, mac_address):
        normalized_ip = self._normalize_ip(ip_address)
        normalized_mac = self._normalize_mac(mac_address)
        protected_ips = {ip for ip in {self.gateway_ip, self.own_host_ip, self.mikrotik_ip} if ip}

        if not normalized_ip:
            logging.warning("Skipping attacker validation with empty IP")
            return False

        if normalized_ip in protected_ips:
            logging.warning("Skipping protected host: %s", normalized_ip)
            return False

        if not normalized_ip.startswith(LAB_SUBNET_PREFIX):
            logging.warning("Skipping non-lab IP: %s", normalized_ip)
            return False

        if normalized_mac and normalized_mac in self.protected_macs:
            logging.warning("Skipping protected MAC: %s", normalized_mac)
            return False

        return True

    def _resolve_attacker_identity(self, attacker_ip, attacker_mac):
        normalized_mac = self._normalize_mac(attacker_mac)
        candidates = []

        if attacker_ip:
            candidates.append(self._normalize_ip(attacker_ip))
        candidates.extend(self._candidate_ips_for_mac(normalized_mac))

        if DEBUG or DETECTION_DEBUG:
            logging.info(
                "[DEBUG] Attacker candidates for mac=%s -> %s",
                normalized_mac or "unknown",
                candidates,
            )

        for candidate_ip in candidates:
            if self.is_valid_attacker(candidate_ip, normalized_mac):
                return candidate_ip, normalized_mac

        return None, normalized_mac

    def handle_packet(self, packet):
        self.window.packet_count += 1
        self.detection_engine.process_packet(packet)
        self.packet_event_queue.put(packet.summary())

    def flush_packet_events(self):
        displayed = 0
        while displayed < 30:
            try:
                summary = self.packet_event_queue.get_nowait()
            except queue.Empty:
                break
            self.window.packet_received_signal.emit(summary)
            displayed += 1

    def handle_alert(self, message):
        self.window.anomaly_detected_signal.emit(message)

    def pause_capture(self):
        self.network_capture.pause_capture()

    def continue_capture(self):
        self.network_capture.resume_capture()

    def stop_capture(self):
        self.network_capture.stop_capture()

    def block_attacker_connection(self, attacker_ip, attacker_mac=None, attack_type="ARP Spoofing"):
        resolved_ip, resolved_mac = self._resolve_attacker_identity(attacker_ip, attacker_mac)
        logging.info(
            "[DETECTION] Attacker detected -> IP: %s, MAC: %s",
            resolved_ip or attacker_ip or "unknown",
            resolved_mac or "unknown",
        )

        if not resolved_ip:
            logging.error("Attacker validation failed - blocking cancelled")
            return

        if self.mikrotik and not self.mikrotik.is_connected():
            self.mikrotik.connect()

        if self.mikrotik and self.mikrotik.is_connected():
            blocked = self.mikrotik.block_ip(resolved_ip)
        else:
            logging.error("MikroTik connection failed or not initialized")
            return

        if blocked:
            existing = self.window.hosts.get(resolved_ip, {})
            self.window.update_hosts(
                resolved_ip,
                resolved_mac or existing.get("mac", "unknown"),
                status="Blocked",
                host_type=existing.get("type", "Host"),
                activity=attack_type,
            )

            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.window.anomaly_detected_signal.emit(
                "\n".join(
                    [
                        "[BLOCKED] Attacker blocked",
                        f"Timestamp: {timestamp}",
                        f"Attacker IP: {resolved_ip}",
                        f"Attacker MAC: {resolved_mac or 'unknown'}",
                        f"Attack Type: {attack_type}",
                    ]
                )
            )

    def unblock_attacker_connection(self, attacker_ip, attacker_mac=None):
        resolved_ip, resolved_mac = self._resolve_attacker_identity(attacker_ip, attacker_mac)
        target_ip = resolved_ip or self._normalize_ip(attacker_ip)

        if not target_ip:
            logging.warning("No attacker IP available for MikroTik unblock")
            return

        if self.mikrotik and not self.mikrotik.is_connected():
            self.mikrotik.connect()

        if self.mikrotik and self.mikrotik.is_connected():
            unblocked = self.mikrotik.unblock_ip(target_ip)
        else:
            logging.error("MikroTik connection failed or not initialized")
            return

        if unblocked:
            existing = self.window.hosts.get(target_ip, {})
            self.window.update_hosts(
                target_ip,
                resolved_mac or existing.get("mac", "unknown"),
                status="Trusted",
                host_type=existing.get("type", "Host"),
                activity="Manual Unblock",
            )

            self.window.anomaly_detected_signal.emit(
                "\n".join(
                    [
                        "[UNBLOCKED] Host allowed again",
                        f"Attacker IP: {target_ip}",
                        f"Attacker MAC: {resolved_mac or 'unknown'}",
                    ]
                )
            )

    def ask_user_interface_if_needed(self):
        if len(self.friendly_interfaces) <= 1:
            return

        friendly_names = [friendly for friendly, _real in self.friendly_interfaces]
        selected_name, accepted = QInputDialog.getItem(
            self.window,
            "Seleccionar interfaz de red",
            "Se detectaron multiples interfaces. Elige cual deseas usar:",
            friendly_names,
            editable=False,
        )

        if not accepted or not selected_name:
            return

        selected_real = next(
            (real for friendly, real in self.friendly_interfaces if friendly == selected_name),
            None,
        )
        if selected_real:
            self.window.set_selected_capture_interface(selected_real)

    def run(self):
        self.ask_user_interface_if_needed()

        selected_interface = self.window.get_selected_capture_interface()
        self.network_capture.interface = selected_interface
        self.detection_engine.set_capture_interface(selected_interface)
        self.detection_engine.configure_mitigation(**self.window.get_mitigation_options())
        self._initialize_mikrotik(selected_interface)
        self._refresh_protection_lists(selected_interface)
        self.detection_engine.build_arp_baseline()

        if selected_interface is None:
            QMessageBox.warning(
                self.window,
                "Interfaz de red",
                "No se pudo determinar una interfaz de captura. Se usara la interfaz por defecto de Scapy.",
            )

        self.packet_flush_timer.start()
        self.window.show()
        self.network_capture.start_capture_thread()


def main():
    app = QApplication(sys.argv)
    controller = AppController()
    controller.run()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
