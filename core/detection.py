import socket
import logging

from dataclasses import dataclass

from scapy.all import conf, get_if_hwaddr, getmacbyip

from detection_engine import DetectionEngine

from configuration import load_ids_config


@dataclass(frozen=True)
class ProtectionContext:
    interface_ip: str | None
    interface_network: object | None
    gateway_ip: str | None
    protected_ips: set[str]
    protected_macs: set[str]


class DetectionService:
    def __init__(self, alert_callback, block_callback):
        self.config = load_ids_config()

        self.engine = DetectionEngine()
        self.engine.set_alert_callback(alert_callback)
        self.engine.set_block_callback(block_callback)
        self.apply_configuration(self.config)

    def _normalize_ip(self, value):
        if value is None:
            return None
        text = str(value).strip()
        return text or None

    def _normalize_mac(self, value):
        if value is None:
            return None
        text = str(value).strip().lower()
        return text or None

    def _resolve_gateway_ip(self):
        try:
            route = conf.route.route("0.0.0.0")
            gateway_ip = route[2] if len(route) > 2 else None
            return self._normalize_ip(gateway_ip)
        except Exception:
            return None

    def _resolve_local_mac(self, interface_name):
        try:
            return self._normalize_mac(get_if_hwaddr(interface_name))
        except Exception:
            return None

    def _resolve_gateway_mac(self, gateway_ip):
        try:
            return self._normalize_mac(getmacbyip(gateway_ip))
        except Exception:
            return None

    def configure_for_capture(self, interface_name, interface_ip=None, interface_network=None, mikrotik_ip=None):
        self.engine.set_capture_interface(interface_name)
        if interface_network is not None:
            self.engine.set_local_networks([interface_network])

        gateway_ip = self._resolve_gateway_ip()
        local_mac = self._resolve_local_mac(interface_name)
        gateway_mac = self._resolve_gateway_mac(gateway_ip) if gateway_ip else None

        protected_ips = {
            value
            for value in {
                self._normalize_ip(interface_ip),
                self._normalize_ip(gateway_ip),
                self._normalize_ip(mikrotik_ip),
            }
            if value
        }
        protected_macs = {
            value
            for value in {
                self._normalize_mac(local_mac),
                self._normalize_mac(gateway_mac),
            }
            if value
        }

        self.engine.set_whitelist(protected_ips)
        self.engine.set_mac_whitelist(protected_macs)

        return ProtectionContext(
            interface_ip=self._normalize_ip(interface_ip),
            interface_network=interface_network,
            gateway_ip=self._normalize_ip(gateway_ip),
            protected_ips=protected_ips,
            protected_macs=protected_macs,
        )

    def add_protected_ip(self, ip_address):
        logging.info("[DEBUG PROTECTION] Entró a add_protected_ip: %s", ip_address)

        normalized_ip = self._normalize_ip(ip_address)
        logging.info(
            "[DEBUG PROTECTION] IP normalizada: %s",
            normalized_ip,
        )

        if not normalized_ip:
            logging.info("[DEBUG PROTECTION] IP inválida, retornando")
            return

        logging.info("[DEBUG PROTECTION] Obteniendo block_whitelist")

        protected_ips = set(self.engine.block_whitelist)

        logging.info(
            "[DEBUG PROTECTION] Whitelist actual: %s",
            sorted(protected_ips),
        )

        protected_ips.add(normalized_ip)

        logging.info(
            "[DEBUG PROTECTION] Whitelist nueva: %s",
            sorted(protected_ips),
        )

        logging.info("[DEBUG PROTECTION] Ejecutando set_whitelist")

        self.engine.set_whitelist(protected_ips)

        logging.info("[DEBUG PROTECTION] set_whitelist terminó")

        logging.info(
            "[PROTECTION] IP protegidas actualmente: %s",
            sorted(self.engine.block_whitelist),
        )

        logging.info("[DEBUG PROTECTION] add_protected_ip terminó")

    def build_baseline(self, interface_network=None):
        self.engine.build_arp_baseline(network_cidr=str(interface_network) if interface_network else None)

    def process_packet(self, packet):
        self.engine.process_packet(packet)

    def get_attack_context(self, attacker_ip=None, attacker_mac=None):
        return self.engine.get_attack_context(attacker_ip, attacker_mac)

    def activate_post_block_mitigation(self, attack_context):
        return self.engine.activate_post_block_mitigation(attack_context)

    def clear_attack_state(self, ip_address):
        self.engine.clear_attack_state(ip_address)

    def reset_host_state(self, ip_address):
        self.engine.reset_host_state(ip_address)

    def apply_configuration(self, config=None):
        if config is None:
            config = load_ids_config()

        self.config = config

        arp_config = config.get("arp", {})
        port_scan_config = config.get("port_scan", {})
        dos_config = config.get("dos", {})
        mitigation_config = config.get("arp_mitigation", {})

        self.engine.configure_arp_thresholds(
            suspicion_window_s=arp_config.get("suspicion_window_s"),
            suspicion_threshold=arp_config.get("suspicion_threshold"),
        )

        self.engine.configure_port_scan_thresholds(
            window_s=port_scan_config.get("window_s"),
            threshold=port_scan_config.get("threshold"),
        )

        self.engine.configure_dos_thresholds(
            profiles=dos_config.get("profiles"),
            window_s=dos_config.get("window_s"),
            suspicious_events=dos_config.get("min_suspicious_events"),
            alert_cooldown_s=dos_config.get("alert_cooldown_s"),
            event_reset_s=dos_config.get("event_reset_s"),
        )

        self.engine.configure_mitigation(
            mitigation_enabled=mitigation_config.get("enabled", True),
            periodic_enabled=mitigation_config.get("periodic_enabled", False),
            lock_gateway_enabled=mitigation_config.get("lock_gateway_enabled", False),
            aggressive_mode=mitigation_config.get("aggressive_mode", False),
        )
