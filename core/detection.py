import socket
from dataclasses import dataclass

from scapy.all import conf, get_if_hwaddr, getmacbyip

from detection_engine import DetectionEngine


@dataclass(frozen=True)
class ProtectionContext:
    interface_ip: str | None
    interface_network: object | None
    gateway_ip: str | None
    protected_ips: set[str]
    protected_macs: set[str]


class DetectionService:
    def __init__(self, alert_callback, block_callback):
        self.engine = DetectionEngine()
        self.engine.set_alert_callback(alert_callback)
        self.engine.set_block_callback(block_callback)
        self.engine.configure_mitigation(
            mitigation_enabled=True,
            periodic_enabled=False,
            lock_gateway_enabled=False,
            aggressive_mode=False,
        )

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
