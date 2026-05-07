import socket
from dataclasses import dataclass
from datetime import datetime
import logging

import psutil
from scapy.all import ARP, Ether, IP, TCP, UDP, conf
from scapy.layers.inet import ICMP

from network_capture import NetworkCaptureScanner


@dataclass(frozen=True)
class InterfaceInfo:
    identifier: str
    name: str
    description: str
    ip_address: str


@dataclass(frozen=True)
class PacketRecord:
    number: int
    time: str
    source: str
    destination: str
    protocol: str
    length: int
    info: str


def _safe_text(*values, fallback="N/A"):
    for value in values:
        text = str(value).strip() if value is not None else ""
        if text:
            return text
    return fallback


def _resolve_ipv4_address(interface_candidates):
    addresses = psutil.net_if_addrs()
    lowered_candidates = [candidate.lower() for candidate in interface_candidates if candidate]
    for interface_name, addr_list in addresses.items():
        interface_name_lower = interface_name.lower()
        if lowered_candidates and not any(
            candidate == interface_name_lower or candidate in interface_name_lower or interface_name_lower in candidate
            for candidate in lowered_candidates
        ):
            continue

        for address in addr_list:
            if address.family == socket.AF_INET and address.address:
                return address.address
    return "N/A"


def list_available_interfaces():
    interfaces = {}
    for iface in conf.ifaces.values():
        identifier = _safe_text(getattr(iface, "name", None), getattr(iface, "network_name", None), fallback="")
        if not identifier:
            continue

        friendly_name = _safe_text(
            getattr(iface, "description", None),
            getattr(iface, "network_name", None),
            getattr(iface, "name", None),
        )
        description = _safe_text(
            getattr(iface, "network_name", None),
            getattr(iface, "description", None),
            fallback="No description",
        )
        ip_address = _resolve_ipv4_address([identifier, friendly_name, description])
        interfaces[identifier] = InterfaceInfo(
            identifier=identifier,
            name=friendly_name,
            description=description,
            ip_address=ip_address,
        )

    if not interfaces:
        for interface_name, addr_list in psutil.net_if_addrs().items():
            ipv4_address = "N/A"
            for address in addr_list:
                if address.family == socket.AF_INET and address.address:
                    ipv4_address = address.address
                    break
            interfaces[interface_name] = InterfaceInfo(
                identifier=interface_name,
                name=interface_name,
                description="System interface",
                ip_address=ipv4_address,
            )

    return sorted(interfaces.values(), key=lambda item: item.name.lower())


def resolve_capture_interface(interface_name):
    if not interface_name:
        return None

    lookup = str(interface_name).strip().lower()
    for iface in conf.ifaces.values():
        candidates = {
            str(getattr(iface, "name", "")).strip(),
            str(getattr(iface, "network_name", "")).strip(),
            str(getattr(iface, "description", "")).strip(),
        }
        normalized_candidates = {value.lower() for value in candidates if value}
        if lookup in normalized_candidates:
            resolved_name = str(getattr(iface, "name", "")).strip() or str(interface_name).strip()
            logging.info("[CAPTURE] Resolved interface '%s' -> '%s'", interface_name, resolved_name)
            return resolved_name
        if any(lookup in candidate or candidate in lookup for candidate in normalized_candidates):
            resolved_name = str(getattr(iface, "name", "")).strip() or str(interface_name).strip()
            logging.info("[CAPTURE] Resolved interface '%s' -> '%s'", interface_name, resolved_name)
            return resolved_name

    logging.info("[CAPTURE] Using interface without remap: %s", interface_name)
    return str(interface_name).strip()


def _describe_tcp(packet):
    tcp_layer = packet[TCP]
    flag_names = []
    if tcp_layer.flags & 0x02:
        flag_names.append("SYN")
    if tcp_layer.flags & 0x10:
        flag_names.append("ACK")
    if tcp_layer.flags & 0x01:
        flag_names.append("FIN")
    if tcp_layer.flags & 0x04:
        flag_names.append("RST")
    if tcp_layer.flags & 0x08:
        flag_names.append("PSH")
    if tcp_layer.flags & 0x20:
        flag_names.append("URG")
    flag_text = "+".join(flag_names) if flag_names else "segment"
    return f"TCP {flag_text} to port {tcp_layer.dport}"


def _describe_udp(packet):
    udp_layer = packet[UDP]
    return f"UDP to port {udp_layer.dport}"


def _describe_icmp(packet):
    icmp_layer = packet[ICMP]
    icmp_labels = {
        0: "ICMP Echo reply",
        3: "ICMP Destination unreachable",
        8: "ICMP Echo request",
        11: "ICMP Time exceeded",
    }
    return icmp_labels.get(int(icmp_layer.type), f"ICMP type {icmp_layer.type}")


def _describe_arp(packet):
    arp_layer = packet[ARP]
    if int(arp_layer.op) == 1:
        return f"ARP who-has {arp_layer.pdst}?"
    if int(arp_layer.op) == 2:
        return f"ARP reply {arp_layer.psrc} is-at {arp_layer.hwsrc}"
    return "ARP packet"


def format_packet_record(packet, packet_number):
    timestamp = datetime.fromtimestamp(float(getattr(packet, "time", datetime.now().timestamp()))).strftime("%H:%M:%S")
    packet_length = len(packet)

    source = "N/A"
    destination = "N/A"
    protocol = "OTHER"
    info = packet.summary()

    if packet.haslayer(ARP):
        source = _safe_text(packet[ARP].psrc)
        destination = _safe_text(packet[ARP].pdst)
        protocol = "ARP"
        info = _describe_arp(packet)
    elif packet.haslayer(IP):
        source = _safe_text(packet[IP].src)
        destination = _safe_text(packet[IP].dst)

        if packet.haslayer(TCP):
            protocol = "TCP"
            info = _describe_tcp(packet)
        elif packet.haslayer(UDP):
            protocol = "UDP"
            info = _describe_udp(packet)
        elif packet.haslayer(ICMP):
            protocol = "ICMP"
            info = _describe_icmp(packet)
        else:
            protocol = "IP"
            info = f"IP traffic {source} -> {destination}"
    elif packet.haslayer(Ether):
        source = _safe_text(packet[Ether].src)
        destination = _safe_text(packet[Ether].dst)
        protocol = "ETH"
        info = "Ethernet frame"

    return PacketRecord(
        number=packet_number,
        time=timestamp,
        source=source,
        destination=destination,
        protocol=protocol,
        length=packet_length,
        info=info,
    )


class CaptureService:
    def __init__(self, packet_callback):
        self.scanner = NetworkCaptureScanner(
            packet_callback=packet_callback,
            hosts_callback=lambda _hosts: None,
        )

    def start(self, interface_name):
        real_interface_name = resolve_capture_interface(interface_name)
        self.scanner.set_interfaces(real_interface_name)
        return self.scanner.start_capture_thread(real_interface_name)

    def stop(self):
        self.scanner.stop_capture()

    def pause(self):
        self.scanner.pause_capture()

    def resume(self):
        self.scanner.resume_capture()

    def get_interface_ip(self, interface_name):
        return self.scanner.get_interface_ip(interface_name)

    def get_interface_network(self, interface_name):
        return self.scanner.get_interface_network(interface_name)
