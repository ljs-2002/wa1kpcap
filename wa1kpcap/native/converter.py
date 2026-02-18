"""
Convert C++ engine output dicts to ParsedPacket objects.

Ensures downstream FlowManager / FeatureExtractor / reassemblers
get the same ParsedPacket they expect from the dpkt path.
"""

from __future__ import annotations

from wa1kpcap.core.packet import (
    ParsedPacket, EthernetInfo, IPInfo, IP6Info,
    TCPInfo, UDPInfo, DNSInfo, TLSInfo,
    ARPInfo, ICMPInfo, ICMP6Info,
    ProtocolInfo, ProtocolRegistry,
)


def dict_to_parsed_packet(d: dict, timestamp: float, raw_data: bytes,
                           link_type: int) -> ParsedPacket:
    """Convert a C++ parsed dict into a ParsedPacket.

    Args:
        d: Dict returned by NativeParser.parse_packet()
        timestamp: Packet timestamp
        raw_data: Raw packet bytes
        link_type: DLT link layer type

    Returns:
        ParsedPacket with protocol layers populated
    """
    pkt = ParsedPacket(
        timestamp=timestamp,
        raw_data=raw_data,
        link_layer_type=link_type,
        caplen=len(raw_data),
        wirelen=len(raw_data),
    )

    # ── Ethernet ──
    eth = d.get("ethernet")
    if eth and isinstance(eth, dict):
        pkt.eth = EthernetInfo(
            src=eth.get("src", ""),
            dst=eth.get("dst", ""),
            type=eth.get("ether_type", 0),
        )

    # ── IPv4 ──
    ip = d.get("ipv4")
    if ip and isinstance(ip, dict):
        flags_raw = 0
        if ip.get("mf", 0):
            flags_raw |= 0x1  # MF bit
        if ip.get("df", 0):
            flags_raw |= 0x2  # DF bit

        pkt.ip = IPInfo(
            version=ip.get("version", 4),
            src=ip.get("src", ""),
            dst=ip.get("dst", ""),
            proto=ip.get("protocol", 0),
            ttl=ip.get("ttl", 0),
            len=ip.get("total_length", 0),
            id=ip.get("identification", 0),
            flags=flags_raw,
            offset=ip.get("fragment_offset", 0),
            _raw=ip.get("options_raw", b""),
        )
        pkt.ip_len = ip.get("total_length", 0)

    # ── IPv6 ──
    ip6 = d.get("ipv6")
    if ip6 and isinstance(ip6, dict):
        pkt.ip6 = IP6Info(
            version=ip6.get("version", 6),
            src=ip6.get("src", ""),
            dst=ip6.get("dst", ""),
            next_header=ip6.get("next_header", 0),
            hop_limit=ip6.get("hop_limit", 0),
            flow_label=ip6.get("flow_label", 0),
            len=ip6.get("payload_length", 0),
            _raw=ip6.get("options_raw", b""),
        )
        pkt.ip_len = 40 + ip6.get("payload_length", 0)

    # ── TCP ──
    tcp = d.get("tcp")
    if tcp and isinstance(tcp, dict):
        pkt.tcp = TCPInfo(
            sport=tcp.get("src_port", 0),
            dport=tcp.get("dst_port", 0),
            seq=tcp.get("seq", 0),
            ack_num=tcp.get("ack_num", 0),
            flags=tcp.get("flags", 0),
            win=tcp.get("window", 0),
            urgent=tcp.get("urgent_pointer", 0),
            options=tcp.get("options", b""),
        )
        header_len = tcp.get("header_length", 20)
        pkt.trans_len = header_len + d.get("app_len", 0)
        pkt.app_len = d.get("app_len", 0)

        # Raw TCP payload for reassembly
        raw_payload = d.get("_raw_tcp_payload")
        if raw_payload and isinstance(raw_payload, (bytes, bytearray)):
            pkt._raw_tcp_payload = bytes(raw_payload)

    # ── UDP ──
    udp = d.get("udp")
    if udp and isinstance(udp, dict):
        pkt.udp = UDPInfo(
            sport=udp.get("src_port", 0),
            dport=udp.get("dst_port", 0),
            len=udp.get("length", 0),
        )
        pkt.trans_len = udp.get("length", 0)
        pkt.app_len = d.get("app_len", 0)

        # Reuse _raw_tcp_payload field for UDP app payload (same as dpkt path)
        raw_payload = d.get("_raw_tcp_payload")
        if raw_payload and isinstance(raw_payload, (bytes, bytearray)):
            pkt._raw_tcp_payload = bytes(raw_payload)

    # ── DNS ──
    dns = d.get("dns")
    if dns and isinstance(dns, dict):
        pkt.dns = DNSInfo(
            queries=[],  # DNS query names need hardcoded parser
            response_code=dns.get("response_code", 0),
            question_count=dns.get("question_count", 0),
            answer_count=dns.get("answer_count", 0),
            authority_count=dns.get("authority_count", 0),
            additional_count=dns.get("additional_count", 0),
            flags=dns.get("flags", 0),
        )

    # ── ARP ──
    arp = d.get("arp")
    if arp and isinstance(arp, dict):
        pkt.arp = ARPInfo(
            hw_type=arp.get("hw_type", 0),
            proto_type=arp.get("proto_type", 0),
            opcode=arp.get("opcode", 0),
            sender_mac=arp.get("sender_mac", ""),
            sender_ip=arp.get("sender_ip", ""),
            target_mac=arp.get("target_mac", ""),
            target_ip=arp.get("target_ip", ""),
        )

    # ── ICMP ──
    icmp = d.get("icmp")
    if icmp and isinstance(icmp, dict):
        pkt.icmp = ICMPInfo(
            type=icmp.get("type", 0),
            code=icmp.get("code", 0),
        )

    # ── ICMPv6 ──
    icmpv6 = d.get("icmpv6")
    if icmpv6 and isinstance(icmpv6, dict):
        pkt.icmp6 = ICMP6Info(
            type=icmpv6.get("type", 0),
            code=icmpv6.get("code", 0),
            checksum=icmpv6.get("checksum", 0),
        )

    # ── TLS ──
    tls_record = d.get("tls_record")
    if tls_record and isinstance(tls_record, dict):
        version_str = None
        major = tls_record.get("version_major", 0)
        minor = tls_record.get("version_minor", 0)
        if major and minor:
            version_str = f"{major}.{minor}"

        pkt.tls = TLSInfo(
            version=version_str,
            content_type=tls_record.get("content_type"),
            record_length=tls_record.get("record_length", 0),
        )

        # Handshake info
        hs = d.get("tls_handshake")
        if hs and isinstance(hs, dict):
            pkt.tls.handshake_type = hs.get("handshake_type")

        # ClientHello
        ch = d.get("tls_client_hello")
        if ch and isinstance(ch, dict):
            pkt.tls.handshake_type = 1
            cs = ch.get("cipher_suites")
            if cs and isinstance(cs, list):
                pkt.tls.cipher_suites = list(cs)

        # ServerHello
        sh = d.get("tls_server_hello")
        if sh and isinstance(sh, dict):
            pkt.tls.handshake_type = 2
            pkt.tls.cipher_suite = sh.get("cipher_suite")

    # ── Generic fallback for unknown protocols ──
    _KNOWN_KEYS = {
        'ethernet', 'ipv4', 'ipv6', 'tcp', 'udp', 'dns',
        'arp', 'icmp', 'icmpv6',
        'tls_record', 'tls_handshake', 'tls_client_hello',
        'tls_server_hello', 'tls_certificate', 'tls_stream',
        '_raw_tcp_payload', '_raw_data', '_link_type', 'app_len',
    }
    registry = ProtocolRegistry.get_instance()
    for key, val in d.items():
        if key in _KNOWN_KEYS or not isinstance(val, dict):
            continue
        if key not in pkt.layers:
            cls = registry.get(key)
            if cls is not None:
                pkt.layers[key] = cls(fields=val)
            else:
                pkt.layers[key] = ProtocolInfo(fields=val)

    return pkt
