"""Groups tshark packet records into classified mail protocol Sessions."""

from __future__ import annotations

import datetime
from collections import defaultdict
from pathlib import Path

import yaml

from core.cert_parser import parse_hex_cert_list
from core.models import TLS_VERSION_NAMES, Session, TLSInfo

DEFAULT_PORTS_FILE = Path(__file__).parent.parent / "rules" / "ports.yaml"

TLS_HANDSHAKE_CLIENT_HELLO = "1"
TLS_HANDSHAKE_CERTIFICATE = "11"
TLS_HANDSHAKE_SERVER_HELLO = "2"


def load_port_map(ports_file: Path = DEFAULT_PORTS_FILE) -> dict[str, dict[str, list[int]]]:
    with open(ports_file) as f:
        return yaml.safe_load(f)


def _classify_port(port: int, port_map: dict) -> tuple[str, str, str] | None:
    """Return (protocol, 'starttls'|'implicit', role) if port is known, else None."""
    for protocol, modes in port_map.items():
        for mode_key, roles in (("starttls_ports", "starttls"), ("implicit_ports", "implicit")):
            for role, ports in modes.get(mode_key, {}).items():
                if port in ports:
                    return protocol, roles, role
    return None


def group_packets_by_stream(packets: list[dict[str, str]]) -> dict[int, list[dict[str, str]]]:
    by_stream: dict[str, list[dict[str, str]]] = defaultdict(list)
    for pkt in packets:
        stream = pkt.get("tcp.stream")
        if stream:
            by_stream[stream].append(pkt)
    return {
        int(stream_id): sorted(pkts, key=lambda p: int(p["frame.number"]))
        for stream_id, pkts in by_stream.items()
    }


def _int_or_none(value: str) -> int | None:
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _first_hex_value(value: str) -> int | None:
    """tshark emits multi-valued fields comma-separated; take the first."""
    if not value:
        return None
    first = value.split(",")[0].strip()
    if not first:
        return None
    try:
        return int(first, 16)
    except ValueError:
        return None


def build_sessions(
    packets: list[dict[str, str]], port_map: dict | None = None
) -> list[Session]:
    if port_map is None:
        port_map = load_port_map()

    by_stream = group_packets_by_stream(packets)

    sessions: list[Session] = []
    for stream_id, pkts in by_stream.items():
        session = _build_one_session(stream_id, pkts, port_map)
        if session is not None:
            sessions.append(session)
    return sessions


def _build_one_session(
    stream_id: int, pkts: list[dict[str, str]], port_map: dict
) -> Session | None:
    server_port = None
    server_ip = client_ip = None
    classification = None

    for pkt in pkts:
        srcport = _int_or_none(pkt.get("tcp.srcport"))
        dstport = _int_or_none(pkt.get("tcp.dstport"))
        for port, ip_if_server, ip_if_client in (
            (srcport, pkt.get("ip.src"), pkt.get("ip.dst")),
            (dstport, pkt.get("ip.dst"), pkt.get("ip.src")),
        ):
            hit = _classify_port(port, port_map) if port is not None else None
            if hit is not None:
                classification = hit
                server_port = port
                server_ip = ip_if_server
                client_ip = ip_if_client
                break
        if classification is not None:
            break

    if classification is None:
        return None  # not a mail protocol session we recognize
    protocol, _expected_mode, role = classification

    first_payload_pkt = next(
        (p for p in pkts if _int_or_none(p.get("tcp.len")) and int(p["tcp.len"]) > 0), None
    )
    tls_seen_from_start = bool(
        first_payload_pkt and first_payload_pkt.get("tls.record.content_type")
    )
    any_tls_handshake = any(p.get("tls.handshake.type") for p in pkts)

    if tls_seen_from_start:
        tls_mode = "implicit"
    elif any_tls_handshake:
        tls_mode = "starttls"
    else:
        tls_mode = "plaintext_only"

    tls_info = None
    if tls_mode in ("implicit", "starttls"):
        tls_info = _extract_tls_info(pkts)

    return Session(
        tcp_stream=stream_id,
        protocol=protocol,
        tls_mode=tls_mode,
        role=role,
        client_ip=client_ip,
        server_ip=server_ip,
        server_port=server_port,
        tls_info=tls_info,
        first_frame=int(pkts[0]["frame.number"]),
        last_frame=int(pkts[-1]["frame.number"]),
    )


def _extract_tls_info(pkts: list[dict[str, str]]) -> TLSInfo:
    negotiated_version_code = None
    cipher_suite_code = None
    cert_hex_list = None
    cert_frame_time_epoch = None
    sni_hostname = None

    for pkt in pkts:
        handshake_types = (pkt.get("tls.handshake.type") or "").split(",")
        if TLS_HANDSHAKE_CLIENT_HELLO in handshake_types and pkt.get(
            "tls.handshake.extensions_server_name"
        ):
            # Multi-valued fields come back comma-separated; SNI has one value.
            sni_hostname = pkt["tls.handshake.extensions_server_name"].split(",")[0].strip()
        if TLS_HANDSHAKE_SERVER_HELLO in handshake_types:
            supported_version = pkt.get("tls.handshake.extensions.supported_version")
            if supported_version:
                # Present only when the server negotiated TLS 1.3.
                negotiated_version_code = _first_hex_value(supported_version)
            else:
                # No supported_versions extension: fall back to the
                # ServerHello's legacy_version field (valid for TLS <= 1.2).
                negotiated_version_code = _first_hex_value(pkt.get("tls.handshake.version"))
            cipher_suite_code = _first_hex_value(pkt.get("tls.handshake.ciphersuite"))
        if TLS_HANDSHAKE_CERTIFICATE in handshake_types and pkt.get("tls.handshake.certificate"):
            cert_hex_list = pkt["tls.handshake.certificate"]
            cert_frame_time_epoch = pkt.get("frame.time_epoch")

    negotiated_version = TLS_VERSION_NAMES.get(negotiated_version_code)
    cipher_suite = f"0x{cipher_suite_code:04x}" if cipher_suite_code is not None else None

    # Certificate validity must be judged against when the traffic was
    # actually captured, not whenever this analysis happens to run - a
    # pcap analyzed long after capture must not have its cert expiry
    # flip based on wall-clock time. See core/cert_parser.py.
    capture_time = None
    if cert_frame_time_epoch:
        capture_time = datetime.datetime.fromtimestamp(
            float(cert_frame_time_epoch), tz=datetime.timezone.utc
        )
    certs = parse_hex_cert_list(cert_hex_list, capture_time) if cert_hex_list else []
    leaf_cert = certs[0] if certs else None
    chain_certs = certs[1:] if len(certs) > 1 else []

    cert_observable = leaf_cert is not None
    reason = None
    if not cert_observable:
        if negotiated_version == "TLS 1.3":
            reason = (
                "TLS 1.3 encrypts the Certificate message; not observable to a "
                "passive listener without the private key."
            )
        elif negotiated_version is not None:
            reason = (
                "No Certificate message observed for this pre-TLS-1.3 session "
                "(capture may be incomplete)."
            )
        else:
            reason = "TLS version could not be determined from this capture."

    return TLSInfo(
        negotiated_version=negotiated_version,
        cipher_suite=cipher_suite,
        cert_observable=cert_observable,
        cert_not_observable_reason=reason,
        leaf_cert=leaf_cert,
        sni_hostname=sni_hostname,
        chain_certs=chain_certs,
    )
