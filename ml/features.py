"""Extracts a fixed-order numeric feature vector per session for the ML
classifier (Part B). Reuses core/* parsing and classification code
directly - this module never re-parses a pcap from scratch; it only
converts already-computed Session/TLSInfo/CertInfo/StarttlsAnalysis
objects into numbers.

Feature groups, per the plan's Section 7.2: protocol/transport, TLS/
cipher, certificate, and STARTTLS/behavioural.
"""

from __future__ import annotations

import datetime
from pathlib import Path

from core.models import TLS_VERSION_NAMES, Session, TLSInfo
from core.pcap_reader import read_packets
from core.rules_engine import _classify_key_exchange, load_rules
from core.session_builder import build_sessions, group_packets_by_stream
from core.starttls import StarttlsAnalysis, build_timeline

TLS_VERSION_ORDINAL = {
    None: 0,
    "SSL 3.0": 1,
    "TLS 1.0": 2,
    "TLS 1.1": 3,
    "TLS 1.2": 4,
    "TLS 1.3": 5,
}

FEATURE_NAMES = [
    # protocol / transport
    "protocol_smtp",
    "protocol_imap",
    "protocol_pop3",
    "tls_mode_implicit",
    "tls_mode_starttls",
    "tls_mode_plaintext_only",
    "role_submission",
    "role_mx",
    "server_port",
    # TLS / cipher
    "tls_version_ordinal",
    "tls_version_is_legacy",
    "cipher_suite_numeric",
    "cipher_is_weak",
    "kex_is_ephemeral",
    "kex_is_static",
    "kex_is_unknown",
    "has_sni",
    # certificate
    "cert_observable",
    "cert_is_expired",
    "cert_is_selfsigned",
    "cert_key_size",
    "cert_key_is_rsa_or_dsa",
    "cert_sig_is_weak",
    "cert_hostname_mismatch",
    "cert_hostname_checked",
    "cert_validity_period_days",
    # STARTTLS / behavioural
    "capability_advertised_starttls",  # -1 unknown, 0 False, 1 True
    "starttls_issued",
    "starttls_success",
    "tls_followed",
    "auth_before_tls",
    "timeline_length",
    "frame_span",
]

assert len(FEATURE_NAMES) == 33  # ~30, per the plan


def _hostname_matches_san(hostname: str, san_dns_names: list[str]) -> bool:
    # Local copy of core.rules_engine's RFC 6125-lite matcher - kept in
    # sync deliberately rather than importing a private function across
    # module boundaries for a one-line helper.
    hostname = hostname.rstrip(".").lower()
    for san in san_dns_names:
        san = san.rstrip(".").lower()
        if san == hostname:
            return True
        if san.startswith("*."):
            san_suffix = san[1:]
            if hostname.endswith(san_suffix) and hostname.count(".") == san.count("."):
                return True
    return False


def extract_features(
    session: Session, starttls_analysis: StarttlsAnalysis | None, rules: dict | None = None
) -> dict[str, float]:
    if rules is None:
        rules = load_rules()

    tls_info: TLSInfo | None = session.tls_info
    f: dict[str, float] = {}

    f["protocol_smtp"] = float(session.protocol == "smtp")
    f["protocol_imap"] = float(session.protocol == "imap")
    f["protocol_pop3"] = float(session.protocol == "pop3")
    f["tls_mode_implicit"] = float(session.tls_mode == "implicit")
    f["tls_mode_starttls"] = float(session.tls_mode == "starttls")
    f["tls_mode_plaintext_only"] = float(session.tls_mode == "plaintext_only")
    f["role_submission"] = float(session.role == "submission")
    f["role_mx"] = float(session.role == "mx")
    f["server_port"] = float(session.server_port)

    negotiated_version = tls_info.negotiated_version if tls_info else None
    version_ord = TLS_VERSION_ORDINAL.get(negotiated_version, 0)
    f["tls_version_ordinal"] = float(version_ord)
    f["tls_version_is_legacy"] = float(0 < version_ord < 4)

    cipher_suite = tls_info.cipher_suite if tls_info else None
    f["cipher_suite_numeric"] = float(int(cipher_suite, 16)) if cipher_suite else -1.0
    weak_suites = rules["weak_ciphers"]["weak_suites"]
    f["cipher_is_weak"] = float(cipher_suite in weak_suites) if cipher_suite else 0.0

    kex = _classify_key_exchange(negotiated_version, cipher_suite, rules) if tls_info else "unknown"
    f["kex_is_ephemeral"] = float(kex == "ephemeral")
    f["kex_is_static"] = float(kex == "static")
    f["kex_is_unknown"] = float(kex == "unknown")
    f["has_sni"] = float(bool(tls_info and tls_info.sni_hostname))

    cert = tls_info.leaf_cert if (tls_info and tls_info.cert_observable) else None
    f["cert_observable"] = float(cert is not None)
    f["cert_is_expired"] = float(cert.is_expired) if cert else 0.0
    f["cert_is_selfsigned"] = float(cert.self_signed) if cert else 0.0
    f["cert_key_size"] = float(cert.key_size) if (cert and cert.key_size) else 0.0
    f["cert_key_is_rsa_or_dsa"] = float(cert.key_algorithm in ("RSA", "DSA")) if cert else 0.0
    f["cert_sig_is_weak"] = (
        float(cert.signature_hash_algorithm in ("md5", "sha1")) if cert else 0.0
    )

    hostname_checked = bool(cert and tls_info.sni_hostname)
    f["cert_hostname_checked"] = float(hostname_checked)
    f["cert_hostname_mismatch"] = (
        float(not _hostname_matches_san(tls_info.sni_hostname, cert.san_dns_names))
        if hostname_checked
        else 0.0
    )
    f["cert_validity_period_days"] = (
        float((cert.not_after - cert.not_before).days) if cert else 0.0
    )

    if starttls_analysis is not None:
        cap = starttls_analysis.capability_advertised_starttls
        f["capability_advertised_starttls"] = -1.0 if cap is None else float(cap)
        f["starttls_issued"] = float(starttls_analysis.starttls_issued)
        f["starttls_success"] = float(starttls_analysis.starttls_success)
        f["tls_followed"] = float(starttls_analysis.tls_followed)
        f["auth_before_tls"] = float(starttls_analysis.auth_before_tls)
        f["timeline_length"] = float(len(starttls_analysis.timeline))
    else:
        f["capability_advertised_starttls"] = -1.0
        f["starttls_issued"] = 0.0
        f["starttls_success"] = 0.0
        f["tls_followed"] = float(session.tls_mode == "implicit")
        f["auth_before_tls"] = 0.0
        f["timeline_length"] = 0.0

    f["frame_span"] = float(session.last_frame - session.first_frame)

    return {name: f[name] for name in FEATURE_NAMES}


def extract_features_for_pcap(pcap_path: Path, rules: dict | None = None) -> list[dict[str, float]]:
    """One row per recognized session in the pcap. Reuses the exact same
    parsing pipeline as core/analyze.py - no re-parsing logic here.
    """
    if rules is None:
        rules = load_rules()

    packets = read_packets(pcap_path)
    sessions = build_sessions(packets)
    packets_by_stream = group_packets_by_stream(packets)

    rows = []
    for session in sessions:
        starttls_analysis = None
        if session.tls_mode in ("plaintext_only", "starttls"):
            starttls_analysis = build_timeline(
                packets_by_stream[session.tcp_stream], session.server_port, session.protocol
            )
        rows.append(extract_features(session, starttls_analysis, rules))
    return rows
