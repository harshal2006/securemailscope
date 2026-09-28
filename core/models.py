"""Data models for parsed SMTP/IMAP/POP3 sessions and TLS/certificate info."""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field


# TLS version numbers as they appear in the supported_versions extension /
# legacy record version field.
TLS_VERSION_NAMES = {
    0x0304: "TLS 1.3",
    0x0303: "TLS 1.2",
    0x0302: "TLS 1.1",
    0x0301: "TLS 1.0",
    0x0300: "SSL 3.0",
}


@dataclass
class CertInfo:
    """Parsed X.509 certificate fields relevant to posture scoring."""

    subject_cn: str | None
    issuer_cn: str | None
    self_signed: bool
    key_algorithm: str
    key_size: int | None
    signature_hash_algorithm: str | None
    san_dns_names: list[str]
    not_before: datetime.datetime
    not_after: datetime.datetime
    is_expired: bool


@dataclass
class TLSInfo:
    """What was observed of the TLS handshake for a session."""

    negotiated_version: str | None  # e.g. "TLS 1.3", None if no handshake seen
    cipher_suite: str | None
    cert_observable: bool
    cert_not_observable_reason: str | None  # set when cert_observable is False
    leaf_cert: CertInfo | None
    sni_hostname: str | None = None  # from ClientHello SNI; None if absent
    chain_certs: list[CertInfo] = field(default_factory=list)


@dataclass
class Session:
    """One reassembled TCP stream classified as a mail protocol session."""

    tcp_stream: int
    protocol: str  # "smtp" | "imap" | "pop3"
    tls_mode: str  # "implicit" | "starttls" | "plaintext_only"
    role: str  # "mx" | "submission"
    client_ip: str
    server_ip: str
    server_port: int
    tls_info: TLSInfo | None
    first_frame: int
    last_frame: int
