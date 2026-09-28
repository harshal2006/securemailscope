"""Parses X.509 certificates observed on the wire into CertInfo."""

from __future__ import annotations

import datetime

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

from core.models import CertInfo


def _key_algorithm_and_size(public_key) -> tuple[str, int | None]:
    if isinstance(public_key, rsa.RSAPublicKey):
        return "RSA", public_key.key_size
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return f"EC ({public_key.curve.name})", public_key.key_size
    if isinstance(public_key, dsa.DSAPublicKey):
        return "DSA", public_key.key_size
    if isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        return "EdDSA", None
    return type(public_key).__name__, None


def parse_der_certificate(
    der_bytes: bytes, reference_time: datetime.datetime | None = None
) -> CertInfo:
    """Parse a single DER-encoded certificate as captured on the wire.

    `reference_time` should be the pcap's own capture timestamp (from
    tshark's frame.time_epoch), not wall-clock time - this is a passive
    forensic tool that may analyze pcaps long after capture, and a cert
    valid at capture time but since expired (or vice versa) must be
    judged against the capture time, not whenever the analyzer happens
    to run. Defaults to wall-clock `now` only for standalone use (e.g.
    inspecting a cert file directly, not from a capture).
    """
    cert = x509.load_der_x509_certificate(der_bytes)

    subject_cn = _get_common_name(cert.subject)
    issuer_cn = _get_common_name(cert.issuer)

    key_algorithm, key_size = _key_algorithm_and_size(cert.public_key())

    try:
        sig_hash = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None
    except UnsupportedAlgorithm:
        sig_hash = None

    san_dns_names: list[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_dns_names = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass

    if reference_time is None:
        reference_time = datetime.datetime.now(datetime.timezone.utc)
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc

    return CertInfo(
        subject_cn=subject_cn,
        issuer_cn=issuer_cn,
        self_signed=(cert.issuer == cert.subject),
        key_algorithm=key_algorithm,
        key_size=key_size,
        signature_hash_algorithm=sig_hash,
        san_dns_names=san_dns_names,
        not_before=not_before,
        not_after=not_after,
        is_expired=not (not_before <= reference_time <= not_after),
    )


def _get_common_name(name: x509.Name) -> str | None:
    attrs = name.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    return attrs[0].value if attrs else None


def parse_hex_cert_list(
    hex_list: str, reference_time: datetime.datetime | None = None
) -> list[CertInfo]:
    """Parse tshark's comma-separated tls.handshake.certificate hex field."""
    if not hex_list:
        return []
    certs = []
    for hex_der in hex_list.split(","):
        hex_der = hex_der.strip()
        if not hex_der:
            continue
        certs.append(parse_der_certificate(bytes.fromhex(hex_der), reference_time))
    return certs
