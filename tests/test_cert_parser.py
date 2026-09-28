import datetime
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from core.cert_parser import parse_der_certificate

CERTS_DIR = Path(__file__).parent.parent / "lab" / "certs"


def _der_bytes(name: str) -> bytes:
    pem = (CERTS_DIR / name).read_bytes()
    return x509.load_pem_x509_certificate(pem).public_bytes(
        encoding=serialization.Encoding.DER
    )


@pytest.fixture(scope="module", autouse=True)
def ensure_certs_exist():
    if not (CERTS_DIR / "valid.crt").exists():
        pytest.skip("lab/certs not generated; run `python lab/gen_certs.py` first")


def test_parse_valid_cert():
    info = parse_der_certificate(_der_bytes("valid.crt"))
    assert info.subject_cn == "mail.lab.test"
    assert info.issuer_cn == "SecureMailScope Lab Test CA"
    assert info.self_signed is False
    assert info.key_algorithm == "RSA"
    assert info.key_size == 2048
    assert info.signature_hash_algorithm == "sha256"
    assert info.san_dns_names == ["mail.lab.test"]
    assert info.is_expired is False


def test_parse_expired_cert():
    info = parse_der_certificate(_der_bytes("expired.crt"))
    assert info.is_expired is True
    assert info.not_after < datetime.datetime.now(datetime.timezone.utc)


def test_parse_selfsigned_cert():
    info = parse_der_certificate(_der_bytes("selfsigned.crt"))
    assert info.self_signed is True
    assert info.subject_cn == info.issuer_cn == "mail.lab.test"


def test_expiry_uses_reference_time_not_wall_clock():
    # expired.crt: notBefore 2024-09-28, notAfter 2025-09-28. Wall clock
    # is now well past that, so the default (no reference_time) call
    # must say expired...
    default_info = parse_der_certificate(_der_bytes("expired.crt"))
    assert default_info.is_expired is True

    # ...but if we pass a reference_time from back when the cert was
    # still valid (simulating a pcap captured then), it must not be
    # judged expired - expiry is relative to the capture, not to
    # whenever parse_der_certificate happens to be called.
    reference_time = datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc)
    past_info = parse_der_certificate(_der_bytes("expired.crt"), reference_time)
    assert past_info.is_expired is False
