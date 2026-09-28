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
