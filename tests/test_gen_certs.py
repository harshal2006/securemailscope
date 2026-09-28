import datetime
import shutil
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa

from lab.gen_certs import LAB_SAN, generate_all


@pytest.fixture(scope="module")
def certs_dir(tmp_path_factory):
    out_dir = tmp_path_factory.mktemp("certs")
    generate_all(out_dir)
    yield out_dir
    shutil.rmtree(out_dir, ignore_errors=True)


def _load_cert(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(path.read_bytes())


def test_ca_cert_generated(certs_dir):
    cert = _load_cert(certs_dir / "ca.crt")
    assert cert.public_key().key_size == 2048
    assert isinstance(cert.public_key(), rsa.RSAPublicKey)


def test_valid_cert_key_size_and_hash(certs_dir):
    cert = _load_cert(certs_dir / "valid.crt")
    assert cert.public_key().key_size == 2048
    assert cert.signature_hash_algorithm.name == "sha256"


def test_valid_cert_san(certs_dir):
    cert = _load_cert(certs_dir / "valid.crt")
    san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    dns_names = san_ext.value.get_values_for_type(x509.DNSName)
    assert dns_names == [LAB_SAN]


def test_valid_cert_is_currently_valid(certs_dir):
    cert = _load_cert(certs_dir / "valid.crt")
    now = datetime.datetime.now(datetime.timezone.utc)
    assert cert.not_valid_before_utc <= now <= cert.not_valid_after_utc


def test_expired_cert_key_size_and_hash(certs_dir):
    cert = _load_cert(certs_dir / "expired.crt")
    assert cert.public_key().key_size == 2048
    assert cert.signature_hash_algorithm.name == "sha256"


def test_expired_cert_is_actually_expired(certs_dir):
    cert = _load_cert(certs_dir / "expired.crt")
    now = datetime.datetime.now(datetime.timezone.utc)
    assert cert.not_valid_after_utc < now
    assert cert.not_valid_before_utc < cert.not_valid_after_utc


def test_selfsigned_cert_key_size_and_hash(certs_dir):
    cert = _load_cert(certs_dir / "selfsigned.crt")
    assert cert.public_key().key_size == 2048
    assert cert.signature_hash_algorithm.name == "sha256"


def test_selfsigned_cert_issuer_equals_subject(certs_dir):
    cert = _load_cert(certs_dir / "selfsigned.crt")
    assert cert.issuer == cert.subject


def test_selfsigned_cert_san(certs_dir):
    cert = _load_cert(certs_dir / "selfsigned.crt")
    san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    dns_names = san_ext.value.get_values_for_type(x509.DNSName)
    assert dns_names == [LAB_SAN]


def test_valid_cert_issued_by_ca_not_self(certs_dir):
    valid_cert = _load_cert(certs_dir / "valid.crt")
    ca_cert = _load_cert(certs_dir / "ca.crt")
    assert valid_cert.issuer == ca_cert.subject
    assert valid_cert.issuer != valid_cert.subject
