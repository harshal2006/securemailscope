"""
Generate lab-only X.509 certificates for SecureMailScope testing.

Produces a local test CA and leaf certificates into lab/certs/:
  - ca.key / ca.crt          : local test CA (self-signed)
  - valid.key / valid.crt    : RSA-2048, SHA-256, SAN=mail.lab.test, signed by ca
  - expired.key / expired.crt: same as valid but notAfter is in the past
  - selfsigned.key / selfsigned.crt: RSA-2048, SHA-256, signed by itself

These are lab certificates only. Never use them, or certificates generated
by this script, against a real mail server.
"""

from __future__ import annotations

import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

CERTS_DIR = Path(__file__).parent / "certs"

LAB_SAN = "mail.lab.test"


def generate_rsa_key(key_size: int = 2048) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)


def _write_key(key: rsa.RSAPrivateKey, path: Path) -> None:
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )


def _write_cert(cert: x509.Certificate, path: Path) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def build_ca(key_size: int = 2048) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = generate_rsa_key(key_size)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "SecureMailScope Lab Test CA")]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def build_leaf(
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
    *,
    common_name: str = LAB_SAN,
    san: str = LAB_SAN,
    key_size: int = 2048,
    hash_algorithm: hashes.HashAlgorithm | None = None,
    not_before_offset: datetime.timedelta = datetime.timedelta(days=-1),
    not_after_offset: datetime.timedelta = datetime.timedelta(days=365),
    self_signed: bool = False,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Build a leaf certificate.

    Signature hash defaults to SHA-256. Pass hash_algorithm=hashes.SHA1() to
    produce a legacy SHA-1-signed cert for future legacy-TLS test cases.
    If self_signed is True, the leaf signs its own key instead of ca_key,
    and ca_cert is ignored for the issuer name.
    """
    if hash_algorithm is None:
        hash_algorithm = hashes.SHA256()

    key = generate_rsa_key(key_size)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    issuer = subject if self_signed else ca_cert.subject
    signing_key = key if self_signed else ca_key

    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + not_before_offset)
        .not_valid_after(now + not_after_offset)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )
    if san:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(san)]), critical=False
        )

    cert = builder.sign(signing_key, hash_algorithm)
    return key, cert


def generate_all(
    out_dir: Path = CERTS_DIR,
    *,
    include_rsa1024: bool = False,
    include_sha1: bool = False,
    include_wrong_san: bool = False,
) -> None:
    """Generate the standard lab certificate set.

    Optional legacy/malformed cases (RSA-1024, SHA-1, wrong SAN) are gated
    behind flags so they can be added later without changing the default
    (valid/expired/self-signed) set.
    """
    out_dir.mkdir(parents=True, exist_ok=True)

    ca_key, ca_cert = build_ca()
    _write_key(ca_key, out_dir / "ca.key")
    _write_cert(ca_cert, out_dir / "ca.crt")

    valid_key, valid_cert = build_leaf(ca_key, ca_cert)
    _write_key(valid_key, out_dir / "valid.key")
    _write_cert(valid_cert, out_dir / "valid.crt")

    expired_key, expired_cert = build_leaf(
        ca_key,
        ca_cert,
        not_before_offset=datetime.timedelta(days=-730),
        not_after_offset=datetime.timedelta(days=-365),
    )
    _write_key(expired_key, out_dir / "expired.key")
    _write_cert(expired_cert, out_dir / "expired.crt")

    selfsigned_key, selfsigned_cert = build_leaf(ca_key, ca_cert, self_signed=True)
    _write_key(selfsigned_key, out_dir / "selfsigned.key")
    _write_cert(selfsigned_cert, out_dir / "selfsigned.crt")

    if include_rsa1024:
        rsa1024_key, rsa1024_cert = build_leaf(ca_key, ca_cert, key_size=1024)
        _write_key(rsa1024_key, out_dir / "rsa1024.key")
        _write_cert(rsa1024_cert, out_dir / "rsa1024.crt")

    if include_sha1:
        sha1_key, sha1_cert = build_leaf(ca_key, ca_cert, hash_algorithm=hashes.SHA1())
        _write_key(sha1_key, out_dir / "sha1.key")
        _write_cert(sha1_cert, out_dir / "sha1.crt")

    if include_wrong_san:
        wrong_san_key, wrong_san_cert = build_leaf(
            ca_key, ca_cert, san="wrong.example.test"
        )
        _write_key(wrong_san_key, out_dir / "wrongsan.key")
        _write_cert(wrong_san_cert, out_dir / "wrongsan.crt")


if __name__ == "__main__":
    generate_all()
    print(f"Generated lab certificates in {CERTS_DIR}")
