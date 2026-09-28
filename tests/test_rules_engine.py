import datetime

import pytest

from core.findings import Finding
from core.models import CertInfo, Session, TLSInfo
from core.rules_engine import evaluate_session, load_rules

NOW = datetime.datetime.now(datetime.timezone.utc)


@pytest.fixture(scope="module")
def rules():
    return load_rules()


def _cert(**overrides) -> CertInfo:
    defaults = dict(
        subject_cn="mail.lab.test",
        issuer_cn="SecureMailScope Lab Test CA",
        self_signed=False,
        key_algorithm="RSA",
        key_size=2048,
        signature_hash_algorithm="sha256",
        san_dns_names=["mail.lab.test"],
        not_before=NOW - datetime.timedelta(days=1),
        not_after=NOW + datetime.timedelta(days=365),
        is_expired=False,
    )
    defaults.update(overrides)
    return CertInfo(**defaults)


def _session(tls_mode="starttls", tls_info=None, protocol="smtp") -> Session:
    return Session(
        tcp_stream=0,
        protocol=protocol,
        tls_mode=tls_mode,
        client_ip="127.0.0.1",
        server_ip="127.0.0.1",
        server_port=2525,
        tls_info=tls_info,
        first_frame=1,
        last_frame=10,
    )


def _tls_info(**overrides) -> TLSInfo:
    defaults = dict(
        negotiated_version="TLS 1.2",
        cipher_suite="0xc030",
        cert_observable=True,
        cert_not_observable_reason=None,
        leaf_cert=_cert(),
        chain_certs=[],
    )
    defaults.update(overrides)
    return TLSInfo(**defaults)


def test_no_tls_observed_is_critical(rules):
    session = _session(tls_mode="plaintext_only", tls_info=None)
    findings = evaluate_session(session, rules)
    assert len(findings) == 1
    assert findings[0].rule_id == "NO_TLS_OBSERVED"
    assert findings[0].severity == "CRITICAL"


def test_tls13_no_cert_findings_are_informational(rules):
    tls_info = _tls_info(
        negotiated_version="TLS 1.3",
        cert_observable=False,
        cert_not_observable_reason="TLS 1.3 encrypts the Certificate message.",
        leaf_cert=None,
    )
    findings = evaluate_session(_session(tls_info=tls_info), rules)
    rule_ids = {f.rule_id for f in findings}
    assert rule_ids == {"TLS_VERSION_1_3", "CERT_NOT_OBSERVABLE"}
    assert all(f.severity == "INFO" for f in findings)


def test_tls10_flagged_high(rules):
    tls_info = _tls_info(negotiated_version="TLS 1.0")
    findings = evaluate_session(_session(tls_info=tls_info), rules)
    version_finding = next(f for f in findings if f.rule_id == "TLS_VERSION_1_0")
    assert version_finding.severity == "HIGH"


def test_expired_cert_flagged(rules):
    tls_info = _tls_info(leaf_cert=_cert(is_expired=True))
    findings = evaluate_session(_session(tls_info=tls_info), rules)
    assert any(f.rule_id == "CERT_EXPIRED" for f in findings)


def test_self_signed_cert_flagged(rules):
    tls_info = _tls_info(leaf_cert=_cert(self_signed=True))
    findings = evaluate_session(_session(tls_info=tls_info), rules)
    assert any(f.rule_id == "CERT_SELF_SIGNED" for f in findings)


def test_weak_rsa_key_flagged(rules):
    tls_info = _tls_info(leaf_cert=_cert(key_size=1024))
    findings = evaluate_session(_session(tls_info=tls_info), rules)
    assert any(f.rule_id == "CERT_WEAK_KEY" for f in findings)


def test_strong_ec_key_not_flagged_as_weak(rules):
    tls_info = _tls_info(leaf_cert=_cert(key_algorithm="EC (secp256r1)", key_size=256))
    findings = evaluate_session(_session(tls_info=tls_info), rules)
    assert not any(f.rule_id == "CERT_WEAK_KEY" for f in findings)


def test_sha1_signature_flagged(rules):
    tls_info = _tls_info(leaf_cert=_cert(signature_hash_algorithm="sha1"))
    findings = evaluate_session(_session(tls_info=tls_info), rules)
    assert any(f.rule_id == "CERT_WEAK_SIGNATURE_HASH" for f in findings)


def test_weak_cipher_suite_flagged(rules):
    tls_info = _tls_info(cipher_suite="0x0004")  # RC4
    findings = evaluate_session(_session(tls_info=tls_info), rules)
    weak_finding = next(f for f in findings if f.rule_id == "WEAK_CIPHER_SUITE")
    assert "RC4" in weak_finding.message


def test_strong_cipher_not_flagged(rules):
    tls_info = _tls_info(cipher_suite="0x1303")  # TLS_AES_256_GCM_SHA384
    findings = evaluate_session(_session(tls_info=tls_info), rules)
    assert not any(f.rule_id == "WEAK_CIPHER_SUITE" for f in findings)


def test_valid_cert_no_cert_findings(rules):
    tls_info = _tls_info()  # all defaults: valid, not self-signed, strong key/hash
    findings = evaluate_session(_session(tls_info=tls_info), rules)
    cert_finding_ids = {f.rule_id for f in findings} - {"TLS_VERSION_1_2"}
    assert cert_finding_ids == set()
