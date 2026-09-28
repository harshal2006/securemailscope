import datetime
from pathlib import Path

import pytest

from core.findings import Finding
from core.models import CertInfo, Session, TLSInfo
from core.pcap_reader import read_packets
from core.rules_engine import evaluate_session, load_rules
from core.session_builder import build_sessions, group_packets_by_stream
from core.starttls import StarttlsAnalysis, build_timeline

NOW = datetime.datetime.now(datetime.timezone.utc)
FIXTURES = Path(__file__).parent / "fixtures" / "pcaps"


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


def _session(tls_mode="starttls", tls_info=None, protocol="smtp", role="mx") -> Session:
    return Session(
        tcp_stream=0,
        protocol=protocol,
        tls_mode=tls_mode,
        role=role,
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


# --- T-01 / T-02 / T-03: STARTTLS and plaintext-auth rules ---


def _starttls(**overrides) -> StarttlsAnalysis:
    defaults = dict(
        protocol="smtp",
        capability_advertised_starttls=True,
        starttls_issued=True,
        starttls_success=True,
        tls_followed=True,
        auth_before_tls=False,
        auth_after_tls=None,
    )
    defaults.update(overrides)
    return StarttlsAnalysis(**defaults)


def test_t01_plaintext_auth_before_tls_is_critical(rules):
    session = _session(tls_mode="plaintext_only", tls_info=None, role="submission")
    analysis = _starttls(auth_before_tls=True, starttls_issued=False, tls_followed=False)
    findings = evaluate_session(session, rules, analysis)
    t01 = next(f for f in findings if f.rule_id == "T-01")
    assert t01.severity == "CRITICAL"


def test_t01_not_flagged_when_auth_happens_after_tls(rules):
    session = _session(tls_mode="starttls", tls_info=_tls_info(), role="submission")
    analysis = _starttls(auth_before_tls=False)
    findings = evaluate_session(session, rules, analysis)
    assert not any(f.rule_id == "T-01" for f in findings)


def test_t02_advertised_but_unused_is_high_on_submission(rules):
    session = _session(tls_mode="plaintext_only", tls_info=None, role="submission")
    analysis = _starttls(
        capability_advertised_starttls=True, starttls_issued=False, tls_followed=False
    )
    findings = evaluate_session(session, rules, analysis)
    t02 = next(f for f in findings if f.rule_id == "T-02")
    assert t02.severity == "HIGH"


def test_t02_advertised_but_unused_is_info_on_mx(rules):
    session = _session(tls_mode="plaintext_only", tls_info=None, role="mx")
    analysis = _starttls(
        capability_advertised_starttls=True, starttls_issued=False, tls_followed=False
    )
    findings = evaluate_session(session, rules, analysis)
    t02 = next(f for f in findings if f.rule_id == "T-02")
    assert t02.severity == "INFO"


def test_t02_not_flagged_when_client_upgrades(rules):
    session = _session(tls_mode="starttls", tls_info=_tls_info(), role="submission")
    analysis = _starttls()  # capability advertised AND used
    findings = evaluate_session(session, rules, analysis)
    assert not any(f.rule_id == "T-02" for f in findings)


def test_t03_not_offered_is_high_on_submission(rules):
    session = _session(tls_mode="plaintext_only", tls_info=None, role="submission")
    analysis = _starttls(
        capability_advertised_starttls=False, starttls_issued=False, tls_followed=False
    )
    findings = evaluate_session(session, rules, analysis)
    t03 = next(f for f in findings if f.rule_id == "T-03")
    assert t03.severity == "HIGH"


def test_t03_not_offered_is_low_on_mx(rules):
    session = _session(tls_mode="plaintext_only", tls_info=None, role="mx")
    analysis = _starttls(
        capability_advertised_starttls=False, starttls_issued=False, tls_followed=False
    )
    findings = evaluate_session(session, rules, analysis)
    t03 = next(f for f in findings if f.rule_id == "T-03")
    assert t03.severity == "LOW"


def test_t03_not_flagged_when_capability_unknown(rules):
    # capability_advertised_starttls stays None when we never actually
    # observed a full capability listing - must not guess "not offered".
    session = _session(tls_mode="plaintext_only", tls_info=None, role="submission")
    analysis = _starttls(
        capability_advertised_starttls=None, starttls_issued=False, tls_followed=False
    )
    findings = evaluate_session(session, rules, analysis)
    assert not any(f.rule_id == "T-03" for f in findings)


def test_t01_t02_implicit_tls_sessions_never_evaluated(rules):
    # Implicit-TLS sessions have no plaintext-exposure window at all.
    session = _session(tls_mode="implicit", tls_info=_tls_info(), role="submission")
    analysis = _starttls(auth_before_tls=True, capability_advertised_starttls=False)
    findings = evaluate_session(session, rules, analysis)
    assert not any(f.rule_id in ("T-01", "T-02", "T-03") for f in findings)


# --- Real captures: S17 (plaintext AUTH, no STARTTLS) / S01b (STARTTLS then AUTH) ---


def _real_session_and_analysis(pcap_name: str):
    packets = read_packets(FIXTURES / pcap_name)
    sessions = build_sessions(packets)
    assert len(sessions) == 1
    session = sessions[0]
    by_stream = group_packets_by_stream(packets)
    analysis = build_timeline(by_stream[session.tcp_stream], session.server_port, session.protocol)
    return session, analysis


def test_real_s17_triggers_t01_and_t02(rules):
    session, analysis = _real_session_and_analysis("S17_smtp_587_plaintext_auth.pcap")
    assert session.role == "submission"
    findings = evaluate_session(session, rules, analysis)
    rule_ids = {f.rule_id for f in findings}
    assert "T-01" in rule_ids
    assert "T-02" in rule_ids
    t01 = next(f for f in findings if f.rule_id == "T-01")
    t02 = next(f for f in findings if f.rule_id == "T-02")
    assert t01.severity == "CRITICAL"
    assert t02.severity == "HIGH"


def test_real_s01b_triggers_neither_t01_nor_t02(rules):
    session, analysis = _real_session_and_analysis("S01b_smtp_587_starttls_auth.pcap")
    findings = evaluate_session(session, rules, analysis)
    rule_ids = {f.rule_id for f in findings}
    assert "T-01" not in rule_ids
    assert "T-02" not in rule_ids
    assert "T-03" not in rule_ids
