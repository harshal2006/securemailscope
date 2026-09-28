import datetime
from pathlib import Path

import pytest

from core.pcap_reader import read_packets
from core.session_builder import build_sessions

FIXTURES = Path(__file__).parent / "fixtures" / "pcaps"


@pytest.fixture(scope="module")
def tls13_starttls_session():
    packets = read_packets(FIXTURES / "smtp_starttls_tls13_valid.pcap")
    sessions = build_sessions(packets)
    assert len(sessions) == 1
    return sessions[0]


@pytest.fixture(scope="module")
def tls12_starttls_session():
    packets = read_packets(FIXTURES / "smtp_starttls_tls12_valid.pcap")
    sessions = build_sessions(packets)
    assert len(sessions) == 1
    return sessions[0]


@pytest.fixture(scope="module")
def tls13_implicit_session():
    packets = read_packets(FIXTURES / "smtp_implicit_tls13_valid.pcap")
    sessions = build_sessions(packets)
    assert len(sessions) == 1
    return sessions[0]


def test_tls13_starttls_protocol_and_mode(tls13_starttls_session):
    s = tls13_starttls_session
    assert s.protocol == "smtp"
    assert s.tls_mode == "starttls"
    assert s.server_port == 2525


def test_tls13_starttls_negotiated_version(tls13_starttls_session):
    assert tls13_starttls_session.tls_info.negotiated_version == "TLS 1.3"


def test_tls13_cert_not_observable(tls13_starttls_session):
    tls_info = tls13_starttls_session.tls_info
    assert tls_info.cert_observable is False
    assert tls_info.leaf_cert is None
    assert "TLS 1.3" in tls_info.cert_not_observable_reason


def test_tls12_starttls_protocol_and_mode(tls12_starttls_session):
    s = tls12_starttls_session
    assert s.protocol == "smtp"
    assert s.tls_mode == "starttls"


def test_tls12_negotiated_version(tls12_starttls_session):
    assert tls12_starttls_session.tls_info.negotiated_version == "TLS 1.2"


def test_tls12_cert_is_observable_and_correct(tls12_starttls_session):
    tls_info = tls12_starttls_session.tls_info
    assert tls_info.cert_observable is True
    cert = tls_info.leaf_cert
    assert cert.subject_cn == "mail.lab.test"
    assert cert.issuer_cn == "SecureMailScope Lab Test CA"
    assert cert.self_signed is False
    assert cert.key_algorithm == "RSA"
    assert cert.key_size == 2048
    assert cert.signature_hash_algorithm == "sha256"
    assert cert.san_dns_names == ["mail.lab.test"]
    assert cert.is_expired is False


def test_tls13_implicit_mode(tls13_implicit_session):
    s = tls13_implicit_session
    assert s.protocol == "smtp"
    assert s.tls_mode == "implicit"
    assert s.server_port == 4465


def test_tls13_implicit_cert_not_observable(tls13_implicit_session):
    assert tls13_implicit_session.tls_info.cert_observable is False


@pytest.fixture(scope="module")
def expired_cert_session():
    packets = read_packets(FIXTURES / "S18_smtp_587_starttls_expired_cert.pcap")
    sessions = build_sessions(packets)
    assert len(sessions) == 1
    return sessions[0]


def test_expired_cert_session_protocol_and_role(expired_cert_session):
    s = expired_cert_session
    assert s.protocol == "smtp"
    assert s.tls_mode == "starttls"
    assert s.role == "submission"


def test_expired_cert_is_observed_and_flagged_expired(expired_cert_session):
    tls_info = expired_cert_session.tls_info
    assert tls_info.negotiated_version == "TLS 1.2"
    assert tls_info.cert_observable is True
    cert = tls_info.leaf_cert
    assert cert.subject_cn == "mail.lab.test"
    assert cert.is_expired is True
    assert cert.not_after.year == 2025
    assert cert.not_after.month == 9
    assert cert.not_after.day == 28


@pytest.fixture(scope="module")
def selfsigned_cert_session():
    packets = read_packets(FIXTURES / "S19_smtp_587_starttls_selfsigned_cert.pcap")
    sessions = build_sessions(packets)
    assert len(sessions) == 1
    return sessions[0]


def test_cert_expiry_uses_capture_time_not_wall_clock():
    # Regression test for a real bug: cert expiry was judged against
    # datetime.now() (when the analyzer runs) instead of the pcap's own
    # capture timestamp. This fixture's cert was valid from
    # 2026-09-28T18:45:58Z to 2026-09-28T18:47:58Z, and was captured at
    # 2026-09-28T18:46:43Z - inside that window. Wall-clock time is now
    # (and will permanently remain) past notAfter, so a wall-clock-based
    # implementation would incorrectly report this cert as expired
    # whenever the test suite runs; the capture-time-based fix must
    # always report it as not expired, regardless of when the test runs.
    packets = read_packets(FIXTURES / "S20_smtp_587_shortlived_cert.pcap")
    sessions = build_sessions(packets)
    assert len(sessions) == 1
    cert = sessions[0].tls_info.leaf_cert
    assert cert.not_after < datetime.datetime.now(datetime.timezone.utc)  # sanity check
    assert cert.is_expired is False


def test_selfsigned_cert_is_observed_and_flagged(selfsigned_cert_session):
    tls_info = selfsigned_cert_session.tls_info
    assert tls_info.cert_observable is True
    cert = tls_info.leaf_cert
    assert cert.subject_cn == "mail.lab.test"
    assert cert.self_signed is True
    assert cert.issuer_cn == cert.subject_cn
    assert cert.is_expired is False
