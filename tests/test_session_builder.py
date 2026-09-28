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
    assert s.role == "mx"


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


@pytest.fixture(scope="module")
def rsa1024_cert_session():
    packets = read_packets(FIXTURES / "S23_smtp_587_rsa1024_cert.pcap")
    sessions = build_sessions(packets)
    assert len(sessions) == 1
    return sessions[0]


def test_rsa1024_cert_key_size_observed(rsa1024_cert_session):
    cert = rsa1024_cert_session.tls_info.leaf_cert
    assert cert.key_algorithm == "RSA"
    assert cert.key_size == 1024


@pytest.fixture(scope="module")
def sha1_cert_session():
    packets = read_packets(FIXTURES / "S22_smtp_587_sha1_signed_cert.pcap")
    sessions = build_sessions(packets)
    assert len(sessions) == 1
    return sessions[0]


def test_sha1_cert_signature_hash_observed(sha1_cert_session):
    cert = sha1_cert_session.tls_info.leaf_cert
    assert cert.signature_hash_algorithm == "sha1"
    assert cert.key_size == 2048  # only the signature hash is weak here


@pytest.fixture(scope="module")
def wrong_sni_session():
    packets = read_packets(FIXTURES / "S24_smtp_587_wrong_sni.pcap")
    sessions = build_sessions(packets)
    assert len(sessions) == 1
    return sessions[0]


def test_wrong_sni_is_observed(wrong_sni_session):
    tls_info = wrong_sni_session.tls_info
    assert tls_info.sni_hostname == "notmail.lab.test"
    assert tls_info.leaf_cert.san_dns_names == ["mail.lab.test"]


@pytest.fixture(scope="module")
def no_sni_session():
    packets = read_packets(FIXTURES / "S25_smtp_587_no_sni.pcap")
    sessions = build_sessions(packets)
    assert len(sessions) == 1
    return sessions[0]


def test_no_sni_observed(no_sni_session):
    assert no_sni_session.tls_info.sni_hostname is None


@pytest.fixture(scope="module")
def tls1_0_session():
    packets = read_packets(FIXTURES / "S27_smtp_587_tls1_0.pcap")
    sessions = build_sessions(packets)
    assert len(sessions) == 1
    return sessions[0]


def test_tls1_0_negotiated_version_observed(tls1_0_session):
    # Real client forced to TLS 1.0 via `openssl s_client -tls1
    # -cipher DEFAULT@SECLEVEL=0` (local OpenSSL 3.0 refuses the
    # legacy ServerKeyExchange sigalg at its default security level).
    assert tls1_0_session.tls_info.negotiated_version == "TLS 1.0"


def test_imap_plaintext_session_protocol_and_mode():
    packets = read_packets(FIXTURES / "S28_imap_2143_plaintext_login.pcap")
    sessions = build_sessions(packets)
    assert len(sessions) == 1
    assert sessions[0].protocol == "imap"
    assert sessions[0].tls_mode == "plaintext_only"


def test_imap_starttls_session_cert_observable():
    packets = read_packets(FIXTURES / "S29_imap_2143_starttls_login.pcap")
    sessions = build_sessions(packets)
    assert len(sessions) == 1
    assert sessions[0].protocol == "imap"
    assert sessions[0].tls_mode == "starttls"
    assert sessions[0].tls_info.cert_observable is True


def test_pop3_plaintext_session_protocol_and_mode():
    packets = read_packets(FIXTURES / "S30_pop3_2110_plaintext_userpass.pcap")
    sessions = build_sessions(packets)
    assert len(sessions) == 1
    assert sessions[0].protocol == "pop3"
    assert sessions[0].tls_mode == "plaintext_only"


def test_pop3_stls_session_cert_observable():
    packets = read_packets(FIXTURES / "S31_pop3_2110_stls_userpass.pcap")
    sessions = build_sessions(packets)
    assert len(sessions) == 1
    assert sessions[0].protocol == "pop3"
    assert sessions[0].tls_mode == "starttls"
    assert sessions[0].tls_info.cert_observable is True


# --- Legacy TLS/cipher captures (Debian Jessie, OpenSSL 1.0.1t, both
# client and server, on a dedicated docker network) ---


def test_legacy_rc4_cipher_suite_observed():
    packets = read_packets(FIXTURES / "S32_legacy_rc4.pcap")
    sessions = build_sessions(packets)
    assert len(sessions) == 1
    assert sessions[0].tls_mode == "implicit"
    assert sessions[0].tls_info.cipher_suite == "0x0005"  # TLS_RSA_WITH_RC4_128_SHA


def test_legacy_3des_cipher_suite_observed():
    packets = read_packets(FIXTURES / "S33_legacy_3des.pcap")
    sessions = build_sessions(packets)
    assert len(sessions) == 1
    assert sessions[0].tls_info.cipher_suite == "0x000a"  # TLS_RSA_WITH_3DES_EDE_CBC_SHA


def test_legacy_sslv3_version_observed():
    packets = read_packets(FIXTURES / "S34_legacy_ssl3.pcap")
    sessions = build_sessions(packets)
    assert len(sessions) == 1
    assert sessions[0].tls_info.negotiated_version == "SSL 3.0"


def test_legacy_tls1_1_version_observed():
    packets = read_packets(FIXTURES / "S35_legacy_tls1_1.pcap")
    sessions = build_sessions(packets)
    assert len(sessions) == 1
    assert sessions[0].tls_info.negotiated_version == "TLS 1.1"
