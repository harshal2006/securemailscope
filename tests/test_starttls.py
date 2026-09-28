from pathlib import Path

import pytest

from core.pcap_reader import read_packets
from core.session_builder import group_packets_by_stream
from core.starttls import build_timeline

FIXTURES = Path(__file__).parent / "fixtures" / "pcaps"


def _timeline_for(pcap_name: str, server_port: int, protocol: str = "smtp"):
    packets = read_packets(FIXTURES / pcap_name)
    by_stream = group_packets_by_stream(packets)
    stream_id, pkts = next(iter(by_stream.items()))
    return build_timeline(pkts, server_port=server_port, protocol=protocol)


@pytest.fixture(scope="module")
def s17_plaintext_auth():
    # 2587 is the lab's host-published port for container port 587.
    return _timeline_for("S17_smtp_587_plaintext_auth.pcap", 2587)


@pytest.fixture(scope="module")
def s01b_starttls_auth():
    return _timeline_for("S01b_smtp_587_starttls_auth.pcap", 2587)


# --- S17: AUTH LOGIN without STARTTLS ---


def test_s17_capability_advertised(s17_plaintext_auth):
    assert s17_plaintext_auth.capability_advertised_starttls is True


def test_s17_starttls_never_issued(s17_plaintext_auth):
    assert s17_plaintext_auth.starttls_issued is False
    assert s17_plaintext_auth.tls_followed is False


def test_s17_auth_before_tls(s17_plaintext_auth):
    assert s17_plaintext_auth.auth_before_tls is True


def test_s17_timeline_never_contains_raw_credentials(s17_plaintext_auth):
    # "labuser" legitimately appears in envelope addresses (MAIL FROM,
    # RCPT TO, message headers) - that's not a credential leak. The
    # actual AUTH LOGIN base64 blobs and the bare password must never
    # appear anywhere in the timeline.
    all_text = " ".join(ev.text for ev in s17_plaintext_auth.timeline)
    assert "bGFidXNlcg" not in all_text  # base64("labuser") as an AUTH blob
    assert "bGFicGFzcw" not in all_text  # base64("labpass")
    assert "labpass" not in all_text


def test_s17_auth_lines_are_redacted(s17_plaintext_auth):
    redacted_count = sum(1 for ev in s17_plaintext_auth.timeline if ev.text == "[REDACTED]")
    assert redacted_count == 3  # AUTH LOGIN command + username line + password line


# --- S01b: STARTTLS then AUTH inside TLS ---


def test_s01b_capability_advertised(s01b_starttls_auth):
    assert s01b_starttls_auth.capability_advertised_starttls is True


def test_s01b_starttls_issued_and_succeeded(s01b_starttls_auth):
    assert s01b_starttls_auth.starttls_issued is True
    assert s01b_starttls_auth.starttls_success is True
    assert s01b_starttls_auth.tls_followed is True


def test_s01b_auth_not_before_tls(s01b_starttls_auth):
    assert s01b_starttls_auth.auth_before_tls is False


def test_s01b_timeline_stops_at_tls_start(s01b_starttls_auth):
    kinds = [ev.kind for ev in s01b_starttls_auth.timeline]
    assert kinds[-1] == "tls_start"
    assert "auth_command" not in kinds  # AUTH happens inside TLS, never observed


# --- S26: STARTTLS not offered at all (second lab service, port 2588) ---


def test_s26_capability_confirmed_absent():
    timeline = _timeline_for("S26_smtp_2588_starttls_disabled.pcap", 2588)
    # False (confirmed absent from a fully-observed capability listing),
    # not None (unobserved) - the EHLO reply was seen in full and never
    # mentioned STARTTLS.
    assert timeline.capability_advertised_starttls is False
    assert timeline.starttls_issued is False
    assert timeline.tls_followed is False


# --- S28: IMAP plaintext LOGIN, no STARTTLS ---
#
# Regression coverage for a real bug found via this capture: IMAP
# commands are tagged ("a1 LOGIN user pass"), so checking only the first
# word missed the LOGIN command entirely - auth_before_tls stayed False
# and T-01 never fired despite real plaintext credentials on the wire.
# Fixed in core/starttls.py's _client_command_candidates.


@pytest.fixture(scope="module")
def s28_imap_plaintext_login():
    return _timeline_for("S28_imap_2143_plaintext_login.pcap", 2143, protocol="imap")


def test_s28_tagged_login_detected_as_auth(s28_imap_plaintext_login):
    assert s28_imap_plaintext_login.auth_before_tls is True


def test_s28_tagged_login_credentials_redacted(s28_imap_plaintext_login):
    all_text = " ".join(ev.text for ev in s28_imap_plaintext_login.timeline)
    assert "labpass" not in all_text
    assert "[REDACTED]" in all_text


def test_s28_capability_advertised(s28_imap_plaintext_login):
    assert s28_imap_plaintext_login.capability_advertised_starttls is True


# --- S29: IMAP STARTTLS then LOGIN inside TLS ---
#
# Regression coverage for a second bug found via this capture: IMAP's
# tagged STARTTLS success reply ("a1 OK Begin TLS negotiation now.")
# wasn't recognized as a success reply (only untagged "220"/"+OK" were),
# so starttls_success stayed False even though STARTTLS genuinely
# succeeded. Fixed in core/starttls.py's _is_success_reply.


@pytest.fixture(scope="module")
def s29_imap_starttls_login():
    return _timeline_for("S29_imap_2143_starttls_login.pcap", 2143, protocol="imap")


def test_s29_tagged_starttls_command_detected(s29_imap_starttls_login):
    assert s29_imap_starttls_login.starttls_issued is True


def test_s29_tagged_starttls_success_detected(s29_imap_starttls_login):
    assert s29_imap_starttls_login.starttls_success is True
    assert s29_imap_starttls_login.tls_followed is True


def test_s29_auth_not_before_tls(s29_imap_starttls_login):
    assert s29_imap_starttls_login.auth_before_tls is False


# --- S30: POP3 plaintext USER/PASS, no STLS ---


@pytest.fixture(scope="module")
def s30_pop3_plaintext_userpass():
    return _timeline_for("S30_pop3_2110_plaintext_userpass.pcap", 2110, protocol="pop3")


def test_s30_auth_before_tls(s30_pop3_plaintext_userpass):
    assert s30_pop3_plaintext_userpass.auth_before_tls is True


def test_s30_credentials_redacted(s30_pop3_plaintext_userpass):
    all_text = " ".join(ev.text for ev in s30_pop3_plaintext_userpass.timeline)
    assert "labpass" not in all_text


def test_s30_stls_capability_observed_via_capa(s30_pop3_plaintext_userpass):
    # This capture issues CAPA before USER/PASS, so we actually observe
    # the capability listing (unlike S31, which skips straight to STLS).
    assert s30_pop3_plaintext_userpass.capability_advertised_starttls is True


# --- S31: POP3 STLS then USER/PASS inside TLS ---


@pytest.fixture(scope="module")
def s31_pop3_stls_userpass():
    return _timeline_for("S31_pop3_2110_stls_userpass.pcap", 2110, protocol="pop3")


def test_s31_stls_issued_and_succeeded(s31_pop3_stls_userpass):
    assert s31_pop3_stls_userpass.starttls_issued is True
    assert s31_pop3_stls_userpass.starttls_success is True


def test_s31_auth_not_before_tls(s31_pop3_stls_userpass):
    assert s31_pop3_stls_userpass.auth_before_tls is False


def test_s31_capability_unknown_not_guessed(s31_pop3_stls_userpass):
    # No CAPA was sent in this capture (straight to STLS), so we never
    # observed the capability listing - must stay None, not be guessed
    # as True or False.
    assert s31_pop3_stls_userpass.capability_advertised_starttls is None
