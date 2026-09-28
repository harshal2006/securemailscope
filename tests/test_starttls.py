from pathlib import Path

import pytest

from core.pcap_reader import read_packets
from core.session_builder import group_packets_by_stream
from core.starttls import build_timeline

FIXTURES = Path(__file__).parent / "fixtures" / "pcaps"


def _timeline_for(pcap_name: str, server_port: int):
    packets = read_packets(FIXTURES / pcap_name)
    by_stream = group_packets_by_stream(packets)
    stream_id, pkts = next(iter(by_stream.items()))
    return build_timeline(pkts, server_port=server_port, protocol="smtp")


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
