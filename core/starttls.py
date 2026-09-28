"""Per-session STARTTLS / plaintext-auth timeline.

Builds an ordered, credential-redacted timeline of the plaintext phase of
an SMTP/IMAP/POP3 session directly from raw TCP payload bytes. This is
protocol-agnostic by design (regex over decoded lines, not tshark's
per-protocol dissectors), so it works regardless of decode-as port hints
- the same reason core/session_builder.py detects implicit-vs-STARTTLS
from packet order rather than protocol dissection.

Once a session's TLS handshake begins, payload bytes are ciphertext and
are not decoded further; only whether AUTH-looking commands appeared
*before* that point is recorded. Never logs or returns credential
material - see CLAUDE.md.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from core.redact import REDACTED, is_auth_continuation_line, redact_line

STARTTLS_COMMAND_WORDS = {"STARTTLS", "STLS"}
AUTH_COMMAND_WORDS = {"AUTH", "USER", "PASS", "LOGIN"}


@dataclass
class TimelineEvent:
    frame_number: int
    direction: str  # "client" | "server"
    kind: str  # "banner" | "capability" | "command" | "response" | "tls_start"
    text: str  # already redacted; safe to print/store


@dataclass
class StarttlsAnalysis:
    protocol: str
    timeline: list[TimelineEvent] = field(default_factory=list)
    capability_advertised_starttls: bool | None = None  # None = not observed/not probed
    starttls_issued: bool = False
    starttls_success: bool = False
    tls_followed: bool = False
    auth_before_tls: bool = False
    auth_after_tls: bool | None = None  # None = can't be observed (encrypted)


def _decode_payload(hex_payload: str) -> str:
    if not hex_payload:
        return ""
    try:
        raw = bytes.fromhex(hex_payload)
    except ValueError:
        return ""
    return raw.decode("latin-1", errors="replace")


def _split_lines(text: str) -> list[str]:
    return [line for line in text.replace("\r\n", "\n").split("\n") if line]


def first_word_is(line: str, *words: str) -> bool:
    stripped = line.strip()
    first = stripped.split(None, 1)[0].upper() if stripped else ""
    return first in words


def _client_command_candidates(stripped: str) -> list[str]:
    """Words to check against command-keyword sets.

    IMAP commands are tagged ("a1 LOGIN user pass"), unlike SMTP/POP3
    ("LOGIN"/"USER"/"PASS" as the first word). Checking both the first
    and second word catches both without needing per-protocol parsing -
    found as a real bug: a real plaintext IMAP LOGIN capture was not
    being classified as auth_command because only the tag ("a1") was
    checked, silently missing a real T-01 (plaintext auth before TLS).
    """
    words = stripped.split()
    return [w.upper() for w in words[:2]]


def _is_success_reply(stripped: str) -> bool:
    """SMTP/POP3: untagged "220 ..." / "+OK ..." / "* OK ...". IMAP:
    tagged "<tag> OK ..." where <tag> is client-chosen (often "a1",
    ".", "A001", ...) - found as a real bug: an IMAP STARTTLS success
    reply ("a1 OK Begin TLS negotiation now.") was not recognized
    because only the untagged forms were checked, so starttls_success
    stayed False even when STARTTLS genuinely succeeded.
    """
    if stripped.startswith(("220", "+OK", "* OK")):
        return True
    words = stripped.split(None, 2)
    return len(words) >= 2 and words[1].upper() == "OK"


def _classify_line(line: str, direction: str) -> str:
    stripped = line.strip()
    candidates = _client_command_candidates(stripped)

    if direction == "client":
        if any(w in STARTTLS_COMMAND_WORDS for w in candidates):
            return "starttls_command"
        if any(w in AUTH_COMMAND_WORDS for w in candidates):
            return "auth_command"
        return "command"

    # server -> client
    if "STARTTLS" in stripped.upper() or "STLS" in stripped.upper():
        return "capability_starttls"
    if _is_success_reply(stripped):
        return "banner_or_success"
    return "response"


def build_timeline(
    pkts: list[dict[str, str]], server_port: int, protocol: str
) -> StarttlsAnalysis:
    analysis = StarttlsAnalysis(protocol=protocol)
    tls_started = False
    awaiting_starttls_reply = False
    awaiting_auth_continuation = False
    # Tracks whether we're inside a server capability listing we can fully
    # see the end of, so that "STARTTLS absent" can become a confirmed
    # False rather than staying an unobserved None. SMTP: the multi-line
    # 250-.../250 EHLO reply. POP3: the CAPA response, ending in a lone ".".
    in_smtp_capability_block = False
    in_pop3_capability_block = False

    for pkt in pkts:
        frame_number = int(pkt["frame.number"])

        if tls_started:
            # Once the handshake has begun, every subsequent packet in
            # this stream is ciphertext by definition - the STARTTLS
            # upgrade wraps the rest of the session in TLS. Do not rely
            # on tls.record.content_type here: tshark does not reliably
            # populate it for TLS 1.3 application-data records.
            continue

        if pkt.get("tls.record.content_type") or pkt.get("tls.handshake.type"):
            tls_started = True
            analysis.tls_followed = True
            analysis.timeline.append(
                TimelineEvent(frame_number, "-", "tls_start", "[TLS handshake begins]")
            )
            continue

        payload = _decode_payload(pkt.get("tcp.payload", ""))
        if not payload:
            continue

        direction = "server" if pkt.get("tcp.srcport") == str(server_port) else "client"

        for line in _split_lines(payload):
            stripped = line.strip()

            if (
                direction == "client"
                and awaiting_auth_continuation
                and is_auth_continuation_line(stripped)
            ):
                # Username/password sent after a bare AUTH LOGIN/PLAIN.
                if not tls_started:
                    analysis.auth_before_tls = True
                analysis.timeline.append(
                    TimelineEvent(frame_number, direction, "command", REDACTED)
                )
                continue
            if direction == "client":
                awaiting_auth_continuation = False

            kind = _classify_line(line, direction)
            redacted_text = redact_line(stripped)
            upper = stripped.upper()

            if direction == "client":
                if first_word_is(stripped, "EHLO", "HELO"):
                    in_smtp_capability_block = True
                elif first_word_is(stripped, "CAPA"):
                    in_pop3_capability_block = True

            if kind == "starttls_command":
                analysis.starttls_issued = True
                awaiting_starttls_reply = True
                analysis.timeline.append(
                    TimelineEvent(frame_number, direction, "command", redacted_text)
                )
            elif kind == "auth_command":
                if not tls_started:
                    analysis.auth_before_tls = True
                if stripped.upper() in ("AUTH LOGIN", "AUTH PLAIN"):
                    awaiting_auth_continuation = True
                analysis.timeline.append(
                    TimelineEvent(frame_number, direction, "command", redacted_text)
                )
            elif kind == "capability_starttls":
                analysis.capability_advertised_starttls = True
                analysis.timeline.append(
                    TimelineEvent(frame_number, direction, "capability", redacted_text)
                )
            elif kind == "banner_or_success":
                # _classify_line already confirmed this line is a
                # success-shaped reply (_is_success_reply); if we were
                # waiting on the STARTTLS response, this is it.
                if awaiting_starttls_reply:
                    analysis.starttls_success = True
                    awaiting_starttls_reply = False
                    analysis.timeline.append(
                        TimelineEvent(frame_number, direction, "response", redacted_text)
                    )
                else:
                    analysis.timeline.append(
                        TimelineEvent(frame_number, direction, "banner", redacted_text)
                    )
            else:
                analysis.timeline.append(
                    TimelineEvent(frame_number, direction, kind, redacted_text)
                )

            if direction == "server":
                if in_smtp_capability_block and re.match(r"^\d{3}([ ]|$)", stripped):
                    # Terminal line of a multi-line EHLO reply is "NNN "
                    # (space, not dash) or a bare 3-digit single-line reply.
                    in_smtp_capability_block = False
                    if analysis.capability_advertised_starttls is None:
                        analysis.capability_advertised_starttls = False
                elif in_pop3_capability_block and stripped == ".":
                    in_pop3_capability_block = False
                    if analysis.capability_advertised_starttls is None:
                        analysis.capability_advertised_starttls = False
                elif "CAPABILITY" in upper and kind != "capability_starttls":
                    # IMAP: capability listing is a single line (greeting
                    # banner, or an untagged response to CAPABILITY).
                    if analysis.capability_advertised_starttls is None:
                        analysis.capability_advertised_starttls = False

    return analysis
