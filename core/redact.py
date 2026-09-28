"""Redacts credential-looking material from any text before it is printed
or written out, per CLAUDE.md's "never store real credentials, redact auth
strings" rule.
"""

from __future__ import annotations

import re

# Matches SMTP/IMAP/POP3 AUTH LOGIN/PLAIN base64 continuation lines and the
# USER/PASS and LOGIN commands that carry credentials in plaintext.
_AUTH_CONTINUATION_RE = re.compile(r"^[A-Za-z0-9+/=]{4,}$")
_AUTH_COMMAND_RE = re.compile(
    r"^(AUTH\s+(LOGIN|PLAIN)(\s+\S+)?|USER\s+\S+|PASS\s+\S+|(\w+\s+)?LOGIN\s+\S+\s+\S+)",
    re.IGNORECASE,
)

REDACTED = "[REDACTED]"


def redact_line(line: str) -> str:
    """Redact a single protocol line if it looks like it carries a credential."""
    stripped = line.strip()
    if _AUTH_COMMAND_RE.match(stripped):
        return REDACTED
    return line


def redact_lines(lines: list[str]) -> list[str]:
    """Redact an AUTH LOGIN exchange: the command line and any bare base64
    continuation line immediately following it (username/password).
    """
    out = []
    redact_next = False
    for line in lines:
        stripped = line.strip()
        if redact_next and _AUTH_CONTINUATION_RE.match(stripped):
            out.append(REDACTED)
            continue
        redact_next = False

        if _AUTH_COMMAND_RE.match(stripped):
            out.append(REDACTED)
            if re.match(r"^AUTH\s+(LOGIN|PLAIN)\s*$", stripped, re.IGNORECASE):
                redact_next = True
            continue

        out.append(line)
    return out
