# SecureMailScope

## Project goal

A PASSIVE, offline PCAP analyzer that assesses the cryptographic security
posture of SMTP/IMAP/POP3 traffic (STARTTLS/STLS and implicit TLS). It parses
sessions, TLS handshakes, and X.509 certificates, applies rules, and produces
a 0-100 posture score with prioritized findings.

Built for Smart India Hackathon 2026, Problem Statement 26159 (NTRO).
Idea submission deadline: 30 Sep 2026. MVP first — no Streamlit, ML, or API
in the initial build.

## Hard rules

- **Passive only.** This tool never connects to, probes, or sends traffic to
  any real mail server. It only reads pcap/pcapng files that already exist.
- **Lab traffic only**, captured on an isolated network under our control.
  Never point this tool at production or third-party mail infrastructure.
- **Never store message payloads or real credentials.** Lab captures use
  dummy logins only (e.g. `user`/`pass`). Never use real usernames or
  passwords, even in a "throwaway" test.
- **Redact auth strings in any output.** AUTH LOGIN/PLAIN base64 blobs and
  any credential-looking material must be masked before being written to
  logs, reports, or terminal output.

## Stack

- Python 3.11+
- `tshark` for packet/session decoding
- `cryptography` library for X.509 certificate parsing and lab cert generation
- `pyyaml` for rule definitions
- `pytest` for tests

## Working rules

- Small, focused commits per step. Don't bundle unrelated work.
- Every module gets pytest tests before being considered done.
- Never claim something works without actually running it and showing the
  output. No "should work" — run it, paste the result.
- If a legacy-TLS (or any other) lab case cannot actually be produced, say
  so explicitly. Do not fake, mock, or hand-wave a result to make a check
  appear to pass.

## TLS 1.3 note

Under TLS 1.3, the server Certificate message is encrypted (sent after the
handshake keys are derived), so a passive observer without the private key
cannot see the server's certificate. Any certificate-related check
(validity, key size, hash algorithm, SAN, self-signed, etc.) for a TLS 1.3
session must be reported as **"not observable"** — never inferred, guessed,
or defaulted to pass/fail.
