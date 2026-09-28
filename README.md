# SecureMailScope

A passive, offline PCAP analyzer that assesses the cryptographic security
posture of SMTP/IMAP/POP3 traffic (STARTTLS/STLS and implicit TLS). It
parses sessions, TLS handshakes, and X.509 certificates, applies rules, and
produces a 0-100 posture score with prioritized findings.

Built for **Smart India Hackathon 2026, Problem Statement 26159 (NTRO)**.
This is an MVP: no Streamlit, no ML, no API, no dashboard.

See [CLAUDE.md](CLAUDE.md) for the hard rules this project is built under
(passive-only, lab-only traffic, no real credentials, redaction
requirements, TLS 1.3 certificate observability).

## Install

Requires Python 3.11+. On macOS:

```
brew install --cask wireshark   # provides tshark
brew install --cask docker      # for the lab mail server
brew install swaks              # for generating test SMTP traffic
```

Then, from `securemailscope/`:

```
python3 -m venv .venv
source .venv/bin/activate
pip install cryptography pyyaml pytest
```

(There is no `pip install -e .` packaging step yet - `pyproject.toml` only
declares dependencies, not a build backend.)

## Running the lab

The lab is a Docker-based Postfix + Dovecot mail server, published only to
`127.0.0.1`, for generating real traffic to analyze. It never connects to
a real mail server - see CLAUDE.md.

```
cd lab/docker
docker compose up -d --build
```

Generate lab certificates (valid, expired, self-signed) first if you
haven't:

```
python lab/gen_certs.py
```

Published ports (host -> container):

| Port | Protocol | Mode | Role |
|---|---|---|---|
| 2525 | SMTP | STARTTLS | mx (server-to-server) |
| 2587 | SMTP | STARTTLS | submission (client-facing) |
| 4465 | SMTP | implicit TLS | submission |
| 2143 | IMAP | STARTTLS | submission |
| 2993 | IMAP | implicit TLS | submission |
| 2110 | POP3 | STLS | submission |
| 2995 | POP3 | implicit TLS | submission |

Generate traffic with `swaks` (SMTP) or `openssl s_client` (any protocol),
capture with `tcpdump -i lo0 -w <file>.pcap 'tcp port <port>'`. See
`data/pcaps/CAPTURES.md` for exact examples.

Tear down when done: `docker compose down` (from `lab/docker/`).

## Running the analyzer

```
python -m core.analyze <path-to-pcap>
```

Prints, per recognized SMTP/IMAP/POP3 session: protocol/TLS mode/role,
negotiated TLS version and cipher suite, certificate details (or why the
certificate isn't observable), the STARTTLS/plaintext-auth timeline, rule
findings, and a session score, followed by the overall posture score.

Machine-readable output:

```
python -m core.analyze <path-to-pcap> --json
```

Emits a single JSON object: `{pcap, overall_score, sessions: [...]}`, where
each session includes its TLS/cert info, its full STARTTLS timeline (with
frame numbers), findings, and score. All credential-bearing text is
redacted before being placed in this output - see CLAUDE.md.

## What the rules check

- **TLS version** (`rules/tls_version_rules.yaml`): SSLv3/TLS 1.0/TLS 1.1
  flagged CRITICAL/HIGH/HIGH; TLS 1.2 LOW; TLS 1.3 INFO.
- **Weak cipher suites** (`rules/weak_ciphers.yaml`): NULL, RC4, 3DES,
  anonymous-DH.
- **Certificate issues** (`rules/cert_rules.yaml`): expired, self-signed,
  weak key (RSA/DSA < 2048 bits), weak signature hash (MD5/SHA-1). Only
  evaluated when a certificate was actually observed on the wire - never
  guessed for TLS 1.3 sessions, where the Certificate message is
  encrypted.
- **STARTTLS / plaintext auth** (`rules/starttls_rules.yaml`):
  - `T-01` - plaintext AUTH/USER/PASS observed before TLS. Always
    CRITICAL.
  - `T-02` - STARTTLS advertised but the client never upgraded. HIGH on a
    client-facing (submission) port, INFO on a server-to-server (mx, port
    25) port, where opportunistic/unused TLS is normal.
  - `T-03` - STARTTLS not offered by the server at all (only asserted
    when a full capability listing was actually observed and STARTTLS was
    absent from it - never guessed). HIGH on submission, LOW on mx.

A session's score is 100 minus the sum of its findings' score impact,
floored at 0. The overall posture score for a capture is the minimum
across its sessions.

## Verified vs not yet verified

This reflects what has actually been run and checked, not what the code
is theoretically capable of.

**Verified against real captures:**
- TLS 1.3 and TLS 1.2 STARTTLS SMTP sessions, and TLS 1.3 implicit-TLS
  SMTP: correct protocol/mode detection, correct TLS version, correct
  certificate extraction when observable (TLS 1.2), correct
  "not observable" reporting for TLS 1.3.
- Plaintext AUTH LOGIN without STARTTLS on port 587 (`T-01`, `T-02`
  firing) vs. STARTTLS-then-AUTH on the same port (neither firing).
  Confirmed independently with `tshark`/`strings` that credentials never
  appear in cleartext in the STARTTLS case, and that they do (as
  expected, dummy creds only) in the plaintext case.
- Credential redaction: confirmed via `grep`/`strings` on both text and
  `--json` output that AUTH LOGIN/PLAIN base64 blobs and raw passwords
  never appear, while non-secret envelope data (e.g. `MAIL FROM`
  addresses) is left intact.

**Not yet verified against real captures** (implemented, but only
exercised with synthetic `Session`/`TLSInfo`/`CertInfo`/`StarttlsAnalysis`
objects in unit tests, not real pcaps):
- Expired, self-signed, weak-key (RSA-1024), and weak-signature-hash
  (SHA-1) certificate findings.
- Weak cipher suite findings (RC4/3DES/NULL/anonymous-DH) - the lab
  server's OpenSSL only negotiates modern ciphers by default, and no
  legacy-cipher lab config has been built.
- `T-03` ("STARTTLS not offered") - the lab server always advertises
  STARTTLS; producing a real negative would need a second lab
  configuration with STARTTLS disabled.
- IMAP/POP3 STARTTLS timeline parsing (capability detection, STLS) -
  implemented with the same logic as SMTP, but no real IMAP/POP3
  plaintext-auth pcap has been captured, only SMTP.

**Not built:** report rendering (HTML/PDF), a web UI or dashboard, an
API, and any ML-based scoring or anomaly detection. Out of scope for this
MVP by design.
