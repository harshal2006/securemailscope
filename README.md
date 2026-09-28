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
  weak key (RSA/DSA < 2048 bits), weak signature hash (MD5/SHA-1),
  hostname/SAN mismatch (`X-05`, RFC 6125-style match including a single
  leftmost `*` wildcard label). Only evaluated when a certificate was
  actually observed on the wire - never guessed for TLS 1.3 sessions,
  where the Certificate message is encrypted. Hostname matching is only
  attempted when the client actually sent SNI in its ClientHello; if not,
  the finding is `CERT_HOSTNAME_NOT_EVALUABLE` (INFO), never guessed as
  a match or mismatch.
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

## Rule coverage

Plan ID is the hackathon plan's own rule numbering, where one has been
confirmed; a blank means no plan ID applies (informational finding) or
the rule isn't implemented yet. "Real pcap" / "Synthetic" reflect actual
test coverage in `tests/`, not theoretical code-path sharing - e.g.
`TLS_VERSION_1_1` shares its matching code with `TLS_VERSION_1_0`, which
*is* tested, but has no test of its own, so it's marked untested here.

| Rule ID | Plan ID | Name | Severity | Real pcap | Synthetic |
|---|---|---|---|---|---|
| `NO_TLS_OBSERVED` | | No TLS/STARTTLS observed at all | CRITICAL | y | y |
| `TLS_VERSION_SSL3` | P-02 | SSLv3 negotiated | CRITICAL | n | n |
| `TLS_VERSION_1_0` | P-02 | TLS 1.0 negotiated | HIGH | n | y |
| `TLS_VERSION_1_1` | P-02 | TLS 1.1 negotiated | HIGH | n | n |
| `TLS_VERSION_1_2` | P-03 | TLS 1.2 negotiated | LOW | y | y |
| `TLS_VERSION_1_3` | | TLS 1.3 negotiated | INFO | y | y |
| `WEAK_CIPHER_SUITE` | C-02 | NULL/RC4/3DES/anon-DH cipher | HIGH | n | y |
| — (not implemented) | C-03 | No forward secrecy | — | n | n |
| — (not implemented) | C-05 | Weak DH parameters | — | n | n |
| `CERT_EXPIRED` | X-01 | Certificate expired | HIGH | y | y |
| `CERT_SELF_SIGNED` | X-03 | Certificate self-signed | MEDIUM | y | y |
| `CERT_WEAK_KEY` | X-06 | RSA/DSA key < 2048 bits | HIGH | y | y |
| `CERT_WEAK_SIGNATURE_HASH` | X-07 | MD5/SHA-1 signature | HIGH | y | y |
| `CERT_HOSTNAME_MISMATCH` | X-05 | SNI hostname not covered by cert's SAN | HIGH | y | y |
| `CERT_HOSTNAME_NOT_EVALUABLE` | | No SNI observed; match not evaluable | INFO | y | y |
| `CERT_NOT_OBSERVABLE` | | Cert not observable (TLS 1.3, etc.) | INFO | y | y |
| `T-01` | T-01 | Plaintext AUTH before TLS | CRITICAL | y | y |
| `T-02` | T-02 | STARTTLS advertised but unused | HIGH (submission) / INFO (mx) | y | y |
| `T-03` | T-03 | STARTTLS not offered at all | HIGH (submission) / LOW (mx) | n | y |

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
- Expired and self-signed certificates: captured real STARTTLS sessions
  against the lab server temporarily configured with
  `lab/certs/expired.crt` and `lab/certs/selfsigned.crt`. Independently
  confirmed with `openssl s_client` (`Verify return code: 10`/`18`) and
  `tshark` (decoded the wire cert's ASN.1 `notAfter`) before running the
  analyzer, which correctly fired `CERT_EXPIRED` (HIGH, score 65) and
  `CERT_SELF_SIGNED` (MEDIUM, score 80) respectively.
- Certificate expiry uses the pcap's own capture timestamp, not the
  analyzer's wall-clock time: captured a real session against a cert
  valid for ~2 minutes, then waited for wall-clock time to pass its
  `notAfter` before running the analyzer. It correctly reported
  `expired=False` (using capture time), while explicitly re-checking the
  same cert against `datetime.now()` confirms a wall-clock-based
  implementation would have wrongly said `True`.
- `T-02`'s role-aware downgrade (HIGH on submission, INFO on mx):
  captured the same plaintext-AUTH-without-STARTTLS scenario on both
  port 587 (submission, fires HIGH) and port 25 (mx, fires INFO) and
  confirmed both with the analyzer.
- `CERT_HOSTNAME_MISMATCH` (X-05): connected with `openssl s_client
  -servername notmail.lab.test` against a cert whose SAN is only
  `mail.lab.test`. Independently confirmed the mismatch with `openssl
  s_client -verify_hostname` (`Verify return code: 62, hostname
  mismatch`) and with `tshark` (SNI extension shows `notmail.lab.test`)
  before running the analyzer, which fired `CERT_HOSTNAME_MISMATCH`
  (HIGH). A second capture with `-noservername` (confirmed via `tshark`
  to carry no SNI extension at all) correctly produces
  `CERT_HOSTNAME_NOT_EVALUABLE` (INFO) instead of guessing a
  match/mismatch.

- Weak-key (RSA-1024) and weak-signature-hash (SHA-1) certificate
  findings: `cryptography` refuses to sign with SHA-1 at the API level,
  so the SHA-1 cert was built with the `openssl` CLI directly (chained
  to the lab CA, correct SAN) instead of `lab/gen_certs.py`. `openssl
  s_client` independently confirmed `Verify return code: 68 (CA
  signature digest algorithm too weak)` and `Server public key is 1024
  bit` respectively, before the analyzer correctly fired
  `CERT_WEAK_SIGNATURE_HASH` and `CERT_WEAK_KEY`.

**Not yet verified against real captures** (implemented, but only
exercised with synthetic `Session`/`TLSInfo`/`CertInfo`/`StarttlsAnalysis`
objects in unit tests, not real pcaps):
- Weak cipher suite findings (RC4/3DES/NULL/anonymous-DH) - the lab
  server's OpenSSL only negotiates modern ciphers by default, and no
  legacy-cipher lab config has been built.
- `SSL 3.0` and `TLS 1.1` findings - no test at all, real or synthetic,
  exercises these two specifically (only TLS 1.0/1.2/1.3 have dedicated
  tests), even though the matching code path is shared.
- `T-03` ("STARTTLS not offered") - the lab server always advertises
  STARTTLS; producing a real negative would need a second lab
  configuration with STARTTLS disabled.
- IMAP/POP3 STARTTLS timeline parsing (capability detection, STLS) -
  implemented with the same logic as SMTP, but no real IMAP/POP3
  plaintext-auth pcap has been captured, only SMTP.

**Not built:** report rendering (HTML/PDF), a web UI or dashboard, an
API, and any ML-based scoring or anomaly detection. Out of scope for this
MVP by design.
