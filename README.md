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
pip install cryptography pyyaml pytest jinja2 jsonschema
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
| 2588 | SMTP | STARTTLS disabled entirely (`smtpd_tls_security_level=none`) | submission - for `T-03` testing |
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

## Generating a report

`core/report.py` renders the same analysis into a richer, structured report
(executive summary, endpoint inventory, findings with evidence, certificate
inventory, recommendations, and an appendix of limitations/rule catalogue)
as JSON (schema-validated against `REPORT_JSON_SCHEMA`) or HTML:

```
python -m core.report <path-to-pcap>                # JSON to stdout
python -m core.report <path-to-pcap> --json out.json
python -m core.report <path-to-pcap> --html out.html
```

Recommendations (`rules/recommendations.yaml`) are only included for rule
IDs that actually appear as findings, and only for rules we implemented -
never the full plan's imagined catalogue. Each has a short fix (with
Postfix/Dovecot config snippets where relevant) and a verification command.
All credential-bearing text is redacted the same way as `core/analyze.py`.

## Running the API

`api/main.py` is a FastAPI wrapper around the same analyzer/report
pipeline - every endpoint reads results computed by one real call into
`core/report.py` (never reimplemented), cached in a SQLite job store
(`api/db.py`) so results are consistent for the life of a job.

```
pip install fastapi "uvicorn[standard]" sqlalchemy python-multipart httpx
uvicorn api.main:app --reload
```

Then, e.g.:

```
curl -F file=@tests/fixtures/pcaps/S17_smtp_587_plaintext_auth.pcap \
     http://127.0.0.1:8000/api/v1/analyze
# {"job_id": "..."}

curl http://127.0.0.1:8000/api/v1/jobs/<job_id>
curl http://127.0.0.1:8000/api/v1/jobs/<job_id>/summary
curl http://127.0.0.1:8000/api/v1/jobs/<job_id>/sessions
curl http://127.0.0.1:8000/api/v1/jobs/<job_id>/sessions/0
curl http://127.0.0.1:8000/api/v1/jobs/<job_id>/findings
curl http://127.0.0.1:8000/api/v1/jobs/<job_id>/report?format=html
```

Interactive API docs: `http://127.0.0.1:8000/docs` (FastAPI's built-in
Swagger UI).

The upload is analyzed by a `BackgroundTasks` job (queued → running →
done/failed), so `POST /analyze` returns immediately regardless of pcap
size - confirmed with a real running server (not just Starlette's
`TestClient`, whose background-task execution doesn't actually prove
non-blocking behavior) in `tests/test_api_live_server.py`.

## Running the dashboard

`dashboard/app.py` is a Streamlit UI that talks to the API over plain
HTTP only - it never imports `core.*` or runs analysis itself, so it
also serves as a standalone proof that the API works on its own.

```
pip install streamlit plotly requests
uvicorn api.main:app          # in one terminal
streamlit run dashboard/app.py  # in another
```

On first launch it auto-loads a real fixture (S17, the worst-case
plaintext-AUTH capture) through the real API, so it never opens to an
empty state - "demo mode". The sidebar lets you switch to another
bundled fixture or upload your own pcap. Pages: **Overview** (posture
gauge, KPI tiles, severity donut, top-3 fix-first), **Sessions**
(filterable table + drill-down using the dedicated `/sessions`
endpoint), **Certificates** (inventory + expiry), **Findings**
(prioritized queue with recommendations pulled from the API's
`/report` response).

Verified by actually running both processes, uploading S17 through the
UI, and reviewing screenshots of the Overview and Findings pages: the
posture score (0/100), grade (F), findings-by-severity donut
(CRITICAL 2 / HIGH 1), and the findings queue (T-01, NO_TLS_OBSERVED,
T-02, in that order) all matched `core.analyze`'s output for the same
file exactly. Also covered by `tests/test_dashboard.py` using
Streamlit's own `AppTest` framework against a real running API (not
mocked) - more reliable for automated/CI verification than a
screenshot, which was done as a one-time manual check alongside it.

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
test coverage in `tests/`, not theoretical code-path sharing.

| Rule ID | Plan ID | Name | Severity | Real pcap | Synthetic |
|---|---|---|---|---|---|
| `NO_TLS_OBSERVED` | | No TLS/STARTTLS observed at all | CRITICAL | y | y |
| `TLS_VERSION_SSL3` | P-02 | SSLv3 negotiated | CRITICAL | y | n |
| `TLS_VERSION_1_0` | P-02 | TLS 1.0 negotiated | HIGH | y | y |
| `TLS_VERSION_1_1` | P-02 | TLS 1.1 negotiated | HIGH | y | n |
| `TLS_VERSION_1_2` | P-03 | TLS 1.2 negotiated | LOW | y | y |
| `TLS_VERSION_1_3` | | TLS 1.3 negotiated | INFO | y | y |
| `WEAK_CIPHER_SUITE` | C-02 | NULL/RC4/3DES/anon-DH cipher | HIGH | y | y |
| — (not implemented) | C-03 | Weak DH parameters (<=1024 bits) | — | n | n |
| `NO_FORWARD_SECRECY` | C-05 | Static RSA/DH key exchange (no forward secrecy) | MEDIUM | y | y |
| `FORWARD_SECRECY_NOT_EVALUABLE` | | Cipher suite not in our kex classification table | INFO | n | y |
| `CERT_EXPIRED` | X-01 | Certificate expired | HIGH | y | y |
| `CERT_SELF_SIGNED` | X-03 | Certificate self-signed | MEDIUM | y | y |
| `CERT_WEAK_KEY` | X-06 | RSA/DSA key < 2048 bits | HIGH | y | y |
| `CERT_WEAK_SIGNATURE_HASH` | X-07 | MD5/SHA-1 signature | HIGH | y | y |
| `CERT_HOSTNAME_MISMATCH` | X-05 | SNI hostname not covered by cert's SAN | HIGH | y | y |
| `CERT_HOSTNAME_NOT_EVALUABLE` | | No SNI observed; match not evaluable | INFO | y | y |
| `CERT_NOT_OBSERVABLE` | | Cert not observable (TLS 1.3, etc.) | INFO | y | y |
| `T-01` | T-01 | Plaintext AUTH before TLS | CRITICAL | y | y |
| `T-02` | T-02 | STARTTLS advertised but unused | HIGH (submission) / INFO (mx) | y | y |
| `T-03` | T-03 | STARTTLS not offered at all | HIGH (submission) / LOW (mx) | y | y |

`TLS_VERSION_SSL3`, `TLS_VERSION_1_1`, `WEAK_CIPHER_SUITE`, and
`NO_FORWARD_SECRECY` are now real-verified against a purpose-built
legacy TLS endpoint (Debian Jessie, OpenSSL 1.0.1t, both client and
server) - see below and `data/pcaps/CAPTURES.md` (S32-S35). The
earlier attempt against our *mail-server* lab genuinely failed because
the mail server itself (modern OpenSSL) doesn't support these
configs; controlling both ends of a dedicated TLS test endpoint removed
that constraint.

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

- `T-03` ("STARTTLS not offered"): added a second lab Postfix service on
  port 2588 with `smtpd_tls_security_level=none`. Independently
  confirmed with a raw `EHLO` probe (no `STARTTLS` line in the reply,
  and issuing `STARTTLS` anyway gets `502 5.5.1 Error: command not
  implemented`) and `tshark` (no TLS handshake anywhere in the capture)
  before running the analyzer, which correctly reported
  `capability_advertised_starttls=False` (confirmed absent, not
  unobserved) and fired `T-03` HIGH.

- `TLS_VERSION_1_0`: local macOS OpenSSL 3.0.18 refuses TLS 1.0's legacy
  ServerKeyExchange signature algorithm at its default security level
  (`legacy sigalg disallowed or unsupported`), but `-cipher
  DEFAULT@SECLEVEL=0` unlocks a genuine TLS 1.0 handshake (confirmed:
  `Protocol: TLSv1`, `Verify return code: 0`, real SMTP responses flow
  afterward). Captured and confirmed with `tshark`
  (`tls.handshake.version = 0x0301` on both ClientHello and ServerHello)
  before running the analyzer, which fired `TLS_VERSION_1_0` HIGH.

- `TLS_VERSION_SSL3`, `TLS_VERSION_1_1`, `WEAK_CIPHER_SUITE` (RC4,
  3DES), and `NO_FORWARD_SECRECY`: a dedicated legacy TLS test endpoint
  (two Debian Jessie/OpenSSL 1.0.1t containers, one as `openssl
  s_server`, one as client, on a private docker network) forced each
  config one at a time. `openssl s_client` and `tshark` independently
  confirmed the negotiated protocol/cipher on the wire before running
  the analyzer each time (e.g. `Cipher is RC4-SHA` /
  `tls.handshake.ciphersuite = 0x0005`). `NO_FORWARD_SECRECY` got real
  coverage as a side effect: RC4-SHA is static-RSA key exchange.

**Previously found infeasible against the mail-server lab, now closed
with a dedicated legacy TLS endpoint:** weak cipher suites
(RC4/3DES) and SSLv3/TLS 1.1. The earlier attempt used a legacy
*client* (Debian Jessie, OpenSSL 1.0.1t) against our *mail-server* lab
(Debian bookworm, OpenSSL 3.0) and genuinely failed
(`sslv3 alert handshake failure`) - the server itself didn't support
these configs, and weak cipher/protocol negotiation needs both sides to
agree. The fix: a purpose-built legacy TLS test endpoint controlling
*both* ends (two Debian Jessie containers on a dedicated docker
network, one running `openssl s_server`, no mail server needed since
these rules only depend on TLS-layer facts) - see
`data/pcaps/CAPTURES.md` (S32-S35). All four (RC4, 3DES, SSLv3,
TLS 1.1) worked; none were infeasible once both ends were controlled.
NULL ciphers and anonymous-DH were not attempted (not required by this
round's task) and remain synthetic-only.

**Not yet verified against real captures** (implemented, but only
exercised with synthetic `Session`/`TLSInfo`/`CertInfo`/`StarttlsAnalysis`
objects in unit tests, not real pcaps):
- IMAP/POP3 STARTTLS timeline parsing (capability detection, STLS,
  T-01/T-02): captured plaintext `LOGIN`/`USER`+`PASS` and
  STARTTLS/STLS-then-auth for both protocols. This surfaced two real
  bugs, both fixed: (1) IMAP commands are tagged (`a1 LOGIN user
  pass`), so checking only the first word of a line missed the LOGIN
  command entirely - `auth_before_tls` stayed `False` and `T-01` never
  fired despite real plaintext credentials on the wire; (2) IMAP's
  tagged STARTTLS success reply (`a1 OK Begin TLS negotiation now.`)
  wasn't recognized as a success reply (only untagged `220`/`+OK` were),
  so `starttls_success` stayed `False` even when STARTTLS genuinely
  succeeded. Both fixed by checking the first *two* words for tagged
  commands and generalizing the success-reply check
  (`core/starttls.py`). Confirmed with `tshark`/`strings` that
  credentials never leak in either the wire capture (STARTTLS/STLS
  cases) or the tool's own output (all cases, via redaction).
**Not implemented: `C-03`** (weak DH parameters, <=1024 bits). Checked
feasibility first: tshark's TLS dissector does expose
`tls.handshake.p_len` (the DH prime length) for classic (non-EC)
ServerKeyExchange messages, but we don't currently parse
ServerKeyExchange at all - only ClientHello, ServerHello, and
Certificate. Implementing this would mean new field extraction and new
session_builder parsing logic, not just reading data we already have.
Flagged to the user rather than built.

**Not built:** report rendering (HTML/PDF), a web UI or dashboard, an
API, and any ML-based scoring or anomaly detection. Out of scope for this
MVP by design.
