# SecureMailScope — status

Consolidated, honest status as of this session. Every claim below was
checked, not assumed — see `data/pcaps/CAPTURES.md` for exact commands
and wire-level verification (`openssl`/`tshark` output) behind each real
capture, and `README.md`'s "Rule coverage" table for the same rules in
prose form.

Repo is **local-only**: no git remote is configured, and none was added
in this session.

## Rule-by-rule status

Legend: **Impl** = implemented in code. **Real** = fired (or its
absence was confirmed) on an actual pcap. **Synthetic** = covered by a
unit test using constructed `Session`/`TLSInfo`/`CertInfo` objects, not
a pcap.

| Plan ID | Rule ID | Impl | Real | Synthetic | Note |
|---|---|---|---|---|---|
| P-01 | — | no | no | no | No confirmed mapping to this codebase; meaning never established with the user. |
| P-02 | `TLS_VERSION_SSL3` | yes | **yes** | no | Real: purpose-built legacy TLS endpoint (Debian Jessie/OpenSSL 1.0.1t, both ends), forced with `-ssl3`. |
| P-02 | `TLS_VERSION_1_0` | yes | **yes** | yes | Real: `-cipher DEFAULT@SECLEVEL=0` was needed to unlock a genuine TLS 1.0 handshake against the modern mail-server lab. |
| P-02 | `TLS_VERSION_1_1` | yes | **yes** | no | Real: same legacy endpoint as SSLv3, forced with `-tls1_1`. |
| P-03 | `TLS_VERSION_1_2` | yes | **yes** | yes | |
| P-04 | — | no | no | no | No confirmed mapping. |
| P-05 | — | no | no | no | No confirmed mapping. |
| P-06 | — | no | no | no | No confirmed mapping. |
| C-01 | — | no | no | no | No confirmed mapping. |
| C-02 | `WEAK_CIPHER_SUITE` | yes | **yes** | yes | Real: RC4-SHA and DES-CBC3-SHA against the legacy endpoint. Earlier attempt against the modern mail-server lab genuinely failed (server-side, not client-side, limitation) - closed by controlling both ends instead. NULL and anonymous-DH suites remain synthetic-only. |
| C-03 | — | **no** | no | no | Not implemented. tshark exposes `tls.handshake.p_len` (DH prime length) but we don't parse ServerKeyExchange at all today. Checked feasibility, flagged to the user, told to skip rather than build. |
| C-04 | — | no | no | no | No confirmed mapping. |
| C-05 | `NO_FORWARD_SECRECY` | yes | **yes** | yes | Real: RC4-SHA (`TLS_RSA_WITH_RC4_128_SHA`) is static RSA key exchange, so the legacy RC4 capture gives this finding real coverage as a side effect. Static-DH (as opposed to static-RSA) key exchange remains synthetic-only - no real capture negotiated a DH (non-EC) static suite. |
| — | `FORWARD_SECRECY_NOT_EVALUABLE` | yes | no | yes | INFO; fires when a cipher suite isn't in our (non-exhaustive) kex classification table. Never guessed. |
| C-06 | — | no | no | no | No confirmed mapping. |
| C-07 | — | no | no | no | No confirmed mapping. |
| X-01 | `CERT_EXPIRED` | yes | **yes** | yes | |
| X-02 | — | no | no | no | No confirmed mapping. |
| X-03 | `CERT_SELF_SIGNED` | yes | **yes** | yes | |
| X-04 | — | no | no | no | No confirmed mapping. |
| X-05 | `CERT_HOSTNAME_MISMATCH` | yes | **yes** | yes | Real capture with wrong SNI (`Verify return code: 62`); also verified `CERT_HOSTNAME_NOT_EVALUABLE` (no SNI) is reported instead of a guessed mismatch. |
| X-06 | `CERT_WEAK_KEY` | yes | **yes** | yes | RSA-1024. |
| X-07 | `CERT_WEAK_SIGNATURE_HASH` | yes | **yes** | yes | SHA-1; built with the `openssl` CLI since `cryptography` refuses to sign SHA-1 at the API level. |
| X-08 | — | no | no | no | No confirmed mapping. |
| X-09 | — | no | no | no | No confirmed mapping. |
| — | `CERT_NOT_OBSERVABLE` | yes | **yes** | yes | TLS 1.3 encrypts the Certificate message; never guessed. |
| — | `NO_TLS_OBSERVED` | yes | **yes** | yes | |
| T-01 | `T-01` | yes | **yes** | yes | Real: SMTP (587 and 25), IMAP, POP3. IMAP real coverage found and fixed two bugs (tagged commands were invisible to detection) — see below. |
| T-02 | `T-02` | yes | **yes** | yes | Real on both submission (HIGH) and mx (INFO) roles, and on SMTP/IMAP/POP3. |
| T-03 | `T-03` | yes | **yes** | yes | Required a second lab Postfix service with STARTTLS disabled entirely. |
| T-04 | — | no | no | no | No confirmed mapping. |
| T-05 | — | no | no | no | No confirmed mapping. |
| T-06 | — | no | no | no | Raised earlier as "T-06-style" but confirmed with the user to just mean the T-02/T-03 role-aware *pattern*, not a distinct rule — no T-06 rule exists. |
| T-07 | — | no | no | no | No confirmed mapping. |
| T-08 | — | no | no | no | No confirmed mapping. |

**Change this session:** `TLS_VERSION_SSL3`, `TLS_VERSION_1_1`,
`WEAK_CIPHER_SUITE`, and `NO_FORWARD_SECRECY` moved from
synthetic-only to real-verified — see Part A below.

## Report renderer (new this session, Part B)

`core/report.py` renders the analyzer's output into a structured report
(`core/report_models.py` dataclasses): executive summary (score, grade,
findings-by-severity, observable-cert ratio), endpoint inventory,
findings with evidence (the STARTTLS timeline), certificate inventory,
recommendations (fix + verification command, only for rules we actually
implemented and that fired), and an appendix (limitations, full rule
catalogue). Exports as JSON (schema-validated via `jsonschema`) or HTML
(Jinja2, `templates/report.html.j2`).

Verified by rendering S17, S18, S19, and all four legacy captures
(S32-S35) to HTML, opening in headless Chrome, and reviewing
screenshots — not just checking the JSON. This caught a real rendering
bug: `select_autoescape(["html"])` checks the template *filename's own*
extension, and `report.html.j2` ends in `.j2`, so autoescaping was
silently off — `<host>:<port>` placeholders in recommendation commands
were being swallowed as bogus HTML tags by the browser. Fixed by
forcing `autoescape=True` unconditionally; confirmed with a second
screenshot and a regression test (`test_html_placeholders_are_escaped_not_swallowed`).

Not done: PDF export, an API, a dashboard, or ML — explicitly out of
scope for this round.

## Notable bugs found and fixed via real verification, not code review

- **Cert expiry used wall-clock time, not capture time.** A pcap
  analyzed long after capture would have judged a cert's expiry against
  *today*, not the moment it was captured. Fixed by threading the
  packet's own `frame.time_epoch` through as the reference time.
  Verified with a cert valid for ~2 minutes: captured while genuinely
  valid, then the test suite waits for wall-clock time to pass the
  cert's `notAfter` before asserting `is_expired is False` — a
  permanent regression guard.
- **IMAP tagged commands were invisible to auth/STARTTLS detection.**
  `a1 LOGIN user pass` was classified as generic "command" (only the
  tag `a1` was checked, not `LOGIN`), so a real plaintext IMAP `LOGIN`
  never set `auth_before_tls` and `T-01` silently didn't fire — a false
  negative on real credential exposure. A second, related bug: IMAP's
  tagged STARTTLS success reply (`a1 OK Begin TLS negotiation now.`)
  wasn't recognized either, so `starttls_success` stayed `False` even
  when STARTTLS had genuinely succeeded. Both fixed by checking the
  first *two* words of a line, not just the first.
- **Direction-by-IP breaks on loopback.** Client and server share
  `127.0.0.1` in every lab capture, so `ip.src == client_ip` was always
  true. Fixed by keying direction off `server_port` instead.
- **`tls.record.content_type` isn't reliably populated for TLS 1.3
  application-data packets.** Fixed by treating everything after the
  handshake starts as opaque, rather than re-checking TLS fields per
  packet.
- **HTML autoescaping was silently disabled** (this session, Part B) —
  see "Report renderer" above.

## Previously infeasible, now closed (Part A, this session)

Weak cipher suites (RC4/3DES) and SSLv3/TLS 1.1 were previously
attempted against the *mail-server* lab (Debian bookworm, OpenSSL 3.0)
and genuinely failed there — the server itself didn't support these
configs, and negotiation needs both sides to agree. Closed by building
a dedicated legacy TLS test endpoint instead: two Debian Jessie
(OpenSSL 1.0.1t) containers on a private docker network, one running
`openssl s_server` (no full mail server needed — these rules are purely
TLS-layer), one as the client. All four configs (RC4, 3DES, SSLv3,
TLS 1.1) worked once both ends were controlled; none were infeasible.
See `data/pcaps/CAPTURES.md` (S32-S35) for exact commands and wire-level
verification.

NULL-cipher and anonymous-DH suites, and static-DH (non-RSA) key
exchange, were not attempted this round and remain synthetic-only.

## Not built (by design, per explicit instruction)

PDF export, a web UI or dashboard, an API, ML-based scoring or anomaly
detection.

## Reproducing

From `securemailscope/`, with the venv active
(`source .venv/bin/activate`):

### Full test suite

```
pytest -q
```

Expect **136 passed**.

### Analyzer against key captures

All of these are committed fixtures under `tests/fixtures/pcaps/` — no
lab server needs to be running.

```
# S17: plaintext AUTH LOGIN without STARTTLS (T-01, T-02 fire)
python -m core.analyze tests/fixtures/pcaps/S17_smtp_587_plaintext_auth.pcap

# S01b: STARTTLS then AUTH inside TLS (neither T-01 nor T-02 fire)
python -m core.analyze tests/fixtures/pcaps/S01b_smtp_587_starttls_auth.pcap

# S18: expired certificate (CERT_EXPIRED fires)
python -m core.analyze tests/fixtures/pcaps/S18_smtp_587_starttls_expired_cert.pcap

# S19: self-signed certificate (CERT_SELF_SIGNED fires)
python -m core.analyze tests/fixtures/pcaps/S19_smtp_587_starttls_selfsigned_cert.pcap

# S26: STARTTLS disabled entirely on a submission-role port (T-03 fires)
python -m core.analyze tests/fixtures/pcaps/S26_smtp_2588_starttls_disabled.pcap

# S28/S29: IMAP plaintext LOGIN vs STARTTLS-then-LOGIN
python -m core.analyze tests/fixtures/pcaps/S28_imap_2143_plaintext_login.pcap
python -m core.analyze tests/fixtures/pcaps/S29_imap_2143_starttls_login.pcap

# S30/S31: POP3 plaintext USER/PASS vs STLS-then-auth
python -m core.analyze tests/fixtures/pcaps/S30_pop3_2110_plaintext_userpass.pcap
python -m core.analyze tests/fixtures/pcaps/S31_pop3_2110_stls_userpass.pcap

# S32-S35: legacy TLS/cipher captures (RC4, 3DES, SSLv3, TLS 1.1)
python -m core.analyze tests/fixtures/pcaps/S32_legacy_rc4.pcap
python -m core.analyze tests/fixtures/pcaps/S33_legacy_3des.pcap
python -m core.analyze tests/fixtures/pcaps/S34_legacy_ssl3.pcap
python -m core.analyze tests/fixtures/pcaps/S35_legacy_tls1_1.pcap
```

Add `--json` to any of the above for machine-readable output.

### Report renderer

```
python -m core.report tests/fixtures/pcaps/S18_smtp_587_starttls_expired_cert.pcap --html /tmp/report.html
open /tmp/report.html   # macOS
```

Or `--json out.json` for the schema-validated JSON form; omit both flags
to print JSON to stdout.

### Regenerating a live capture (optional, needs Docker)

See `data/pcaps/CAPTURES.md` for the exact `docker`/`openssl`/`swaks`/
`tshark` commands used to produce every fixture above, including the
temporary cert swaps, the second lab service, and the standalone legacy
TLS endpoint used for some of them.
