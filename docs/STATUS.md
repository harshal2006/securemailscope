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
| P-02 | `TLS_VERSION_SSL3` | yes | no | no | SSLv3 predates the local OpenSSL's supported protocol list entirely; no real capture attempted. |
| P-02 | `TLS_VERSION_1_0` | yes | **yes** | yes | Real: `-cipher DEFAULT@SECLEVEL=0` was needed to unlock a genuine TLS 1.0 handshake locally. |
| P-02 | `TLS_VERSION_1_1` | yes | no | no | Shares matching code with TLS 1.0 (which *is* real-tested) but has no test of its own. |
| P-03 | `TLS_VERSION_1_2` | yes | **yes** | yes | |
| P-04 | — | no | no | no | No confirmed mapping. |
| P-05 | — | no | no | no | No confirmed mapping. |
| P-06 | — | no | no | no | No confirmed mapping. |
| C-01 | — | no | no | no | No confirmed mapping. |
| C-02 | `WEAK_CIPHER_SUITE` | yes | no | yes | Requires a server that still supports RC4/3DES/NULL/anon-DH; confirmed our lab server (Debian bookworm, OpenSSL 3.0) does not, even when the *client* offers them (tried 3 client environments, see below). |
| C-03 | — | **no** | no | no | Not implemented. tshark exposes `tls.handshake.p_len` (DH prime length) but we don't parse ServerKeyExchange at all today. Checked feasibility, flagged to the user, told to skip rather than build. |
| C-04 | — | no | no | no | No confirmed mapping. |
| C-05 | `NO_FORWARD_SECRECY` | yes | no* | yes | *The finding's absence (ephemeral kex) is real-verified on every fixture; the finding *firing* (static kex) has no real capture, per instructions ("if none of our captures used static RSA/DH kex, say so — don't build a new capture"). |
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
| T-01 | `T-01` | yes | **yes** | yes | Real: SMTP (587 and 25), IMAP, POP3. Finding IMAP/POP3 real coverage found and fixed two bugs (tagged commands were invisible to detection) — see below. |
| T-02 | `T-02` | yes | **yes** | yes | Real on both submission (HIGH) and mx (INFO) roles, and on SMTP/IMAP/POP3. |
| T-03 | `T-03` | yes | **yes** | yes | Required a second lab Postfix service with STARTTLS disabled entirely. |
| T-04 | — | no | no | no | No confirmed mapping. |
| T-05 | — | no | no | no | No confirmed mapping. |
| T-06 | — | no | no | no | Raised earlier as "T-06-style" but confirmed with the user to just mean the T-02/T-03 role-aware *pattern*, not a distinct rule — no T-06 rule exists. |
| T-07 | — | no | no | no | No confirmed mapping. |
| T-08 | — | no | no | no | No confirmed mapping. |

## Notable bugs found and fixed via real captures (not code review)

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

## Explicitly attempted, found infeasible (not faked)

Weak cipher suites (RC4/3DES/NULL/anonymous-DH), tried three ways:
local OpenSSL 3.0.18 (not compiled in at all), Python's `ssl` module
(same result), and a Debian Jessie (2016, OpenSSL 1.0.1t) container as
the TLS *client* on the lab's own docker network — this one genuinely
offers RC4/3DES, but the handshake still fails because the lab
**server** (Debian bookworm, OpenSSL 3.0) doesn't support these ciphers
server-side either. A real capture would need an entirely separate
legacy mail server image, judged out of scope.

## Not built (by design, per explicit instruction)

Report rendering (HTML/PDF), a web UI or dashboard, an API, ML-based
scoring or anomaly detection.

## Reproducing

From `securemailscope/`, with the venv active
(`source .venv/bin/activate`):

### Full test suite

```
pytest -q
```

Expect **112 passed**.

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
```

Add `--json` to any of the above for machine-readable output.

### Regenerating a live capture (optional, needs Docker)

See `data/pcaps/CAPTURES.md` for the exact `docker compose`/`openssl`/
`swaks`/`tshark` commands used to produce every fixture above, including
the temporary cert swaps and second lab service used for some of them.
