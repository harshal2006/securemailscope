# ML dataset (Part A)

`labels.csv` maps every session to a `scenario_id` (the underlying known
lab configuration) and a `risk_class` (Low/Medium/High/Critical)
determined from that known configuration - **not** from
`core.rules_engine`'s own output. See the `ground_truth_basis` column in
`labels.csv` for the reasoning behind each label.

## How the dataset was built

23 sessions already existed from prior work (see
`data/pcaps/CAPTURES.md`). 7 more were added this round by replaying
existing lab scenarios with a **different client tool** - Python's
stdlib `smtplib`/`imaplib`/`poplib` instead of `swaks`/`openssl
s_client` - to get natural variation in TLS ClientHello fingerprint,
extension order, and timing, without touching any server config. Script:
`lab/generate_ml_variants.py`. No new attack infrastructure was built.

An 8th variant (an additional RC4 cipher against the standalone legacy
TLS endpoint) was attempted but the `openssl s_client` process hung
indefinitely on the second invocation against that endpoint for
unclear reasons; killed and dropped rather than debugged further, since
RC4/3DES already have real coverage from the existing `legacy_rc4`/
`legacy_3des` scenarios (S32/S33).

## Final counts

**30 sessions total, 21 distinct scenarios.**

By risk class:

| Class | Sessions |
|---|---|
| Low | 11 |
| Critical | 10 |
| High | 7 |
| **Medium** | **2** |

**Medium is thin** - only 2 sessions (`smtp_cert_expired`,
`smtp_cert_selfsigned`), both singleton scenarios. This was not padded.
A classifier's Medium-class metrics from this dataset should be treated
as close to unmeasurable, not as a real estimate of recall/precision for
that class.

By scenario, 14 of the 21 scenarios have exactly one session (no
tool-variant was generated for every scenario, given time constraints -
see the list below). This means `GroupKFold` (Part B) will place these
singleton scenarios entirely within one fold each; they contribute to
the fold's training or test set but can never appear in both, and
cross-validation folds containing mostly singleton-scenario groups are
less statistically meaningful than folds built from scenarios with
several sessions.

Scenarios with 2 sessions (tool-variant added): `imap_plaintext_login`,
`imap_starttls_clean`, `pop3_plaintext_userpass`, `pop3_stls_clean`,
`smtp_plaintext_auth_submission`, `smtp_starttls_clean_tls13`.

Scenario with 4 sessions: `smtp_starttls_clean_tls12` (S20, S25, the
original `smtp_starttls_tls12_valid.pcap`, and the new `mlv01` Python
variant).

Scenarios with exactly 1 session (not expanded this round):
`legacy_3des`, `legacy_rc4`, `legacy_sslv3`, `legacy_tls1_1`,
`smtp_cert_expired`, `smtp_cert_hostname_mismatch`,
`smtp_cert_selfsigned`, `smtp_cert_weak_key_rsa1024`,
`smtp_cert_weak_sig_sha1`, `smtp_implicit_clean_tls13`,
`smtp_plaintext_auth_mx`, `smtp_starttls_disabled`,
`smtp_starttls_disabled_with_plaintext_auth`, `smtp_tls1_0`.

## Credential handling

Verified with `strings` on every new capture: plaintext-scenario
captures (mlv02, mlv03, mlv04, mlv06) contain the dummy lab credentials
in cleartext, as expected and intentional (same pattern as all prior
plaintext-auth captures in this project - see CLAUDE.md). STARTTLS/STLS
captures (mlv01, mlv05, mlv07) are clean.
