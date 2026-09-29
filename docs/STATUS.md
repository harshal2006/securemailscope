# SecureMailScope — final consolidated status

Every claim below was checked, not assumed. See `data/pcaps/CAPTURES.md`
for exact commands and wire-level verification (`openssl`/`tshark`
output) behind every real capture, and `ml/models/model_card.md` for
full ML metrics and caveats.

**Repo is local-only: no git remote is configured, and none has been
added at any point.**

This is a natural stopping point for the core build, per explicit
instruction - no new major component should be started after this
without a fresh scoping conversation.

## Component overview

| Component | Status |
|---|---|
| Passive pcap analyzer (`core/`) | Built, real-verified throughout (see rule table) |
| Rules engine | Built for the rules listed below; several plan rule IDs (P/C/X/T) have **no confirmed mapping** in this codebase - see table |
| Report renderer (`core/report.py`) | Built: JSON (schema-validated), HTML, **PDF** (this session). All real-verified |
| REST API (`api/`) | Built, real-verified against real fixtures + a live server |
| Dashboard (`dashboard/`) | Built, real-verified via screenshots + automated `AppTest` |
| ML risk classifier (`ml/train.py`) | Built, **synthetic-lab-only** evaluation (GroupKFold, honestly weak metrics) |
| ML anomaly detection (`ml/anomaly.py`) | Built, **per-session only**; cross-session detectors (cert drift, STARTTLS-stripping) are **not implemented anywhere** - plan claimed otherwise, corrected |
| PDF export | Built this session |
| Not built | ML-based *rule generation*, real-traffic retraining, anything beyond what's listed here |

## Rule-by-rule status

Legend: **Impl** = implemented in code. **Real** = fired (or its
absence was confirmed) on an actual pcap. **Synthetic** = covered only
by a unit test using constructed objects, not a pcap.

| Plan ID | Rule ID | Impl | Real | Synthetic | Note |
|---|---|---|---|---|---|
| P-01 | — | no | no | no | No confirmed mapping to this codebase. |
| P-02 | `TLS_VERSION_SSL3` | yes | **yes** | no | Purpose-built legacy TLS endpoint (Debian Jessie/OpenSSL 1.0.1t, both ends), forced with `-ssl3`. |
| P-02 | `TLS_VERSION_1_0` | yes | **yes** | yes | `-cipher DEFAULT@SECLEVEL=0` was needed to unlock a genuine TLS 1.0 handshake against the modern mail-server lab. |
| P-02 | `TLS_VERSION_1_1` | yes | **yes** | no | Same legacy endpoint as SSLv3, forced with `-tls1_1`. |
| P-03 | `TLS_VERSION_1_2` | yes | **yes** | yes | |
| P-04 | — | no | no | no | No confirmed mapping. |
| P-05 | — | no | no | no | No confirmed mapping. |
| P-06 | — | no | no | no | No confirmed mapping. |
| C-01 | — | no | no | no | No confirmed mapping. |
| C-02 | `WEAK_CIPHER_SUITE` | yes | **yes** | yes | RC4-SHA and DES-CBC3-SHA against the legacy endpoint. Earlier attempt against the modern mail-server lab genuinely failed (server-side limitation) - closed by controlling both ends. NULL and anonymous-DH suites remain synthetic-only. |
| C-03 | — | **no** | no | no | Not implemented. tshark exposes `tls.handshake.p_len` but we don't parse ServerKeyExchange at all. Checked feasibility, flagged, told to skip rather than build. |
| C-04 | — | no | no | no | No confirmed mapping. |
| C-05 | `NO_FORWARD_SECRECY` | yes | **yes** | yes | RC4-SHA is static RSA key exchange, giving this real coverage as a side effect. Static-DH (non-RSA) key exchange remains synthetic-only. |
| — | `FORWARD_SECRECY_NOT_EVALUABLE` | yes | no | yes | INFO; fires when a cipher suite isn't in our (non-exhaustive) kex table. Never guessed. |
| C-06 | — | no | no | no | No confirmed mapping. |
| C-07 | — | no | no | no | No confirmed mapping. |
| X-01 | `CERT_EXPIRED` | yes | **yes** | yes | |
| X-02 | — | no | no | no | No confirmed mapping. |
| X-03 | `CERT_SELF_SIGNED` | yes | **yes** | yes | |
| X-04 | — | no | no | no | No confirmed mapping. |
| X-05 | `CERT_HOSTNAME_MISMATCH` | yes | **yes** | yes | Real capture with wrong SNI (`Verify return code: 62`); `CERT_HOSTNAME_NOT_EVALUABLE` (no SNI) verified reported instead of a guessed mismatch. |
| X-06 | `CERT_WEAK_KEY` | yes | **yes** | yes | RSA-1024. |
| X-07 | `CERT_WEAK_SIGNATURE_HASH` | yes | **yes** | yes | SHA-1; built with `openssl` CLI since `cryptography` refuses to sign SHA-1. |
| X-08 | — | no | no | no | No confirmed mapping. |
| X-09 | — | **no** | no | no | **Certificate drift detection. The plan implied this was already covered - it is not.** Checked `rules/*.yaml` directly, no such rule exists. Would need to compare a session against history for the same endpoint; genuinely cross-session/stateful, out of scope for the current per-session architecture. |
| — | `CERT_NOT_OBSERVABLE` | yes | **yes** | yes | TLS 1.3 encrypts the Certificate message; never guessed. |
| — | `NO_TLS_OBSERVED` | yes | **yes** | yes | |
| T-01 | `T-01` | yes | **yes** | yes | SMTP (587 and 25), IMAP, POP3. IMAP coverage found and fixed two real bugs (tagged commands invisible to detection). |
| T-02 | `T-02` | yes | **yes** | yes | Real on both submission (HIGH) and mx (INFO) roles, SMTP/IMAP/POP3. |
| T-03 | `T-03` | yes | **yes** | yes | Required a second lab Postfix service with STARTTLS disabled entirely. |
| T-04 | — | **no** | no | no | **STARTTLS-stripping detection. The plan implied this was already covered - it is not.** Checked `rules/*.yaml` directly, no such rule exists, and no injected-anomaly captures for it exist either. Needs to compare what a client saw against what the server actually offers; genuinely cross-session/stateful, out of scope for the current architecture. |
| T-05 | — | no | no | no | No confirmed mapping. |
| T-06 | — | no | no | no | Raised once as "T-06-style"; confirmed with the user this meant the T-02/T-03 role-aware *pattern*, not a distinct rule. No T-06 rule exists. |
| T-07 | — | no | no | no | No confirmed mapping. |
| T-08 | — | no | no | no | No confirmed mapping. |

**On the T-04/X-09 correction:** a later task explicitly instructed
building ML anomaly detection "confirming these stay as the existing
rule-based behavioural detectors (already built, per T-04/X-09)".
Checked directly against this file and `rules/*.yaml` before writing
any code - neither rule exists, and never has in this codebase's
history. This was a false premise in the plan, not a regression;
corrected here and in `ml/anomaly.py`'s docstring rather than either
building two new stateful rules under a tight budget or silently
proceeding as if they existed.

## Report renderer: JSON, HTML, PDF

`core/report.py` builds one `Report` dataclass (`core/report_models.py`)
from the analyzer's output and renders it three ways - all from the same
computation, none reimplemented:

- **JSON** - schema-validated against `REPORT_JSON_SCHEMA` (`jsonschema`).
- **HTML** - Jinja2, `templates/report.html.j2`. Verified by rendering
  multiple real captures to HTML, opening in headless Chrome, and
  reviewing screenshots. Caught a real bug this way:
  `select_autoescape(["html"])` checks the template *filename's own*
  extension, and `report.html.j2` ends in `.j2`, so autoescaping was
  silently off - `<host>:<port>` placeholders in recommendation
  commands were being swallowed as bogus HTML tags. Fixed by forcing
  `autoescape=True` unconditionally.
- **PDF** (this session) - `render_pdf_from_html()` prints the *same*
  HTML (no second template) via a headless Chromium's built-in
  `--print-to-pdf`. Verified the same way as HTML: generated PDFs for
  S17 (5 pages) and the legacy RC4 capture (4 pages), converted every
  page to PNG (macOS `sips`) and actually looked at them - correctly
  paginated, dark background renders correctly in print, `<host>:<port>`
  still properly escaped, no garbling across page breaks.

Recommendations (`rules/recommendations.yaml`) only appear for rule IDs
that actually fired and that we actually implemented - never the plan's
full imagined catalogue.

## API

`api/main.py` (FastAPI + SQLite via SQLAlchemy): `POST /api/v1/analyze`
(multipart upload, background job), `GET /api/v1/jobs/{id}` (status),
`/summary`, `/sessions` (paginated + filterable), `/sessions/{id}`,
`/findings` (severity-sorted), `/report?format=json|html|pdf` (all three
reuse `core/report.py` directly), `/health`. The background task calls
`core.report.build_report()` exactly once per job and caches its JSON/
HTML; every read endpoint (including the PDF one) serves from that
cache rather than recomputing.

Verified against real fixtures (`tests/test_api.py`), not mocked data:
uploaded multiple real captures through the actual HTTP API and asserted
every endpoint's response equals what `core.report.build_report()`
computes directly for the same file - no mismatches found. Confirmed
background processing doesn't block the server using a real running
`uvicorn` process, not Starlette's `TestClient` (whose background-task
execution doesn't actually prove this) - `tests/test_api_live_server.py`.

## Dashboard

`dashboard/app.py` (Streamlit + Plotly): talks to the API over HTTP
only, never imports `core.*`. Pages: Overview (gauge, KPI tiles,
severity donut, top-3 fix-first), Sessions (filterable table +
drill-down), Certificates (inventory + expiry), Findings (prioritized
queue with recommendations). "Demo mode" auto-loads a real fixture on
first launch.

Verified by actually running both processes, uploading a real fixture
through the UI, and reviewing real screenshots (not just reading the
code) - numbers matched `core.analyze`'s output exactly. Getting the
screenshot required real debugging: headless Chrome's CDP
`Page.captureScreenshot` hung indefinitely in this sandboxed environment
(confirmed with a trivial `data:` URL, unrelated to Streamlit) - the
dedicated `chrome-headless-shell` binary worked instead. Also covered by
`tests/test_dashboard.py` using Streamlit's `AppTest` against a real
running API.

## ML risk classifier

`ml/features.py` (33 features, reusing `core/*` parsing/classification -
no PCAP re-parsed from scratch), `ml/train.py` (RandomForest,
`class_weight="balanced"`), `ml/explain.py` (SHAP), `ml/fusion.py` +
`ml/predict.py` (rule/ML fusion - ML is never surfaced standalone).

**Training data:** 30 sessions, 21 scenarios, entirely from this
project's own Docker lab, dummy credentials only. **Never real mail
traffic.** See `ml/DATASET.md`.

**Leakage prevention:** `GroupKFold` keyed on `scenario_id`, not a
random split - sessions from the same known scenario can never span
train and test. Asserted inside every fold
(`tests/test_ml.py::test_grouped_cv_never_leaks_a_scenario_across_train_and_test`).

**Circularity caveat, printed on every training run:**

> NOTE: labels and several features derive from the same known lab
> config; treat these metrics as an upper bound on a rule-consistency
> check, not independent validation.

**Actual metrics** (GroupKFold, 5 folds, out-of-fold pooled; reproduce
with `python -m ml.train`):

Macro-F1: **0.386**

| Class | Recall | Support |
|---|---|---|
| Low | 0.636 | 11 |
| Medium | **0.000** | 2 |
| High | 0.143 | 7 |
| Critical | 0.800 | 10 |

```
Confusion matrix (rows=true, cols=pred):
              Low     Medium       High   Critical
Low             7          0          4          0
Medium          1          0          1          0
High            4          0          1          2
Critical        0          0          2          8
```

Genuinely weak, not smoothed over - Medium's 0.000 recall directly
reflects its 2-session support. Full detail, including SHAP evidence
(real PNGs per class, not claimed) and the fusion logic
(`final = max(rule_severity, ml_severity discounted by one level when
rules are silent)`), is in `ml/models/model_card.md`.

**This model has not seen a single real mail server, real credential,
or real network's traffic. Retraining or re-evaluating on real captured
traffic is required before any use beyond an internal, clearly-labelled
experimental signal alongside the rule engine.**

## ML anomaly detection

`ml/anomaly.py`: `IsolationForest`, **per-session only** - rare cipher
suite/TLS version/key exchange, handshake duration, bytes-before-TLS.
Trained only on baseline/compliant sessions.

**Explicitly out of scope, confirmed not built anywhere:** certificate
drift and STARTTLS-stripping. See the T-04/X-09 correction above - the
plan assumed these existed as rules; they don't, and building them was
not what this per-session model could do regardless (both are
cross-session/stateful).

**Evaluation:** no purpose-built injected-anomaly captures exist.
Evaluated against the 4 legacy-cipher sessions (RC4/3DES/SSLv3/TLS 1.1)
repurposed from the risk-classifier dataset, vs. 17 baseline sessions.
Reproduce with `python -m ml.anomaly`.

| Metric | Value |
|---|---|
| TP / FN / FP / TN | 4 / 0 / 10 / 7 |
| Precision | 0.286 |
| Recall | 1.000 |
| FPR | 0.588 |

Perfect recall on this tiny set, but low precision and a high false-
positive rate - reported as-is, not tuned to look better. Treat as a
smoke test that the approach is wired correctly, not a validated
detector.

## Notable bugs found and fixed via real verification, not code review

- **Cert expiry used wall-clock time, not capture time.** Fixed by
  threading the packet's own `frame.time_epoch` through as the
  reference time. Verified with a cert valid for ~2 minutes: captured
  while genuinely valid, then the test suite waits for wall-clock time
  to pass the cert's `notAfter` before asserting `is_expired is False` -
  a permanent regression guard.
- **IMAP tagged commands were invisible to auth/STARTTLS detection.**
  `a1 LOGIN user pass` was classified as generic "command" (only the
  tag `a1` was checked), so a real plaintext IMAP `LOGIN` never set
  `auth_before_tls` and `T-01` silently didn't fire - a false negative
  on real credential exposure. A second bug: IMAP's tagged STARTTLS
  success reply wasn't recognized either. Both fixed by checking the
  first *two* words of a line, not just the first.
- **Direction-by-IP breaks on loopback.** Client and server share
  `127.0.0.1` in every lab capture. Fixed by keying direction off
  `server_port` instead.
- **`tls.record.content_type` isn't reliably populated for TLS 1.3
  application-data packets.** Fixed by treating everything after the
  handshake starts as opaque.
- **HTML autoescaping was silently disabled** - see "Report renderer"
  above.
- **An orphaned `uvicorn` process from an earlier debugging session**
  was found still running on port 8123 during this session's cleanup
  pass and killed. No other orphaned processes, containers, or docker
  networks were found.

## Previously infeasible, now closed

Weak cipher suites (RC4/3DES) and SSLv3/TLS 1.1 were originally
attempted against the *mail-server* lab (Debian bookworm, OpenSSL 3.0)
and genuinely failed there - the server itself didn't support these
configs. Closed by building a dedicated legacy TLS test endpoint
instead: two Debian Jessie (OpenSSL 1.0.1t) containers on a private
docker network, one running `openssl s_server`. All four configs worked
once both ends were controlled. See `data/pcaps/CAPTURES.md` (S32-S35).

NULL-cipher and anonymous-DH suites, and static-DH (non-RSA) key
exchange, were never attempted and remain synthetic-only.

## Not built

PDF export was the last item on this list; it's now built (see above).
Remaining, genuinely not built: retraining either ML model on real
traffic, ML-driven rule generation, cert-drift/STARTTLS-stripping
detection in any form.

## Reproducing

From `securemailscope/`, with the venv active
(`source .venv/bin/activate`):

### Full test suite

```
pytest -q
```

Expect **192 passed**.

### Analyzer against key captures

All fixtures under `tests/fixtures/pcaps/` - no lab server needs to be
running.

```
python -m core.analyze tests/fixtures/pcaps/S17_smtp_587_plaintext_auth.pcap   # T-01, T-02 fire
python -m core.analyze tests/fixtures/pcaps/S01b_smtp_587_starttls_auth.pcap   # neither fires
python -m core.analyze tests/fixtures/pcaps/S18_smtp_587_starttls_expired_cert.pcap  # CERT_EXPIRED
python -m core.analyze tests/fixtures/pcaps/S19_smtp_587_starttls_selfsigned_cert.pcap  # CERT_SELF_SIGNED
python -m core.analyze tests/fixtures/pcaps/S26_smtp_2588_starttls_disabled.pcap  # T-03
python -m core.analyze tests/fixtures/pcaps/S32_legacy_rc4.pcap  # WEAK_CIPHER_SUITE, NO_FORWARD_SECRECY
```

Add `--json` for machine-readable output.

### Report renderer (JSON / HTML / PDF)

```
python -m core.report tests/fixtures/pcaps/S18_smtp_587_starttls_expired_cert.pcap --html /tmp/report.html
python -m core.report tests/fixtures/pcaps/S18_smtp_587_starttls_expired_cert.pcap --pdf /tmp/report.pdf
open /tmp/report.html /tmp/report.pdf   # macOS
```

Requires Google Chrome or Chromium installed for `--pdf`
(`$CHROME_PATH` to override the auto-detected binary).

### API + dashboard

```
pip install fastapi "uvicorn[standard]" sqlalchemy python-multipart httpx
uvicorn api.main:app          # terminal 1

pip install streamlit plotly requests
streamlit run dashboard/app.py  # terminal 2
```

The dashboard auto-loads S17 on first launch. Or drive the API directly:

```
curl -F file=@tests/fixtures/pcaps/S17_smtp_587_plaintext_auth.pcap \
     http://127.0.0.1:8000/api/v1/analyze
curl http://127.0.0.1:8000/api/v1/jobs/<job_id>/summary
curl http://127.0.0.1:8000/api/v1/jobs/<job_id>/report?format=pdf -o report.pdf
```

### ML layer

```
pip install scikit-learn pandas shap joblib matplotlib pypdf

python -m ml.train      # grouped CV + prints the confusion matrix + trains the final model
python -m ml.explain    # SHAP evidence per class -> ml/models/shap_explanations/
python -m ml.anomaly    # Isolation Forest eval -> ml/models/anomaly_metrics.json
python -m ml.predict tests/fixtures/pcaps/S17_smtp_587_plaintext_auth.pcap  # rules + ML fused
```

See `ml/models/model_card.md` for full metrics and caveats.

### Regenerating a live capture (optional, needs Docker)

See `data/pcaps/CAPTURES.md` for the exact `docker`/`openssl`/`swaks`/
`tshark` commands used to produce every fixture above, including the
temporary cert swaps, the second lab service, and the standalone legacy
TLS endpoint used for some of them.
