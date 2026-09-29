# Model card — SecureMailScope ML layer

Two models, both trained and evaluated on the same small, entirely
synthetic lab dataset. **Neither has been trained or validated on real
production mail traffic.** See "Before any production use" below.

## 1. Risk classifier (`risk_classifier.joblib`)

**Type:** `sklearn.ensemble.RandomForestClassifier`, 200 trees,
`class_weight="balanced"`, `random_state=42`.

**Task:** classify a session's 33-feature vector (`ml/features.py`)
into one of `Low` / `Medium` / `High` / `Critical`.

### Training data

30 sessions across 21 distinct known lab configurations ("scenarios"),
built entirely from this project's own Docker lab and a standalone
legacy-TLS test endpoint - see `ml/DATASET.md` for the full breakdown
and `data/pcaps/CAPTURES.md` for how every underlying pcap was
generated and independently verified (`openssl`/`tshark`) before being
labelled. All credentials involved are dummy lab credentials
(`labuser`/`labpass`), per `CLAUDE.md`. No real mail server, real
credentials, or real user traffic was involved anywhere in this
dataset.

Class distribution: Low 11, Critical 10, High 7, **Medium 2** (thin,
not padded - see `ml/DATASET.md`).

### The circularity caveat (verbatim, printed on every training run)

> NOTE: labels and several features derive from the same known lab
> config; treat these metrics as an upper bound on a rule-consistency
> check, not independent validation.

Concretely: `ml/labels.csv`'s `risk_class` was assigned from the KNOWN
lab configuration we set up (e.g. "this pcap is from the
expired-certificate scenario, therefore Medium"), never copied from
`core.rules_engine`'s own severity output - that avoids *label*
circularity. But several *features* (e.g. `cipher_is_weak`,
`cert_is_expired`) are computed using the same domain logic the rule
engine also uses, on a dataset we ourselves built specifically to
exercise those rules. So a high score here mostly demonstrates that the
model can recover a scenario's intended risk category from its own
domain features on data shaped exactly like its labels - not that it
would generalize to real-world traffic with a different distribution of
configurations, attacker behavior, or noise.

### Metrics (GroupKFold on `scenario_id`, 5 folds, out-of-fold pooled)

**Not a random split.** `GroupKFold` keyed on `scenario_id` guarantees
every session from the same known scenario stays entirely within one
fold - two captures of "clean STARTTLS TLS 1.2" taken with different
client tools can never end up split across train and test. Verified by
an assertion inside every fold (`assert train_groups.isdisjoint(test_groups)`)
and by `tests/test_ml.py::test_grouped_cv_never_leaks_a_scenario_across_train_and_test`.

Reproduce: `python -m ml.train`. Raw output saved to
`ml/models/cv_metrics.json`.

**Macro-F1: 0.386**

| Class | Recall | Support |
|---|---|---|
| Low | 0.636 | 11 |
| Medium | **0.000** | 2 |
| High | 0.143 | 7 |
| Critical | 0.800 | 10 |

Confusion matrix (rows = true, columns = predicted):

```
              Low     Medium       High   Critical
Low             7          0          4          0
Medium          1          0          1          0
High            4          0          1          2
Critical        0          0          2          8
```

These are genuinely weak, unfiltered numbers, not smoothed over. Medium's
0.000 recall directly reflects its 2-session, singleton-scenario
support - with only 2 examples split across a 5-fold grouped CV, most
folds simply never see a Medium example in training. High's 0.143
recall shows the model frequently confuses High with Low (4 of 7 High
sessions predicted Low) - plausible given High-class scenarios in this
dataset (weak cert key/signature, deprecated TLS 1.0/1.1, hostname
mismatch) share many raw feature values with Low-class clean sessions
except for one or two specific fields, and a 24-sample training fold
isn't enough for the forest to isolate that reliably every time.

## 2. Per-session anomaly detector (`anomaly_detector.joblib`)

**Type:** `sklearn.ensemble.IsolationForest`, `contamination="auto"`,
`random_state=42`, trained **only** on baseline/compliant sessions (the
17 non-legacy-cipher TLS sessions in the dataset).

**Task:** flag a single session's TLS fingerprint (cipher suite, TLS
version, key exchange type, cert key size) and two timing/volume
signals (`handshake_duration_seconds`, `bytes_before_tls` - computed by
reusing already-extracted raw packet fields, not by re-parsing pcaps)
as anomalous relative to the baseline distribution it was trained on.

**Explicitly out of scope, and why:** certificate drift (an endpoint's
cert changing between sessions) and STARTTLS-stripping (a MITM
suppressing the STARTTLS advertisement) are cross-session/stateful
questions this per-session model structurally cannot answer - it never
sees more than one session at a time. The original plan implied these
were already covered by rules `T-04`/`X-09`; checked directly against
`rules/*.yaml` and `docs/STATUS.md` and confirmed **neither rule
exists** in this codebase. This is a gap in the plan, documented here
and in `docs/STATUS.md` rather than quietly built around under this
task's time budget.

### Evaluation

No purpose-built injected-anomaly captures exist. Evaluated instead
against the 4 legacy-cipher sessions from Part A's dataset (RC4, 3DES,
SSLv3, TLS 1.1) as ground-truth anomalies vs. the 17 baseline sessions.
Reproduce: `python -m ml.anomaly`. Raw output saved to
`ml/models/anomaly_metrics.json`.

| Metric | Value |
|---|---|
| TP / FN / FP / TN | 4 / 0 / 10 / 7 |
| Precision | 0.286 |
| Recall | 1.000 |
| FPR | 0.588 |

Recall is perfect on this tiny set (all 4 legacy-cipher sessions
flagged), but precision is low and the false-positive rate is high -
the detector over-flags baseline sessions too, most likely because 17
training examples isn't enough to characterize "normal" tightly. This
is reported as-is, not tuned to look better. Treat as a smoke test that
the approach is wired correctly, not a validated detector.

## 3. Rule/ML fusion (`ml/fusion.py`)

The ML classifier is never surfaced standalone. `fuse_severity()`
combines a session's rule-engine findings with the risk classifier's
prediction: `final severity = max(rule severity, ML class)`, where the
ML class is discounted by exactly one severity level before that `max`
whenever the rules are "silent" (no above-INFO finding for the
session). Rules are never overridden or discounted - only the ML
model's independent contribution is (cautiously) trusted less when
nothing else corroborates it. See `ml/predict.py` for a real,
end-to-end demonstration against actual pcaps (not a standalone ML run).

## Before any production use

This entire ML layer - both models - is trained and evaluated
exclusively on ~30 synthetic lab sessions generated by this project's
own Docker containers, with dummy credentials, covering a narrow, known
set of configurations we ourselves constructed. **It has not seen a
single real mail server, real credential, or real network's traffic.**
Both the circularity caveat above and the thin/repurposed evaluation
data mean these metrics cannot be read as an estimate of real-world
accuracy.

**Retraining (or at minimum re-evaluating) on real captured traffic -
traffic this project's tool was not used to generate, ideally from
multiple independent real mail deployments - is required before either
model is used for any decision beyond an internal, clearly-labelled
"experimental" signal alongside the deterministic rule engine's output.**
The rule engine (`core/rules_engine.py`), independently verified against
real captures throughout this project (see `docs/STATUS.md`), should
remain the primary, trusted source of findings regardless.
