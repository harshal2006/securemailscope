"""Isolation Forest for PER-SESSION anomalies only: rare cipher suite /
TLS version, unusual key exchange, unusual handshake duration, and
unusual byte volume before TLS starts.

Scope, stated explicitly per instruction: certificate drift (the same
endpoint presenting a different certificate over time) and
STARTTLS-stripping detection (an active MITM that suppresses the
STARTTLS capability advertisement) are CROSS-SESSION / stateful
questions - they require comparing a session against *history* for the
same endpoint, or comparing what a client saw against what the server
actually offers. A per-session Isolation Forest has no access to either
and cannot meaningfully detect them; forcing it to try would just be
noise dressed up as a feature.

The original plan implied these were already covered by existing rules
T-04/X-09. That's not accurate: checked against docs/STATUS.md and
rules/*.yaml directly - no such rules exist in this codebase, and no
T-04/T-05 injected-anomaly captures exist either. That's a gap in the
plan's narrative, not in this code; documented here and in
docs/STATUS.md rather than silently building two new stateful rules
under this task's time budget, or silently claiming they exist.

Evaluation data: no purpose-built injected-anomaly captures exist. This
reuses the real captures we do have: the legacy TLS/cipher captures
(S32-S35: RC4, 3DES, SSLv3, TLS 1.1) are genuine per-session anomalies
relative to our baseline (clean TLS 1.2/1.3, ECDHE) captures - not
synthetic, but repurposed from Part A's dataset rather than a dedicated
anomaly-capture set. Coverage is thin (4 positive examples); reported
as such, not padded.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import confusion_matrix

from core.pcap_reader import read_packets
from core.rules_engine import load_rules
from core.session_builder import build_sessions, group_packets_by_stream
from ml.features import extract_features

ML_DIR = Path(__file__).parent
FIXTURES_DIR = ML_DIR.parent / "tests" / "fixtures" / "pcaps"
LABELS_CSV = ML_DIR / "labels.csv"
MODELS_DIR = ML_DIR / "models"
MODELS_DIR.mkdir(exist_ok=True)

# Scenario IDs from ml/labels.csv treated as ground-truth per-session
# anomalies for evaluation - the legacy/weak-crypto captures. Everything
# else is treated as baseline/normal for this evaluation.
ANOMALOUS_SCENARIOS = {"legacy_rc4", "legacy_3des", "legacy_sslv3", "legacy_tls1_1"}

ANOMALY_FEATURE_NAMES = [
    "cipher_suite_numeric",
    "tls_version_ordinal",
    "kex_is_static",
    "kex_is_unknown",
    "cert_key_size",
    "handshake_duration_seconds",
    "bytes_before_tls",
    "frame_span",
]


def _extra_timing_features(pcap_path: Path, tcp_stream: int) -> dict[str, float]:
    """handshake_duration_seconds and bytes_before_tls - computed directly
    from already-extracted raw packet fields (frame.time_epoch, tcp.len),
    not by re-parsing the pcap's TLS structure again.
    """
    packets = read_packets(pcap_path)
    by_stream = group_packets_by_stream(packets)
    pkts = by_stream[tcp_stream]

    handshake_times = []
    bytes_before_tls = 0
    tls_started = False

    for pkt in pkts:
        is_tls_pkt = bool(pkt.get("tls.handshake.type") or pkt.get("tls.record.content_type"))
        if is_tls_pkt:
            tls_started = True
            if pkt.get("tls.handshake.type"):
                t = pkt.get("frame.time_epoch")
                if t:
                    handshake_times.append(float(t))
        elif not tls_started:
            tcp_len = pkt.get("tcp.len")
            if tcp_len:
                try:
                    bytes_before_tls += int(tcp_len)
                except ValueError:
                    pass

    duration = (max(handshake_times) - min(handshake_times)) if len(handshake_times) >= 2 else 0.0
    return {
        "handshake_duration_seconds": duration,
        "bytes_before_tls": float(bytes_before_tls),
    }


def extract_anomaly_features_for_pcap(pcap_path: Path, rules: dict | None = None) -> list[dict[str, float]]:
    if rules is None:
        rules = load_rules()
    packets = read_packets(pcap_path)
    sessions = build_sessions(packets)

    rows = []
    for session in sessions:
        if session.tls_info is None:
            continue  # no TLS ever observed - nothing to compare on a cipher/kex basis
        full = extract_features(session, None, rules)
        extra = _extra_timing_features(pcap_path, session.tcp_stream)
        row = {name: full[name] for name in ANOMALY_FEATURE_NAMES if name in full}
        row.update(extra)
        rows.append({name: row[name] for name in ANOMALY_FEATURE_NAMES})
    return rows


def load_dataset() -> tuple[pd.DataFrame, np.ndarray, list[str], list[str]]:
    rows = list(csv.DictReader(open(LABELS_CSV)))
    rules = load_rules()

    feature_rows = []
    is_anomaly = []
    scenario_ids = []
    pcap_paths = []

    for row in rows:
        pcap_path = FIXTURES_DIR / row["pcap_path"]
        feats = extract_anomaly_features_for_pcap(pcap_path, rules)
        if not feats:
            continue  # no TLS in this session - excluded, not a cipher/kex anomaly candidate
        feature_rows.append(feats[0])
        is_anomaly.append(row["scenario_id"] in ANOMALOUS_SCENARIOS)
        scenario_ids.append(row["scenario_id"])
        pcap_paths.append(row["pcap_path"])

    X = pd.DataFrame(feature_rows, columns=ANOMALY_FEATURE_NAMES)
    y = np.array(is_anomaly)
    return X, y, scenario_ids, pcap_paths


def main() -> None:
    X, y, scenario_ids, pcap_paths = load_dataset()
    print(f"Loaded {len(X)} TLS sessions ({int(y.sum())} treated as ground-truth anomalies: "
          f"{sorted(set(s for s, a in zip(scenario_ids, y) if a))}).")

    baseline_mask = ~y
    X_baseline = X[baseline_mask]
    print(f"Training Isolation Forest on {len(X_baseline)} baseline/compliant sessions only.")

    clf = IsolationForest(contamination="auto", random_state=42)
    clf.fit(X_baseline)

    # -1 = anomaly, 1 = normal (sklearn convention)
    raw_pred = clf.predict(X)
    pred_is_anomaly = raw_pred == -1

    tp = int(((pred_is_anomaly) & (y)).sum())
    fn = int(((~pred_is_anomaly) & (y)).sum())
    fp = int(((pred_is_anomaly) & (~y)).sum())
    tn = int(((~pred_is_anomaly) & (~y)).sum())

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0

    print()
    print("=" * 70)
    print("Per-session Isolation Forest evaluation")
    print("=" * 70)
    print(
        "NOTE: ground-truth anomalies here are the 4 legacy-cipher sessions "
        "(S32-S35) repurposed from Part A's labelled dataset, not a dedicated "
        "injected-anomaly capture set. Coverage is thin (4 positive examples); "
        "treat these numbers as a smoke test, not a validated detector."
    )
    print()
    print(f"TP={tp} FN={fn} FP={fp} TN={tn}")
    print(f"Precision: {precision:.3f}")
    print(f"Recall:    {recall:.3f}")
    print(f"FPR:       {fpr:.3f}")
    cm = confusion_matrix(y, pred_is_anomaly, labels=[False, True])
    print("\nConfusion matrix (rows=true, cols=pred), labels=[Normal, Anomaly]:")
    print("           Normal   Anomaly")
    for label, row in zip(["Normal", "Anomaly"], cm):
        print(f"{label:8s}  {row[0]:7d}  {row[1]:7d}")
    print("=" * 70)

    joblib.dump(clf, MODELS_DIR / "anomaly_detector.joblib")
    metrics_out = {
        "n_sessions": len(X),
        "n_ground_truth_anomalies": int(y.sum()),
        "anomalous_scenarios": sorted(ANOMALOUS_SCENARIOS),
        "tp": tp,
        "fn": fn,
        "fp": fp,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "fpr": fpr,
        "note": (
            "Ground-truth anomalies are 4 legacy-cipher sessions repurposed from "
            "Part A's labelled dataset, not a dedicated injected-anomaly capture "
            "set. Coverage is thin; treat as a smoke test, not a validated detector."
        ),
    }
    with open(MODELS_DIR / "anomaly_metrics.json", "w") as f:
        json.dump(metrics_out, f, indent=2)
    print(f"\nSaved: ml/models/anomaly_detector.joblib, ml/models/anomaly_metrics.json")


if __name__ == "__main__":
    main()
