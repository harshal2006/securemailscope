"""Trains the risk classifier and reports honest, leakage-free metrics.

Two things this script is careful about, per explicit instruction:

1. Split leakage: uses GroupKFold keyed on scenario_id, NOT a random
   k-fold. Sessions from the same known lab scenario (e.g. two captures
   of "clean STARTTLS TLS 1.2" taken with different client tools) must
   never span train and test - a random split could let the model
   memorize a scenario's exact feature fingerprint in training and then
   "predict" it trivially in test, which would look like real
   generalization but isn't.

2. Label/feature circularity: ml/labels.csv's risk_class comes from the
   KNOWN lab configuration (see ml/DATASET.md), never from
   core.rules_engine's output. But several *features* (e.g.
   cipher_is_weak, cert_is_expired) are extracted using the same
   domain logic the rule engine also uses, and the dataset itself was
   built by us to exercise those rules. So even with grouped CV and
   independently-sourced labels, these metrics measure "does the model
   recover a config's intended risk category from its own domain
   features" - a rule-consistency check - not independent validation
   against real-world traffic distributions. This caveat is printed
   below, not just in a docstring.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, f1_score
from sklearn.model_selection import GroupKFold

from ml.features import FEATURE_NAMES, extract_features_for_pcap

ML_DIR = Path(__file__).parent
FIXTURES_DIR = ML_DIR.parent / "tests" / "fixtures" / "pcaps"
LABELS_CSV = ML_DIR / "labels.csv"
MODELS_DIR = ML_DIR / "models"
MODELS_DIR.mkdir(exist_ok=True)

RISK_CLASSES = ["Low", "Medium", "High", "Critical"]
N_SPLITS = 5

CIRCULARITY_NOTICE = (
    "NOTE: labels and several features derive from the same known lab config; "
    "treat these metrics as an upper bound on a rule-consistency check, "
    "not independent validation."
)


def load_dataset() -> tuple[pd.DataFrame, np.ndarray, np.ndarray, list[str]]:
    rows = list(csv.DictReader(open(LABELS_CSV)))
    feature_rows = []
    labels = []
    groups = []
    pcap_paths = []

    for row in rows:
        pcap_path = FIXTURES_DIR / row["pcap_path"]
        sessions_features = extract_features_for_pcap(pcap_path)
        if not sessions_features:
            print(f"WARNING: no recognized session in {row['pcap_path']}, skipping")
            continue
        # One label per pcap in labels.csv; every fixture here has
        # exactly one relevant session, but guard explicitly rather
        # than silently mis-mapping if that ever changes.
        if len(sessions_features) != 1:
            print(
                f"WARNING: {row['pcap_path']} has {len(sessions_features)} sessions, "
                f"using the first and ignoring the rest"
            )
        feature_rows.append(sessions_features[0])
        labels.append(row["risk_class"])
        groups.append(row["scenario_id"])
        pcap_paths.append(row["pcap_path"])

    X = pd.DataFrame(feature_rows, columns=FEATURE_NAMES)
    y = np.array(labels)
    g = np.array(groups)
    return X, y, g, pcap_paths


def run_grouped_cv(X: pd.DataFrame, y: np.ndarray, groups: np.ndarray) -> dict:
    n_splits = min(N_SPLITS, len(set(groups)))
    gkf = GroupKFold(n_splits=n_splits)

    y_true_all = []
    y_pred_all = []

    for fold, (train_idx, test_idx) in enumerate(gkf.split(X, y, groups)):
        train_groups = set(groups[train_idx])
        test_groups = set(groups[test_idx])
        assert train_groups.isdisjoint(test_groups), "scenario leaked across train/test!"

        clf = RandomForestClassifier(
            n_estimators=200, class_weight="balanced", random_state=42
        )
        clf.fit(X.iloc[train_idx], y[train_idx])
        preds = clf.predict(X.iloc[test_idx])

        y_true_all.extend(y[test_idx])
        y_pred_all.extend(preds)

        print(
            f"fold {fold}: {len(train_idx)} train / {len(test_idx)} test "
            f"({len(test_groups)} scenario(s) held out: {sorted(test_groups)})"
        )

    y_true_all = np.array(y_true_all)
    y_pred_all = np.array(y_pred_all)

    labels_present = [c for c in RISK_CLASSES if c in set(y_true_all) | set(y_pred_all)]
    cm = confusion_matrix(y_true_all, y_pred_all, labels=labels_present)
    report = classification_report(
        y_true_all, y_pred_all, labels=labels_present, zero_division=0, output_dict=True
    )
    macro_f1 = f1_score(y_true_all, y_pred_all, labels=labels_present, average="macro", zero_division=0)

    return {
        "n_splits": n_splits,
        "labels_present": labels_present,
        "confusion_matrix": cm,
        "classification_report": report,
        "macro_f1": macro_f1,
        "y_true": y_true_all,
        "y_pred": y_pred_all,
    }


def print_report(results: dict) -> None:
    print()
    print("=" * 70)
    print(f"Grouped {results['n_splits']}-fold CV results (GroupKFold on scenario_id)")
    print("=" * 70)
    print(CIRCULARITY_NOTICE)
    print()
    print(f"Macro-F1 (out-of-fold, all folds pooled): {results['macro_f1']:.3f}")
    print()
    print("Per-class recall:")
    for cls in results["labels_present"]:
        recall = results["classification_report"].get(cls, {}).get("recall")
        support = results["classification_report"].get(cls, {}).get("support")
        print(f"  {cls:10s} recall={recall:.3f}  support={int(support)}")
    print()
    print("Confusion matrix (rows=true, cols=pred), labels =", results["labels_present"])
    header = "        " + "  ".join(f"{c:>9s}" for c in results["labels_present"])
    print(header)
    for label, row in zip(results["labels_present"], results["confusion_matrix"]):
        print(f"{label:8s}" + "  ".join(f"{v:9d}" for v in row))
    print("=" * 70)


def main() -> None:
    X, y, groups, pcap_paths = load_dataset()
    print(f"Loaded {len(X)} sessions, {len(set(groups))} distinct scenarios.")
    print(f"Class distribution: {dict(zip(*np.unique(y, return_counts=True)))}")

    results = run_grouped_cv(X, y, groups)
    print_report(results)

    # Final model: fit on ALL data for use by the fusion logic
    # (core/ml_fusion.py) and SHAP explanations. This is standard
    # practice (the CV above is what tells you how well it generalizes;
    # the deployed model uses every available labelled example) but is
    # NOT what the metrics above describe - the metrics above are from
    # held-out grouped folds, never from data the final model was
    # fit on.
    final_clf = RandomForestClassifier(n_estimators=200, class_weight="balanced", random_state=42)
    final_clf.fit(X, y)
    joblib.dump(final_clf, MODELS_DIR / "risk_classifier.joblib")
    print(f"\nFinal model (fit on all {len(X)} sessions) saved to ml/models/risk_classifier.joblib")

    metrics_out = {
        "n_sessions": len(X),
        "n_scenarios": len(set(groups)),
        "n_splits": results["n_splits"],
        "macro_f1": results["macro_f1"],
        "labels_present": results["labels_present"],
        "confusion_matrix": results["confusion_matrix"].tolist(),
        "per_class_recall": {
            cls: results["classification_report"][cls]["recall"]
            for cls in results["labels_present"]
        },
        "per_class_support": {
            cls: int(results["classification_report"][cls]["support"])
            for cls in results["labels_present"]
        },
        "circularity_notice": CIRCULARITY_NOTICE,
    }
    with open(MODELS_DIR / "cv_metrics.json", "w") as f:
        json.dump(metrics_out, f, indent=2)
    print("Metrics saved to ml/models/cv_metrics.json")


if __name__ == "__main__":
    main()
