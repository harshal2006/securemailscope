"""SHAP explanations for at least one prediction per risk class, saved
as actual evidence (a plot + the raw per-feature values), not just
claimed. Uses the final model (fit on all data) from ml/train.py.
"""

from __future__ import annotations

import json
from pathlib import Path

import joblib
import matplotlib

matplotlib.use("Agg")  # no display in this environment
import matplotlib.pyplot as plt
import numpy as np
import shap

from ml.train import RISK_CLASSES, load_dataset

ML_DIR = Path(__file__).parent
MODELS_DIR = ML_DIR / "models"
EXPLANATIONS_DIR = MODELS_DIR / "shap_explanations"


def main() -> None:
    EXPLANATIONS_DIR.mkdir(parents=True, exist_ok=True)

    clf = joblib.load(MODELS_DIR / "risk_classifier.joblib")
    X, y, groups, pcap_paths = load_dataset()

    explainer = shap.TreeExplainer(clf)
    shap_values = explainer.shap_values(X)  # shape: (n_samples, n_features, n_classes) or list per class

    # sklearn's class order (alphabetical by default for RandomForestClassifier.classes_)
    class_order = list(clf.classes_)
    print("Model class order:", class_order)

    summary = []

    for target_class in RISK_CLASSES:
        if target_class not in y:
            print(f"[{target_class}] no example in dataset, skipping")
            continue
        idx = int(np.where(y == target_class)[0][0])
        pcap_name = pcap_paths[idx]
        class_idx = class_order.index(target_class)

        # shap_values can be a list (one array per class) or a single
        # 3D array depending on shap version; handle both.
        if isinstance(shap_values, list):
            sv_row = shap_values[class_idx][idx]
        else:
            sv_row = shap_values[idx, :, class_idx]

        feature_names = list(X.columns)
        contributions = sorted(
            zip(feature_names, sv_row.tolist()), key=lambda t: -abs(t[1])
        )[:10]

        print(f"\n[{target_class}] example: {pcap_name} (scenario={groups[idx]})")
        for name, val in contributions:
            print(f"    {name:30s} {val:+.4f}")

        fig, ax = plt.subplots(figsize=(8, 5))
        names = [c[0] for c in contributions][::-1]
        values = [c[1] for c in contributions][::-1]
        colors = ["#ff5470" if v > 0 else "#4fd1c5" for v in values]
        ax.barh(names, values, color=colors)
        ax.set_title(f"SHAP contributions - {target_class}\n{pcap_name}")
        ax.set_xlabel(f"SHAP value (impact on predicting '{target_class}')")
        fig.tight_layout()
        out_path = EXPLANATIONS_DIR / f"{target_class.lower()}_{Path(pcap_name).stem}.png"
        fig.savefig(out_path, dpi=120)
        plt.close(fig)
        print(f"    saved plot: {out_path}")

        summary.append(
            {
                "risk_class": target_class,
                "pcap": pcap_name,
                "scenario_id": groups[idx],
                "predicted_class": clf.predict(X.iloc[[idx]])[0],
                "top_features": [{"feature": n, "shap_value": v} for n, v in contributions],
                "plot": str(out_path.relative_to(ML_DIR)),
            }
        )

    with open(EXPLANATIONS_DIR / "summary.json", "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\nSaved explanation summary: {EXPLANATIONS_DIR / 'summary.json'}")


if __name__ == "__main__":
    main()
