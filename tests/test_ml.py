from pathlib import Path

import pytest

from core.findings import Finding
from ml.features import FEATURE_NAMES, extract_features_for_pcap
from ml.fusion import fuse_severity
from ml.train import load_dataset, run_grouped_cv

FIXTURES = Path(__file__).parent / "fixtures" / "pcaps"


# --- ml/features.py ---


def test_feature_vector_length():
    rows = extract_features_for_pcap(FIXTURES / "S17_smtp_587_plaintext_auth.pcap")
    assert len(rows) == 1
    assert list(rows[0].keys()) == FEATURE_NAMES
    assert len(rows[0]) == 33


def test_plaintext_auth_features():
    rows = extract_features_for_pcap(FIXTURES / "S17_smtp_587_plaintext_auth.pcap")
    f = rows[0]
    assert f["tls_mode_plaintext_only"] == 1.0
    assert f["auth_before_tls"] == 1.0
    assert f["tls_version_ordinal"] == 0.0  # no TLS ever negotiated
    assert f["capability_advertised_starttls"] == 1.0  # server did advertise it


def test_legacy_rc4_features():
    rows = extract_features_for_pcap(FIXTURES / "S32_legacy_rc4.pcap")
    f = rows[0]
    assert f["cipher_is_weak"] == 1.0
    assert f["kex_is_static"] == 1.0
    assert f["kex_is_ephemeral"] == 0.0
    assert f["cert_is_selfsigned"] == 1.0


def test_expired_cert_features():
    rows = extract_features_for_pcap(FIXTURES / "S18_smtp_587_starttls_expired_cert.pcap")
    f = rows[0]
    assert f["cert_observable"] == 1.0
    assert f["cert_is_expired"] == 1.0


def test_clean_tls13_features_no_observable_cert():
    rows = extract_features_for_pcap(FIXTURES / "S01b_smtp_587_starttls_auth.pcap")
    f = rows[0]
    assert f["tls_version_ordinal"] == 5.0
    assert f["cert_observable"] == 0.0  # TLS 1.3 - never guessed


# --- ml/fusion.py: no real pcap needed, pure logic ---


def _finding(severity: str, rule_id: str = "X") -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        score_impact=0,
        message="test",
        tcp_stream=0,
        protocol="smtp",
        server_port=587,
    )


def test_fusion_rules_loud_ml_agrees():
    verdict = fuse_severity([_finding("CRITICAL", "T-01")], "Critical")
    assert verdict.rules_silent is False
    assert verdict.final_severity == "CRITICAL"


def test_fusion_rules_silent_ml_critical_is_discounted_one_level():
    verdict = fuse_severity([], "Critical")
    assert verdict.rules_silent is True
    assert verdict.ml_severity_raw == "CRITICAL"
    assert verdict.ml_severity_adjusted == "HIGH"  # discounted by exactly one level
    assert verdict.final_severity == "HIGH"


def test_fusion_rules_silent_only_info_findings_ml_medium_discounted():
    verdict = fuse_severity([_finding("INFO", "CERT_NOT_OBSERVABLE")], "Medium")
    assert verdict.rules_silent is True  # INFO-only counts as silent
    assert verdict.ml_severity_adjusted == "LOW"
    assert verdict.final_severity == "LOW"


def test_fusion_rules_dominate_when_higher_than_discounted_ml():
    # Rules already found something worse than the ML's (undiscounted,
    # since rules are NOT silent here) contribution.
    verdict = fuse_severity([_finding("HIGH", "CERT_WEAK_KEY")], "Low")
    assert verdict.rules_silent is False
    assert verdict.final_severity == "HIGH"


def test_fusion_ml_can_raise_severity_above_rules_when_rules_not_silent():
    # Rules found something (not silent), but ML's undiscounted class is
    # still higher - fusion must take the max, not just defer to rules.
    verdict = fuse_severity([_finding("LOW", "TLS_VERSION_1_2")], "Critical")
    assert verdict.rules_silent is False
    assert verdict.ml_severity_adjusted == "CRITICAL"  # no discount - rules not silent
    assert verdict.final_severity == "CRITICAL"


def test_fusion_never_lowers_below_info():
    verdict = fuse_severity([], "Low")
    assert verdict.ml_severity_raw == "LOW"
    assert verdict.ml_severity_adjusted == "INFO"  # floor at INFO, not negative
    assert verdict.final_severity == "INFO"


def test_fusion_rejects_unknown_risk_class():
    with pytest.raises(ValueError):
        fuse_severity([], "Unknown")


# --- ml/train.py: leakage guard ---


def test_grouped_cv_never_leaks_a_scenario_across_train_and_test():
    X, y, groups, pcap_paths = load_dataset()
    assert len(X) == 30
    assert len(set(groups)) == 21
    # run_grouped_cv itself asserts train/test group disjointness per
    # fold internally; this test additionally confirms it completes
    # without raising and returns a well-formed result.
    results = run_grouped_cv(X, y, groups)
    assert results["n_splits"] >= 2
    assert set(results["y_true"]) <= {"Low", "Medium", "High", "Critical"}
    assert results["confusion_matrix"].shape[0] == len(results["labels_present"])
