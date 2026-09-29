"""Fuses rule-engine findings with the ML risk classifier's prediction
into one final severity per session, instead of running the ML model
standalone.

Fusion rule (as specified): final severity = max(rule severity, ML
class), where the ML class is lowered by at most one level before that
max whenever the rules are "silent" - i.e. produced no actionable
(above-INFO) finding for the session. This means:

- If the rules already flagged something, the ML class competes at full
  strength (it can still raise the final severity above what the rules
  alone found, e.g. if ML learned a pattern the rules don't check for).
- If the rules found nothing actionable, the ML class is discounted by
  one level before competing - so a lone, uncorroborated ML "Critical"
  call on an otherwise rule-clean session surfaces as at most "High",
  reflecting lower trust in an ML-only verdict with no rule evidence
  behind it.

This is deliberately conservative: rules (deterministic, explainable,
verified against real captures - see docs/STATUS.md) are never
overridden or discounted; ML can only ever add signal, and only
cautiously when it's the sole source.
"""

from __future__ import annotations

from dataclasses import dataclass

from core.findings import Finding

SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
RISK_CLASS_TO_SEVERITY = {
    "Low": "LOW",
    "Medium": "MEDIUM",
    "High": "HIGH",
    "Critical": "CRITICAL",
}


def _rank(severity: str) -> int:
    return SEVERITY_ORDER.index(severity)


@dataclass
class FusedVerdict:
    rule_severity: str  # worst severity among this session's findings ("INFO" if none)
    rules_silent: bool  # True if no above-INFO finding exists
    ml_risk_class: str
    ml_severity_raw: str
    ml_severity_adjusted: str  # after the one-level discount, if applied
    final_severity: str


def fuse_severity(rule_findings: list[Finding], ml_risk_class: str) -> FusedVerdict:
    if ml_risk_class not in RISK_CLASS_TO_SEVERITY:
        raise ValueError(f"unknown ML risk class: {ml_risk_class!r}")

    rule_severities = [f.severity for f in rule_findings]
    actionable = [s for s in rule_severities if s != "INFO"]
    rules_silent = len(actionable) == 0
    rule_worst = max(rule_severities, key=_rank) if rule_severities else "INFO"

    ml_severity_raw = RISK_CLASS_TO_SEVERITY[ml_risk_class]
    if rules_silent:
        ml_severity_adjusted = SEVERITY_ORDER[max(0, _rank(ml_severity_raw) - 1)]
    else:
        ml_severity_adjusted = ml_severity_raw

    final_severity = max([rule_worst, ml_severity_adjusted], key=_rank)

    return FusedVerdict(
        rule_severity=rule_worst,
        rules_silent=rules_silent,
        ml_risk_class=ml_risk_class,
        ml_severity_raw=ml_severity_raw,
        ml_severity_adjusted=ml_severity_adjusted,
        final_severity=final_severity,
    )
