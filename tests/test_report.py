from pathlib import Path

import jsonschema
import pytest

from core.report import (
    REPORT_JSON_SCHEMA,
    build_report,
    render_html,
    report_to_dict,
    report_to_json,
)

FIXTURES = Path(__file__).parent / "fixtures" / "pcaps"


def test_s17_report_json_validates_against_schema():
    report = build_report(FIXTURES / "S17_smtp_587_plaintext_auth.pcap")
    data = report_to_dict(report)
    jsonschema.validate(instance=data, schema=REPORT_JSON_SCHEMA)  # raises on failure


def test_s18_report_json_validates_against_schema():
    report = build_report(FIXTURES / "S18_smtp_587_starttls_expired_cert.pcap")
    report_to_json(report)  # validates internally by default


def test_report_to_json_raises_on_schema_violation():
    report = build_report(FIXTURES / "S17_smtp_587_plaintext_auth.pcap")
    data = report_to_dict(report)
    del data["summary"]["grade"]  # required field
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(instance=data, schema=REPORT_JSON_SCHEMA)


def test_s17_summary_values():
    report = build_report(FIXTURES / "S17_smtp_587_plaintext_auth.pcap")
    assert report.summary.overall_score == 0
    assert report.summary.grade == "F"
    assert report.summary.findings_by_severity.get("CRITICAL") == 2
    assert report.summary.findings_by_severity.get("HIGH") == 1


def test_s18_cert_expired_summary():
    report = build_report(FIXTURES / "S18_smtp_587_starttls_expired_cert.pcap")
    assert report.summary.overall_score == 65
    assert report.summary.grade == "D"
    assert report.summary.observable_cert_ratio == 1.0
    cert = report.sessions[0].certificate
    assert cert is not None
    assert cert.is_expired is True


def test_grade_boundaries():
    from core.report import _grade

    assert _grade(None) == "N/A"
    assert _grade(100) == "A"
    assert _grade(90) == "A"
    assert _grade(89) == "B"
    assert _grade(70) == "C"
    assert _grade(60) == "D"
    assert _grade(59) == "F"
    assert _grade(0) == "F"


def test_report_never_leaks_credentials_json():
    report = build_report(FIXTURES / "S17_smtp_587_plaintext_auth.pcap")
    text = report_to_json(report)
    assert "labpass" not in text
    assert "bGFicGFzcw" not in text
    assert "bGFidXNlcg" not in text


def test_report_never_leaks_credentials_html():
    report = build_report(FIXTURES / "S17_smtp_587_plaintext_auth.pcap")
    html = render_html(report)
    assert "labpass" not in html
    assert "bGFicGFzcw" not in html


def test_recommendations_only_for_actionable_findings():
    report = build_report(FIXTURES / "S01b_smtp_587_starttls_auth.pcap")
    # S01b: TLS 1.3, cert not observable - both purely informational.
    rec_rule_ids = {r.rule_id for r in report.recommendations}
    assert "TLS_VERSION_1_3" not in rec_rule_ids
    assert "CERT_NOT_OBSERVABLE" not in rec_rule_ids


def test_recommendations_deduplicated_across_sessions():
    report = build_report(FIXTURES / "S17_smtp_587_plaintext_auth.pcap")
    rule_ids = [r.rule_id for r in report.recommendations]
    assert len(rule_ids) == len(set(rule_ids))


def test_rules_reference_covers_implemented_rules():
    report = build_report(FIXTURES / "S17_smtp_587_plaintext_auth.pcap")
    rule_ids = {r.rule_id for r in report.rules_reference}
    for expected in (
        "TLS_VERSION_SSL3", "TLS_VERSION_1_0", "TLS_VERSION_1_1", "TLS_VERSION_1_2",
        "CERT_EXPIRED", "CERT_SELF_SIGNED", "CERT_WEAK_KEY", "CERT_WEAK_SIGNATURE_HASH",
        "CERT_HOSTNAME_MISMATCH", "WEAK_CIPHER_SUITE", "NO_FORWARD_SECRECY",
        "T-01", "T-02", "T-03",
    ):
        assert expected in rule_ids


# --- HTML rendering: content checks against known fixtures ---


def test_s17_html_contains_expected_finding_ids():
    report = build_report(FIXTURES / "S17_smtp_587_plaintext_auth.pcap")
    html = render_html(report)
    assert "T-01" in html
    assert "T-02" in html
    assert "NO_TLS_OBSERVED" in html
    assert "CRITICAL" in html


def test_s18_html_contains_expired_cert_evidence():
    report = build_report(FIXTURES / "S18_smtp_587_starttls_expired_cert.pcap")
    html = render_html(report)
    assert "CERT_EXPIRED" in html
    assert "X-01" in html
    assert "mail.lab.test" in html
    assert "expired" in html


def test_html_placeholders_are_escaped_not_swallowed():
    # Regression test: <host>:<port> in recommendation commands were
    # silently eaten by the browser because select_autoescape(["html"])
    # checked the template filename's extension (report.html.j2 ends in
    # .j2, not .html), leaving autoescaping off. Found via screenshot
    # review, fixed by forcing autoescape=True unconditionally.
    report = build_report(FIXTURES / "S17_smtp_587_plaintext_auth.pcap")
    html = render_html(report)
    assert "&lt;host&gt;" in html
    assert "<host>" not in html


def test_html_has_no_unrendered_jinja_syntax():
    report = build_report(FIXTURES / "S17_smtp_587_plaintext_auth.pcap")
    html = render_html(report)
    assert "{{" not in html
    assert "{%" not in html


def test_multiple_reports_all_validate(tmp_path):
    for name in [
        "S17_smtp_587_plaintext_auth.pcap",
        "S01b_smtp_587_starttls_auth.pcap",
        "S18_smtp_587_starttls_expired_cert.pcap",
        "S19_smtp_587_starttls_selfsigned_cert.pcap",
        "S26_smtp_2588_starttls_disabled.pcap",
        "S32_legacy_rc4.pcap",
        "S33_legacy_3des.pcap",
        "S34_legacy_ssl3.pcap",
        "S35_legacy_tls1_1.pcap",
    ]:
        report = build_report(FIXTURES / name)
        report_to_json(report)  # schema-validates internally
        html = render_html(report)
        assert "{{" not in html
