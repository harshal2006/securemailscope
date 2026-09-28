from core.findings import Finding
from core.scoring import build_posture_report, score_session_findings


def _finding(rule_id, severity, score_impact) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        score_impact=score_impact,
        message="test",
        tcp_stream=0,
        protocol="smtp",
        server_port=2525,
    )


def test_score_session_with_no_findings_is_100():
    assert score_session_findings([]) == 100


def test_score_session_subtracts_impact():
    findings = [_finding("A", "LOW", 5), _finding("B", "HIGH", 25)]
    assert score_session_findings(findings) == 70


def test_score_session_floors_at_zero():
    findings = [_finding("A", "CRITICAL", 60), _finding("B", "CRITICAL", 60)]
    assert score_session_findings(findings) == 0


class _FakeSession:
    def __init__(self, tcp_stream, protocol, server_port):
        self.tcp_stream = tcp_stream
        self.protocol = protocol
        self.server_port = server_port


def test_overall_score_is_minimum_of_sessions():
    good_session = _FakeSession(0, "smtp", 465)
    bad_session = _FakeSession(1, "imap", 143)

    report = build_posture_report(
        [
            (good_session, []),
            (bad_session, [_finding("NO_TLS_OBSERVED", "CRITICAL", 60)]),
        ]
    )
    assert report.session_scores[0].score == 100
    assert report.session_scores[1].score == 40
    assert report.overall_score == 40


def test_overall_score_none_when_no_sessions():
    report = build_posture_report([])
    assert report.overall_score is None
    assert report.session_scores == []
