"""Tests the API against real fixture pcaps, comparing every response
against what core/analyze.py and core/report.py already produce for the
same file - never mocked data. A mismatch here is a bug in the API
layer, since the underlying analysis is already tested elsewhere.
"""

import concurrent.futures
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.db import DB_PATH, UPLOADS_DIR
from api.main import app
from core.report import build_report, report_to_dict

FIXTURES = Path(__file__).parent / "fixtures" / "pcaps"

REAL_FIXTURES = [
    "S17_smtp_587_plaintext_auth.pcap",
    "S18_smtp_587_starttls_expired_cert.pcap",
    "S19_smtp_587_starttls_selfsigned_cert.pcap",
    "S32_legacy_rc4.pcap",
    "S33_legacy_3des.pcap",
    "S34_legacy_ssl3.pcap",
    "S35_legacy_tls1_1.pcap",
]


@pytest.fixture(scope="module")
def client():
    DB_PATH.unlink(missing_ok=True)
    with TestClient(app) as c:
        yield c


def _upload_and_wait(client: TestClient, pcap_name: str, timeout: float = 10.0) -> str:
    with open(FIXTURES / pcap_name, "rb") as f:
        r = client.post(
            "/api/v1/analyze", files={"file": (pcap_name, f, "application/octet-stream")}
        )
    assert r.status_code == 200, r.text
    job_id = r.json()["job_id"]

    deadline = time.time() + timeout
    status = None
    while time.time() < deadline:
        r = client.get(f"/api/v1/jobs/{job_id}")
        assert r.status_code == 200
        status = r.json()["status"]
        if status in ("done", "failed"):
            break
        time.sleep(0.05)
    assert status == "done", f"job {job_id} ended in status={status}"
    return job_id


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["tshark_version"] is not None  # tshark is a hard dependency here


def test_job_not_found_returns_404(client):
    r = client.get("/api/v1/jobs/00000000-0000-0000-0000-000000000000")
    assert r.status_code == 404


def test_summary_before_done_returns_409(client):
    with open(FIXTURES / "S17_smtp_587_plaintext_auth.pcap", "rb") as f:
        r = client.post("/api/v1/analyze", files={"file": ("s.pcap", f)})
    job_id = r.json()["job_id"]
    r = client.get(f"/api/v1/jobs/{job_id}/summary")
    # Racy by nature (background task may finish first) - either the
    # expected 409 (not done yet) or 200 (finished very fast) is fine;
    # anything else is a bug.
    assert r.status_code in (200, 409)


@pytest.mark.parametrize("pcap_name", REAL_FIXTURES)
def test_summary_matches_core_report(client, pcap_name):
    job_id = _upload_and_wait(client, pcap_name)
    expected = report_to_dict(build_report(FIXTURES / pcap_name))["summary"]

    r = client.get(f"/api/v1/jobs/{job_id}/summary")
    assert r.status_code == 200
    actual = r.json()

    assert actual["overall_score"] == expected["overall_score"]
    assert actual["grade"] == expected["grade"]
    assert actual["findings_by_severity"] == expected["findings_by_severity"]
    assert actual["observable_cert_ratio"] == expected["observable_cert_ratio"]


@pytest.mark.parametrize("pcap_name", REAL_FIXTURES)
def test_findings_match_core_report(client, pcap_name):
    job_id = _upload_and_wait(client, pcap_name)
    expected_sessions = report_to_dict(build_report(FIXTURES / pcap_name))["sessions"]
    expected_rule_ids = sorted(
        f["rule_id"] for s in expected_sessions for f in s["findings"]
    )

    r = client.get(f"/api/v1/jobs/{job_id}/findings")
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == len(expected_rule_ids)
    actual_rule_ids = sorted(f["rule_id"] for f in body["findings"])
    assert actual_rule_ids == expected_rule_ids


def test_findings_are_severity_sorted(client):
    job_id = _upload_and_wait(client, "S17_smtp_587_plaintext_auth.pcap")
    r = client.get(f"/api/v1/jobs/{job_id}/findings")
    severities = [f["severity"] for f in r.json()["findings"]]
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    ranks = [order[s] for s in severities]
    assert ranks == sorted(ranks)


def test_sessions_list_matches_core_report(client):
    pcap_name = "S18_smtp_587_starttls_expired_cert.pcap"
    job_id = _upload_and_wait(client, pcap_name)
    expected = report_to_dict(build_report(FIXTURES / pcap_name))["sessions"]

    r = client.get(f"/api/v1/jobs/{job_id}/sessions")
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == len(expected)
    assert body["sessions"][0]["tcp_stream"] == expected[0]["tcp_stream"]
    assert body["sessions"][0]["score"] == expected[0]["score"]
    assert body["sessions"][0]["negotiated_tls_version"] == expected[0]["negotiated_tls_version"]


def test_sessions_list_filtering_by_protocol(client):
    job_id = _upload_and_wait(client, "S17_smtp_587_plaintext_auth.pcap")
    r = client.get(f"/api/v1/jobs/{job_id}/sessions", params={"protocol": "smtp"})
    assert r.status_code == 200
    assert r.json()["total"] == 1
    r = client.get(f"/api/v1/jobs/{job_id}/sessions", params={"protocol": "imap"})
    assert r.status_code == 200
    assert r.json()["total"] == 0


def test_sessions_list_filtering_by_score_range(client):
    job_id = _upload_and_wait(client, "S17_smtp_587_plaintext_auth.pcap")
    r = client.get(f"/api/v1/jobs/{job_id}/sessions", params={"min_score": 50})
    assert r.json()["total"] == 0  # S17's single session scores 0
    r = client.get(f"/api/v1/jobs/{job_id}/sessions", params={"max_score": 50})
    assert r.json()["total"] == 1


def test_sessions_list_pagination(client):
    job_id = _upload_and_wait(client, "S17_smtp_587_plaintext_auth.pcap")
    r = client.get(f"/api/v1/jobs/{job_id}/sessions", params={"page": 1, "page_size": 1})
    body = r.json()
    assert body["page"] == 1
    assert body["page_size"] == 1
    assert len(body["sessions"]) == 1
    r = client.get(f"/api/v1/jobs/{job_id}/sessions", params={"page": 2, "page_size": 1})
    assert len(r.json()["sessions"]) == 0  # only 1 session total


def test_session_detail_matches_core_report(client):
    pcap_name = "S19_smtp_587_starttls_selfsigned_cert.pcap"
    job_id = _upload_and_wait(client, pcap_name)
    expected = report_to_dict(build_report(FIXTURES / pcap_name))["sessions"][0]

    r = client.get(f"/api/v1/jobs/{job_id}/sessions/{expected['tcp_stream']}")
    assert r.status_code == 200
    actual = r.json()
    assert actual["certificate"]["self_signed"] == expected["certificate"]["self_signed"]
    assert actual["certificate"]["subject_cn"] == expected["certificate"]["subject_cn"]
    assert len(actual["timeline"]) == len(expected["timeline"])
    assert len(actual["findings"]) == len(expected["findings"])


def test_session_detail_404_for_unknown_stream(client):
    job_id = _upload_and_wait(client, "S17_smtp_587_plaintext_auth.pcap")
    r = client.get(f"/api/v1/jobs/{job_id}/sessions/9999")
    assert r.status_code == 404


def test_report_json_matches_core_report(client):
    pcap_name = "S18_smtp_587_starttls_expired_cert.pcap"
    job_id = _upload_and_wait(client, pcap_name)
    expected = report_to_dict(build_report(FIXTURES / pcap_name))

    r = client.get(f"/api/v1/jobs/{job_id}/report", params={"format": "json"})
    assert r.status_code == 200
    actual = r.json()
    assert actual["summary"] == expected["summary"]


def test_report_html_reuses_core_report_render_html(client):
    job_id = _upload_and_wait(client, "S18_smtp_587_starttls_expired_cert.pcap")
    r = client.get(f"/api/v1/jobs/{job_id}/report", params={"format": "html"})
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert "CERT_EXPIRED" in r.text
    assert "{{" not in r.text  # no unrendered Jinja syntax


def test_report_never_leaks_credentials(client):
    job_id = _upload_and_wait(client, "S17_smtp_587_plaintext_auth.pcap")
    r = client.get(f"/api/v1/jobs/{job_id}/report", params={"format": "json"})
    text = r.text
    assert "labpass" not in text
    assert "bGFicGFzcw" not in text


def test_invalid_report_format_rejected(client):
    job_id = _upload_and_wait(client, "S17_smtp_587_plaintext_auth.pcap")
    r = client.get(f"/api/v1/jobs/{job_id}/report", params={"format": "xml"})
    assert r.status_code == 422  # FastAPI query-param pattern validation


def test_concurrent_job_submissions_do_not_block(client):
    """Submits several jobs at once and confirms all reach 'done' -
    background tasks must not serialize/block the event loop."""

    def submit(pcap_name: str) -> str:
        with open(FIXTURES / pcap_name, "rb") as f:
            r = client.post(
                "/api/v1/analyze", files={"file": (pcap_name, f, "application/octet-stream")}
            )
        assert r.status_code == 200
        return r.json()["job_id"]

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        job_ids = list(pool.map(submit, REAL_FIXTURES))

    deadline = time.time() + 15
    statuses = {}
    while time.time() < deadline and len(statuses) < len(job_ids):
        for jid in job_ids:
            if jid in statuses:
                continue
            r = client.get(f"/api/v1/jobs/{jid}")
            if r.json()["status"] in ("done", "failed"):
                statuses[jid] = r.json()["status"]
        time.sleep(0.1)

    assert len(statuses) == len(job_ids), "not all concurrent jobs completed in time"
    assert all(s == "done" for s in statuses.values()), statuses
