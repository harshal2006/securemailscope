"""Verifies dashboard/app.py against a real running API (never mocked),
using Streamlit's own testing framework (st.testing.v1.AppTest) rather
than a screenshot - this runs the actual script and inspects its
rendered elements programmatically, which is more reliable for CI than
a browser screenshot. Manual screenshot verification against the same
S17 fixture (Overview and Findings pages) was also done separately and
matched this test's assertions exactly - see docs/STATUS.md.
"""

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest
import requests
from streamlit.testing.v1 import AppTest

REPO_ROOT = Path(__file__).parent.parent
APP_PATH = REPO_ROOT / "dashboard" / "app.py"


@pytest.fixture(scope="module")
def live_api():
    """Runs the real API on the dashboard's default port (8000), backed
    by an isolated DB file, so dashboard/app.py's DEFAULT_API_BASE_URL
    just works without needing to drive the sidebar text_input widget.
    """
    db_path = REPO_ROOT / "data" / "securemailscope_dashboard_test.db"
    db_path.unlink(missing_ok=True)

    env = {**os.environ, "SECUREMAILSCOPE_DB_PATH": str(db_path)}
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "api.main:app", "--port", "8000", "--host", "127.0.0.1"],
        cwd=REPO_ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    deadline = time.time() + 15
    up = False
    while time.time() < deadline:
        try:
            r = requests.get("http://127.0.0.1:8000/health", timeout=1)
            if r.status_code == 200:
                up = True
                break
        except requests.exceptions.ConnectionError:
            time.sleep(0.2)
    if not up:
        proc.terminate()
        out = proc.stdout.read() if proc.stdout else ""
        pytest.fail(f"API did not start in time for dashboard tests. Output:\n{out}")

    yield "http://127.0.0.1:8000"

    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
    db_path.unlink(missing_ok=True)


def test_dashboard_demo_mode_loads_s17_by_default(live_api):
    # No job_id in session_state -> dashboard's demo-mode auto-loads
    # S17 (plaintext AUTH, no STARTTLS) through the real API on first run.
    at = AppTest.from_file(str(APP_PATH), default_timeout=30)
    at.run()

    assert not at.exception, [str(e) for e in at.exception]

    metric_values = {m.label: m.value for m in list(at.sidebar.metric) + list(at.metric)}
    assert metric_values.get("Posture score") == "0/100"
    assert metric_values.get("Grade") == "F"
    assert metric_values.get("Sessions") == "1"


def test_dashboard_findings_page_matches_api(live_api):
    at = AppTest.from_file(str(APP_PATH), default_timeout=30)
    at.run()
    assert not at.exception

    at.sidebar.radio[0].set_value("Findings").run()
    assert not at.exception

    body_text = "\n".join(m.value for m in at.markdown)
    code_text = "\n".join(c.value for c in at.code)
    assert "T-01" in body_text
    assert "T-02" in body_text
    assert "NO_TLS_OBSERVED" in body_text
    assert "CRITICAL" in body_text
    # Recommendation fix text and verification command must appear too.
    assert "smtpd_tls_auth_only" in body_text
    assert "swaks" in code_text


def test_dashboard_never_leaks_credentials(live_api):
    at = AppTest.from_file(str(APP_PATH), default_timeout=30)
    at.run()
    at.sidebar.radio[0].set_value("Sessions").run()
    assert not at.exception

    all_text = "\n".join(m.value for m in at.markdown) + "\n".join(
        str(df.value) for df in at.dataframe
    )
    assert "labpass" not in all_text
    assert "bGFicGFzcw" not in all_text
