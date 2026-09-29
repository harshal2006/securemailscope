"""Runs a real uvicorn server (not Starlette's TestClient, which executes
background tasks essentially synchronously and wouldn't actually prove
non-blocking behavior) and confirms POST /analyze returns immediately
while analysis continues in the background, and that concurrent
submissions don't serialize.
"""

import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest
import requests

FIXTURES = Path(__file__).parent / "fixtures" / "pcaps"
REPO_ROOT = Path(__file__).parent.parent


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def live_server():
    port = _free_port()
    db_path = REPO_ROOT / "data" / "securemailscope_live_test.db"
    db_path.unlink(missing_ok=True)

    env = {"SECUREMAILSCOPE_DB_PATH": str(db_path)}
    import os

    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "api.main:app", "--port", str(port), "--host", "127.0.0.1"],
        cwd=REPO_ROOT,
        env={**os.environ, **env},
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    base_url = f"http://127.0.0.1:{port}"

    deadline = time.time() + 15
    up = False
    while time.time() < deadline:
        try:
            r = requests.get(f"{base_url}/health", timeout=1)
            if r.status_code == 200:
                up = True
                break
        except requests.exceptions.ConnectionError:
            time.sleep(0.2)
    if not up:
        proc.terminate()
        out = proc.stdout.read() if proc.stdout else ""
        pytest.fail(f"live server did not start in time. Output:\n{out}")

    yield base_url

    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
    db_path.unlink(missing_ok=True)


def test_post_analyze_returns_before_analysis_completes(live_server):
    with open(FIXTURES / "S17_smtp_587_plaintext_auth.pcap", "rb") as f:
        t0 = time.monotonic()
        r = requests.post(
            f"{live_server}/api/v1/analyze",
            files={"file": ("S17.pcap", f, "application/octet-stream")},
        )
        post_elapsed = time.monotonic() - t0
    assert r.status_code == 200
    job_id = r.json()["job_id"]

    # The POST itself must return fast - it only needs to save the
    # upload and schedule the background task, not run the analysis.
    assert post_elapsed < 1.0, f"POST /analyze took {post_elapsed:.2f}s - looks like it's blocking"

    # Poll until done (proves the background task actually runs).
    deadline = time.time() + 10
    status = None
    while time.time() < deadline:
        status = requests.get(f"{live_server}/api/v1/jobs/{job_id}").json()["status"]
        if status in ("done", "failed"):
            break
        time.sleep(0.1)
    assert status == "done"


def test_concurrent_submissions_do_not_serialize(live_server):
    """Submits 4 real jobs concurrently against the live server and
    confirms total wall-clock time is nowhere near 4x a single job's
    time - proving the server isn't processing them one at a time while
    blocking new requests.
    """
    pcaps = [
        "S17_smtp_587_plaintext_auth.pcap",
        "S18_smtp_587_starttls_expired_cert.pcap",
        "S32_legacy_rc4.pcap",
        "S33_legacy_3des.pcap",
    ]

    def submit(name: str) -> tuple[str, float]:
        with open(FIXTURES / name, "rb") as f:
            t0 = time.monotonic()
            r = requests.post(
                f"{live_server}/api/v1/analyze",
                files={"file": (name, f, "application/octet-stream")},
            )
        assert r.status_code == 200
        return r.json()["job_id"], time.monotonic() - t0

    import concurrent.futures

    t_start = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(submit, pcaps))
    submit_wall_time = time.monotonic() - t_start

    # All 4 POSTs together must complete quickly - if analysis blocked
    # the event loop, this would take roughly 4x a single job's real
    # analysis time instead.
    assert submit_wall_time < 4.0, f"4 concurrent POSTs took {submit_wall_time:.2f}s combined"

    job_ids = [jid for jid, _ in results]
    deadline = time.time() + 15
    statuses = {}
    while time.time() < deadline and len(statuses) < len(job_ids):
        for jid in job_ids:
            if jid in statuses:
                continue
            s = requests.get(f"{live_server}/api/v1/jobs/{jid}").json()["status"]
            if s in ("done", "failed"):
                statuses[jid] = s
        time.sleep(0.1)

    assert len(statuses) == len(job_ids)
    assert all(s == "done" for s in statuses.values()), statuses
