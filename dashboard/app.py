"""SecureMailScope dashboard.

Talks to api/main.py over plain HTTP only - it never imports core.* or
runs analysis itself. This is deliberate: if this dashboard works, it
proves the API is a real, standalone, usable service, not just an
internal implementation detail of this UI.

Run: streamlit run dashboard/app.py
(with the API running separately: uvicorn api.main:app)
"""

from __future__ import annotations

import time
from pathlib import Path

import plotly.graph_objects as go
import requests
import streamlit as st

DEFAULT_API_BASE_URL = "http://127.0.0.1:8000"
FIXTURES_DIR = Path(__file__).parent.parent / "tests" / "fixtures" / "pcaps"

DEMO_FIXTURES = {
    "S17 - plaintext AUTH LOGIN, no STARTTLS (score 0, worst case)": "S17_smtp_587_plaintext_auth.pcap",
    "S32 - legacy RC4 cipher + no forward secrecy": "S32_legacy_rc4.pcap",
    "S18 - expired certificate": "S18_smtp_587_starttls_expired_cert.pcap",
    "S01b - clean STARTTLS + AUTH inside TLS (score 100, best case)": "S01b_smtp_587_starttls_auth.pcap",
}

SEVERITY_COLORS = {
    "CRITICAL": "#ff5470",
    "HIGH": "#ff9f43",
    "MEDIUM": "#f5d90a",
    "LOW": "#4fd1c5",
    "INFO": "#6c8cff",
}

st.set_page_config(page_title="SecureMailScope", layout="wide", page_icon="\U0001f4e7")


# --- API helpers (the only place this file talks to anything analysis-related) ---


def api_get(path: str, **params) -> dict:
    r = requests.get(f"{API_BASE_URL}{path}", params=params, timeout=10)
    r.raise_for_status()
    return r.json()


def submit_pcap(file_bytes: bytes, filename: str) -> str:
    r = requests.post(
        f"{API_BASE_URL}/api/v1/analyze",
        files={"file": (filename, file_bytes, "application/octet-stream")},
        timeout=30,
    )
    r.raise_for_status()
    return r.json()["job_id"]


def wait_for_job(job_id: str, timeout: float = 15.0) -> dict:
    deadline = time.time() + timeout
    status = api_get(f"/api/v1/jobs/{job_id}")
    while status["status"] in ("queued", "running") and time.time() < deadline:
        time.sleep(0.2)
        status = api_get(f"/api/v1/jobs/{job_id}")
    return status


@st.cache_data(ttl=30, show_spinner=False)
def fetch_report(job_id: str) -> dict:
    return api_get(f"/api/v1/jobs/{job_id}/report", format="json")


# --- Sidebar: API health, load a demo fixture, or upload a pcap ---


with st.sidebar:
    st.title("\U0001f4e7 SecureMailScope")
    st.caption("Passive email-crypto posture dashboard")

    API_BASE_URL = st.text_input("API base URL", value=DEFAULT_API_BASE_URL)

    try:
        health = api_get("/health")
        st.success(f"API up · tshark: {health['tshark_version'] or 'not found'}")
    except requests.exceptions.RequestException as exc:
        st.error(f"API unreachable at {API_BASE_URL}: {exc}")
        st.stop()

    st.divider()
    st.subheader("Load a capture")

    demo_label = st.selectbox("Demo fixture (real lab pcap)", list(DEMO_FIXTURES.keys()))
    if st.button("Analyze demo fixture", type="primary", use_container_width=True):
        pcap_path = FIXTURES_DIR / DEMO_FIXTURES[demo_label]
        with st.spinner(f"Uploading and analyzing {pcap_path.name}..."):
            job_id = submit_pcap(pcap_path.read_bytes(), pcap_path.name)
            status = wait_for_job(job_id)
        if status["status"] != "done":
            st.error(f"Analysis {status['status']}: {status.get('error')}")
        else:
            st.session_state["job_id"] = job_id
            st.session_state["pcap_label"] = pcap_path.name
            fetch_report.clear()

    uploaded = st.file_uploader("...or upload your own pcap", type=["pcap", "pcapng"])
    if uploaded is not None and st.button("Analyze upload", use_container_width=True):
        with st.spinner(f"Uploading and analyzing {uploaded.name}..."):
            job_id = submit_pcap(uploaded.getvalue(), uploaded.name)
            status = wait_for_job(job_id)
        if status["status"] != "done":
            st.error(f"Analysis {status['status']}: {status.get('error')}")
        else:
            st.session_state["job_id"] = job_id
            st.session_state["pcap_label"] = uploaded.name
            fetch_report.clear()

    # Demo mode: nothing analyzed yet on first launch - load a default
    # fixture automatically so the dashboard never opens to an empty
    # state.
    if "job_id" not in st.session_state:
        default_name = DEMO_FIXTURES["S17 - plaintext AUTH LOGIN, no STARTTLS (score 0, worst case)"]
        pcap_path = FIXTURES_DIR / default_name
        with st.spinner("Loading default demo capture..."):
            job_id = submit_pcap(pcap_path.read_bytes(), pcap_path.name)
            status = wait_for_job(job_id)
        if status["status"] == "done":
            st.session_state["job_id"] = job_id
            st.session_state["pcap_label"] = pcap_path.name

    if "job_id" in st.session_state:
        st.divider()
        st.caption(f"Current: **{st.session_state.get('pcap_label', '?')}**")
        st.caption(f"job_id: `{st.session_state['job_id']}`")

    st.divider()
    page = st.radio("Page", ["Overview", "Sessions", "Certificates", "Findings"])


if "job_id" not in st.session_state:
    st.info("Load a capture from the sidebar to begin.")
    st.stop()

job_id = st.session_state["job_id"]
try:
    report = fetch_report(job_id)
except requests.exceptions.RequestException as exc:
    st.error(f"Could not fetch report: {exc}")
    st.stop()

summary = report["summary"]
sessions = report["sessions"]
recommendations = report["recommendations"]


# --- Overview ---

if page == "Overview":
    st.header("Overview")

    score = summary["overall_score"]
    grade = summary["grade"]

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Posture score", f"{score}/100" if score is not None else "N/A")
    col2.metric("Grade", grade)
    col3.metric("Sessions", summary["session_count"])
    col4.metric(
        "Certs observable",
        f"{summary['observable_cert_sessions']}/{summary['tls_session_count']}"
        if summary["tls_session_count"]
        else "N/A",
    )

    gauge_col, donut_col = st.columns(2)

    with gauge_col:
        gauge = go.Figure(
            go.Indicator(
                mode="gauge+number",
                value=score if score is not None else 0,
                title={"text": "Posture score"},
                gauge={
                    "axis": {"range": [0, 100]},
                    "bar": {"color": "#4fd1c5"},
                    "steps": [
                        {"range": [0, 60], "color": "#3a1520"},
                        {"range": [60, 80], "color": "#3a2f10"},
                        {"range": [80, 100], "color": "#123a30"},
                    ],
                },
            )
        )
        gauge.update_layout(height=320, margin=dict(t=40, b=10))
        st.plotly_chart(gauge, use_container_width=True)

    with donut_col:
        sev_counts = summary["findings_by_severity"]
        if sev_counts:
            donut = go.Figure(
                go.Pie(
                    labels=list(sev_counts.keys()),
                    values=list(sev_counts.values()),
                    hole=0.55,
                    marker=dict(colors=[SEVERITY_COLORS.get(k, "#888") for k in sev_counts]),
                )
            )
            donut.update_layout(height=320, title="Findings by severity", margin=dict(t=40, b=10))
            st.plotly_chart(donut, use_container_width=True)
        else:
            st.success("No findings - clean capture.")

    st.subheader("Top 3, fix first")
    severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    top3 = sorted(recommendations, key=lambda r: severity_rank.get(
        next((f["severity"] for s in sessions for f in s["findings"] if f["rule_id"] == r["rule_id"]), "INFO"), 5
    ))[:3]
    if not top3:
        st.success("Nothing to fix.")
    for rec in top3:
        with st.container(border=True):
            plan_suffix = f" ({rec['plan_id']})" if rec["plan_id"] else ""
            st.markdown(f"**{rec['rule_id']}**{plan_suffix} — {rec['title']}")
            st.write(rec["fix"])
            if rec["verification_command"]:
                st.code(rec["verification_command"], language="bash")


# --- Sessions (uses the dedicated, filterable /sessions endpoint) ---

elif page == "Sessions":
    st.header("Sessions")

    f1, f2, f3, f4 = st.columns(4)
    protocol = f1.selectbox("Protocol", ["(any)", "smtp", "imap", "pop3"])
    tls_mode = f2.selectbox("TLS mode", ["(any)", "starttls", "implicit", "plaintext_only"])
    role = f3.selectbox("Role", ["(any)", "submission", "mx"])
    max_score = f4.slider("Max score", 0, 100, 100)

    params = {"max_score": max_score}
    if protocol != "(any)":
        params["protocol"] = protocol
    if tls_mode != "(any)":
        params["tls_mode"] = tls_mode
    if role != "(any)":
        params["role"] = role

    listing = api_get(f"/api/v1/jobs/{job_id}/sessions", **params)
    st.caption(f"{listing['total']} session(s) match")

    if listing["sessions"]:
        st.dataframe(
            [
                {
                    "Stream": s["tcp_stream"],
                    "Protocol": s["protocol"],
                    "Mode": s["tls_mode"],
                    "Role": s["role"],
                    "Endpoint": f"{s['client_ip']} → {s['server_ip']}:{s['server_port']}",
                    "TLS": s["negotiated_tls_version"] or "—",
                    "Score": s["score"],
                    "Findings": s["finding_count"],
                }
                for s in listing["sessions"]
            ],
            use_container_width=True,
            hide_index=True,
        )

        stream_options = [s["tcp_stream"] for s in listing["sessions"]]
        selected = st.selectbox("Drill into stream", stream_options)
        detail = api_get(f"/api/v1/jobs/{job_id}/sessions/{selected}")

        st.subheader(f"Stream {selected} detail")
        d1, d2, d3 = st.columns(3)
        d1.metric("Score", detail["score"])
        d2.metric("Cipher suite", detail["cipher_suite"] or "—")
        d3.metric("SNI", detail["sni_hostname"] or "—")

        if detail["findings"]:
            st.markdown("**Findings**")
            for f in detail["findings"]:
                st.markdown(f":{'red' if f['severity'] in ('CRITICAL', 'HIGH') else 'orange'}[{f['severity']}] `{f['rule_id']}` — {f['message']}")

        if detail["timeline"]:
            st.markdown("**STARTTLS timeline**")
            st.dataframe(
                [
                    {"Frame": e["frame_number"], "Dir": e["direction"], "Kind": e["kind"], "Text": e["text"]}
                    for e in detail["timeline"]
                ],
                use_container_width=True,
                hide_index=True,
            )
    else:
        st.info("No sessions match these filters.")


# --- Certificates ---

elif page == "Certificates":
    st.header("Certificate inventory")

    rows = []
    for s in sessions:
        cert = s.get("certificate")
        if cert:
            rows.append(
                {
                    "Stream": s["tcp_stream"],
                    "Subject": cert["subject_cn"],
                    "Issuer": cert["issuer_cn"] + (" (self-signed)" if cert["self_signed"] else ""),
                    "Key": f"{cert['key_algorithm']}-{cert['key_size']}",
                    "Signature": cert["signature_hash_algorithm"],
                    "SAN": ", ".join(cert["san_dns_names"]),
                    "Valid": "❌ expired" if cert["is_expired"] else "✅ valid",
                }
            )
    if rows:
        st.dataframe(rows, use_container_width=True, hide_index=True)
    else:
        st.info("No certificates observed in this capture (e.g. all-TLS-1.3, or no TLS at all).")

    not_observable = [s for s in sessions if s.get("cert_observable") is False]
    if not_observable:
        st.subheader("Not observable")
        for s in not_observable:
            st.caption(f"Stream {s['tcp_stream']}: {s['cert_not_observable_reason']}")


# --- Findings ---

elif page == "Findings":
    st.header("Findings queue")

    findings_resp = api_get(f"/api/v1/jobs/{job_id}/findings")
    findings = findings_resp["findings"]
    st.caption(f"{findings_resp['total']} finding(s), prioritized by severity")

    rec_by_rule = {r["rule_id"]: r for r in recommendations}

    for f in findings:
        color = SEVERITY_COLORS.get(f["severity"], "#888")
        plan_suffix = f" ({f['plan_id']})" if f["plan_id"] else ""
        with st.container(border=True):
            st.markdown(
                f"<span style='background:{color}22;color:{color};padding:2px 8px;"
                f"border-radius:999px;font-weight:700;font-size:12px'>{f['severity']}</span> "
                f"&nbsp;**{f['rule_id']}**{plan_suffix} "
                f"&nbsp;·&nbsp; stream {f['tcp_stream']} ({f['protocol']})",
                unsafe_allow_html=True,
            )
            st.write(f["message"])
            rec = rec_by_rule.get(f["rule_id"])
            if rec:
                st.markdown(f"**Fix:** {rec['fix']}")
                if rec["verification_command"]:
                    st.code(rec["verification_command"], language="bash")
