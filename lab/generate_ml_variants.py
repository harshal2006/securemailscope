"""Generates additional real captures for the ML dataset (Part A) by
replaying EXISTING lab scenarios with a different client tool (Python's
stdlib smtplib/imaplib/poplib instead of swaks/openssl), to get natural
variation in TLS fingerprint/timing/extension order without changing
any underlying server config.

Must be run with the lab mail server up (`docker compose up -d` in
lab/docker/) and tcpdump permitted on lo0 (no sudo needed on macOS with
the access_bpf group, see CLAUDE.md). Writes pcaps to
tests/fixtures/pcaps/ml_variants/ - review before committing.

Dummy credentials only (labuser/labpass), per CLAUDE.md.
"""

from __future__ import annotations

import imaplib
import poplib
import smtplib
import socket
import ssl
import subprocess
import time
from pathlib import Path

OUT_DIR = Path(__file__).parent.parent / "tests" / "fixtures" / "pcaps" / "ml_variants"
OUT_DIR.mkdir(parents=True, exist_ok=True)

HOST = "127.0.0.1"


def _capture(name: str, port: int, action, duration: float = 3.0) -> Path:
    out_path = OUT_DIR / f"{name}.pcap"
    proc = subprocess.Popen(
        ["tcpdump", "-i", "lo0", "-w", str(out_path), f"tcp port {port}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(1)
    try:
        action()
    except Exception as exc:  # noqa: BLE001 - report and keep the capture anyway
        print(f"  [{name}] action raised: {exc!r}")
    time.sleep(1)
    proc.terminate()
    proc.wait(timeout=5)
    print(f"  [{name}] -> {out_path} ({out_path.stat().st_size} bytes)")
    return out_path


def smtp_starttls_clean_tls12() -> None:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    with smtplib.SMTP(HOST, 2587, timeout=10) as s:
        s.ehlo("mail.example.com")
        s.starttls(context=ctx)
        s.ehlo("mail.example.com")
        s.login("labuser", "labpass")
        s.sendmail("labuser@lab.test", "labuser@lab.test", "Subject: test\r\n\r\nbody\r\n")


def smtp_plaintext_auth_submission() -> None:
    with smtplib.SMTP(HOST, 2587, timeout=10) as s:
        s.ehlo("mail.example.com")
        s.login("labuser", "labpass")  # no starttls() call - AUTH in the clear
        s.sendmail("labuser@lab.test", "labuser@lab.test", "Subject: test\r\n\r\nbody\r\n")


def smtp_starttls_disabled() -> None:
    # Port 2588: STARTTLS disabled entirely in lab config (T-03 scenario).
    with smtplib.SMTP(HOST, 2588, timeout=10) as s:
        s.ehlo("mail.example.com")
        try:
            s.login("labuser", "labpass")
        except smtplib.SMTPException:
            pass  # relay/auth may be rejected server-side; the plaintext exchange is what matters


def imap_plaintext_login() -> None:
    conn = imaplib.IMAP4(HOST, 2143)
    try:
        conn.login("labuser", "labpass")
        conn.logout()
    except (imaplib.IMAP4.error, OSError):
        pass


def imap_starttls_clean() -> None:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    conn = imaplib.IMAP4(HOST, 2143)
    conn.starttls(ssl_context=ctx)
    conn.login("labuser", "labpass")
    conn.logout()


def pop3_plaintext_userpass() -> None:
    conn = poplib.POP3(HOST, 2110, timeout=10)
    try:
        conn.user("labuser")
        conn.pass_("labpass")
        conn.quit()
    except (poplib.error_proto, OSError):
        pass


def pop3_stls_clean() -> None:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    conn = poplib.POP3(HOST, 2110, timeout=10)
    conn.stls(context=ctx)
    conn.user("labuser")
    conn.pass_("labpass")
    conn.quit()


SCENARIOS = [
    ("mlv01_smtp_starttls_clean_tls12_pysmtplib", 2587, smtp_starttls_clean_tls12),
    ("mlv02_smtp_plaintext_auth_submission_pysmtplib", 2587, smtp_plaintext_auth_submission),
    ("mlv03_smtp_starttls_disabled_pysmtplib", 2588, smtp_starttls_disabled),
    ("mlv04_imap_plaintext_login_pyimaplib", 2143, imap_plaintext_login),
    ("mlv05_imap_starttls_clean_pyimaplib", 2143, imap_starttls_clean),
    ("mlv06_pop3_plaintext_userpass_pypoplib", 2110, pop3_plaintext_userpass),
    ("mlv07_pop3_stls_clean_pypoplib", 2110, pop3_stls_clean),
]


if __name__ == "__main__":
    for name, port, action in SCENARIOS:
        print(f"capturing {name} ...")
        _capture(name, port, action)
    print("done")
