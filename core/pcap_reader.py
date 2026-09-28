"""Runs tshark against a pcap and returns per-packet field dicts.

This module never sends network traffic; it only invokes the `tshark`
binary to decode a pcap file that already exists on disk.
"""

from __future__ import annotations

import csv
import io
import shutil
import subprocess
from pathlib import Path

FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "tcp.stream",
    "ip.src",
    "ip.dst",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.len",
    "tls.record.content_type",
    "tls.handshake.type",
    "tls.handshake.version",
    "tls.handshake.extensions.supported_version",
    "tls.handshake.certificate",
    "tls.handshake.ciphersuite",
    "tls.alert_message.desc",
]

SEPARATOR = "\x1f"  # unit separator: won't collide with cert hex/comma lists


def _tshark_path() -> str:
    path = shutil.which("tshark")
    if path is None:
        raise RuntimeError(
            "tshark not found on PATH. Install it (e.g. `brew install --cask "
            "wireshark` on macOS) before parsing pcaps."
        )
    return path


def read_packets(pcap_path: Path) -> list[dict[str, str]]:
    """Decode a pcap into a list of per-packet field dicts via tshark.

    Multi-valued fields (e.g. tls.handshake.certificate for a chain, or
    supported_version for a ClientHello) come back comma-separated, exactly
    as tshark emits them; callers split on "," where relevant.
    """
    pcap_path = Path(pcap_path)
    if not pcap_path.is_file():
        raise FileNotFoundError(f"pcap not found: {pcap_path}")

    cmd = [_tshark_path(), "-r", str(pcap_path), "-T", "fields"]
    for f in FIELDS:
        cmd += ["-e", f]
    cmd += ["-E", "header=y", "-E", f"separator={SEPARATOR}"]

    result = subprocess.run(cmd, capture_output=True, text=True, check=True)

    reader = csv.DictReader(io.StringIO(result.stdout), delimiter=SEPARATOR)
    return [dict(row) for row in reader]
