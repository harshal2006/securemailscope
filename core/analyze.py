"""CLI: parse a pcap and print the classified sessions found in it.

Usage: python -m core.analyze <path-to-pcap>
"""

from __future__ import annotations

import sys
from pathlib import Path

from core.pcap_reader import read_packets
from core.session_builder import build_sessions


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: python -m core.analyze <pcap>", file=sys.stderr)
        return 2

    pcap_path = Path(argv[1])
    packets = read_packets(pcap_path)
    sessions = build_sessions(packets)

    if not sessions:
        print("No SMTP/IMAP/POP3 sessions recognized in this capture.")
        return 0

    for s in sessions:
        print(f"stream {s.tcp_stream}: {s.protocol} {s.tls_mode} "
              f"{s.client_ip} -> {s.server_ip}:{s.server_port} "
              f"(frames {s.first_frame}-{s.last_frame})")
        if s.tls_info:
            t = s.tls_info
            print(f"  negotiated TLS version: {t.negotiated_version}")
            print(f"  cipher suite: {t.cipher_suite}")
            if t.cert_observable:
                c = t.leaf_cert
                print(f"  certificate: CN={c.subject_cn} issuer={c.issuer_cn} "
                      f"{c.key_algorithm}-{c.key_size} sig={c.signature_hash_algorithm} "
                      f"self_signed={c.self_signed} expired={c.is_expired}")
            else:
                print(f"  certificate: not observable ({t.cert_not_observable_reason})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
