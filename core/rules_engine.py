"""Applies rules/*.yaml to a Session and produces Findings.

Rule *matching logic* (what counts as a weak key, which TLS version
triggers which rule, etc.) lives here in code. The YAML files under
rules/ hold only the severity/score/message metadata for each rule ID,
so that tuning wording or weights doesn't require touching this module.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from core.findings import Finding
from core.models import Session

RULES_DIR = Path(__file__).parent.parent / "rules"

MIN_SAFE_RSA_DSA_KEY_SIZE = 2048
WEAK_SIGNATURE_HASHES = {"md5", "sha1"}


def _load_yaml(name: str) -> dict:
    with open(RULES_DIR / name) as f:
        return yaml.safe_load(f)


def load_rules() -> dict:
    return {
        "tls_version": _load_yaml("tls_version_rules.yaml"),
        "cert": _load_yaml("cert_rules.yaml"),
        "mode": _load_yaml("mode_rules.yaml"),
        "weak_ciphers": _load_yaml("weak_ciphers.yaml"),
    }


def _finding(rule_meta: dict, rule_id: str, session: Session, message: str | None = None) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=rule_meta["severity"],
        score_impact=rule_meta["score_impact"],
        message=message or rule_meta["message"],
        tcp_stream=session.tcp_stream,
        protocol=session.protocol,
        server_port=session.server_port,
    )


def evaluate_session(session: Session, rules: dict | None = None) -> list[Finding]:
    if rules is None:
        rules = load_rules()

    findings: list[Finding] = []

    if session.tls_mode == "plaintext_only":
        mode_rule = rules["mode"]["NO_TLS_OBSERVED"]
        findings.append(_finding(mode_rule, "NO_TLS_OBSERVED", session))
        return findings

    tls_info = session.tls_info
    if tls_info is None:
        return findings

    if tls_info.negotiated_version is not None:
        version_rule = rules["tls_version"].get(tls_info.negotiated_version)
        if version_rule is not None:
            findings.append(_finding(version_rule, version_rule["rule_id"], session))

    if tls_info.cipher_suite is not None:
        weak_ciphers = rules["weak_ciphers"]
        weak_reason = weak_ciphers["weak_suites"].get(tls_info.cipher_suite)
        if weak_reason is not None:
            findings.append(
                _finding(
                    weak_ciphers,
                    weak_ciphers["rule_id"],
                    session,
                    message=f"{weak_ciphers['message']} ({tls_info.cipher_suite}: {weak_reason})",
                )
            )

    if tls_info.cert_observable:
        cert = tls_info.leaf_cert
        cert_rules = rules["cert"]

        if cert.is_expired:
            findings.append(_finding(cert_rules["CERT_EXPIRED"], "CERT_EXPIRED", session))

        if cert.self_signed:
            findings.append(_finding(cert_rules["CERT_SELF_SIGNED"], "CERT_SELF_SIGNED", session))

        if (
            cert.key_algorithm in ("RSA", "DSA")
            and cert.key_size is not None
            and cert.key_size < MIN_SAFE_RSA_DSA_KEY_SIZE
        ):
            findings.append(_finding(cert_rules["CERT_WEAK_KEY"], "CERT_WEAK_KEY", session))

        if cert.signature_hash_algorithm in WEAK_SIGNATURE_HASHES:
            findings.append(
                _finding(cert_rules["CERT_WEAK_SIGNATURE_HASH"], "CERT_WEAK_SIGNATURE_HASH", session)
            )
    else:
        cert_rules = rules["cert"]
        findings.append(
            _finding(
                cert_rules["CERT_NOT_OBSERVABLE"],
                "CERT_NOT_OBSERVABLE",
                session,
                message=tls_info.cert_not_observable_reason,
            )
        )

    return findings
