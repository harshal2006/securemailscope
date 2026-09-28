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
from core.starttls import StarttlsAnalysis

RULES_DIR = Path(__file__).parent.parent / "rules"

MIN_SAFE_RSA_DSA_KEY_SIZE = 2048
WEAK_SIGNATURE_HASHES = {"md5", "sha1"}


def _load_yaml(name: str) -> dict:
    with open(RULES_DIR / name) as f:
        return yaml.safe_load(f)


def _hostname_matches_san(hostname: str, san_dns_names: list[str]) -> bool:
    """RFC 6125-style match: exact, or a single leftmost `*` label wildcard."""
    hostname = hostname.rstrip(".").lower()
    for san in san_dns_names:
        san = san.rstrip(".").lower()
        if san == hostname:
            return True
        if san.startswith("*."):
            san_suffix = san[1:]  # ".example.com"
            if hostname.endswith(san_suffix) and hostname.count(".") == san.count("."):
                return True
    return False


def load_rules() -> dict:
    return {
        "tls_version": _load_yaml("tls_version_rules.yaml"),
        "cert": _load_yaml("cert_rules.yaml"),
        "mode": _load_yaml("mode_rules.yaml"),
        "weak_ciphers": _load_yaml("weak_ciphers.yaml"),
        "starttls": _load_yaml("starttls_rules.yaml"),
        "forward_secrecy": _load_yaml("forward_secrecy.yaml"),
    }


def _classify_key_exchange(negotiated_version: str | None, cipher_suite: str | None, rules: dict) -> str:
    """Returns 'ephemeral', 'static', or 'unknown' (never guessed)."""
    if negotiated_version == "TLS 1.3":
        # TLS 1.3 has no static-RSA-style key exchange; key_share is
        # always ephemeral, regardless of which suite is negotiated.
        return "ephemeral"
    if cipher_suite is None:
        return "unknown"
    fs_rules = rules["forward_secrecy"]
    if cipher_suite in fs_rules["ephemeral_suites"]:
        return "ephemeral"
    if cipher_suite in fs_rules["static_suites"]:
        return "static"
    return "unknown"


def _finding(rule_meta: dict, rule_id: str, session: Session, message: str | None = None) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=rule_meta["severity"],
        score_impact=rule_meta["score_impact"],
        message=message or rule_meta["message"],
        tcp_stream=session.tcp_stream,
        protocol=session.protocol,
        server_port=session.server_port,
        plan_id=rule_meta.get("id"),
    )


def evaluate_session(
    session: Session,
    rules: dict | None = None,
    starttls_analysis: StarttlsAnalysis | None = None,
) -> list[Finding]:
    if rules is None:
        rules = load_rules()

    findings: list[Finding] = []
    findings.extend(_evaluate_starttls_rules(session, starttls_analysis, rules))

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

    kex = _classify_key_exchange(tls_info.negotiated_version, tls_info.cipher_suite, rules)
    fs_rules = rules["forward_secrecy"]
    if kex == "static":
        findings.append(_finding(fs_rules, fs_rules["rule_id"], session))
    elif kex == "unknown":
        findings.append(_finding(fs_rules["not_evaluable"], "FORWARD_SECRECY_NOT_EVALUABLE", session))

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

        if tls_info.sni_hostname is None:
            findings.append(
                _finding(
                    cert_rules["CERT_HOSTNAME_NOT_EVALUABLE"], "CERT_HOSTNAME_NOT_EVALUABLE", session
                )
            )
        elif not _hostname_matches_san(tls_info.sni_hostname, cert.san_dns_names):
            findings.append(
                _finding(
                    cert_rules["CERT_HOSTNAME_MISMATCH"],
                    "CERT_HOSTNAME_MISMATCH",
                    session,
                    message=(
                        f"Client requested '{tls_info.sni_hostname}' (SNI) but the "
                        f"certificate's SAN only covers {cert.san_dns_names}."
                    ),
                )
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


def _finding_by_role(rule_meta: dict, rule_id: str, session: Session) -> Finding:
    role_meta = rule_meta["by_role"][session.role]
    return Finding(
        rule_id=rule_id,
        severity=role_meta["severity"],
        score_impact=role_meta["score_impact"],
        message=rule_meta["message"],
        tcp_stream=session.tcp_stream,
        protocol=session.protocol,
        server_port=session.server_port,
        plan_id=rule_meta.get("id"),
    )


def _evaluate_starttls_rules(
    session: Session, starttls_analysis: StarttlsAnalysis | None, rules: dict
) -> list[Finding]:
    findings: list[Finding] = []
    if starttls_analysis is None or session.tls_mode == "implicit":
        # T-01/T-02/T-03 only apply to STARTTLS-capable (plaintext-first)
        # ports; implicit-TLS sessions are encrypted from byte one, so
        # there is no plaintext-exposure window to evaluate.
        return findings

    starttls_rules = rules["starttls"]

    if starttls_analysis.auth_before_tls:
        findings.append(_finding(starttls_rules["T-01"], "T-01", session))

    if (
        session.tls_mode == "plaintext_only"
        and starttls_analysis.capability_advertised_starttls is True
    ):
        findings.append(_finding_by_role(starttls_rules["T-02"], "T-02", session))

    if starttls_analysis.capability_advertised_starttls is False:
        findings.append(_finding_by_role(starttls_rules["T-03"], "T-03", session))

    return findings
