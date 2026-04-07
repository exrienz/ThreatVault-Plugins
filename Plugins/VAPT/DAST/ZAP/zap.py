"""
OWASP ZAP Plugin for ThreatVault

Processes OWASP ZAP JSON scan reports and transforms them into ThreatVault VAPT format.

Input: JSON file from ZAP scan (filtered or full report)
Output: Polars DataFrame with standardized VAPT schema

Field Mapping:
    ZAP Field               -> ThreatVault Field
    -----------------------------------------------
    (none)                  -> cve (empty - ZAP uses rule-based detection, not CVEs)
    severity                -> risk (High->HIGH, Medium->MEDIUM, Low->LOW)
    target                  -> host (extracted hostname)
    target                  -> port (extracted port, default 80/443)
    name                    -> name
    description             -> description
    solution                -> remediation
    instances[]             -> evidence (each instance creates a separate row)
    (none)                  -> vpr_score (not provided by ZAP)

Evidence Format (per instance):
    URI: <uri>
    Method: <method>
    Parameter: <param>
    Attack: <attack>
    Evidence: <evidence>
    Other Info: <otherinfo>

Note: Each instance is output as a separate row.
      A finding with 3 instances will produce 3 rows in the output.
"""

import json
from urllib.parse import urlparse

import polars as pl


def process(file: bytes, file_type: str) -> pl.DataFrame:
    """
    Process OWASP ZAP JSON scan report.

    Args:
        file: Raw JSON file content as bytes
        file_type: MIME type ("json" or "application/json")

    Returns:
        Polars DataFrame with ThreatVault VAPT schema:
        [cve, risk, host, port, name, description, remediation, evidence, vpr_score]
    """
    if file_type not in ("json", "application/json"):
        raise ValueError(f"File type not supported: {file_type}")

    data = json.loads(file.decode("utf-8"))

    # Extract target URL for host/port defaults
    target = data.get("target", "")
    default_host, default_port = _parse_url(target)

    findings = data.get("findings", [])

    if not findings:
        # Return empty DataFrame with correct schema
        return pl.DataFrame(
            schema={
                "cve": pl.Utf8,
                "risk": pl.Utf8,
                "host": pl.Utf8,
                "port": pl.Int64,
                "name": pl.Utf8,
                "description": pl.Utf8,
                "remediation": pl.Utf8,
                "evidence": pl.Utf8,
                "vpr_score": pl.Utf8,
            }
        )

    # Severity mapping: ZAP uses title case
    severity_map = {
        "High": "HIGH",
        "Medium": "MEDIUM",
        "Low": "LOW",
        "Informational": "LOW",  # Map informational to LOW
    }

    rows = []
    for finding in findings:
        severity = finding.get("severity", "Medium")
        risk = severity_map.get(severity, "MEDIUM")

        name = finding.get("name", "")
        description = finding.get("description", "")
        solution = finding.get("solution", "")
        instances = finding.get("instances", [])

        # Each instance becomes a separate entry with full evidence details
        if instances:
            for instance in instances:
                evidence = _build_evidence(instance)
                rows.append(
                    {
                        "cve": "",  # ZAP doesn't provide CVEs
                        "risk": risk,
                        "host": default_host,
                        "port": default_port,
                        "name": name,
                        "description": description,
                        "remediation": solution,
                        "evidence": evidence,
                        "vpr_score": "",  # ZAP doesn't provide VPR scores
                    }
                )
        else:
            # Finding with no instances still gets one row with empty evidence
            rows.append(
                {
                    "cve": "",  # ZAP doesn't provide CVEs
                    "risk": risk,
                    "host": default_host,
                    "port": default_port,
                    "name": name,
                    "description": description,
                    "remediation": solution,
                    "evidence": "",
                    "vpr_score": "",  # ZAP doesn't provide VPR scores
                }
            )

    df = pl.DataFrame(rows)

    # Ensure correct column order
    return df.select(
        [
            "cve",
            "risk",
            "host",
            "port",
            "name",
            "description",
            "remediation",
            "evidence",
            "vpr_score",
        ]
    )


def _parse_url(url: str) -> tuple[str, int]:
    """
    Extract hostname and port from URL.

    Args:
        url: URL string to parse

    Returns:
        Tuple of (hostname, port)
    """
    if not url:
        return ("", 80)

    parsed = urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port

    if port is None:
        port = 443 if parsed.scheme == "https" else 80

    return (host, port)


def _build_evidence(instance: dict) -> str:
    """
    Build evidence string from ZAP instance data.

    Args:
        instance: Dictionary containing instance details from ZAP

    Returns:
        Formatted evidence string with all instance details
    """
    parts = []

    uri = instance.get("uri", "")
    if uri:
        parts.append(f"URI: {uri}")

    method = instance.get("method", "")
    if method:
        parts.append(f"Method: {method}")

    param = instance.get("param", "")
    if param:
        parts.append(f"Parameter: {param}")

    attack = instance.get("attack", "")
    if attack:
        parts.append(f"Attack: {attack}")

    evidence = instance.get("evidence", "")
    if evidence:
        parts.append(f"Evidence: {evidence}")

    otherinfo = instance.get("otherinfo", "")
    if otherinfo:
        parts.append(f"Other Info: {otherinfo}")

    return "<br/>".join(parts)
