"""
ThreatVault Plugin for AWS Inspector JSON Results

This plugin converts AWS Inspector vulnerability scan JSON exports to
ThreatVault VAPT format.
"""

import json
import polars as pl


def _extract_host(resources: list) -> str:
    """
    Extract host name from AWS Inspector resources.

    Args:
        resources: List of resource objects from finding

    Returns:
        Name tag value, or resource ID as fallback
    """
    if not resources:
        return "Unknown"

    resource = resources[0]
    tags = resource.get("tags", {})

    # Try Name tag first
    if "Name" in tags:
        return tags["Name"]

    # Fallback to resource ID
    return resource.get("id", "Unknown")


def _build_evidence(finding: dict) -> str:
    """
    Build evidence string from vulnerable packages.

    Args:
        finding: AWS Inspector finding object

    Returns:
        Formatted evidence string with package details
    """
    pkg_details = finding.get("packageVulnerabilityDetails", {})
    packages = pkg_details.get("vulnerablePackages", [])

    if not packages:
        return "No package details available"

    evidence_parts = []
    for pkg in packages:
        name = pkg.get("name", "Unknown")
        version = pkg.get("version", "Unknown")
        arch = pkg.get("arch", "")
        fixed_in = pkg.get("fixedInVersion", "N/A")

        evidence_parts.append(
            f"Package: {name} ({arch})<br/>"
            f"Installed Version: {version}<br/>"
            f"Fixed in Version: {fixed_in}"
        )

    return "<br/><br/>".join(evidence_parts)


def _build_remediation(finding: dict) -> str:
    """
    Build remediation string from finding details.

    Args:
        finding: AWS Inspector finding object

    Returns:
        Formatted remediation string
    """
    # Get remediation recommendation
    remediation_obj = finding.get("remediation", {})
    recommendation = remediation_obj.get("recommendation", {})
    rec_text = recommendation.get("text", "")

    # Get package-level remediation commands
    pkg_details = finding.get("packageVulnerabilityDetails", {})
    packages = pkg_details.get("vulnerablePackages", [])

    remediation_parts = []

    # Add recommendation text if available and not generic
    if rec_text and rec_text != "None Provided":
        remediation_parts.append(rec_text)

    # Get unique fixed versions
    fixed_versions = set()
    remediation_cmds = set()
    for pkg in packages:
        fixed_in = pkg.get("fixedInVersion")
        if fixed_in:
            fixed_versions.add(f"{pkg.get('name', 'package')}: {fixed_in}")

        cmd = pkg.get("remediation")
        if cmd:
            remediation_cmds.add(cmd)

    if fixed_versions:
        remediation_parts.append("Update to fixed versions:<br/>" + "<br/>".join(sorted(fixed_versions)))

    if remediation_cmds:
        remediation_parts.append("Commands:<br/>" + "<br/>".join(sorted(remediation_cmds)))

    return "<br/><br/>".join(remediation_parts) if remediation_parts else "No remediation available"


def process(file: bytes, file_type: str) -> pl.DataFrame:
    """
    Process AWS Inspector JSON results and convert to ThreatVault format.

    Args:
        file: The uploaded file content as bytes
        file_type: MIME type of the uploaded file (expected: "application/json" or "json")

    Returns:
        pl.DataFrame: DataFrame with ThreatVault schema fields:
            - cve: CVE identifier
            - risk: Severity level (CRITICAL, HIGH, MEDIUM, LOW)
            - host: Instance name from Resource Tags (e.g., on_demand_workers_c)
            - port: Port number (0 for AWS Inspector scans)
            - name: Vulnerability title
            - description: Vulnerability description
            - remediation: Package remediation commands and fixed versions
            - evidence: Affected packages, versions, and instance details
            - vpr_score: AWS Inspector score

    Raises:
        ValueError: If file_type is not JSON
    """
    # Validate file type
    if file_type not in ["application/json", "json"]:
        raise ValueError(f"Unsupported file type: {file_type}. Expected JSON.")

    # Parse JSON
    data = json.loads(file.decode("utf-8"))

    # Extract findings array
    findings = data.get("findings", [])

    if not findings:
        # Return empty DataFrame with correct schema
        return pl.DataFrame(schema={
            "cve": pl.Utf8,
            "risk": pl.Utf8,
            "host": pl.Utf8,
            "port": pl.Int64,
            "name": pl.Utf8,
            "description": pl.Utf8,
            "remediation": pl.Utf8,
            "evidence": pl.Utf8,
            "vpr_score": pl.Utf8,
        })

    # Transform findings to ThreatVault schema
    rows = []
    for finding in findings:
        # Extract CVE from packageVulnerabilityDetails
        pkg_details = finding.get("packageVulnerabilityDetails", {})
        cve = pkg_details.get("vulnerabilityId", "")

        # Get severity and uppercase it
        risk = finding.get("severity", "").upper()

        # Skip if not a valid risk level
        if risk not in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            continue

        # Extract host from resources
        resources = finding.get("resources", [])
        host = _extract_host(resources)

        # Get title
        name = finding.get("title", "")

        # Get description and replace newlines
        description = finding.get("description", "").replace("\n", "<br/>")

        # Build remediation
        remediation = _build_remediation(finding)

        # Build evidence
        evidence = _build_evidence(finding)

        # Get inspector score
        inspector_score = finding.get("inspectorScore")
        vpr_score = str(inspector_score) if inspector_score is not None else ""

        rows.append({
            "cve": cve,
            "risk": risk,
            "host": host,
            "port": 0,
            "name": name,
            "description": description,
            "remediation": remediation,
            "evidence": evidence,
            "vpr_score": vpr_score,
        })

    # Create DataFrame
    df = pl.DataFrame(rows)

    return df
