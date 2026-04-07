"""
ThreatVault Plugin for AWS SecurityHub Findings

This plugin converts AWS SecurityHub findings export (NDJSON format) to 
ThreatVault Compliance format.
"""

import json
import polars as pl


def _map_severity(label: str) -> str:
    """
    Map AWS SecurityHub severity label to ThreatVault risk level.
    
    Args:
        label: SecurityHub severity label (CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL)
    
    Returns:
        ThreatVault risk level
    """
    mapping = {
        "CRITICAL": "Critical",
        "HIGH": "High",
        "MEDIUM": "Medium",
        "LOW": "Low",
        "INFORMATIONAL": "Info",
    }
    return mapping.get(label.upper(), "Medium")


def _extract_host(finding: dict) -> str:
    """
    Extract host/resource name from finding.
    
    Priority:
    1. Name tag from Resources[0].Tags
    2. Resource ID basename from Resources[0].Id
    
    Args:
        finding: SecurityHub finding dict
    
    Returns:
        Host/resource identifier
    """
    resources = finding.get("Resources", [])
    if not resources:
        return "Unknown"
    
    resource = resources[0]
    
    # Try to get Name tag
    tags = resource.get("Tags", {})
    if isinstance(tags, dict) and tags.get("Name"):
        return tags["Name"]
    
    # Fallback to resource ID (extract instance/volume ID from ARN)
    resource_id = resource.get("Id", "")
    if "/" in resource_id:
        return resource_id.split("/")[-1]
    return resource_id or "Unknown"


def _build_evidence(finding: dict) -> str:
    """
    Build evidence string from finding details.
    
    Args:
        finding: SecurityHub finding dict
    
    Returns:
        Formatted evidence string
    """
    parts = []
    
    # Resource ID
    resources = finding.get("Resources", [])
    if resources:
        resource_id = resources[0].get("Id", "")
        if resource_id:
            parts.append(f"Resource: {resource_id}")
        
        resource_type = resources[0].get("Type", "")
        if resource_type:
            parts.append(f"Type: {resource_type}")
    
    # Account info
    account_id = finding.get("AwsAccountId", "")
    account_name = finding.get("AwsAccountName", "")
    if account_name:
        parts.append(f"Account: {account_name} ({account_id})")
    elif account_id:
        parts.append(f"Account: {account_id}")
    
    # Region
    region = finding.get("Region", "")
    if region:
        parts.append(f"Region: {region}")
    
    # Workflow status
    workflow = finding.get("Workflow", {})
    if workflow.get("Status"):
        parts.append(f"Workflow: {workflow['Status']}")
    
    return " | ".join(parts) if parts else "N/A"


def _build_remediation(finding: dict) -> str:
    """
    Build remediation string from finding.
    
    Args:
        finding: SecurityHub finding dict
    
    Returns:
        Remediation text with URL if available
    """
    remediation = finding.get("Remediation", {})
    recommendation = remediation.get("Recommendation", {})
    
    text = recommendation.get("Text", "")
    url = recommendation.get("Url", "")
    
    if text and url:
        return f"{text}<br/><br/>Reference: {url}"
    elif text:
        return text
    elif url:
        return f"Reference: {url}"
    return "No remediation guidance available"


def process(file: bytes, file_type: str) -> pl.DataFrame:
    """
    Process AWS SecurityHub findings export and convert to ThreatVault format.

    Args:
        file: The uploaded file content as bytes
        file_type: MIME type of the uploaded file

    Returns:
        pl.DataFrame: DataFrame with ThreatVault Compliance schema fields:
            - risk: Severity level (Critical, High, Medium, Low, Info)
            - host: Resource name or instance ID
            - port: Always 0
            - name: Finding title
            - description: Finding description
            - remediation: Remediation guidance
            - evidence: Resource details
            - status: Compliance status (PASSED, FAILED, NOT_AVAILABLE)

    Raises:
        ValueError: If file_type is not supported
    """
    # Validate file type
    supported_types = ["text/csv", "csv", "application/json", "json", "ndjson", "application/x-ndjson"]
    if file_type not in supported_types:
        raise ValueError(f"Unsupported file type: {file_type}. Expected CSV, JSON, or NDJSON.")

    # Decode file content
    content = file.decode("utf-8")
    
    # Parse NDJSON (one JSON object per line)
    findings = []
    for line in content.strip().split("\n"):
        line = line.strip()
        if line:
            try:
                finding = json.loads(line)
                findings.append(finding)
            except json.JSONDecodeError:
                continue  # Skip invalid lines
    
    if not findings:
        raise ValueError("No valid findings found in file")

    # Valid severity levels to process
    valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}

    # Transform findings to ThreatVault schema
    rows = []
    for finding in findings:
        severity = finding.get("Severity", {})
        severity_label = severity.get("Label", "").upper()
        
        # Skip findings with invalid/unsupported severity levels
        if severity_label not in valid_severities:
            continue
        
        compliance = finding.get("Compliance", {})
        
        row = {
            "risk": _map_severity(severity.get("Label", "MEDIUM")),
            "host": _extract_host(finding),
            "port": 0,
            "name": finding.get("Title", "Unknown Finding"),
            "description": finding.get("Description", "").replace("\n", "<br/>"),
            "remediation": _build_remediation(finding),
            "evidence": _build_evidence(finding),
            "status": compliance.get("Status", "NOT_AVAILABLE"),
        }
        rows.append(row)

    # Create DataFrame
    result = pl.DataFrame(rows)

    return result
