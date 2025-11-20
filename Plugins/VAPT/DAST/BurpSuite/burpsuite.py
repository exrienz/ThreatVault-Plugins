"""
ThreatVault Plugin for Burp Suite XML Results

This plugin converts Burp Suite XML scan results to ThreatVault VAPT format.
It processes XML exports from Burp Suite Professional/Enterprise and maps
findings to the required schema fields.
"""

import xml.etree.ElementTree as ET
from io import BytesIO
import polars as pl


def process(file: bytes, file_type: str) -> pl.DataFrame:
    """
    Process Burp Suite XML results and convert to ThreatVault format.

    Args:
        file: The uploaded file content as bytes
        file_type: MIME type of the uploaded file (expected: "xml", "application/xml", or "text/xml")

    Returns:
        pl.DataFrame: DataFrame with ThreatVault schema fields:
            - cve: CVE identifier (empty for Burp Suite)
            - risk: Severity level (CRITICAL, HIGH, MEDIUM, LOW)
            - host: Target hostname (prefers hostname, falls back to IP)
            - port: Port number (0 for web applications)
            - name: Issue name/title
            - description: Issue background or details
            - remediation: Remediation guidance
            - evidence: HTTP request data
            - vpr_score: VPR score (empty for Burp Suite)

    Raises:
        ValueError: If file_type is not XML
        ET.ParseError: If XML parsing fails
    """
    # Validate file type
    supported_types = ["xml", "application/xml", "text/xml", "application/x-xml"]
    if file_type.lower() not in [t.lower() for t in supported_types]:
        raise ValueError(
            f"Unsupported file type: {file_type}. Expected XML format."
        )

    # Parse XML data
    try:
        tree = ET.parse(BytesIO(file))
        root = tree.getroot()
    except ET.ParseError as e:
        raise ET.ParseError(f"Failed to parse Burp Suite XML: {e}")

    # Prepare data for DataFrame
    records = []

    # Iterate through each issue in the XML
    for issue in root.findall('issue'):
        # Extract severity and convert to ThreatVault risk format
        # Burp Suite uses: 'Critical', 'High', 'Medium', 'Low', 'Information'
        severity = issue.findtext('severity', '')

        # Extract host information (prefer hostname, fallback to IP)
        host_elem = issue.find('host')
        if host_elem is not None:
            host = host_elem.text or host_elem.get('ip', '') or ''
        else:
            host = ''

        # Extract issue name
        name = issue.findtext('name', '')

        # Extract description (prefer issueBackground, fallback to issueDetail)
        issue_background = issue.findtext('issueBackground', '')
        issue_detail = issue.findtext('issueDetail', '')
        description = issue_background if issue_background else issue_detail

        # Extract remediation (prefer remediationBackground, fallback to remediationDetail)
        remediation_background = issue.findtext('remediationBackground', '')
        remediation_detail = issue.findtext('remediationDetail', '')
        remediation = remediation_background if remediation_background else remediation_detail

        # Extract evidence from request data
        evidence = ''
        requestresponse_elem = issue.find('requestresponse')
        if requestresponse_elem is not None:
            request_elem = requestresponse_elem.find('request')
            if request_elem is not None:
                evidence = request_elem.text or ''

        # Create the record
        record = {
            'cve': '',
            'risk': severity,  # Will be normalized later
            'host': host,
            'port': 0,  # Burp Suite doesn't provide port in XML
            'name': name,
            'description': description,
            'remediation': remediation,
            'evidence': evidence,
            'vpr_score': ''
        }

        records.append(record)

    # Create Polars DataFrame
    if not records:
        # Return empty DataFrame with correct schema
        return pl.DataFrame(
            schema={
                'cve': pl.Utf8,
                'risk': pl.Utf8,
                'host': pl.Utf8,
                'port': pl.Int64,
                'name': pl.Utf8,
                'description': pl.Utf8,
                'remediation': pl.Utf8,
                'evidence': pl.Utf8,
                'vpr_score': pl.Utf8,
            }
        )

    df = pl.DataFrame(records)

    # Handle newline replacement in text fields for better display
    df = df.with_columns(
        [
            pl.col("description").str.replace_all("\n", "<br/>"),
            pl.col("remediation").str.replace_all("\n", "<br/>"),
            pl.col("evidence").str.replace_all("\n", "<br/>"),
        ]
    )

    # Normalize risk values to uppercase
    df = df.with_columns(
        pl.col("risk").str.to_uppercase()
    )

    # Filter out invalid risk values
    # Only keep: CRITICAL, HIGH, MEDIUM, LOW (excludes INFORMATION)
    valid_risks = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    df = df.filter(pl.col("risk").is_in(valid_risks))

    return df
