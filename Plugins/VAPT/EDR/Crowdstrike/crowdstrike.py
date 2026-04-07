"""
ThreatVault Plugin for CrowdStrike Falcon Spotlight Vulnerability Results

This plugin converts CrowdStrike Falcon Spotlight CSV scan results to ThreatVault VAPT format.
CrowdStrike Falcon provides endpoint detection and vulnerability assessment for hosts.
"""

import polars as pl


def process(file: bytes, file_type: str) -> pl.LazyFrame:
    """
    Process CrowdStrike CSV results and convert to ThreatVault format.

    Args:
        file: The uploaded file content as bytes
        file_type: MIME type of the uploaded file (expected: "text/csv" or "csv")

    Returns:
        pl.LazyFrame: LazyFrame with ThreatVault VAPT schema fields:
            - cve: CVE identifier
            - risk: Severity level (CRITICAL, HIGH, MEDIUM, LOW)
            - host: Hostname from CrowdStrike
            - port: Port number (0 for EDR scans)
            - name: Vulnerability/Software name
            - description: Vulnerability description
            - remediation: Solution/patch information
            - evidence: Additional context (IP, Platform, Group Names)
            - vpr_score: VPR score from CrowdStrike

    Raises:
        ValueError: If file_type is not CSV
    """
    # Validate file type
    if file_type not in ["text/csv", "csv"]:
        raise ValueError(f"File type not supported: {file_type}")

    return (
        pl.scan_csv(file)
        # Normalize column names to lowercase with underscores
        .select(pl.all().name.map(lambda x: "_".join(x.lower().split(" "))))
        # Create evidence field from IP, Platform, and Group Names
        .with_columns(
            pl.concat_str(
                [
                    pl.lit("<b>IP:</b> "),
                    pl.col("ip"),
                    pl.lit(" <br/> <b>Platform:</b> "),
                    pl.col("platform"),
                    pl.lit(" <br/> <b>Group Names:</b> "),
                    pl.col("group_names"),
                ],
                separator=""
            ).alias("evidence")
        )
        # Replace newlines with HTML breaks for better display
        .with_columns(
            pl.col("solution", "description").str.replace_all("\n", "<br/>")
        )
        # Rename columns to match ThreatVault schema
        .rename(
            {
                "severity": "risk",
                "solution": "remediation",
            }
        )
        # Add port column (EDR scans don't have specific ports)
        .with_columns(
            pl.lit(0).alias("port")
        )
        # Normalize VPR score to string and handle null values
        .with_columns(
            pl.col("vpr_score").cast(pl.Utf8).fill_null("")
        )
        # Select only required fields in correct order
        .select(
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
        # Filter out invalid risk values
        .filter(pl.col("risk").is_in(["CRITICAL", "HIGH", "MEDIUM", "LOW"]))
    )
