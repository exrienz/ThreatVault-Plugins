"""
ThreatVault Plugin for ThreatCode AI Security Scan Results

This plugin converts ThreatCode CSV scan results to ThreatVault VAPT format.
ThreatCode is an AI-powered security scanner that analyzes source code using
Large Language Models to identify vulnerabilities.

GitHub: https://github.com/exrienz/ThreatCode
"""

import re
import polars as pl


def process(file: bytes, file_type: str) -> pl.DataFrame:
    """
    Process ThreatCode CSV results and convert to ThreatVault format.

    Args:
        file: The uploaded file content as bytes
        file_type: MIME type of the uploaded file (expected: "text/csv" or "csv")

    Returns:
        pl.DataFrame: DataFrame with ThreatVault schema fields:
            - cve: CVE identifier (from ThreatCode output)
            - risk: Severity level (CRITICAL, HIGH, MEDIUM, LOW)
            - host: Application/repository name from the scan
            - port: Line number where issue was found (extracted from Plugin Output)
            - name: Vulnerability name/title
            - description: Detailed vulnerability description
            - remediation: Fix recommendations
            - evidence: Location information (file paths, line numbers, code snippets)
            - vpr_score: VPR score (usually 0 for SAST)

    Raises:
        ValueError: If file_type is not CSV
    """
    # Validate file type
    if file_type not in ["text/csv", "csv"]:
        raise ValueError(f"Unsupported file type: {file_type}. Expected CSV.")

    # Parse CSV data using Polars
    df = pl.read_csv(file)

    # Normalize column names (remove spaces, convert to lowercase)
    df = df.select(pl.all().name.map(lambda x: x.strip().lower().replace(" ", "_")))

    # Extract line number from plugin_output field
    # The plugin_output contains multiple entries like:
    # File: src/main.py
    # Line: 18
    # Code: ...
    # ---
    # We want to extract the first Line number
    def extract_first_line_number(plugin_output: str) -> int:
        """Extract the first line number from plugin output."""
        if not plugin_output or plugin_output.strip() == "":
            return 0

        # Look for "Line: <number>" pattern
        match = re.search(r'Line:\s*(\d+)', str(plugin_output))
        if match:
            return int(match.group(1))
        return 0

    # Apply the extraction function
    df = df.with_columns(
        pl.col("plugin_output")
        .map_elements(extract_first_line_number, return_dtype=pl.Int64)
        .alias("line_number")
    )

    # Map to ThreatVault schema
    df = df.select([
        pl.col("cve").fill_null("").alias("cve"),
        pl.col("risk").str.to_uppercase().alias("risk"),
        pl.col("host").alias("host"),
        pl.col("line_number").alias("port"),
        pl.col("name").alias("name"),
        pl.col("description").alias("description"),
        pl.col("solution").alias("remediation"),
        pl.col("plugin_output").alias("evidence"),
        pl.col("vpr_score").cast(pl.Utf8).fill_null("0").alias("vpr_score"),
    ])

    # Handle newline replacement in text fields for better HTML display
    df = df.with_columns([
        pl.col("description").str.replace_all("\n", "<br/>"),
        pl.col("remediation").str.replace_all("\n", "<br/>"),
        pl.col("evidence").str.replace_all("\n", "<br/>"),
    ])

    # Filter valid risk values
    # Only keep CRITICAL, HIGH, MEDIUM, LOW
    valid_risks = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    df = df.filter(pl.col("risk").is_in(valid_risks))

    # Handle empty results
    if df.shape[0] == 0:
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

    return df
