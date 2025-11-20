"""
ThreatVault Plugin for Semgrep JSON Results

This plugin converts Semgrep JSON scan results to ThreatVault VAPT format.
It processes the 'results' array from Semgrep output and maps it to the
required schema fields.
"""

import json
import polars as pl


def process(file: bytes, file_type: str) -> pl.DataFrame:
    """
    Process Semgrep JSON results and convert to ThreatVault format.

    Args:
        file: The uploaded file content as bytes
        file_type: MIME type of the uploaded file (expected: "application/json" or "json")

    Returns:
        pl.DataFrame: DataFrame with ThreatVault schema fields:
            - cve: CVE identifier (empty for Semgrep)
            - risk: Severity level (defaults to 'Medium')
            - host: Target host (set to 'semgrep' for static analysis)
            - port: Line number where issue was found
            - name: Rule/check identifier
            - description: Issue description/message
            - remediation: Suggested fix
            - evidence: Location information (file path and line numbers)
            - vpr_score: VPR score (empty for Semgrep)

    Raises:
        ValueError: If file_type is not JSON
    """
    # Validate file type
    if file_type not in ["application/json", "json"]:
        raise ValueError(f"Unsupported file type: {file_type}. Expected JSON.")

    # Parse JSON data
    data = json.loads(file.decode('utf-8'))

    # Prepare data for DataFrame
    records = []

    for result in data.get('results', []):
        # Extract values from the result
        check_id = result.get('check_id', '')
        path = result.get('path', '')
        start = result.get('start', {})
        end = result.get('end', {})
        extra = result.get('extra', {})

        start_line = start.get('line', 0)
        end_line = end.get('line', 0)
        message = extra.get('message', '')
        fix = extra.get('fix', '')

        # Build evidence string: "Line start_line - end_line in file : path"
        evidence = f"Line {start_line} - {end_line} in file : {path}"

        # Create the record
        record = {
            'cve': '',
            'risk': 'Medium',
            'host': 'semgrep',
            'port': start_line,
            'name': check_id,
            'description': message,
            'remediation': fix,
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

    return df
