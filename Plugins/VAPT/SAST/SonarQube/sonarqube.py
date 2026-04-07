"""
ThreatVault Plugin for SonarQube Hotspots CSV Export

This plugin converts SonarQube security hotspots CSV export to ThreatVault VAPT format.
It processes hotspots data and maps it to the required schema fields.

CSV Columns Expected:
    productName, key, filePath, startLine, endLine, securityCategory, vulnerabilityProbability,
    status, message, ruleKey, ruleName, description, author, creationDate, updateDate,
    codeSnippet, fixRecommendations
"""

import polars as pl


def process(file: bytes, file_type: str) -> pl.DataFrame:
    """
    Process SonarQube Hotspots CSV and convert to ThreatVault VAPT format.

    Args:
        file: The uploaded file content as bytes
        file_type: MIME type of the uploaded file (expected: "text/csv")

    Returns:
        pl.DataFrame: DataFrame with ThreatVault VAPT schema fields:
            - cve: Empty string (not applicable for SAST)
            - risk: Severity level from vulnerabilityProbability (uppercase)
            - host: Always "Repo:Branch" (default for SAST)
            - port: Always 0 (not applicable for SAST)
            - name: message
            - description: Detailed description of the vulnerability
            - remediation: fixRecommendations from SonarQube
            - evidence: {filePath}<br/>Line: {startLine} - {endLine}<br/><br/>{codeSnippet}
            - vpr_score: Empty string (not applicable for SAST)

    Raises:
        ValueError: If file_type is not CSV
    """
    # Validate file type
    if file_type not in ["text/csv", "csv"]:
        raise ValueError(f"Unsupported file type: {file_type}. Expected CSV.")

    # Load CSV data
    df = pl.read_csv(file)

    # Map vulnerabilityProbability to ThreatVault risk levels
    risk_mapping = {
        "CRITICAL": "CRITICAL",
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW",
    }

    # Process the data
    result_df = df.with_columns(
        [
            # cve: empty for SAST findings
            pl.lit("").alias("cve"),
            # risk: map from vulnerabilityProbability
            pl.col("vulnerabilityProbability")
            .str.to_uppercase()
            .replace(risk_mapping, default="MEDIUM")
            .alias("risk"),
            # host: always "Repo:Branch" (default value for SAST)
            pl.lit("Repo:Branch").alias("host"),
            # port: not applicable for SAST, always 0
            pl.lit(0).alias("port"),
            # name: message only
            pl.col("message").fill_null("").alias("name"),
            # description: detailed description (trimmed)
            pl.col("description")
            .fill_null("")
            .str.strip_chars()
            .str.replace_all("\n", "<br/>")
            .alias("description"),
            # remediation: fix recommendations (trimmed)
            pl.col("fixRecommendations")
            .fill_null("")
            .str.strip_chars()
            .str.replace_all("\n", "<br/>")
            .alias("remediation"),
            # evidence: filePath, line numbers, and code snippet (trimmed)
            pl.concat_str(
                [
                    pl.col("filePath").fill_null("").str.strip_chars(),
                    pl.lit("<br/>Line: "),
                    pl.col("startLine").cast(pl.Utf8).fill_null(""),
                    pl.lit(" - "),
                    pl.col("endLine").cast(pl.Utf8).fill_null(""),
                    pl.lit("<br/><br/>"),
                    pl.col("codeSnippet").fill_null("").str.strip_chars(),
                ]
            )
            .str.replace_all("\n", "<br/>")
            .alias("evidence"),
            # vpr_score: empty for SAST
            pl.lit("").alias("vpr_score"),
        ]
    )

    # Select only the required columns in the correct order
    result_df = result_df.select(
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

    return result_df
