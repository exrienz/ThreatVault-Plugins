import polars as pl


def process(file: bytes, file_type: str) -> pl.LazyFrame | pl.DataFrame:
    """
    Process DependencyTrack CSV output and transform it into ThreatVault VAPT format.

    Args:
        file: Raw file content as bytes
        file_type: MIME type (expected: "text/csv" or "csv")

    Returns:
        Polars LazyFrame with standardized VAPT schema

    Raises:
        ValueError: If file_type is not "text/csv" or "csv"
    """
    # Validate file type - accept both "text/csv" and "csv"
    if file_type not in ["text/csv", "csv"]:
        raise ValueError(f"File type not supported: {file_type}. Expected 'text/csv' or 'csv'")

    # Parse CSV file
    df = pl.scan_csv(file)

    # Transform and map fields to ThreatVault VAPT schema
    # Required fields: cve, risk, host, port, name, description, remediation, evidence, vpr_score
    result = df.select([
        # CVE - direct mapping
        pl.col("cve"),

        # Risk - handle UNASSIGNED by converting to MEDIUM
        pl.when(pl.col("risk") == "UNASSIGNED")
          .then(pl.lit("MEDIUM"))
          .otherwise(pl.col("risk"))
          .alias("risk"),

        # Host - direct mapping from host field
        pl.col("host"),

        # Port - DependencyTrack doesn't have port info, set to 0
        pl.lit(0).alias("port"),

        # Name - include CVE number in format "name : CVE"
        pl.col("name"),

        # Description - replace newlines with <br/> for HTML display
        pl.col("description").str.replace_all("\n", "<br/>"),

        # Remediation - already contains URLs, replace newlines with <br/>
        pl.col("remediation").str.replace_all("\n", "<br/>"),

        # Evidence - fill empty with default message
        pl.when(pl.col("evidence").is_null() | (pl.col("evidence").str.strip_chars() == ""))
          .then(pl.lit("no evidence provided"))
          .otherwise(pl.col("evidence"))
          .alias("evidence"),

        # VPR Score - DependencyTrack doesn't provide VPR score, set to 0
        pl.lit(0).alias("vpr_score")
    ])

    # Filter out any invalid risk values (should only be CRITICAL, HIGH, MEDIUM, LOW)
    result = result.filter(
        pl.col("risk").is_in(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    )

    return result
