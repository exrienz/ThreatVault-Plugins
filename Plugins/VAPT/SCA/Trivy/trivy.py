import polars as pl


def process(file: bytes, file_type: str):
    # Validate file type
    if file_type != "json":
        raise ValueError(f"Unsupported file type: {file_type}")

    # Load JSON data
    # lf = pl.scan_ndjson(file)
    lf = pl.read_json(file)

    # Extract vulnerabilities array from nested structure
    lf = lf.explode(pl.col("vulnerabilities")).unnest("vulnerabilities")

    # Extract nested fields
    lf = lf.with_columns(
        [
            # Extract host from location.image
            pl.col("location").struct.field("image").alias("host"),
            # Extract package name from nested location.dependency.package.name
            pl.col("location")
            .struct.field("dependency")
            .struct.field("package")
            .struct.field("name")
            .alias("pkg_name"),
            # Extract package version
            pl.col("location")
            .struct.field("dependency")
            .struct.field("version")
            .alias("pkg_version"),
        ]
    )

    # Apply field mappings and transformations
    lf = lf.with_columns(
        [
            # CVE: Use id field (contains CVE ID)
            pl.col("id").alias("cve"),
            # Risk: Map severity to uppercase
            pl.col("severity").str.to_uppercase().alias("risk"),
            # Host: Already extracted above
            pl.col("host"),
            # Port: Default to 0 as specified
            pl.lit(0).alias("port"),
            # Name: Use fallback logic - pkg_name → message → cve
            pl.coalesce([pl.col("pkg_name"), pl.col("message"), pl.col("cve")]).alias(
                "name"
            ),
            # Description: Use description field
            pl.col("description").alias("description"),
            # Remediation: Use solution field (FixedVersion not available in this format)
            pl.col("solution").alias("remediation"),
            # Evidence: Empty as specified
            pl.lit("").alias("evidence"),
            # VPR Score: Empty as specified
            pl.lit("").alias("vpr_score"),
        ]
    )

    # Filter out invalid risk values
    lf = lf.filter(pl.col("risk").is_in(["CRITICAL", "HIGH", "MEDIUM", "LOW"]))

    # Handle newline replacement in text fields
    lf = lf.with_columns(
        [
            pl.col("description").str.replace_all("\n", "<br/>"),
            pl.col("remediation").str.replace_all("\n", "<br/>"),
        ]
    )

    # Select final columns with correct order
    lf = lf.select(
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

    return lf
