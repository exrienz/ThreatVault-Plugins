import polars as pl


def process(file: bytes, file_type: str) -> pl.LazyFrame:
    if file_type != "text/csv":
        raise ValueError(f"File type not supported: {file_type}")
    # pattern1 = r"Actual Value:\s*\n((?s).*?)\n\s*\n"
    pattern2 = r"Actual Value:\s*\n(?s)(.*)"
    lf = pl.scan_csv(file)
    lf = (
        lf.with_columns(
            name=pl.col("Description").str.extract(r"^(.*): \[.*\]", 1),
            description=pl.col("Description")
            .str.extract(r"^(?:.*\n){2}((?s).*?)(?:^Actual Value:|$)", 1)
            .str.replace(pattern2, "")
            .str.replace_all("\n", "<br/>"),
            evidence=pl.col("Description")
            .str.extract(pattern2)
            .str.replace_all("\n", "<br/>")
            .str.strip_chars(),
            risk=pl.lit(None, dtype=pl.String),
        )
        .filter(pl.col("Risk") != "None", pl.col("Risk").is_not_null())
        .rename({"Solution": "remediation", "Risk": "status"})
        .drop(["VPR Score", "CVE", "Name", "Plugin Output", "Description"])
    )
    return lf
