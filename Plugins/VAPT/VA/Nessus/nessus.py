import polars as pl


def process(file: bytes, file_type: str) -> pl.LazyFrame:
    if file_type != "text/csv":
        raise ValueError(f"File type not supported: {file_type}")
    return (
        pl.scan_csv(file)
        .select(pl.all().name.map(lambda x: "_".join(x.lower().split(" "))))
        .filter(pl.col("risk") != "None")
        .with_columns(
            pl.col("solution", "description", "plugin_output").str.replace_all(
                "\n", " <br/> "
            )
        )
        .rename(
            {
                "solution": "remediation",
                "plugin_output": "evidence",
            }
        )
    )
