# ThreatVault Plugin Quick Reference

**A one-page cheat sheet for plugin development**

---

## Required Function Signature

```python
import polars as pl

def process(file: bytes, file_type: str) -> pl.LazyFrame | pl.DataFrame:
    # Your code here
    pass
```

---

## Schema Requirements

### VAPT Schema (9 fields)

**Exact order:**
```python
["cve", "risk", "host", "port", "name", "description", "remediation", "evidence", "vpr_score"]
```

**Data types:**
- `cve`: String (empty string if no CVE)
- `risk`: String - Must be: `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW`
- `host`: String (IP or hostname)
- `port`: **Int64** (use 0 if not applicable)
- `name`: String
- `description`: String (newlines → `<br/>`)
- `remediation`: String (newlines → `<br/>`)
- `evidence`: String (newlines → `<br/>`)
- `vpr_score`: String (empty string if not available)

### Compliance Schema (8 fields)

**Exact order:**
```python
["risk", "host", "port", "name", "description", "remediation", "evidence", "status"]
```

**Data types:**
- `risk`: String or None - Can be: `HIGH`, `MEDIUM`, `LOW`, or `None`
- `host`: String
- `port`: **Int64** (always 0 for compliance)
- `name`: String
- `description`: String (newlines → `<br/>`)
- `remediation`: String (newlines → `<br/>`)
- `evidence`: String (newlines → `<br/>`)
- `status`: String - Must be: `PASSED`, `FAILED`, or `WARNING`

---

## Common Polars Operations

### Load Data

```python
# CSV (lazy - preferred)
lf = pl.scan_csv(file)

# CSV (eager)
df = pl.read_csv(file)

# JSON
df = pl.read_json(file)

# JSON Lines
lf = pl.scan_ndjson(file)
```

### Rename Columns

```python
lf = lf.rename({
    "OldName": "new_name",
    "Another Old": "another_new"
})

# Auto-normalize: "Plugin Output" → "plugin_output"
lf = lf.select(
    pl.all().name.map(lambda x: "_".join(x.lower().split(" ")))
)
```

### Transform Columns

```python
lf = lf.with_columns([
    # Uppercase
    pl.col("risk").str.to_uppercase(),

    # Cast to integer
    pl.col("port").cast(pl.Int64, strict=False),

    # Handle nulls
    pl.col("cve").fill_null(""),

    # Conditional
    pl.when(pl.col("cve").is_null())
      .then(pl.lit(""))
      .otherwise(pl.col("cve"))
      .alias("cve"),

    # String replacement
    pl.col("description").str.replace_all("\n", "<br/>"),

    # Regex extract
    pl.col("text").str.extract(r"Pattern: (.*)", 1),

    # Add constant column
    pl.lit(0).alias("port"),

    # Combine columns
    pl.concat_str([pl.col("a"), pl.lit(" - "), pl.col("b")]).alias("combined")
])
```

### Filter Rows

```python
# Filter by value
lf = lf.filter(pl.col("risk") != "None")

# Filter by list
lf = lf.filter(pl.col("risk").is_in(["CRITICAL", "HIGH", "MEDIUM", "LOW"]))

# Multiple conditions (AND)
lf = lf.filter(
    (pl.col("risk") != "None") & (pl.col("port") > 0)
)

# Multiple conditions (OR)
lf = lf.filter(
    (pl.col("risk") == "CRITICAL") | (pl.col("risk") == "HIGH")
)

# Not null
lf = lf.filter(pl.col("name").is_not_null())
```

### Select Columns

```python
# Select specific columns
lf = lf.select(["cve", "risk", "host"])

# Select and reorder
lf = lf.select([
    "cve", "risk", "host", "port", "name",
    "description", "remediation", "evidence", "vpr_score"
])

# Exclude columns
lf = lf.drop(["unwanted_col1", "unwanted_col2"])
```

### JSON Nested Fields

```python
# Extract from nested structure
lf = lf.with_columns([
    # Simple: data.field
    pl.col("data").struct.field("field_name").alias("extracted"),

    # Deep: data.nested.deeply.value
    pl.col("data")
      .struct.field("nested")
      .struct.field("deeply")
      .struct.field("value")
      .alias("deep_value")
])

# Explode array
lf = lf.explode(pl.col("vulnerabilities"))

# Unnest struct
lf = lf.unnest("vulnerabilities")
```

---

## Essential Code Snippets

### File Type Validation

```python
# CSV only
if file_type != "text/csv":
    raise ValueError(f"File type not supported: {file_type}")

# JSON only
if file_type not in ["json", "application/json"]:
    raise ValueError(f"Unsupported file type: {file_type}")

# Multiple types
if file_type == "text/csv":
    return process_csv(file)
elif file_type in ["json", "application/json"]:
    return process_json(file)
else:
    raise ValueError(f"Unsupported: {file_type}")
```

### Handle Empty/Null CVE

```python
pl.when(pl.col("cve").is_null() | (pl.col("cve") == ""))
  .then(pl.lit(""))
  .otherwise(pl.col("cve"))
  .alias("cve")

# Or simpler:
pl.col("cve").fill_null("")
```

### Replace Newlines (Required!)

```python
lf = lf.with_columns([
    pl.col("description").str.replace_all("\n", "<br/>"),
    pl.col("remediation").str.replace_all("\n", "<br/>"),
    pl.col("evidence").str.replace_all("\n", "<br/>")
])
```

### Port to Integer

```python
pl.col("port").cast(pl.Int64, strict=False).fill_null(0)
```

### Uppercase Risk/Status

```python
# VAPT risk
pl.col("risk").str.to_uppercase()

# Compliance status
pl.col("status").str.to_uppercase()
```

### Filter Valid Risk Values

```python
# VAPT
lf = lf.filter(
    pl.col("risk").is_in(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
)

# Compliance
lf = lf.filter(
    pl.col("status").is_in(["PASSED", "FAILED", "WARNING"])
)
```

---

## Complete VAPT Plugin Template

```python
import polars as pl


def process(file: bytes, file_type: str) -> pl.LazyFrame:
    """Transform to ThreatVault VAPT format."""

    # 1. Validate file type
    if file_type != "text/csv":
        raise ValueError(f"Unsupported file type: {file_type}")

    # 2. Load and transform
    lf = (
        pl.scan_csv(file)

        # 3. Rename columns
        .rename({
            "SourceColumn1": "cve",
            "SourceColumn2": "risk",
            "SourceColumn3": "host",
            "SourceColumn4": "port",
            "SourceColumn5": "name",
            "SourceColumn6": "description",
            "SourceColumn7": "remediation",
            "SourceColumn8": "evidence",
            "SourceColumn9": "vpr_score"
        })

        # 4. Transform data
        .with_columns([
            pl.col("cve").fill_null(""),
            pl.col("risk").str.to_uppercase(),
            pl.col("port").cast(pl.Int64, strict=False).fill_null(0),
            pl.col("description").str.replace_all("\n", "<br/>"),
            pl.col("remediation").str.replace_all("\n", "<br/>"),
            pl.col("evidence").str.replace_all("\n", "<br/>"),
            pl.col("vpr_score").fill_null("")
        ])

        # 5. Filter valid rows
        .filter(pl.col("risk").is_in(["CRITICAL", "HIGH", "MEDIUM", "LOW"]))

        # 6. Select in exact order
        .select([
            "cve", "risk", "host", "port", "name",
            "description", "remediation", "evidence", "vpr_score"
        ])
    )

    return lf
```

---

## Complete Compliance Plugin Template

```python
import polars as pl


def process(file: bytes, file_type: str) -> pl.LazyFrame:
    """Transform to ThreatVault Compliance format."""

    # 1. Validate file type
    if file_type != "text/csv":
        raise ValueError(f"Unsupported file type: {file_type}")

    # 2. Load and transform
    lf = (
        pl.scan_csv(file)

        # 3. Rename columns
        .rename({
            "SourceColumn1": "risk",
            "SourceColumn2": "host",
            "SourceColumn3": "name",
            "SourceColumn4": "description",
            "SourceColumn5": "remediation",
            "SourceColumn6": "evidence",
            "SourceColumn7": "status"
        })

        # 4. Add port (always 0)
        .with_columns(pl.lit(0).alias("port"))

        # 5. Transform data
        .with_columns([
            pl.when(pl.col("risk").is_null())
              .then(pl.lit(None, dtype=pl.String))
              .otherwise(pl.col("risk").str.to_uppercase())
              .alias("risk"),
            pl.col("status").str.to_uppercase(),
            pl.col("description").str.replace_all("\n", "<br/>"),
            pl.col("remediation").str.replace_all("\n", "<br/>"),
            pl.col("evidence").str.replace_all("\n", "<br/>")
        ])

        # 6. Filter valid rows
        .filter(pl.col("status").is_in(["PASSED", "FAILED", "WARNING"]))

        # 7. Select in exact order
        .select([
            "risk", "host", "port", "name",
            "description", "remediation", "evidence", "status"
        ])
    )

    return lf
```

---

## Testing Template

```python
import polars as pl
from pathlib import Path
from your_plugin import process


def test_plugin():
    # Load sample file
    sample_file = Path("sample_scan.csv")
    with open(sample_file, "rb") as f:
        file_content = f.read()

    # Process
    result = process(file_content, "text/csv")

    # Collect (if LazyFrame)
    if hasattr(result, 'collect'):
        df = result.collect()
    else:
        df = result

    print(f"✅ Processed {len(df)} rows")
    print(df.head())

    # Validate schema (VAPT example)
    expected = ["cve", "risk", "host", "port", "name",
               "description", "remediation", "evidence", "vpr_score"]

    assert df.columns == expected, f"Schema mismatch!"
    assert df["port"].dtype == pl.Int64, "Port must be Int64"

    print("✅ All tests passed!")


if __name__ == "__main__":
    test_plugin()
```

---

## Common Mistakes Checklist

- [ ] Wrong column order (must match exactly!)
- [ ] Port is string (must be Int64)
- [ ] Forgot to replace `\n` with `<br/>`
- [ ] Null handling for CVE/VPR score
- [ ] Invalid risk values (not CRITICAL/HIGH/MEDIUM/LOW)
- [ ] Invalid status values (not PASSED/FAILED/WARNING)
- [ ] Using VAPT schema for Compliance (or vice versa)
- [ ] Not filtering out invalid rows
- [ ] File type validation missing

---

## Directory Structure

```
Plugins/
├── VAPT/
│   ├── VA/          # Vulnerability Assessment (Nessus, OpenVAS)
│   ├── SAST/        # Static Analysis (Semgrep, Bandit)
│   ├── DAST/        # Dynamic Analysis (Burp, ZAP)
│   └── SCA/         # Software Composition (Trivy, Snyk)
├── Compliance/      # CIS, ISO 27001, NIST
└── SBOM/            # Bill of Materials
```

---

## Helpful Links

- Full guide: `PLUGIN_CREATION_GUIDE.md`
- README: `README.md`
- Specification: `blueprint.txt`
- Example plugins: `Plugins/` directory

---

**Print this for quick reference while coding! 📄**
