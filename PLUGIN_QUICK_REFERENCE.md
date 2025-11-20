# ThreatVault Plugin Quick Reference

**One-page cheat sheet for plugin development**

---

## Plugin Function Signature

```python
import polars as pl

def process(file: bytes, file_type: str) -> pl.DataFrame:
    # Your code here
    return df
```

---

## VA (Vulnerability) Fields - 9 Required

| Field | Type | Required | Can be Empty? | Valid Values |
|-------|------|----------|---------------|--------------|
| `cve` | String | ✅ | ✅ | "CVE-2023-1234" or "" |
| `risk` | String | ✅ | ❌ | CRITICAL, HIGH, MEDIUM, LOW |
| `host` | String | ✅ | ❌ | IP or hostname |
| `port` | Integer | ✅ | ✅ | 0-65535 (use 0 if N/A) |
| `name` | String | ✅ | ❌ | Issue title |
| `description` | String | ✅ | ❌ | Full details |
| `remediation` | String | ✅ | ❌ | How to fix |
| `evidence` | String | ✅ | ✅ | Scan output or "" |
| `vpr_score` | String | ✅ | ✅ | "0.0" to "10.0" or "" |

---

## Compliance Fields - 8 Required

| Field | Type | Required | Can be Empty? | Valid Values |
|-------|------|----------|---------------|--------------|
| `risk` | String | ✅ | ✅* | HIGH, MEDIUM, LOW or None |
| `host` | String | ✅ | ❌ | Server/system name |
| `port` | Integer | ✅ | ✅ | Usually 0 |
| `name` | String | ✅ | ❌ | Rule name |
| `description` | String | ✅ | ❌ | What rule checks |
| `remediation` | String | ✅ | ❌ | How to comply |
| `evidence` | String | ✅ | ✅ | Actual value or "" |
| `status` | String | ✅ | ❌ | PASSED, FAILED, WARNING |

**\*If empty, auto-assigned to "Medium"**

❌ **Do NOT include:** `cve`, `vpr_score`

---

## Common Polars Operations

### Read Files

```python
# CSV
df = pl.read_csv(file)
df = pl.scan_csv(file)  # Lazy

# JSON
import json
data = json.loads(file.decode('utf-8'))
df = pl.DataFrame(data)
```

### Rename Columns

```python
df = df.with_columns([
    pl.col("Source_Name").alias("name"),
    pl.col("Severity").alias("risk"),
])
```

### Create Literal Columns

```python
df = df.with_columns([
    pl.lit(0).alias("port"),                    # Integer
    pl.lit("").alias("cve"),                    # String
    pl.lit(None, dtype=pl.Utf8).alias("risk"),  # Null
])
```

### Transform Data

```python
# Uppercase
pl.col("risk").str.to_uppercase()

# Replace text
pl.col("status").str.replace("PASS", "PASSED")

# Replace all occurrences
pl.col("description").str.replace_all("\n", "<br/>")

# Cast type
pl.col("port").cast(pl.Int64)

# Fill null values
pl.col("cve").fill_null("")

# Conditional (if-then-else)
pl.when(pl.col("port") == "")
  .then(0)
  .otherwise(pl.col("port").cast(pl.Int64))
```

### Filter Rows

```python
# Single condition
df = df.filter(pl.col("risk") != "NONE")

# Multiple conditions (AND)
df = df.filter(
    pl.col("risk").is_not_null(),
    pl.col("status") != "NONE"
)

# IN list
df = df.filter(
    pl.col("risk").is_in(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
)
```

### Select Columns

```python
df = df.select([
    "cve", "risk", "host", "port",
    "name", "description", "remediation",
    "evidence", "vpr_score"
])
```

---

## Error Handling

```python
# Validate file type
if file_type != "text/csv":
    raise ValueError(f"Unsupported file type: {file_type}")

# Check required columns exist
required = ["Severity", "Host", "Port"]
missing = [col for col in required if col not in df.columns]
if missing:
    raise ValueError(f"Missing columns: {missing}")
```

---

## Text Formatting

```python
# Replace newlines with HTML breaks (REQUIRED!)
df = df.with_columns([
    pl.col("description").str.replace_all("\n", "<br/>"),
    pl.col("remediation").str.replace_all("\n", "<br/>"),
    pl.col("evidence").str.replace_all("\n", "<br/>"),
])
```

---

## Mapping Custom Values

```python
# Map severity levels
df = df.with_columns([
    pl.col("Severity")
      .str.replace("Severe", "CRITICAL")
      .str.replace("Important", "HIGH")
      .str.replace("Moderate", "MEDIUM")
      .str.replace("Minor", "LOW")
      .str.to_uppercase()
      .alias("risk")
])

# Map status values
df = df.with_columns([
    pl.col("Result")
      .str.replace("PASS", "PASSED")
      .str.replace("FAIL", "FAILED")
      .str.replace("OK", "PASSED")
      .str.to_uppercase()
      .alias("status")
])
```

---

## Testing Code

```python
if __name__ == "__main__":
    sample = """Col1,Col2,Col3
value1,value2,value3"""

    file_content = sample.encode('utf-8')

    try:
        result = process(file_content, "text/csv")
        print("✓ Success!")
        print(f"Shape: {result.shape}")
        print(result)
    except Exception as e:
        print(f"✗ Error: {e}")
```

---

## Common Mistakes

### ❌ Wrong

```python
# Missing uppercase
pl.col("Severity").alias("risk")  # Should be .str.to_uppercase()

# Wrong data type
pl.lit(0, dtype=pl.Utf8).alias("port")  # Port should be Int64, not Utf8

# Using None for string
pl.lit(None).alias("cve")  # Should use "" or pl.lit(None, dtype=pl.Utf8)

# Forgetting to convert newlines
# Newlines stay as \n instead of <br/>

# Including cve in compliance
df.select(["cve", "risk", ...])  # cve not allowed in compliance!

# Wrong column order
df.select(["name", "risk", "host", ...])  # Must follow exact order
```

### ✅ Correct

```python
# Uppercase risk
pl.col("Severity").str.to_uppercase().alias("risk")

# Correct data type
pl.lit(0).alias("port")  # Integer

# Empty string for optional fields
pl.lit("").alias("cve")

# Convert newlines
pl.col("description").str.replace_all("\n", "<br/>")

# Compliance without cve/vpr
df.select(["risk", "host", "port", ...])  # Correct

# Correct column order
df.select([
    "cve", "risk", "host", "port", "name",
    "description", "remediation", "evidence", "vpr_score"
])
```

---

## Validation Checklist

### Before Returning DataFrame

```python
# ✅ All required columns present
# ✅ Columns in correct order
# ✅ Correct data types (strings vs integers)
# ✅ No None values (use "" for empty strings)
# ✅ Newlines replaced with <br/>
# ✅ Risk/Status values uppercase
# ✅ Invalid rows filtered out
# ✅ For VA: 9 columns (with cve, vpr_score)
# ✅ For Compliance: 8 columns (NO cve, vpr_score)
```

---

## File Type MIME Types

```python
# CSV
"text/csv"
"application/csv"

# JSON
"application/json"
"json"

# Accept multiple
if file_type not in ["text/csv", "application/csv"]:
    raise ValueError(...)
```

---

## Debug Tips

```python
# Print to see what's happening
print(f"Columns: {df.columns}")
print(f"Shape: {df.shape}")
print(f"First row: {df.head(1)}")
print(f"Data types: {df.dtypes}")

# Check for nulls
print(df.null_count())

# Sample data
print(df.sample(5))
```

---

## Quick Templates

### CSV VA Plugin

```python
import polars as pl

def process(file: bytes, file_type: str) -> pl.DataFrame:
    if file_type != "text/csv":
        raise ValueError(f"Expected CSV, got {file_type}")

    df = pl.read_csv(file)
    df = df.with_columns([
        pl.col("CVE").fill_null("").alias("cve"),
        pl.col("Severity").str.to_uppercase().alias("risk"),
        pl.col("Host").alias("host"),
        pl.col("Port").cast(pl.Int64).alias("port"),
        pl.col("Name").alias("name"),
        pl.col("Description").alias("description"),
        pl.col("Solution").alias("remediation"),
        pl.col("Evidence").fill_null("").alias("evidence"),
        pl.col("VPR").fill_null("").alias("vpr_score"),
    ])
    df = df.with_columns([
        pl.col("description").str.replace_all("\n", "<br/>"),
        pl.col("remediation").str.replace_all("\n", "<br/>"),
    ])
    df = df.filter(pl.col("risk").is_in(["CRITICAL", "HIGH", "MEDIUM", "LOW"]))
    return df.select(["cve", "risk", "host", "port", "name",
                     "description", "remediation", "evidence", "vpr_score"])
```

### CSV Compliance Plugin

```python
import polars as pl

def process(file: bytes, file_type: str) -> pl.DataFrame:
    if file_type != "text/csv":
        raise ValueError(f"Expected CSV, got {file_type}")

    df = pl.read_csv(file)
    df = df.with_columns([
        pl.lit(None, dtype=pl.Utf8).alias("risk"),
        pl.col("Host").alias("host"),
        pl.lit(0).alias("port"),
        pl.col("Rule").alias("name"),
        pl.col("Description").alias("description"),
        pl.col("Solution").alias("remediation"),
        pl.col("ActualValue").fill_null("").alias("evidence"),
        pl.col("Status").str.to_uppercase().alias("status"),
    ])
    df = df.with_columns([
        pl.col("description").str.replace_all("\n", "<br/>"),
        pl.col("remediation").str.replace_all("\n", "<br/>"),
    ])
    df = df.filter(pl.col("status").is_in(["PASSED", "FAILED", "WARNING"]))
    return df.select(["risk", "host", "port", "name",
                     "description", "remediation", "evidence", "status"])
```

### JSON Plugin

```python
import json
import polars as pl

def process(file: bytes, file_type: str) -> pl.DataFrame:
    if file_type not in ["application/json", "json"]:
        raise ValueError(f"Expected JSON, got {file_type}")

    data = json.loads(file.decode('utf-8'))
    records = []

    for item in data.get('results', []):
        record = {
            'cve': item.get('cve', ''),
            'risk': item.get('severity', 'Medium').upper(),
            'host': item.get('host', ''),
            'port': item.get('port', 0),
            'name': item.get('title', ''),
            'description': item.get('description', ''),
            'remediation': item.get('fix', ''),
            'evidence': item.get('evidence', ''),
            'vpr_score': ''
        }
        records.append(record)

    df = pl.DataFrame(records)
    df = df.with_columns([
        pl.col("description").str.replace_all("\n", "<br/>"),
        pl.col("remediation").str.replace_all("\n", "<br/>"),
    ])
    return df
```

---

## Need More Help?

- See full guide: `PLUGIN_DEVELOPMENT_GUIDE.md`
- Use templates: `template_va_plugin.py`, `template_compliance_plugin.py`
- Check examples: `semgrep_plugin.py`, `sample_va_plugins.py`
