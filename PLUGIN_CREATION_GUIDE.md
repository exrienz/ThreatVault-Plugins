# ThreatVault Plugin Creation Guide

**A Complete Step-by-Step Tutorial for Creating Custom Plugins**

This guide will walk you through creating your first ThreatVault plugin from scratch. No prior experience with Polars required!

---

## 📚 Table of Contents

1. [Before You Start](#before-you-start)
2. [Understanding the Basics](#understanding-the-basics)
3. [Tutorial: Creating Your First VAPT Plugin](#tutorial-creating-your-first-vapt-plugin)
4. [Tutorial: Creating Your First Compliance Plugin](#tutorial-creating-your-first-compliance-plugin)
5. [Advanced Patterns](#advanced-patterns)
6. [Testing Best Practices](#testing-best-practices)
7. [Optimization Tips](#optimization-tips)
8. [Common Mistakes to Avoid](#common-mistakes-to-avoid)

---

## Before You Start

### What You Need

1. **Python 3.8 or higher**
   ```bash
   python --version  # Should show 3.8+
   ```

2. **Polars library**
   ```bash
   pip install polars
   ```

3. **A sample scan file** from your security tool (CSV or JSON)

4. **Basic Python knowledge** (variables, functions, dictionaries)

### What You'll Learn

- ✅ How to read and transform CSV/JSON files using Polars
- ✅ Field mapping from any security tool to ThreatVault
- ✅ Handling edge cases and data validation
- ✅ Testing your plugin before submission

---

## Understanding the Basics

### What is a Plugin?

A plugin is a Python file with **one required function**:

```python
def process(file: bytes, file_type: str) -> pl.LazyFrame | pl.DataFrame:
    # Your transformation logic here
    pass
```

**That's it!** Everything else is just data transformation.

### The Process Function

```python
def process(file: bytes, file_type: str):
    """
    ThreatVault calls this function with your uploaded file.

    Parameters:
    -----------
    file : bytes
        Raw content of the uploaded file (CSV, JSON, etc.)

    file_type : str
        MIME type of the file
        - "text/csv" for CSV files
        - "json" or "application/json" for JSON files

    Returns:
    --------
    pl.LazyFrame or pl.DataFrame
        Transformed data in ThreatVault schema
    """
```

### Key Concepts

**Polars vs Pandas**: We use Polars because it's faster and has lazy evaluation (processes data only when needed).

**LazyFrame vs DataFrame**:
- `LazyFrame`: Optimized, doesn't execute until `.collect()` is called (preferred)
- `DataFrame`: Immediate execution (use for JSON or small datasets)

**Schema**: The exact column names and order ThreatVault expects.

---

## Tutorial: Creating Your First VAPT Plugin

Let's create a real plugin for a fictional vulnerability scanner called **"SecureScan"**.

### Step 1: Understand Your Tool's Output

SecureScan creates a CSV file `securescan_results.csv`:

```csv
CVE,Severity,IP Address,Service Port,Vulnerability Title,Full Description,How to Fix,Scan Evidence,Risk Score
CVE-2023-1234,High,192.168.1.10,443,Outdated TLS Version,Server accepts TLS 1.0 which is deprecated,Disable TLS 1.0 and enable TLS 1.2+,TLS 1.0 handshake succeeded,8.5
,Medium,192.168.1.15,22,Weak SSH Configuration,SSH server allows weak ciphers,Update sshd_config to disable CBC ciphers,Cipher: aes128-cbc accepted,6.2
CVE-2023-5678,Critical,192.168.1.20,80,SQL Injection,Login form vulnerable to SQL injection,Use parameterized queries,Payload: ' OR 1=1-- worked,9.8
```

**Observations**:
- Some CVE fields are empty
- Column names have spaces
- We have all the data we need

### Step 2: Map Fields

Create a mapping table:

| SecureScan Column | ThreatVault Field | Transformation Needed |
|-------------------|-------------------|-----------------------|
| CVE | `cve` | Use as-is (handle empty) |
| Severity | `risk` | Convert to UPPERCASE |
| IP Address | `host` | Rename |
| Service Port | `port` | Rename (ensure integer) |
| Vulnerability Title | `name` | Rename |
| Full Description | `description` | Replace newlines with `<br/>` |
| How to Fix | `remediation` | Replace newlines with `<br/>` |
| Scan Evidence | `evidence` | Replace newlines with `<br/>` |
| Risk Score | `vpr_score` | Rename |

### Step 3: Create Plugin Directory

```bash
# Navigate to repository
cd ThreatVault-Plugins

# Create directory structure
mkdir -p Plugins/VAPT/VA/SecureScan
cd Plugins/VAPT/VA/SecureScan

# Create plugin file
touch securescan.py
```

### Step 4: Write the Plugin

Open `securescan.py` and start coding:

```python
import polars as pl


def process(file: bytes, file_type: str) -> pl.LazyFrame:
    """
    Transform SecureScan CSV output to ThreatVault VAPT format.

    Args:
        file: Raw CSV file content
        file_type: MIME type (expected: "text/csv")

    Returns:
        LazyFrame with ThreatVault schema
    """

    # ============================================
    # STEP 1: Validate File Type
    # ============================================
    if file_type != "text/csv":
        raise ValueError(
            f"Unsupported file type: {file_type}. "
            f"SecureScan plugin only supports CSV files."
        )

    # ============================================
    # STEP 2: Load CSV (Lazy Loading)
    # ============================================
    lf = pl.scan_csv(file)

    # ============================================
    # STEP 3: Rename Columns
    # ============================================
    lf = lf.rename({
        "CVE": "cve",
        "Severity": "risk",
        "IP Address": "host",
        "Service Port": "port",
        "Vulnerability Title": "name",
        "Full Description": "description",
        "How to Fix": "remediation",
        "Scan Evidence": "evidence",
        "Risk Score": "vpr_score"
    })

    # ============================================
    # STEP 4: Transform Data
    # ============================================
    lf = lf.with_columns([
        # Convert risk to uppercase (HIGH, MEDIUM, LOW, CRITICAL)
        pl.col("risk").str.to_uppercase().alias("risk"),

        # Handle empty CVE values (replace nulls with empty string)
        pl.when(pl.col("cve").is_null() | (pl.col("cve") == ""))
          .then(pl.lit(""))
          .otherwise(pl.col("cve"))
          .alias("cve"),

        # Ensure port is integer
        pl.col("port").cast(pl.Int64, strict=False).fill_null(0).alias("port"),

        # Replace newlines in text fields for HTML display
        pl.col("description").str.replace_all("\n", "<br/>").alias("description"),
        pl.col("remediation").str.replace_all("\n", "<br/>").alias("remediation"),
        pl.col("evidence").str.replace_all("\n", "<br/>").alias("evidence"),

        # Handle VPR score (convert to string, handle nulls)
        pl.col("vpr_score").cast(pl.Utf8).fill_null("").alias("vpr_score")
    ])

    # ============================================
    # STEP 5: Filter Invalid Rows
    # ============================================
    # Only keep rows with valid risk levels
    lf = lf.filter(
        pl.col("risk").is_in(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    )

    # ============================================
    # STEP 6: Select Final Schema (IMPORTANT!)
    # ============================================
    # Must be in EXACT order for VAPT
    lf = lf.select([
        "cve",
        "risk",
        "host",
        "port",
        "name",
        "description",
        "remediation",
        "evidence",
        "vpr_score"
    ])

    return lf
```

### Step 5: Create Test File

Create `test_securescan.py` in the same directory:

```python
import polars as pl
from pathlib import Path
from securescan import process


def test_plugin():
    """Test the SecureScan plugin with sample data."""

    # Create sample CSV data
    sample_csv = """CVE,Severity,IP Address,Service Port,Vulnerability Title,Full Description,How to Fix,Scan Evidence,Risk Score
CVE-2023-1234,High,192.168.1.10,443,Outdated TLS Version,Server accepts TLS 1.0,Disable TLS 1.0,TLS 1.0 handshake succeeded,8.5
,Medium,192.168.1.15,22,Weak SSH Configuration,SSH allows weak ciphers,Update sshd_config,Cipher: aes128-cbc accepted,6.2
CVE-2023-5678,Critical,192.168.1.20,80,SQL Injection,Login form vulnerable,Use parameterized queries,Payload worked,9.8"""

    # Convert to bytes
    file_content = sample_csv.encode('utf-8')

    # Test plugin
    try:
        result = process(file_content, "text/csv")

        # Collect LazyFrame to DataFrame
        df = result.collect()

        print("✅ Plugin executed successfully!")
        print(f"\n📊 Processed {len(df)} vulnerabilities\n")

        # Display results
        print("🔍 Output Preview:")
        print(df)

        # Validate schema
        expected_cols = ["cve", "risk", "host", "port", "name",
                        "description", "remediation", "evidence", "vpr_score"]

        if df.columns == expected_cols:
            print("\n✅ Schema validation PASSED!")
        else:
            print(f"\n❌ Schema validation FAILED!")
            print(f"Expected: {expected_cols}")
            print(f"Got:      {df.columns}")
            return False

        # Validate data types
        print("\n🔍 Data Type Check:")
        print(df.dtypes)

        # Check risk values
        unique_risks = df.select(pl.col("risk").unique()).to_series().to_list()
        print(f"\n🔍 Unique risk values: {unique_risks}")

        valid_risks = all(r in ["CRITICAL", "HIGH", "MEDIUM", "LOW"] for r in unique_risks)
        if valid_risks:
            print("✅ All risk values are valid!")
        else:
            print("❌ Invalid risk values found!")
            return False

        print("\n🎉 All tests PASSED!")
        return True

    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = test_plugin()
    exit(0 if success else 1)
```

### Step 6: Run Tests

```bash
cd Plugins/VAPT/VA/SecureScan
python test_securescan.py
```

**Expected Output**:
```
✅ Plugin executed successfully!

📊 Processed 3 vulnerabilities

🔍 Output Preview:
┌───────────────┬──────────┬───────────────┬──────┬─────────────────────────┬──────────────────────┬─────────────────────────┬────────────────────────┬───────────┐
│ cve           │ risk     │ host          │ port │ name                    │ description          │ remediation             │ evidence               │ vpr_score │
├───────────────┼──────────┼───────────────┼──────┼─────────────────────────┼──────────────────────┼─────────────────────────┼────────────────────────┼───────────┤
│ CVE-2023-1234 │ HIGH     │ 192.168.1.10  │ 443  │ Outdated TLS Version    │ Server accepts...    │ Disable TLS 1.0         │ TLS 1.0 handshake...   │ 8.5       │
│               │ MEDIUM   │ 192.168.1.15  │ 22   │ Weak SSH Configuration  │ SSH allows...        │ Update sshd_config      │ Cipher: aes128-cbc...  │ 6.2       │
│ CVE-2023-5678 │ CRITICAL │ 192.168.1.20  │ 80   │ SQL Injection           │ Login form...        │ Use parameterized...    │ Payload worked         │ 9.8       │
└───────────────┴──────────┴───────────────┴──────┴─────────────────────────┴──────────────────────┴─────────────────────────┴────────────────────────┴───────────┘

✅ Schema validation PASSED!
✅ All risk values are valid!
🎉 All tests PASSED!
```

### Step 7: Submit Your Plugin

You're done! Follow the [submission guidelines](README.md#submitting-your-plugin) to create a PR.

---

## Tutorial: Creating Your First Compliance Plugin

Now let's create a compliance plugin for **"ComplianceChecker"**, a tool that verifies CIS Benchmark controls.

### Step 1: Understand the Output

ComplianceChecker creates `compliance_audit.csv`:

```csv
Rule ID,Server Name,Control Name,Control Description,Audit Result,Fix Instructions,Check Status,Impact Level
CIS-1.1.1,web-server-01,Disable Unused Filesystems,Ensure cramfs filesystem is disabled,cramfs is loaded,Add 'install cramfs /bin/true' to /etc/modprobe.d/,FAILED,High
CIS-1.2.3,db-server-01,Enable GPG Check,Ensure gpgcheck is enabled,gpgcheck=1 in yum.conf,No action needed,PASSED,Medium
CIS-2.1.1,app-server-01,Disable Legacy Services,Ensure chargen services are not enabled,chargen-dgram is active,systemctl disable chargen-dgram,FAILED,Low
```

### Step 2: Map Fields

| ComplianceChecker Column | ThreatVault Field | Notes |
|--------------------------|-------------------|-------|
| Impact Level | `risk` | Convert to uppercase |
| Server Name | `host` | Direct mapping |
| (constant 0) | `port` | Always 0 for compliance |
| Control Name | `name` | Direct mapping |
| Control Description | `description` | Replace newlines |
| Fix Instructions | `remediation` | Replace newlines |
| Audit Result | `evidence` | Current state |
| Check Status | `status` | PASSED/FAILED/WARNING |

### Step 3: Write the Plugin

Create `Plugins/Compliance/ComplianceChecker/compliancechecker.py`:

```python
import polars as pl


def process(file: bytes, file_type: str) -> pl.LazyFrame:
    """
    Transform ComplianceChecker CSV to ThreatVault Compliance format.

    Args:
        file: Raw CSV content
        file_type: MIME type

    Returns:
        LazyFrame with Compliance schema
    """

    # ============================================
    # STEP 1: Validate File Type
    # ============================================
    if file_type != "text/csv":
        raise ValueError(f"Unsupported file type: {file_type}")

    # ============================================
    # STEP 2: Load CSV
    # ============================================
    lf = pl.scan_csv(file)

    # ============================================
    # STEP 3: Rename and Add Columns
    # ============================================
    lf = lf.rename({
        "Impact Level": "risk",
        "Server Name": "host",
        "Control Name": "name",
        "Control Description": "description",
        "Fix Instructions": "remediation",
        "Audit Result": "evidence",
        "Check Status": "status"
    })

    # Add port column (always 0 for compliance)
    lf = lf.with_columns(pl.lit(0).alias("port"))

    # ============================================
    # STEP 4: Transform Data
    # ============================================
    lf = lf.with_columns([
        # Convert risk to uppercase (can be None for compliance)
        pl.when(pl.col("risk").is_null() | (pl.col("risk") == ""))
          .then(pl.lit(None, dtype=pl.String))
          .otherwise(pl.col("risk").str.to_uppercase())
          .alias("risk"),

        # Convert status to uppercase
        pl.col("status").str.to_uppercase().alias("status"),

        # Replace newlines
        pl.col("description").str.replace_all("\n", "<br/>").alias("description"),
        pl.col("remediation").str.replace_all("\n", "<br/>").alias("remediation"),
        pl.col("evidence").str.replace_all("\n", "<br/>").alias("evidence")
    ])

    # ============================================
    # STEP 5: Filter Valid Status Values
    # ============================================
    lf = lf.filter(
        pl.col("status").is_in(["PASSED", "FAILED", "WARNING"])
    )

    # ============================================
    # STEP 6: Select Final Schema (COMPLIANCE ORDER!)
    # ============================================
    lf = lf.select([
        "risk",
        "host",
        "port",
        "name",
        "description",
        "remediation",
        "evidence",
        "status"
    ])

    return lf
```

### Step 4: Test the Compliance Plugin

Create `test_compliancechecker.py`:

```python
import polars as pl
from compliancechecker import process


def test_compliance_plugin():
    """Test ComplianceChecker plugin."""

    sample_csv = """Rule ID,Server Name,Control Name,Control Description,Audit Result,Fix Instructions,Check Status,Impact Level
CIS-1.1.1,web-server-01,Disable Unused Filesystems,Ensure cramfs is disabled,cramfs is loaded,Add install cramfs /bin/true,FAILED,High
CIS-1.2.3,db-server-01,Enable GPG Check,Ensure gpgcheck enabled,gpgcheck=1 in yum.conf,No action needed,PASSED,Medium
CIS-2.1.1,app-server-01,Disable Legacy Services,Ensure chargen not enabled,chargen-dgram is active,systemctl disable chargen-dgram,FAILED,Low"""

    file_content = sample_csv.encode('utf-8')

    try:
        result = process(file_content, "text/csv")
        df = result.collect()

        print("✅ Compliance plugin executed successfully!")
        print(f"\n📊 Processed {len(df)} compliance checks\n")
        print("🔍 Output Preview:")
        print(df)

        # Validate schema
        expected_cols = ["risk", "host", "port", "name",
                        "description", "remediation", "evidence", "status"]

        if df.columns == expected_cols:
            print("\n✅ Schema validation PASSED!")
        else:
            print(f"\n❌ Schema FAILED!")
            print(f"Expected: {expected_cols}")
            print(f"Got:      {df.columns}")
            return False

        # Check status values
        unique_status = df.select(pl.col("status").unique()).to_series().to_list()
        print(f"\n🔍 Unique status values: {unique_status}")

        valid_status = all(s in ["PASSED", "FAILED", "WARNING"] for s in unique_status)
        if valid_status:
            print("✅ All status values valid!")
        else:
            print("❌ Invalid status values!")
            return False

        # Check port is always 0
        port_check = df.select(pl.col("port").unique()).to_series().to_list()
        if port_check == [0]:
            print("✅ Port field correctly set to 0")
        else:
            print(f"❌ Port should be 0, got: {port_check}")
            return False

        print("\n🎉 All compliance tests PASSED!")
        return True

    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = test_compliance_plugin()
    exit(0 if success else 1)
```

---

## Advanced Patterns

### Pattern 1: Handling JSON Input (Nested Data)

For tools that output JSON with nested structures (like Trivy):

```python
import polars as pl


def process(file: bytes, file_type: str):
    if file_type != "json":
        raise ValueError(f"Unsupported: {file_type}")

    # Load JSON
    lf = pl.read_json(file)

    # Explode nested arrays
    lf = lf.explode(pl.col("vulnerabilities")).unnest("vulnerabilities")

    # Extract nested fields using .struct.field()
    lf = lf.with_columns([
        # Extract: vulnerabilities[].location.image
        pl.col("location").struct.field("image").alias("host"),

        # Extract: vulnerabilities[].location.dependency.package.name
        pl.col("location")
          .struct.field("dependency")
          .struct.field("package")
          .struct.field("name")
          .alias("package_name")
    ])

    # Continue with standard transformations...
    return lf
```

### Pattern 2: Complex Regex Extraction

For tools with multi-line descriptions (like Nessus compliance):

```python
# Extract title from: "Title: [Section] ..."
lf = lf.with_columns(
    name=pl.col("Description").str.extract(r"^(.*): \[.*\]", 1)
)

# Extract evidence after "Actual Value:" marker
pattern = r"Actual Value:\s*\n(?s)(.*)"
lf = lf.with_columns(
    evidence=pl.col("Description")
        .str.extract(pattern)
        .str.replace_all("\n", "<br/>")
        .str.strip_chars()
)

# Extract description (everything between line 2 and "Actual Value:")
lf = lf.with_columns(
    description=pl.col("Description")
        .str.extract(r"^(?:.*\n){2}((?s).*?)(?:^Actual Value:|$)", 1)
        .str.replace_all("\n", "<br/>")
)
```

### Pattern 3: Dynamic Column Name Normalization

When CSV columns have inconsistent naming:

```python
# Convert "Plugin Output" → "plugin_output"
lf = pl.scan_csv(file).select(
    pl.all().name.map(lambda x: "_".join(x.lower().split(" ")))
)
```

### Pattern 4: Conditional Field Mapping

When a field value determines the schema:

```python
# If scan type is "compliance", map differently
lf = lf.with_columns([
    pl.when(pl.col("scan_type") == "compliance")
      .then(pl.col("severity"))  # Use severity as status
      .otherwise(pl.lit("NEW"))
      .alias("status")
])
```

### Pattern 5: Handling Multiple File Types

```python
def process(file: bytes, file_type: str):
    if file_type == "text/csv":
        return process_csv(file)
    elif file_type in ["json", "application/json"]:
        return process_json(file)
    else:
        raise ValueError(f"Unsupported file type: {file_type}")


def process_csv(file: bytes):
    # CSV-specific logic
    return pl.scan_csv(file).with_columns(...)


def process_json(file: bytes):
    # JSON-specific logic
    return pl.read_json(file).with_columns(...)
```

---

## Testing Best Practices

### 1. Test with Real Data

Always test with actual output from your tool:

```python
# Load real scan file
with open("real_scan_output.csv", "rb") as f:
    file_content = f.read()

result = process(file_content, "text/csv")
```

### 2. Test Edge Cases

```python
def test_edge_cases():
    """Test plugin with edge cases."""

    # Empty CVE
    # Null values
    # Special characters in descriptions
    # Very long text fields
    # Minimum/maximum port numbers

    edge_case_csv = """CVE,Risk,Host,Port,Name,Description,Solution,Evidence,VPR
,High,10.0.0.1,0,No CVE Issue,Description with "quotes",Fix it,,7.5
CVE-2023-1,Critical,server.local,65535,Max Port,Description\nWith\nNewlines,Remediation,Evidence,
CVE-2023-2,Low,192.168.1.1,443,Special <>&,Desc with <tags>,Fix,Test,5.0"""

    # Test processing
    result = process(edge_case_csv.encode(), "text/csv")
    df = result.collect()

    # Assertions
    assert len(df) == 3
    assert df["cve"][0] == ""  # Empty CVE handled
    assert "<br/>" in df["description"][1]  # Newlines replaced
```

### 3. Validate Output Schema

```python
def validate_schema(df, plugin_type="VAPT"):
    """Validate DataFrame matches ThreatVault schema."""

    if plugin_type == "VAPT":
        expected = ["cve", "risk", "host", "port", "name",
                   "description", "remediation", "evidence", "vpr_score"]
    else:  # Compliance
        expected = ["risk", "host", "port", "name",
                   "description", "remediation", "evidence", "status"]

    assert df.columns == expected, f"Schema mismatch! Expected {expected}, got {df.columns}"

    # Validate data types
    assert df["port"].dtype == pl.Int64, "Port must be Int64"

    print("✅ Schema validation passed!")
```

### 4. Performance Testing

```python
import time


def test_performance():
    """Test plugin performance with large dataset."""

    # Create large test dataset
    large_csv = create_large_test_data(rows=10000)

    start = time.time()
    result = process(large_csv.encode(), "text/csv")
    df = result.collect()
    elapsed = time.time() - start

    print(f"⏱️  Processed {len(df)} rows in {elapsed:.2f} seconds")
    print(f"📊 Throughput: {len(df)/elapsed:.0f} rows/sec")
```

---

## Optimization Tips

### 1. Use Lazy Evaluation

```python
# ✅ GOOD: Lazy loading (efficient)
lf = pl.scan_csv(file)  # Doesn't load immediately
lf = lf.filter(...)      # Builds query plan
lf = lf.select(...)      # Still lazy
# Only executes when .collect() is called

# ❌ BAD: Eager loading (loads entire file into memory)
df = pl.read_csv(file)
```

### 2. Chain Operations

```python
# ✅ GOOD: Chain operations in one go
lf = (
    pl.scan_csv(file)
    .rename({"Old": "new"})
    .with_columns(pl.col("risk").str.to_uppercase())
    .filter(pl.col("risk") != "None")
    .select(["cve", "risk", "host", ...])
)

# ❌ BAD: Multiple separate operations
lf = pl.scan_csv(file)
lf = lf.rename({"Old": "new"})
lf = lf.with_columns(pl.col("risk").str.to_uppercase())
lf = lf.filter(pl.col("risk") != "None")
# ... etc
```

### 3. Use Efficient Filters

```python
# ✅ GOOD: Filter early in the pipeline
lf = (
    pl.scan_csv(file)
    .filter(pl.col("risk") != "None")  # Filter early!
    .with_columns(...)
    .select(...)
)

# ❌ BAD: Filter late (processes unnecessary rows)
lf = (
    pl.scan_csv(file)
    .with_columns(...)
    .select(...)
    .filter(pl.col("risk") != "None")  # Filter late
)
```

### 4. Avoid Unnecessary String Operations

```python
# ✅ GOOD: Single replacement pass
pl.col("description").str.replace_all("\n", "<br/>")

# ❌ BAD: Multiple passes
pl.col("description").str.replace("\n", " ").str.replace(" ", "<br/>")
```

---

## Common Mistakes to Avoid

### ❌ Mistake 1: Wrong Column Order

```python
# ❌ WRONG: Incorrect order
lf.select(["risk", "cve", "host", ...])  # Will fail validation!

# ✅ CORRECT: VAPT exact order
lf.select(["cve", "risk", "host", "port", "name",
          "description", "remediation", "evidence", "vpr_score"])
```

### ❌ Mistake 2: Forgetting to Handle Nulls

```python
# ❌ WRONG: Nulls will cause errors
pl.col("cve")  # What if CVE is null?

# ✅ CORRECT: Handle nulls explicitly
pl.when(pl.col("cve").is_null()).then(pl.lit("")).otherwise(pl.col("cve"))
# OR
pl.col("cve").fill_null("")
```

### ❌ Mistake 3: Port as String

```python
# ❌ WRONG: Port is string
pl.col("port")  # Type: String

# ✅ CORRECT: Port must be Int64
pl.col("port").cast(pl.Int64, strict=False).fill_null(0)
```

### ❌ Mistake 4: Not Replacing Newlines

```python
# ❌ WRONG: Newlines break HTML display
pl.col("description")

# ✅ CORRECT: Replace with <br/>
pl.col("description").str.replace_all("\n", "<br/>")
```

### ❌ Mistake 5: Invalid Risk/Status Values

```python
# ❌ WRONG: Accepts any value
lf.select(...)

# ✅ CORRECT: Filter invalid values
lf.filter(pl.col("risk").is_in(["CRITICAL", "HIGH", "MEDIUM", "LOW"]))
lf.filter(pl.col("status").is_in(["PASSED", "FAILED", "WARNING"]))
```

### ❌ Mistake 6: Using VAPT Schema for Compliance

```python
# ❌ WRONG: VAPT schema for compliance plugin
lf.select(["cve", "risk", ...])  # CVE doesn't exist in compliance!

# ✅ CORRECT: Compliance schema
lf.select(["risk", "host", "port", "name",
          "description", "remediation", "evidence", "status"])
```

---

## Quick Reference

### VAPT Plugin Template

```python
import polars as pl

def process(file: bytes, file_type: str) -> pl.LazyFrame:
    if file_type != "text/csv":
        raise ValueError(f"Unsupported: {file_type}")

    return (
        pl.scan_csv(file)
        .rename({
            # Your column mappings
        })
        .with_columns([
            pl.col("risk").str.to_uppercase(),
            pl.col("cve").fill_null(""),
            pl.col("vpr_score").fill_null(""),
            pl.col("port").cast(pl.Int64).fill_null(0),
            pl.col("description").str.replace_all("\n", "<br/>"),
            pl.col("remediation").str.replace_all("\n", "<br/>"),
            pl.col("evidence").str.replace_all("\n", "<br/>"),
        ])
        .filter(pl.col("risk").is_in(["CRITICAL", "HIGH", "MEDIUM", "LOW"]))
        .select([
            "cve", "risk", "host", "port", "name",
            "description", "remediation", "evidence", "vpr_score"
        ])
    )
```

### Compliance Plugin Template

```python
import polars as pl

def process(file: bytes, file_type: str) -> pl.LazyFrame:
    if file_type != "text/csv":
        raise ValueError(f"Unsupported: {file_type}")

    return (
        pl.scan_csv(file)
        .rename({
            # Your column mappings
        })
        .with_columns([
            pl.lit(0).alias("port"),
            pl.col("risk").str.to_uppercase(),
            pl.col("status").str.to_uppercase(),
            pl.col("description").str.replace_all("\n", "<br/>"),
            pl.col("remediation").str.replace_all("\n", "<br/>"),
            pl.col("evidence").str.replace_all("\n", "<br/>"),
        ])
        .filter(pl.col("status").is_in(["PASSED", "FAILED", "WARNING"]))
        .select([
            "risk", "host", "port", "name",
            "description", "remediation", "evidence", "status"
        ])
    )
```

---

## Next Steps

1. ✅ Choose your security tool
2. ✅ Get sample scan output
3. ✅ Follow the tutorial for your plugin type (VAPT/Compliance)
4. ✅ Test thoroughly
5. ✅ Submit PR!

**Need help?** Check existing plugins in `Plugins/` or open an issue!

**Happy plugin building! 🚀**
