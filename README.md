# ThreatVault Plugins Repository

Welcome to the **ThreatVault Plugins Repository**! This is a community-driven collection of plugins that transform security scan results from various tools into a standardized format for ThreatVault.

## 📋 Table of Contents

- [What is This Repository?](#what-is-this-repository)
- [How to Contribute](#how-to-contribute)
- [Prerequisites](#prerequisites)
- [Understanding Plugin Types](#understanding-plugin-types)
- [Plugin Development Guide](#plugin-development-guide)
  - [VAPT Plugin Development](#vapt-plugin-development)
  - [Compliance Plugin Development](#compliance-plugin-development)
- [Testing Your Plugin](#testing-your-plugin)
- [Submitting Your Plugin](#submitting-your-plugin)
- [Plugin Examples](#plugin-examples)
- [Troubleshooting](#troubleshooting)

---

## What is This Repository?

ThreatVault needs security scan data in a specific format. Different security tools (Nessus, Trivy, Semgrep, etc.) produce outputs in different formats. **Plugins bridge this gap**.

### How It Works

```
┌─────────────────┐
│  Security Tool  │ (Nessus, Trivy, etc.)
│  Scan Output    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Your Plugin    │ ← Transforms data
│  process()      │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  ThreatVault    │ ← Standardized format
│  Database       │
└─────────────────┘
```

**Anyone can contribute** by creating a plugin for their favorite security tool!

---

## How to Contribute

We welcome contributions from the community! Here's the process:

1. **Fork** this repository
2. **Create** your plugin following the guidelines below
3. **Test** your plugin thoroughly
4. **Submit** a Pull Request (PR)
5. **Wait** for review - we'll test your plugin against our requirements
6. Once approved, your plugin will be **merged** and available to all ThreatVault users!

---

## Prerequisites

Before you start, make sure you have:

- **Python 3.8+** installed
- **Polars library** (`pip install polars`)
- A sample scan output file from your target security tool
- Basic understanding of Python and data manipulation

```bash
# Install dependencies
pip install polars
```

---

## Understanding Plugin Types

ThreatVault supports two types of security data:

### 1️⃣ VAPT (Vulnerability Assessment & Penetration Testing)

**Purpose**: Identifies security vulnerabilities, misconfigurations, and weaknesses.

**Examples**: Nessus vulnerability scans, Trivy container scans, Burp Suite findings

**Key Question**: *"What security issues exist?"*

**Required Fields**:
| Field | Description | Example |
|-------|-------------|---------|
| `cve` | CVE identifier (if applicable) | `"CVE-2023-1234"` or `""` |
| `risk` | Severity level | `"CRITICAL"`, `"HIGH"`, `"MEDIUM"`, `"LOW"` |
| `host` | Target IP or hostname | `"192.168.1.100"` or `"webserver01"` |
| `port` | Port number (use `0` if N/A) | `443` or `0` |
| `name` | Vulnerability title | `"SQL Injection in Login Form"` |
| `description` | Detailed explanation | `"The application is vulnerable to..."` |
| `remediation` | How to fix it | `"Update to version 2.0 or apply patch"` |
| `evidence` | Proof/scan output | `"POST /login vulnerable"` |
| `vpr_score` | VPR score (optional) | `"8.2"` or `""` |

### 2️⃣ Compliance

**Purpose**: Checks if systems meet specific standards, policies, or regulations.

**Examples**: CIS Benchmarks, ISO 27001 audits, internal policy checks

**Key Question**: *"Does this system comply with the rules?"*

**Required Fields**:
| Field | Description | Example |
|-------|-------------|---------|
| `risk` | Severity (can be None) | `"HIGH"`, `"MEDIUM"`, `"LOW"`, or `None` |
| `host` | Target system | `"db-server-01"` |
| `port` | Port (use `0` if N/A) | `0` |
| `name` | Rule/control name | `"Password Length >= 8 Characters"` |
| `description` | What the rule checks | `"Passwords must be at least 8 chars"` |
| `remediation` | How to comply | `"Set minimum password length to 8"` |
| `evidence` | Audit result | `"Current setting: 6 characters"` |
| `status` | Compliance result | `"PASSED"`, `"FAILED"`, `"WARNING"` |

**Important Differences**:
- VAPT uses `cve` and `vpr_score` → Compliance does **NOT**
- VAPT uses `risk` for severity → Compliance uses `status` for pass/fail
- Compliance `risk` can be `None` (auto-assigned to `"MEDIUM"`)

---

## Plugin Development Guide

Every plugin must implement a `process()` function with this signature:

```python
import polars as pl

def process(file: bytes, file_type: str) -> pl.LazyFrame | pl.DataFrame:
    """
    Transforms security tool output into ThreatVault format.

    Args:
        file: Raw file content as bytes
        file_type: MIME type (e.g., "text/csv", "json", "application/json")

    Returns:
        Polars LazyFrame or DataFrame with standardized schema
    """
    pass
```

### VAPT Plugin Development

Let's create a VAPT plugin step-by-step using a fictional tool called "VulnScanner".

#### Step 1: Analyze Your Tool's Output

Suppose VulnScanner produces a CSV like this:

```csv
Severity,Target,PortNumber,VulnName,Details,FixRecommendation,ScanOutput,CVE_ID,VPRScore
High,10.0.0.5,443,TLS 1.0 Enabled,Old TLS version detected,Upgrade to TLS 1.2+,Service: HTTPS,CVE-2023-9999,7.5
Critical,10.0.0.10,22,Weak SSH Cipher,Uses deprecated ciphers,Disable CBC ciphers,SSH connection accepted,CVE-2023-8888,9.1
```

#### Step 2: Map Fields to ThreatVault Schema

| VulnScanner Field | → | ThreatVault Field | Transformation |
|-------------------|---|-------------------|----------------|
| CVE_ID | → | `cve` | Direct mapping |
| Severity | → | `risk` | Convert to uppercase |
| Target | → | `host` | Direct mapping |
| PortNumber | → | `port` | Direct mapping (as int) |
| VulnName | → | `name` | Direct mapping |
| Details | → | `description` | Replace `\n` with `<br/>` |
| FixRecommendation | → | `remediation` | Replace `\n` with `<br/>` |
| ScanOutput | → | `evidence` | Replace `\n` with `<br/>` |
| VPRScore | → | `vpr_score` | Direct mapping |

#### Step 3: Write the Plugin

Create file: `Plugins/VAPT/VA/VulnScanner/vulnscanner.py`

```python
import polars as pl


def process(file: bytes, file_type: str) -> pl.LazyFrame:
    # Step 1: Validate file type
    if file_type != "text/csv":
        raise ValueError(f"File type not supported: {file_type}. Expected text/csv")

    # Step 2: Load CSV data
    lf = pl.scan_csv(file)

    # Step 3: Transform and map fields
    lf = (
        lf
        # Rename columns to ThreatVault schema
        .rename({
            "CVE_ID": "cve",
            "Severity": "risk",
            "Target": "host",
            "PortNumber": "port",
            "VulnName": "name",
            "Details": "description",
            "FixRecommendation": "remediation",
            "ScanOutput": "evidence",
            "VPRScore": "vpr_score"
        })
        # Convert risk to uppercase
        .with_columns(
            pl.col("risk").str.to_uppercase()
        )
        # Replace newlines with HTML breaks for better display
        .with_columns([
            pl.col("description").str.replace_all("\n", "<br/>"),
            pl.col("remediation").str.replace_all("\n", "<br/>"),
            pl.col("evidence").str.replace_all("\n", "<br/>")
        ])
        # Filter valid severity levels
        .filter(pl.col("risk").is_in(["CRITICAL", "HIGH", "MEDIUM", "LOW"]))
        # Select only required fields in correct order
        .select([
            "cve", "risk", "host", "port", "name",
            "description", "remediation", "evidence", "vpr_score"
        ])
    )

    return lf
```

#### Step 4: Handle Edge Cases

**Common scenarios to handle**:

```python
# Handle empty CVE fields
.with_columns(
    pl.when(pl.col("cve").is_null())
      .then(pl.lit(""))
      .otherwise(pl.col("cve"))
      .alias("cve")
)

# Handle missing VPR scores
.with_columns(
    pl.when(pl.col("vpr_score").is_null())
      .then(pl.lit(""))
      .otherwise(pl.col("vpr_score"))
      .alias("vpr_score")
)

# Convert port to integer
.with_columns(
    pl.col("port").cast(pl.Int64, strict=False).fill_null(0)
)

# Filter out informational findings
.filter(pl.col("risk") != "INFO")
```

### Compliance Plugin Development

Let's create a Compliance plugin for a fictional tool called "PolicyChecker".

#### Step 1: Analyze Your Tool's Output

PolicyChecker produces CSV like this:

```csv
CheckID,System,PolicyName,PolicyDescription,CurrentValue,RecommendedFix,Status,Severity
POL-001,webserver01,Password Length,Passwords must be at least 8 characters,Current: 6,Set minimum to 8,FAILED,High
POL-002,dbserver01,Encryption Enabled,Database encryption must be enabled,Encryption: ON,N/A,PASSED,Medium
```

#### Step 2: Map Fields to ThreatVault Schema

| PolicyChecker Field | → | ThreatVault Field | Notes |
|---------------------|---|-------------------|-------|
| Severity | → | `risk` | Can be None for compliance |
| System | → | `host` | Direct mapping |
| (constant) | → | `port` | Always `0` for policy checks |
| PolicyName | → | `name` | Direct mapping |
| PolicyDescription | → | `description` | Replace newlines |
| RecommendedFix | → | `remediation` | Replace newlines |
| CurrentValue | → | `evidence` | Actual audit result |
| Status | → | `status` | PASSED/FAILED/WARNING |

#### Step 3: Write the Plugin

Create file: `Plugins/Compliance/PolicyChecker/policychecker.py`

```python
import polars as pl


def process(file: bytes, file_type: str) -> pl.LazyFrame:
    # Step 1: Validate file type
    if file_type != "text/csv":
        raise ValueError(f"File type not supported: {file_type}")

    # Step 2: Load CSV
    lf = pl.scan_csv(file)

    # Step 3: Transform and map fields
    lf = (
        lf
        .rename({
            "Severity": "risk",
            "System": "host",
            "PolicyName": "name",
            "PolicyDescription": "description",
            "RecommendedFix": "remediation",
            "CurrentValue": "evidence",
            "Status": "status"
        })
        # Add port (always 0 for compliance)
        .with_columns(pl.lit(0).alias("port"))
        # Convert risk to uppercase (handle None)
        .with_columns(
            pl.when(pl.col("risk").is_null())
              .then(pl.lit(None, dtype=pl.String))
              .otherwise(pl.col("risk").str.to_uppercase())
              .alias("risk")
        )
        # Convert status to uppercase
        .with_columns(
            pl.col("status").str.to_uppercase()
        )
        # Replace newlines
        .with_columns([
            pl.col("description").str.replace_all("\n", "<br/>"),
            pl.col("remediation").str.replace_all("\n", "<br/>"),
            pl.col("evidence").str.replace_all("\n", "<br/>")
        ])
        # Filter valid status values
        .filter(pl.col("status").is_in(["PASSED", "FAILED", "WARNING"]))
        # Select fields in correct order
        .select([
            "risk", "host", "port", "name",
            "description", "remediation", "evidence", "status"
        ])
    )

    return lf
```

#### Special Case: Complex Field Extraction

For tools with complex nested data (like Nessus compliance scans), you may need regex extraction:

```python
# Example: Extract rule name from description field
.with_columns(
    name=pl.col("Description").str.extract(r"^(.*): \[.*\]", 1)
)

# Extract evidence from multi-line description
pattern = r"Actual Value:\s*\n(?s)(.*)"
.with_columns(
    evidence=pl.col("Description")
        .str.extract(pattern)
        .str.replace_all("\n", "<br/>")
        .str.strip_chars()
)
```

---

## Testing Your Plugin

### 1. Create a Test Script

Create `test_myplugin.py` in your plugin directory:

```python
import sys
from pathlib import Path

# Import your plugin
from vulnscanner import process  # Change to your plugin name


def test_plugin():
    # Load sample scan file
    sample_file = Path("sample_scan.csv")

    with open(sample_file, "rb") as f:
        file_content = f.read()

    # Call your plugin
    result = process(file_content, "text/csv")

    # For LazyFrame, collect to DataFrame
    if hasattr(result, 'collect'):
        df = result.collect()
    else:
        df = result

    # Print results
    print("✅ Plugin executed successfully!")
    print(f"📊 Processed {len(df)} findings")
    print("\n🔍 Sample output:")
    print(df.head())

    # Validate schema
    expected_columns = ["cve", "risk", "host", "port", "name",
                       "description", "remediation", "evidence", "vpr_score"]

    actual_columns = df.columns

    if actual_columns == expected_columns:
        print("\n✅ Schema validation passed!")
    else:
        print(f"\n❌ Schema mismatch!")
        print(f"Expected: {expected_columns}")
        print(f"Got: {actual_columns}")
        sys.exit(1)

    # Validate risk values
    invalid_risks = df.filter(
        ~pl.col("risk").is_in(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    )

    if len(invalid_risks) > 0:
        print(f"\n⚠️  Warning: {len(invalid_risks)} rows have invalid risk values")
        print(invalid_risks)


if __name__ == "__main__":
    test_plugin()
```

### 2. Run Tests

```bash
cd Plugins/VAPT/VA/VulnScanner/
python test_myplugin.py
```

### 3. Validation Checklist

- ✅ Plugin loads and processes sample file without errors
- ✅ Output schema exactly matches required fields
- ✅ All required fields are populated (no nulls where not allowed)
- ✅ `risk` values are valid: CRITICAL/HIGH/MEDIUM/LOW
- ✅ `status` values (compliance) are valid: PASSED/FAILED/WARNING
- ✅ Port numbers are integers (or 0)
- ✅ Newlines are replaced with `<br/>`
- ✅ Empty strings used instead of null for optional fields

---

## Submitting Your Plugin

### 1. Organize Your Files

```
Plugins/
└── VAPT/  (or Compliance/)
    └── <Category>/  (VA, SAST, DAST, SCA, etc.)
        └── <ToolName>/
            ├── toolname.py          # Your plugin (required)
            ├── test_toolname.py     # Test script (optional but recommended)
            ├── sample_scan.csv      # Sample input (helpful for reviewers)
            └── README.md            # Tool-specific notes (optional)
```

### 2. Create a Pull Request

1. **Commit your changes**:
```bash
git add Plugins/VAPT/VA/VulnScanner/
git commit -m "Add VulnScanner VAPT plugin"
git push origin main
```

2. **Create PR** on GitHub with:
   - **Title**: `Add [ToolName] [VAPT/Compliance] Plugin`
   - **Description**:
     ```markdown
     ## Plugin Details
     - **Tool**: VulnScanner
     - **Type**: VAPT (VA)
     - **Input Format**: CSV
     - **Tested**: ✅ Yes (see test_vulnscanner.py)

     ## Description
     This plugin transforms VulnScanner CSV output into ThreatVault VAPT format.

     ## Testing
     - Sample input file included: `sample_scan.csv`
     - All validations passed
     - Handles edge cases: empty CVE, missing VPR scores

     ## Additional Notes
     VulnScanner outputs standard vulnerability data with CVE mappings.
     ```

### 3. Review Process

Your PR will be reviewed for:
- ✅ Correct schema implementation
- ✅ Proper error handling
- ✅ Code quality and readability
- ✅ Test coverage (if provided)
- ✅ Works with sample data

**We'll test your plugin** against our validation suite. If it passes, it will be merged!

---

## Plugin Examples

### Example 1: Trivy (JSON-based SCA)

```python
import polars as pl

def process(file: bytes, file_type: str):
    if file_type != "json":
        raise ValueError(f"Unsupported file type: {file_type}")

    lf = pl.read_json(file)

    # Explode nested vulnerabilities array
    lf = lf.explode(pl.col("vulnerabilities")).unnest("vulnerabilities")

    # Extract nested fields
    lf = lf.with_columns([
        pl.col("location").struct.field("image").alias("host"),
        pl.col("location").struct.field("dependency")
          .struct.field("package").struct.field("name").alias("pkg_name"),
    ])

    # Map to schema
    lf = lf.with_columns([
        pl.col("id").alias("cve"),
        pl.col("severity").str.to_uppercase().alias("risk"),
        pl.lit(0).alias("port"),
        pl.col("pkg_name").alias("name"),
        pl.col("description"),
        pl.col("solution").alias("remediation"),
        pl.lit("").alias("evidence"),
        pl.lit("").alias("vpr_score"),
    ])

    return lf.select([
        "cve", "risk", "host", "port", "name",
        "description", "remediation", "evidence", "vpr_score"
    ])
```

### Example 2: Semgrep (JSON-based SAST)

```python
import json
import polars as pl

def process(file: bytes, file_type: str) -> pl.DataFrame:
    if file_type not in ["application/json", "json"]:
        raise ValueError(f"Unsupported file type: {file_type}")

    data = json.loads(file.decode('utf-8'))
    records = []

    for result in data.get('results', []):
        start_line = result.get('start', {}).get('line', 0)
        end_line = result.get('end', {}).get('line', 0)
        path = result.get('path', '')

        record = {
            'cve': '',
            'risk': 'Medium',
            'host': 'semgrep',  # Static analysis = no host
            'port': start_line,  # Use line number as port
            'name': result.get('check_id', ''),
            'description': result.get('extra', {}).get('message', ''),
            'remediation': result.get('extra', {}).get('fix', ''),
            'evidence': f"Line {start_line} - {end_line} in file : {path}",
            'vpr_score': ''
        }
        records.append(record)

    return pl.DataFrame(records)
```

---

## Troubleshooting

### Common Issues

**❌ "Column not found" error**
```python
# Solution: Check exact column names from your CSV/JSON
print(pl.scan_csv(file).columns)  # Debug: see actual column names
```

**❌ "Invalid schema" validation error**
```python
# Solution: Ensure exact field order
# VAPT order:
["cve", "risk", "host", "port", "name", "description", "remediation", "evidence", "vpr_score"]

# Compliance order:
["risk", "host", "port", "name", "description", "remediation", "evidence", "status"]
```

**❌ "Type mismatch" for port field**
```python
# Solution: Cast port to Int64
.with_columns(pl.col("port").cast(pl.Int64))
```

**❌ Null values in required fields**
```python
# Solution: Use fill_null() or when/then logic
.with_columns(
    pl.col("cve").fill_null("")
)
```

### Getting Help

- 📖 Check `blueprint.txt` for detailed specifications
- 💡 Study existing plugins in `Plugins/` directory
- 🐛 Open an issue if you're stuck
- 💬 Ask questions in your PR comments

---

## Directory Structure Reference

```
ThreatVault-Plugins/
├── README.md                          # This file
├── blueprint.txt                      # Complete specification
├── CLAUDE.md                          # AI assistant guidance
└── Plugins/
    ├── VAPT/
    │   ├── VA/                        # Vulnerability Assessment
    │   │   └── Nessus/
    │   │       └── nessus.py
    │   ├── SAST/                      # Static Application Security Testing
    │   │   └── Semgrep/
    │   │       └── semgrep.py
    │   ├── DAST/                      # Dynamic Application Security Testing
    │   └── SCA/                       # Software Composition Analysis
    │       └── Trivy/
    │           └── trivy.py
    ├── Compliance/
    │   └── Nessus/
    │       └── nessus.py
    └── SBOM/                          # Software Bill of Materials
```

---

## 🎉 Ready to Contribute?

We're excited to see your plugin! Follow the guides above, test thoroughly, and submit your PR.

**Questions?** Open an issue or comment on your PR - we're here to help!

**Thank you for contributing to ThreatVault!** 🚀
