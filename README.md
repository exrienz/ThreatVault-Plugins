# ThreatVault Plugins Repository

Welcome to the **ThreatVault Plugins Repository**! This is a community-driven collection of plugins that transform security scan results from various tools into a standardized format for ThreatVault.

## 📋 Table of Contents

- [What is This Repository?](#what-is-this-repository)
- [🤖 **AI-Assisted Plugin Generation (NEW!)**](#ai-assisted-plugin-generation)
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

## 🤖 AI-Assisted Plugin Generation

**NEW!** Don't want to write plugin code manually? Use our AI Plugin Generator!

### Quick Start with AI

1. **Get the AI Prompt**:
   - Open [`PLUGIN_GENERATOR_PROMPT.md`](./PLUGIN_GENERATOR_PROMPT.md)
   - Copy the entire "SYSTEM PROMPT FOR LLM" section

2. **Use with Any LLM**:
   - Paste the prompt into ChatGPT, Claude, or any LLM
   - Upload your security tool's output file (CSV/JSON/XML)
   - Specify tool name and whether it's VAPT or Compliance

3. **Get Production-Ready Code**:
   - The LLM generates complete plugin code
   - Includes data type handling, null handling, validation
   - Provides test script and usage instructions
   - Ready to use immediately!

### Example AI Conversation

```
[User]: I need a ThreatVault plugin for Acunetix Web Scanner.
        Type: VAPT
        Format: CSV
        [Upload acunetix_scan.csv]

[AI]: Analyzing your file... ✅

      Generated complete plugin with:
      - Proper port Integer conversion
      - All null handling
      - Risk value validation
      - Test script included

      [Provides full production-ready code]
```

### What the AI Generates

✅ Complete `plugin.py` file with all transformations
✅ Test script (`test_plugin.py`)
✅ Installation and usage instructions
✅ Pre-validated against all ThreatVault requirements
✅ Ready for production use

**See [`PLUGIN_GENERATOR_PROMPT.md`](./PLUGIN_GENERATOR_PROMPT.md) for complete instructions!**

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
| Field | Type | Required | Null Handling | Example |
|-------|------|----------|---------------|---------|
| `cve` | String | ✅ | Use `""` (empty string) if no CVE | `"CVE-2023-1234"` or `""` |
| `risk` | String | ✅ | Must be valid value, no nulls | `"CRITICAL"`, `"HIGH"`, `"MEDIUM"`, `"LOW"` |
| `host` | String | ✅ | Must have value, no nulls | `"192.168.1.100"` or `"webserver01"` |
| `port` | **Integer** | ✅ | Use `0` for web apps or if N/A | `443`, `80`, `8080`, or `0` |
| `name` | String | ✅ | Must have value, no nulls | `"SQL Injection in Login Form"` |
| `description` | String | ✅ | Must have value, no nulls | `"The application is vulnerable to..."` |
| `remediation` | String | ✅ | Must have value, no nulls | `"Update to version 2.0 or apply patch"` |
| `evidence` | String | ⚪ Optional | Can be `""` (empty string) | `"POST /login vulnerable"` or `""` |
| `vpr_score` | String | ⚪ Optional | Use `""` (empty string) if N/A | `"8.2"` or `""` |

**⚠️ Critical Requirements**:
- **Port must be Integer type**, not String (e.g., `0` not `"0"` or `null`)
- **All required String fields** must not be null - use empty string `""` if no data
- **Risk values** must be exactly: `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW` (uppercase)
- **CVE format** (if provided): `CVE-YYYY-NNNNN` or empty string `""`
- **Newlines** in text fields should be replaced with `<br/>` for HTML display

### 2️⃣ Compliance

**Purpose**: Checks if systems meet specific standards, policies, or regulations.

**Examples**: CIS Benchmarks, ISO 27001 audits, internal policy checks

**Key Question**: *"Does this system comply with the rules?"*

**Required Fields**:
| Field | Type | Required | Null Handling | Example |
|-------|------|----------|---------------|---------|
| `risk` | String | ⚪ Optional | Can be `None` (auto-assigned to `"MEDIUM"`) | `"HIGH"`, `"MEDIUM"`, `"LOW"`, or `None` |
| `host` | String | ✅ | Must have value, no nulls | `"db-server-01"` or `"192.168.1.50"` |
| `port` | **Integer** | ✅ | Use `0` if not applicable | `0`, `22`, `3306` |
| `name` | String | ✅ | Must have value, no nulls | `"Password Length >= 8 Characters"` |
| `description` | String | ✅ | Must have value, no nulls | `"Passwords must be at least 8 chars"` |
| `remediation` | String | ✅ | Must have value, no nulls | `"Set minimum password length to 8"` |
| `evidence` | String | ⚪ Optional | Can be `""` (empty string) | `"Current setting: 6 characters"` or `""` |
| `status` | String | ✅ | Must be valid value, no nulls | `"PASSED"`, `"FAILED"`, `"WARNING"` |

**⚠️ Critical Requirements**:
- **Port must be Integer type**, not String (e.g., `0` not `"0"` or `null`)
- **Status values** must be exactly: `PASSED`, `FAILED`, or `WARNING` (uppercase)
- **Risk field is optional** - if `None` or missing, ThreatVault assigns `"MEDIUM"`
- **All required String fields** must not be null - use empty string `""` if no data
- **Newlines** in text fields should be replaced with `<br/>` for HTML display

**Important Differences from VAPT**:
- Compliance does **NOT** use `cve` and `vpr_score` fields (VAPT only)
- Compliance uses `status` for pass/fail results (VAPT uses `risk` for severity)
- Compliance `risk` field is optional and can be `None`

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

#### Step 4: Handle Data Types and Null Values

**⚠️ Critical: ThreatVault will reject uploads if data types are incorrect!**

**Common scenarios you MUST handle**:

```python
# 1. Convert Port to Integer (REQUIRED - String ports will cause upload failures!)
# Handle empty strings, nulls, and convert to integer type
.with_columns(
    pl.col("port")
    .fill_null("0")              # Replace nulls with "0" string
    .cast(pl.Utf8)               # Ensure string type first
    .str.replace("^$", "0")      # Replace empty strings with "0"
    .cast(pl.Int64, strict=False) # Convert to integer
    .fill_null(0)                # Final safety: null → 0
    .alias("port")
)

# 2. Handle CVE field - use empty string if no CVE (not null!)
.with_columns(
    pl.col("cve")
    .fill_null("")        # Replace null with empty string
    .cast(pl.Utf8)        # Ensure string type
    .alias("cve")
)

# 3. Handle VPR Score - use empty string if not available (not null!)
.with_columns(
    pl.col("vpr_score")
    .fill_null("")        # Replace null with empty string
    .cast(pl.Utf8)        # Ensure string type
    .alias("vpr_score")
)

# 4. Ensure all required fields have values (no nulls)
.with_columns([
    pl.col("risk").fill_null("MEDIUM"),          # Default risk
    pl.col("host").fill_null("unknown"),         # Default host
    pl.col("name").fill_null("Unknown Issue"),   # Default name
    pl.col("description").fill_null("No description available"),
    pl.col("remediation").fill_null("No remediation available"),
    pl.col("evidence").fill_null(""),            # Evidence can be empty
])

# 5. Filter out invalid risk values
.filter(pl.col("risk").is_in(["CRITICAL", "HIGH", "MEDIUM", "LOW"]))

# 6. Filter out informational findings (if needed)
.filter(pl.col("risk") != "INFO")
```

**Why This Matters**:
- **Port as String → Upload fails with "cannot compare string with numeric type"**
- **Null in required fields → Upload fails with validation error**
- **Invalid risk values → Rows rejected or upload fails**
- **Wrong data types → Infinite retry loop in ThreatVault**

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

Before submitting your plugin, verify ALL of these requirements:

**✅ Basic Functionality**
- [ ] Plugin loads and processes sample file without errors
- [ ] Output schema exactly matches required field names and order
- [ ] Returns `pl.LazyFrame` or `pl.DataFrame` (not dict or list)

**✅ Data Types (Critical!)**
- [ ] `port` field is **Integer type** (`pl.Int64`), NOT String
- [ ] All other fields are String type (`pl.Utf8`)
- [ ] No mixed types in any column

**✅ Null Handling (Critical!)**
- [ ] Required fields have NO nulls (use defaults or empty strings)
- [ ] `cve` uses empty string `""` if no CVE (not null)
- [ ] `vpr_score` uses empty string `""` if not available (not null)
- [ ] `evidence` can be empty string `""` but not null
- [ ] `port` uses `0` for web apps or when not applicable (not null, not empty string)

**✅ Value Validation**
- [ ] VAPT: `risk` values are exactly `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW` (uppercase)
- [ ] Compliance: `status` values are exactly `PASSED`, `FAILED`, or `WARNING` (uppercase)
- [ ] No invalid or informational severity levels in output

**✅ Text Formatting**
- [ ] Newlines (`\n`) are replaced with `<br/>` in description, remediation, evidence
- [ ] Special characters are properly escaped or handled
- [ ] Text truncation (if needed) doesn't break at arbitrary points

**✅ Testing**
- [ ] Test with sample file containing edge cases (nulls, empty values, special chars)
- [ ] Verify output can be uploaded to ThreatVault without errors
- [ ] Check that port column shows as integers (not `"0"` but `0`) when inspecting schema

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
