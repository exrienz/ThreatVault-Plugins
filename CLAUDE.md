# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ThreatVault-Plugins is a collection of Python plugin modules that transform security scan outputs (from tools like Nessus, Trivy, Semgrep, etc.) into a standardized format for ThreatVault ingestion. Each plugin implements a `process()` function that accepts raw scan data and returns structured data using Polars DataFrames.

## Plugin Architecture

### Directory Structure

```
Plugins/
├── Compliance/          # Compliance check plugins (CIS, ISO 27001, etc.)
│   └── Nessus/
├── VAPT/                # Vulnerability Assessment & Penetration Testing
│   ├── VA/              # Vulnerability Assessment (Nessus, OpenVAS)
│   ├── SAST/            # Static Application Security Testing (Semgrep)
│   ├── DAST/            # Dynamic Application Security Testing
│   └── SCA/             # Software Composition Analysis (Trivy)
└── SBOM/                # Software Bill of Materials
```

### Plugin Types

**VAPT Plugins** - For vulnerability scanning tools:
- Required fields: `cve`, `risk`, `host`, `port`, `name`, `description`, `remediation`, `evidence`, `vpr_score`
- Risk values: CRITICAL, HIGH, MEDIUM, LOW
- Status values: NEW, OPEN, CLOSED, EXEMPTION, OTHERS

**Compliance Plugins** - For policy/rule checking:
- Required fields: `risk`, `host`, `port`, `name`, `description`, `remediation`, `evidence`, `status`
- Status values: PASSED, FAILED, WARNING
- Note: `risk` field can be None (auto-assigned to Medium)
- Note: `cve` and `vpr_score` are NOT used for compliance

### Plugin Implementation Pattern

Every plugin must implement:

```python
import polars as pl

def process(file: bytes, file_type: str) -> pl.LazyFrame | pl.DataFrame:
    """
    Args:
        file: Raw file content as bytes
        file_type: MIME type ("text/csv", "json", "application/json")

    Returns:
        Polars LazyFrame or DataFrame with standardized schema
    """
    # 1. Validate file_type
    if file_type != "expected/type":
        raise ValueError(f"File type not supported: {file_type}")

    # 2. Parse input (CSV/JSON)
    # 3. Transform/extract fields
    # 4. Map to ThreatVault schema
    # 5. Return LazyFrame/DataFrame
```

### Common Transformations

1. **Newline handling**: Replace `\n` with `<br/>` for HTML display
   ```python
   pl.col("description").str.replace_all("\n", "<br/>")
   ```

2. **Column renaming**: Use snake_case and map to standard names
   ```python
   .select(pl.all().name.map(lambda x: "_".join(x.lower().split(" "))))
   ```

3. **Field extraction**: Use regex for complex parsing (see Compliance/Nessus for examples)
   ```python
   pl.col("Description").str.extract(r"^(.*): \[.*\]", 1)
   ```

4. **Filtering**: Remove invalid/None values
   ```python
   .filter(pl.col("risk") != "None")
   .filter(pl.col("risk").is_in(["CRITICAL", "HIGH", "MEDIUM", "LOW"]))
   ```

## Development Guidelines

### Adding a New Plugin

1. Identify plugin type (VAPT/Compliance/SBOM)
2. Create directory under appropriate category: `Plugins/<Type>/<Subcategory>/<Tool>/`
3. Create `<tool>.py` with `process()` function
4. Map source fields to ThreatVault schema (see blueprint.txt for mapping details)
5. Handle file type validation (CSV/JSON)
6. Return Polars LazyFrame or DataFrame with exact schema

### Field Mapping Reference

**VAPT Schema Order**:
```python
["cve", "risk", "host", "port", "name", "description", "remediation", "evidence", "vpr_score"]
```

**Compliance Schema Order**:
```python
["risk", "host", "port", "name", "description", "remediation", "evidence", "status"]
```

### Testing a Plugin

Since plugins are called by ThreatVault backend:
1. Create sample CSV/JSON from target tool
2. Test `process()` function with file bytes
3. Verify output schema matches requirements
4. Check all required fields are populated
5. Validate data types (port as int, text fields as str)

### Common Patterns by Tool Type

**CSV-based (Nessus VAPT)**:
- Use `pl.scan_csv()` for lazy loading
- Column name normalization via `.name.map()`
- Direct field mapping

**JSON-based (Trivy, Semgrep)**:
- Use `pl.read_json()` or `json.loads()`
- Handle nested structures with `.struct.field()`
- Use `.explode()` and `.unnest()` for arrays

**Complex parsing (Nessus Compliance)**:
- Multi-line regex extraction
- Parse structured descriptions into separate fields
- Map Risk → status, drop unused columns

## Key Documentation Files

- `README.md` - Main repository documentation with contribution guidelines and overview
- `PLUGIN_CREATION_GUIDE.md` - Comprehensive step-by-step tutorial for creating plugins (use this for learning)
- `blueprint.txt` - Complete technical specification for plugin development, field mappings, and examples
- Individual plugin files in `Plugins/` demonstrate reference implementations

## Dependencies

- **Polars**: Primary data processing library (lazy evaluation support)
- Python 3.x with bytes/string handling

## Quick Commands

```bash
# Install dependencies
pip install polars

# Test a plugin (from plugin directory)
python test_<toolname>.py

# Create new plugin directory structure
mkdir -p Plugins/<Type>/<Subcategory>/<ToolName>
# Where Type is: VAPT, Compliance, or SBOM
# Subcategory (for VAPT): VA, SAST, DAST, or SCA
```
