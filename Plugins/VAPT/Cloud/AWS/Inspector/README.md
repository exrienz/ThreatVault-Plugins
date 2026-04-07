# AWS Inspector VA Plugin

This plugin transforms AWS Inspector vulnerability scan CSV exports into the standardized ThreatVault VAPT schema.

## Overview

AWS Inspector is a vulnerability management service that scans EC2 instances, container images, and Lambda functions for software vulnerabilities. This plugin processes CSV exports from AWS Inspector and converts them into ThreatVault's standardized vulnerability format.

## Plugin Information

- **Tool**: AWS Inspector (Amazon Web Services)
- **Category**: VAPT > Cloud > AWS
- **Input Format**: CSV (`.csv`)
- **Output Schema**: ThreatVault VAPT Schema
- **Plugin Type**: DataFrame (immediate processing)

## Field Mappings

| ThreatVault Field | AWS Inspector Source | Mapping Details |
|------------------|---------------------|-----------------|
| `cve` | `Vulnerability Id` | CVE identifier (e.g., CVE-2025-12345) |
| `risk` | `Severity` | Severity level (CRITICAL, HIGH, MEDIUM, LOW) - uppercase normalized |
| `host` | `Resource ID` | EC2 instance ID (e.g., i-0f329afcf322d1b18) |
| `port` | N/A | Always 0 (not applicable for Inspector scans) |
| `name` | `Title` | Vulnerability title with package info |
| `description` | `Description` | Vulnerability description with newlines → `<br/>` |
| `remediation` | `Package Remediation` / `Fixed in Version` | Remediation commands or upgrade version |
| `evidence` | Multiple fields | Package name, installed version, platform, exploit status |
| `vpr_score` | `Inspector Score` | AWS Inspector vulnerability score |

## Supported File Types

The plugin accepts CSV files with the following MIME types:

- `csv` - Simple CSV format identifier
- `text/csv` - Standard CSV MIME type

## Usage

### Python Import

```python
from awsinspector import process

# Read CSV file as bytes
with open('inspector_findings.csv', 'rb') as f:
    file_bytes = f.read()

# Process the file
df = process(file_bytes, 'text/csv')

# Use the DataFrame
print(df)
print(f"Total vulnerabilities: {df.shape[0]}")
```

## Output Schema

The plugin returns a Polars DataFrame with the following columns:

```python
['cve', 'risk', 'host', 'port', 'name', 'description', 'remediation', 'evidence', 'vpr_score']
```

### Data Types

| Column | Type | Notes |
|--------|------|-------|
| `cve` | String | CVE ID (e.g., CVE-2025-52881) |
| `risk` | String | CRITICAL, HIGH, MEDIUM, or LOW (uppercase) |
| `host` | String | EC2 instance ID |
| `port` | Int64 | Always 0 |
| `name` | String | Vulnerability title |
| `description` | String | HTML content with `<br/>` for line breaks |
| `remediation` | String | Package update command or upgrade version |
| `evidence` | String | Combined package and version info |
| `vpr_score` | String | Inspector score (may be empty) |

## Data Processing

### Severity to Risk Mapping

AWS Inspector severity values are normalized to uppercase:

| AWS Inspector Severity | ThreatVault Risk | Action |
|----------------------|------------------|--------|
| CRITICAL | CRITICAL | Converted |
| HIGH | HIGH | Converted |
| MEDIUM | MEDIUM | Converted |
| LOW | LOW | Converted |
| Other | N/A | **Filtered out** |

### Evidence Field

The evidence field combines multiple AWS Inspector columns for context:

```
Package: <affected_packages> | Installed: <installed_version> | Platform: <platform> | Exploit Available: <exploit_status>
```

### Remediation Logic

1. If `Package Remediation` is available → use it
2. Else if `Fixed in Version` is available → "Upgrade to: <version>"
3. Else → "No fix available"

## Generating AWS Inspector CSV

To export findings from AWS Inspector:

### AWS Console

1. Navigate to AWS Inspector → Findings
2. Select findings to export
3. Click "Export" → "Download as CSV"

### AWS CLI

```bash
aws inspector2 list-findings --output json | \
  jq -r '.findings[] | [.findingArn, .severity, .title] | @csv' > findings.csv
```

## Requirements

- Python 3.8 or higher
- Polars library: `pip install polars`

## Example Output

```
shape: (18, 9)
┌──────────────────┬──────┬─────────────────────┬──────┬──────────────────┐
│ cve              ┆ risk ┆ host                ┆ port ┆ name             │
├──────────────────┼──────┼─────────────────────┼──────┼──────────────────┤
│ CVE-2025-52881   ┆ HIGH ┆ i-0f329afcf322d1b18 ┆ 0    ┆ CVE-2025-52881...│
│ CVE-2025-6075    ┆ LOW  ┆ i-0d1119ba2a5feeec5 ┆ 0    ┆ CVE-2025-6075... │
│ CVE-2025-13601   ┆ HIGH ┆ i-0315e876504508c54 ┆ 0    ┆ CVE-2025-13601...│
└──────────────────┴──────┴─────────────────────┴──────┴──────────────────┘
```

## Error Handling

The plugin raises exceptions for:

- **Invalid file type**: If the MIME type is not CSV
  ```
  ValueError: Unsupported file type: application/json. Expected CSV.
  ```

- **Malformed CSV**: If the CSV structure is invalid

## See Also

- [ThreatVault Plugin Creation Guide](../../../../PLUGIN_CREATION_GUIDE.md)
- [AWS Inspector Documentation](https://docs.aws.amazon.com/inspector/)
- [Trivy VA Plugin](../../VA/Trivy/trivy.py) - Similar plugin for Trivy scans
