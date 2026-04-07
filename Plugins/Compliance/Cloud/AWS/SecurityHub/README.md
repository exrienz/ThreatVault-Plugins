# AWS SecurityHub Compliance Plugin

This plugin transforms AWS SecurityHub compliance finding exports (NDJSON format) into the standardized ThreatVault Compliance schema.

## Overview

AWS SecurityHub is a cloud security posture management service that aggregates, organizes, and prioritizes security findings from AWS services and third-party tools. This plugin processes NDJSON exports from SecurityHub and converts them into ThreatVault's standardized compliance format.

## Plugin Information

- **Tool**: AWS SecurityHub
- **Category**: Compliance > Cloud > AWS
- **Input Format**: NDJSON (Newline Delimited JSON)
- **Output Schema**: ThreatVault Compliance Schema
- **Plugin Type**: DataFrame (immediate processing)

## Severity to Risk Mapping

| SecurityHub Severity | ThreatVault Risk |
|---------------------|------------------|
| `CRITICAL` | `Critical` |
| `HIGH` | `High` |
| `MEDIUM` | `Medium` |
| `LOW` | `Low` |
| `INFORMATIONAL` | `Info` |

## Field Mappings

| ThreatVault Field | SecurityHub JSON Path | Mapping Details |
|------------------|----------------------|-----------------|
| `risk` | `Severity.Label` | Mapped to ThreatVault risk levels (see table above) |
| `host` | `Resources[0].Tags.Name` / `Resources[0].Id` | Name tag extracted, fallback to resource ID |
| `port` | N/A | Always 0 |
| `name` | `Title` | Finding title/rule name |
| `description` | `Description` | Finding description |
| `remediation` | `Remediation.Recommendation.Text` / `Remediation.Recommendation.Url` | Remediation guidance with URL |
| `evidence` | Multiple fields | Resource ID, type, account, region, workflow status |
| `status` | `Compliance.Status` | PASSED, FAILED, NOT_AVAILABLE |

## Supported File Types

- `ndjson` / `application/x-ndjson` - Newline Delimited JSON
- `json` / `application/json` - JSON (parsed as NDJSON)
- `csv` / `text/csv` - CSV (parsed as NDJSON per line)

## Usage

```python
from securityhub import process

with open('securityhub_findings.csv', 'rb') as f:
    df = process(f.read(), 'text/csv')

print(df)
print(f"Total findings: {df.shape[0]}")
```

## Output Schema

```python
['risk', 'host', 'port', 'name', 'description', 'remediation', 'evidence', 'status']
```

| Column | Type | Notes |
|--------|------|-------|
| `risk` | String | Always `None` |
| `host` | String | Resource name or instance ID |
| `port` | Int64 | Always 0 |
| `name` | String | Finding title |
| `description` | String | Finding description |
| `remediation` | String | Remediation guidance |
| `evidence` | String | Resource details |
| `status` | String | PASSED, FAILED, NOT_AVAILABLE |

## Exporting from SecurityHub

### AWS Console

1. Navigate to AWS SecurityHub → Findings
2. Select findings to export
3. Click **Download** → CSV format

### AWS CLI

```bash
aws securityhub get-findings --output json > findings.json
```

## Requirements

- Python 3.8+
- Polars: `pip install polars`

## See Also

- [AWS SecurityHub Documentation](https://docs.aws.amazon.com/securityhub/)
- [Nessus Compliance Plugin](../../Nessus/nessus.py)
