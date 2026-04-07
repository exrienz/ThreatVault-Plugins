# ThreatVault Plugin: Purple Knight (VAPT)

## Overview
This plugin imports vulnerability assessment results from **Semperis Purple Knight** into ThreatVault. It requires the report to be converted to a structured CSV format first.

## Supported Format
- **Source**: Pre-processed CSV file
- **Plugin File**: `purpleknight.py`
- **Utility**: `pk_html_to_csv.py` (Converts HTML report to CSV)

## Features
- **Streamlined Ingestion**: Directly ingests structured CSV data containing AD findings.
- **Auto-Discovery**: Maps the pre-processed CSV columns to ThreatVault fields.

## Usage
### 1. Convert HTML to CSV
First, use the provided utility script to convert the Purple Knight HTML report into a compatible CSV file.
```bash
python3 pk_html_to_csv.py <path_to_purple_knight_report.html> -o output.csv
```

### 2. Upload to ThreatVault
1. Select the **Purple Knight** plugin in ThreatVault.
2. Upload the generated `output.csv`.

## Mapping Details
The input CSV must contain the following headers, which map 1:1 to ThreatVault fields:

| Field | Description |
|-------|-------------|
| `host` | Identification of the affected asset (e.g., Computer Name, Account Name). |
| `port` | 0 (Not applicable for AD). |
| `name` | Name of the indicator/vulnerability. |
| `description` | Detailed description and likelihood of compromise. |
| `severity` | Critical, High, Medium, or Low. |
| `remediation` | Steps to remediate the finding. |
| `evidence` | Specific details for the finding instance. |
| `vulnerability_id`| Unique ID for the finding type. |

## Dependencies
- `polars`: For Dataframe handling.

