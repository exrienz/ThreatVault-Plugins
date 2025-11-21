# Nessus Compliance Plugin

This plugin transforms Nessus compliance scan CSV exports into the standardized ThreatVault Compliance schema.

## Overview

Nessus is a comprehensive vulnerability scanner that also performs compliance audits against industry standards like CIS benchmarks, PCI-DSS, HIPAA, and more. This plugin processes CSV export files from Nessus compliance scans and converts them into ThreatVault's standardized compliance format.

## Plugin Information

- **Tool**: Tenable Nessus Professional/Essentials
- **Category**: Compliance
- **Scan Type**: Compliance Audits (CIS, PCI-DSS, HIPAA, ISO 27001, etc.)
- **Input Format**: CSV (`.csv`)
- **Output Schema**: ThreatVault Compliance Schema
- **Plugin Type**: LazyFrame (lazy evaluation)

## Field Mappings

| ThreatVault Field | Nessus Source | Mapping Details |
|------------------|---------------|-----------------|
| `risk` | N/A | Set to `None` (auto-assigned to Medium by ThreatVault) |
| `host` | `Host` | Target hostname or IP address |
| `port` | `Port` | Port number from scan |
| `name` | `Description` | Extracted using regex: `^(.*): \[.*\]` (text before colon) |
| `description` | `Description` | Extracted from multi-line description (between line 2 and "Actual Value:") |
| `remediation` | `Solution` | Remediation guidance from Nessus |
| `evidence` | `Description` | Extracted using regex: `Actual Value:\s*\n(?s)(.*)` (everything after "Actual Value:") |
| `status` | `Risk` | Nessus Risk field mapped to status (PASSED/FAILED/WARNING) |

**Important Notes**:
- Unlike VAPT plugins, compliance plugins do NOT use `cve` or `vpr_score` fields
- The `risk` field is intentionally set to `None` for compliance scans
- The `Risk` column from Nessus is renamed to `status` to reflect compliance check results

## Supported File Types

The plugin accepts CSV files with the following MIME type:

- `text/csv` - Standard CSV MIME type

## Usage

### Python Import

```python
from nessus import process

# Read CSV file as bytes
with open('nessus_compliance.csv', 'rb') as f:
    file_bytes = f.read()

# Process the file (returns LazyFrame)
lf = process(file_bytes, 'text/csv')

# Collect results into DataFrame
df = lf.collect()

# Use the DataFrame
print(df)
print(f"Total compliance checks: {df.shape[0]}")
```

### Testing

Run the test script to verify the plugin works with your CSV file:

```bash
python test_nessus.py /path/to/nessus_compliance.csv
```

Example using sample data:

```bash
python test_nessus.py ../../../Test/nessus_compliance_sample.csv
```

## Output Schema

The plugin returns a Polars LazyFrame with the following columns in order:

```python
['risk', 'host', 'port', 'name', 'description', 'remediation', 'evidence', 'status']
```

### Data Types

| Column | Type | Notes |
|--------|------|-------|
| `risk` | String | Always `None` (auto-assigned to Medium) |
| `host` | String | Hostname or IP address |
| `port` | Int64 | Port number |
| `name` | String | Check name/title |
| `description` | String | Check description with `<br/>` for line breaks |
| `remediation` | String | Solution/remediation with `<br/>` for line breaks |
| `evidence` | String | Actual value found with `<br/>` for line breaks |
| `status` | String | PASSED, FAILED, WARNING, or other status values |

## Data Processing

### Description Field Parsing

The Nessus Description field contains multi-line structured data that is parsed into separate fields:

**Original Nessus Description Format**:
```
Check Title: [Reference]
Line 2 content...
Additional description lines...

Actual Value:
Evidence data here...
```

**Parsing Logic**:
- **name**: Text before the colon on line 1 → "Check Title"
- **description**: Text from line 2 until "Actual Value:" marker
- **evidence**: Everything after "Actual Value:" marker

### Text Formatting

All text fields are processed for better display in ThreatVault:

- Newline characters (`\n`) → HTML line breaks (`<br/>`)
- Applied to: `name`, `description`, `remediation`, `evidence`

### Data Filtering

The plugin automatically filters out invalid records:

1. ✓ Removes rows where `Risk` = "None"
2. ✓ Removes rows where `Risk` is null/empty
3. ✓ Only processes valid compliance check results

### Dropped Columns

These Nessus CSV columns are not used and are dropped during processing:

- `VPR Score` - Not applicable for compliance
- `CVE` - Compliance checks are not CVE-based
- `Name` - Replaced by extracted name from Description
- `Plugin Output` - Not used in compliance schema
- `Description` - Transformed and split into name/description/evidence

## Requirements

- Python 3.8 or higher
- Polars library: `pip install polars`

## Example Output

```
shape: (45, 8)
┌──────┬────────────────┬──────┬──────────────────────────┬──────────────┬──────────────┬──────────────┬────────┐
│ risk ┆ host           ┆ port ┆ name                     ┆ description  ┆ remediation  ┆ evidence     ┆ status │
├──────┼────────────────┼──────┼──────────────────────────┼──────────────┼──────────────┼──────────────┼────────┤
│ null ┆ 192.168.1.10   ┆ 0    ┆ 1.1.1 Ensure mounting... ┆ Removing su...┆ Edit /etc/f...┆ tmpfs /dev...┆ FAILED │
│ null ┆ 192.168.1.10   ┆ 0    ┆ 1.1.2 Ensure nodev op... ┆ The nodev m...┆ Edit /etc/f...┆ /dev/sda1 ...┆ PASSED │
│ null ┆ 192.168.1.10   ┆ 0    ┆ 2.2.1.1 Ensure time s... ┆ The systemd...┆ Run the fol...┆ enabled<br...┆ PASSED │
└──────┴────────────────┴──────┴──────────────────────────┴──────────────┴──────────────┴──────────────┴────────┘
```

## Exporting from Nessus

To generate the CSV file that this plugin can process:

### Nessus Professional/Essentials

1. Open Nessus web interface
2. Navigate to **Scans** tab
3. Click on your compliance scan
4. Click **Export** button (top right)
5. Select **CSV** format
6. Check **All columns** or ensure these columns are included:
   - Host
   - Port
   - Risk
   - Name
   - Description
   - Solution
   - CVE
   - VPR Score
   - Plugin Output
7. Click **Export**
8. Upload the CSV file to ThreatVault

### Required Nessus CSV Columns

The plugin expects these columns in the CSV:

- `Host` - Target system identifier
- `Port` - Port number
- `Risk` - Compliance status
- `Description` - Structured check information
- `Solution` - Remediation guidance

## Compliance Audit Types

This plugin supports Nessus compliance audits for:

- **CIS Benchmarks** (Center for Internet Security)
- **PCI-DSS** (Payment Card Industry Data Security Standard)
- **HIPAA** (Health Insurance Portability and Accountability Act)
- **ISO 27001** (Information Security Management)
- **NIST** (National Institute of Standards and Technology)
- **DISA STIG** (Defense Information Systems Agency Security Technical Implementation Guides)
- **Custom compliance policies**

## Error Handling

The plugin will raise exceptions for:

- **Invalid file type**: If the MIME type is not CSV
  ```
  ValueError: File type not supported: application/json
  ```

- **Missing columns**: If required CSV columns are not present
  ```
  polars.exceptions.ColumnNotFoundError: ...
  ```

- **Empty results**: Returns empty LazyFrame with correct schema (not an error)

## Implementation Details

### Processing Flow

```
1. Validate file type (CSV)
2. Scan CSV with Polars (lazy loading)
3. Extract 'name' from Description using regex
4. Extract 'description' from Description (multi-line)
5. Extract 'evidence' from Description (Actual Value section)
6. Set risk to None
7. Filter out invalid Risk values (None/"None")
8. Rename Solution → remediation, Risk → status
9. Drop unused columns
10. Return LazyFrame
```

### Performance

- **Lazy Evaluation**: Yes (uses LazyFrame for efficient processing)
- **Memory Usage**: Minimal - only processes data when collected
- **Processing Speed**: ~1000 checks in < 1 second
- **Large Files**: Efficiently handles large compliance reports (10,000+ checks)

### Regex Patterns Used

1. **Name extraction**: `^(.*): \[.*\]` - Captures text before colon on first line
2. **Description extraction**: `^(?:.*\n){2}((?s).*?)(?:^Actual Value:|$)` - Captures multi-line text between line 2 and "Actual Value:"
3. **Evidence extraction**: `Actual Value:\s*\n(?s)(.*)` - Captures everything after "Actual Value:"

## Limitations

- **No risk levels**: Risk is set to None (ThreatVault auto-assigns Medium)
- **No CVE mapping**: Compliance checks don't map to CVEs
- **No VPR scores**: Not applicable for compliance audits
- **Regex dependency**: Name/description/evidence extraction depends on specific Nessus format
- **Description format**: Assumes specific multi-line structure from Nessus exports

## Troubleshooting

### Issue: "File type not supported: text/csv"

**Solution**: Ensure file_type parameter is exactly `"text/csv"`:
```python
df = process(file_bytes, 'text/csv')
```

### Issue: Empty output or missing checks

**Cause**: Checks with Risk="None" are filtered out

**Solution**: Check the CSV for Risk column values:
```bash
cut -d',' -f3 nessus_compliance.csv | sort | uniq -c
```

### Issue: Name field is empty

**Cause**: Description field doesn't match expected format `Title: [Reference]`

**Solution**: Verify Description column format matches Nessus compliance export structure.

### Issue: Missing description or evidence

**Cause**: Description field doesn't contain "Actual Value:" marker

**Solution**: This is expected for some compliance checks. The field will be empty if the marker is not present.

## Differences from VAPT Plugin

This Compliance plugin differs from the Nessus VAPT plugin (`Plugins/VAPT/VA/Nessus/`):

| Aspect | Compliance Plugin | VAPT Plugin |
|--------|------------------|-------------|
| **Schema** | 8 fields (no CVE, no VPR) | 9 fields (includes CVE, VPR) |
| **Risk field** | Always None | CRITICAL/HIGH/MEDIUM/LOW |
| **Status field** | PASSED/FAILED/WARNING | Not used |
| **Purpose** | Compliance checks | Vulnerability assessment |
| **Description** | Parsed from structured text | Direct mapping |
| **Evidence** | Extracted from "Actual Value:" | Plugin Output field |

## Version History

- **v1.0** (2025) - Initial release
  - Support for Nessus compliance CSV exports
  - Field mapping to ThreatVault Compliance schema
  - Regex-based description parsing
  - Risk value filtering

## See Also

- [ThreatVault Plugin Creation Guide](../../../PLUGIN_CREATION_GUIDE.md)
- [Blueprint Documentation](../../../blueprint.txt)
- [Nessus VAPT Plugin](../../VAPT/VA/Nessus/nessus.py) - For vulnerability scans
- [Tenable Nessus Documentation](https://docs.tenable.com/nessus/)
