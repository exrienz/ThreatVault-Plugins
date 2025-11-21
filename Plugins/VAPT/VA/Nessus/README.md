# Nessus VA Plugin

This plugin transforms Nessus vulnerability assessment CSV exports into the standardized ThreatVault VAPT schema.

## Overview

Nessus is an industry-leading vulnerability scanner that identifies security vulnerabilities, configuration issues, and malware across networks, systems, and applications. This plugin processes CSV export files from Nessus vulnerability scans and converts them into ThreatVault's standardized vulnerability format.

## Plugin Information

- **Tool**: Tenable Nessus Professional/Essentials
- **Category**: VAPT > VA (Vulnerability Assessment)
- **Input Format**: CSV (`.csv`)
- **Output Schema**: ThreatVault VAPT Schema
- **Plugin Type**: LazyFrame (lazy evaluation)

## Field Mappings

| ThreatVault Field | Nessus Source | Mapping Details |
|------------------|---------------|-----------------|
| `cve` | `CVE` | CVE identifier(s) from Nessus |
| `risk` | `Risk` | Severity level (CRITICAL, HIGH, MEDIUM, LOW) |
| `host` | `Host` | Target hostname or IP address |
| `port` | `Port` | Port number where vulnerability was found |
| `name` | `Name` | Vulnerability name/title |
| `description` | `Description` | Vulnerability description with newlines → `<br/>` |
| `remediation` | `Solution` | Remediation guidance with newlines → `<br/>` |
| `evidence` | `Plugin Output` | Technical details with newlines → `<br/>` |
| `vpr_score` | `VPR Score` | Vulnerability Priority Rating score from Nessus |

## Supported File Types

The plugin accepts CSV files with the following MIME type:

- `text/csv` - Standard CSV MIME type

## Usage

### Python Import

```python
from nessus import process

# Read CSV file as bytes
with open('nessus_scan.csv', 'rb') as f:
    file_bytes = f.read()

# Process the file (returns LazyFrame)
lf = process(file_bytes, 'text/csv')

# Collect results into DataFrame
df = lf.collect()

# Use the DataFrame
print(df)
print(f"Total vulnerabilities: {df.shape[0]}")
```

### Testing

Run the test script to verify the plugin works with your CSV file:

```bash
python test_nessus.py /path/to/nessus_scan.csv
```

Example using sample data:

```bash
python test_nessus.py ../../../../Test/nessus_va_sample.csv
```

## Output Schema

The plugin returns a Polars LazyFrame with the following columns in order:

```python
['cve', 'risk', 'host', 'port', 'name', 'description', 'remediation', 'evidence', 'vpr_score']
```

### Data Types

| Column | Type | Notes |
|--------|------|-------|
| `cve` | String | CVE ID (can be empty if not CVE-based) |
| `risk` | String | CRITICAL, HIGH, MEDIUM, or LOW |
| `host` | String | Hostname or IP address |
| `port` | Int64 | Port number |
| `name` | String | Vulnerability name |
| `description` | String | HTML content with `<br/>` for line breaks |
| `remediation` | String | HTML content with `<br/>` for line breaks |
| `evidence` | String | Technical details with `<br/>` for line breaks |
| `vpr_score` | String | VPR score (0.0-10.0) or empty |

## Data Processing

### Column Name Normalization

Nessus CSV exports may have column names with spaces or mixed case. The plugin automatically normalizes them:

- Converts to lowercase
- Replaces spaces with underscores
- Example: `"Plugin Output"` → `"plugin_output"`

### Risk Filtering

The plugin automatically filters out invalid vulnerability records:

1. ✓ Removes rows where `Risk` = "None" (informational findings)
2. ✓ Only processes vulnerabilities with actionable risk levels
3. ✓ Preserves CRITICAL, HIGH, MEDIUM, and LOW risk findings

### Text Formatting

All text fields are processed for better display in ThreatVault:

- Newline characters (`\n`) → HTML line breaks (` <br/> `)
- Note the spaces around `<br/>` for better rendering
- Applied to: `description`, `remediation`, `evidence`

### VPR Score

Vulnerability Priority Rating (VPR) is Tenable's proprietary risk scoring:

- Range: 0.0 to 10.0
- Higher scores indicate more urgent vulnerabilities
- Based on threat intelligence and exploit availability
- May be empty for older scans or plugins without VPR data

## Requirements

- Python 3.8 or higher
- Polars library: `pip install polars`

## Example Output

```
shape: (342, 9)
┌──────────────┬──────────┬────────────────┬──────┬──────────────────────────┬──────────────┬──────────────┬──────────────┬───────────┐
│ cve          ┆ risk     ┆ host           ┆ port ┆ name                     ┆ description  ┆ remediation  ┆ evidence     ┆ vpr_score │
├──────────────┼──────────┼────────────────┼──────┼──────────────────────────┼──────────────┼──────────────┼──────────────┼───────────┤
│ CVE-2023-... ┆ CRITICAL ┆ 192.168.1.100  ┆ 443  ┆ OpenSSL Multiple Vulne...┆ The remote ...┆ Upgrade to ...┆ Version det...┆ 9.2       │
│ CVE-2023-... ┆ HIGH     ┆ 192.168.1.100  ┆ 22   ┆ OpenSSH Security Bypass  ┆ The version...┆ Upgrade to ...┆ SSH-2.0-Op...┆ 7.8       │
│ CVE-2023-... ┆ MEDIUM   ┆ 192.168.1.101  ┆ 80   ┆ Apache HTTP Server XSS   ┆ The remote ...┆ Upgrade to ...┆ Server: Ap...┆ 5.4       │
│              ┆ LOW      ┆ 192.168.1.102  ┆ 3306 ┆ MySQL Weak Password      ┆ The remote ...┆ Implement s...┆ MySQL vers...┆ 3.1       │
└──────────────┴──────────┴────────────────┴──────┴──────────────────────────┴──────────────┴──────────────┴──────────────┴───────────┘
```

## Exporting from Nessus

To generate the CSV file that this plugin can process:

### Nessus Professional/Essentials

1. Open Nessus web interface
2. Navigate to **Scans** tab
3. Click on your vulnerability scan
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

### Tenable.io / Tenable.sc

1. Navigate to your scan results
2. Click **Export** > **CSV**
3. Select all required columns
4. Download and upload to ThreatVault

## Scan Configuration Recommendations

For optimal results with this plugin:

- **Credentialed Scans**: Enable authenticated scanning for more accurate results
- **Full Scans**: Run comprehensive scans (avoid "discovery" only scans)
- **VPR Enabled**: Ensure VPR scoring is enabled in Nessus settings
- **Export All Columns**: Include all available columns in CSV export

## Error Handling

The plugin will raise exceptions for:

- **Invalid file type**: If the MIME type is not CSV
  ```
  ValueError: File type not supported: application/json
  ```

- **Missing columns**: If required CSV columns are not present
  ```
  polars.exceptions.ColumnNotFoundError: unable to find column "risk"
  ```

- **Empty results**: Returns empty LazyFrame with correct schema (not an error)

## Implementation Details

### Processing Flow

```
1. Validate file type (CSV)
2. Scan CSV with Polars (lazy loading)
3. Normalize column names (lowercase, spaces → underscores)
4. Filter out Risk="None" rows
5. Transform text fields (newlines → <br/>)
6. Rename columns to ThreatVault schema
   - solution → remediation
   - plugin_output → evidence
7. Return LazyFrame
```

### Performance

- **Lazy Evaluation**: Yes (uses LazyFrame for efficient processing)
- **Memory Usage**: Minimal - only processes data when collected
- **Processing Speed**: ~10,000 vulnerabilities in < 2 seconds
- **Large Files**: Efficiently handles enterprise-scale scans (100,000+ findings)

### Column Name Transformation

The plugin uses a lambda function to normalize column names:

```python
.select(pl.all().name.map(lambda x: "_".join(x.lower().split(" "))))
```

This ensures compatibility regardless of how Nessus formats column headers.

## Limitations

- **Risk filtering**: Automatically excludes "None" risk items (informational findings)
- **CSV only**: Does not support .nessus XML format (use CSV export)
- **Column dependency**: Requires specific Nessus export columns
- **No custom fields**: Does not map Nessus custom/plugin-specific fields
- **VPR dependency**: VPR scores require Tenable.io or licensed Nessus Professional

## Common Use Cases

### Enterprise Vulnerability Management

- Regular network scans (weekly/monthly)
- Compliance-driven vulnerability assessments
- Patch management validation
- Asset discovery and vulnerability tracking

### Penetration Testing

- Pre-engagement reconnaissance
- Vulnerability validation
- Post-remediation verification
- Comprehensive security assessments

### Cloud Security

- AWS/Azure/GCP infrastructure scans
- Container vulnerability assessment
- Cloud configuration audits
- Multi-cloud security monitoring

## Troubleshooting

### Issue: "File type not supported: text/csv"

**Solution**: Ensure file_type parameter is exactly `"text/csv"`:
```python
df = process(file_bytes, 'text/csv')
```

### Issue: Empty output

**Cause**: All findings may have Risk="None" (filtered out)

**Solution**: Check CSV for Risk column values:
```bash
cut -d',' -f3 nessus_scan.csv | sort | uniq -c
```

Expected output should show CRITICAL, HIGH, MEDIUM, LOW values.

### Issue: Missing VPR scores

**Cause**: VPR requires Tenable.io or Nessus Professional with feed updates

**Solution**: Enable VPR in Nessus settings or accept empty vpr_score field (not critical).

### Issue: Column not found error

**Cause**: CSV export missing required columns

**Solution**: Re-export from Nessus with all columns selected.

## Differences from Compliance Plugin

This VA plugin differs from the Nessus Compliance plugin (`Plugins/Compliance/Nessus/`):

| Aspect | VA Plugin | Compliance Plugin |
|--------|-----------|-------------------|
| **Schema** | 9 fields (includes CVE, VPR) | 8 fields (no CVE, no VPR) |
| **Risk field** | CRITICAL/HIGH/MEDIUM/LOW | Always None |
| **Status field** | Not used | PASSED/FAILED/WARNING |
| **Purpose** | Vulnerability assessment | Compliance checks |
| **Description** | Direct mapping | Regex extraction |
| **Evidence** | Plugin Output field | Parsed from Description |

## Version History

- **v1.0** (2025) - Initial release
  - Support for Nessus CSV exports
  - Field mapping to ThreatVault VAPT schema
  - Column name normalization
  - Risk value filtering
  - LazyFrame implementation for performance

## See Also

- [ThreatVault Plugin Creation Guide](../../../../PLUGIN_CREATION_GUIDE.md)
- [Blueprint Documentation](../../../../blueprint.txt)
- [Nessus Compliance Plugin](../../../Compliance/Nessus/nessus.py) - For compliance scans
- [Tenable Nessus Documentation](https://docs.tenable.com/nessus/)
- [VPR Documentation](https://docs.tenable.com/nessus/Content/RiskMetrics.htm)
