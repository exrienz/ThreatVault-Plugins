# Burp Suite DAST Plugin

This plugin transforms Burp Suite XML scan reports into the standardized ThreatVault VAPT schema.

## Overview

Burp Suite is a leading web application security testing tool that performs Dynamic Application Security Testing (DAST). This plugin processes XML export files from Burp Suite Professional/Enterprise and converts them into ThreatVault's standardized vulnerability format.

## Plugin Information

- **Tool**: Burp Suite Professional/Enterprise
- **Category**: VAPT > DAST
- **Input Format**: XML (`.xml`)
- **Output Schema**: ThreatVault VAPT Schema
- **Plugin Type**: DataFrame (immediate processing)

## Field Mappings

| ThreatVault Field | Burp Suite Source | Mapping Details |
|------------------|-------------------|-----------------|
| `cve` | N/A | Empty (Burp Suite doesn't provide CVEs) |
| `risk` | `<severity>` | Converted to uppercase: CRITICAL, HIGH, MEDIUM, LOW |
| `host` | `<host>` or `<host ip="">` | Prefers hostname, falls back to IP address |
| `port` | N/A | Set to 0 (Burp Suite XML doesn't include port) |
| `name` | `<name>` | Issue name/title |
| `description` | `<issueBackground>` or `<issueDetail>` | Uses `issueBackground` if available, otherwise `issueDetail` |
| `remediation` | `<remediationBackground>` or `<remediationDetail>` | Uses `remediationBackground` if available, otherwise `remediationDetail` |
| `evidence` | `<request>` | HTTP request data from `requestresponse` element |
| `vpr_score` | N/A | Empty (Burp Suite doesn't provide VPR scores) |

## Supported File Types

The plugin accepts XML files with any of the following MIME type formats (case-insensitive):

- `xml` - Simple XML format identifier
- `application/xml` - Standard XML MIME type
- `text/xml` - Alternative XML MIME type
- `application/x-xml` - Legacy XML MIME type

**Note**: File type validation is case-insensitive, so `XML`, `Application/XML`, etc. are all accepted.

## Usage

### Python Import

```python
from burpsuite import process

# Read XML file as bytes
with open('burp_scan.xml', 'rb') as f:
    file_bytes = f.read()

# Process the file
df = process(file_bytes, 'xml')

# Use the DataFrame
print(df)
print(f"Total vulnerabilities: {df.shape[0]}")
```

### Testing

Run the test script to verify the plugin works with your XML file:

```bash
python test_burpsuite.py /path/to/burp_scan.xml
```

Example using sample data:

```bash
python test_burpsuite.py ../../../../Test/burp_sample.xml
```

## Output Schema

The plugin returns a Polars DataFrame with the following columns in order:

```python
['cve', 'risk', 'host', 'port', 'name', 'description', 'remediation', 'evidence', 'vpr_score']
```

### Data Types

| Column | Type | Notes |
|--------|------|-------|
| `cve` | String | Always empty |
| `risk` | String | CRITICAL, HIGH, MEDIUM, or LOW |
| `host` | String | Hostname (or IP address if hostname unavailable) |
| `port` | Int64 | Always 0 |
| `name` | String | Issue name |
| `description` | String | HTML content with `<br/>` for line breaks |
| `remediation` | String | HTML content with `<br/>` for line breaks |
| `evidence` | String | Request data with `<br/>` for line breaks |
| `vpr_score` | String | Always empty |

## Data Processing

### Severity to Risk Mapping

Burp Suite severity values (title case) are converted to ThreatVault risk levels (uppercase):

| Burp Suite Severity | ThreatVault Risk | Action |
|---------------------|------------------|--------|
| Critical | CRITICAL | Converted |
| High | HIGH | Converted |
| Medium | MEDIUM | Converted |
| Low | LOW | Converted |
| Information | N/A | **Filtered out** |

**Example**: In a scan with 234 total issues including 9 'Information' findings, the plugin will output 225 vulnerabilities (234 - 9 = 225).

### Text Formatting

All text fields are processed for better display in ThreatVault:

- Newline characters (`\n`) → HTML line breaks (`<br/>`)
- HTML tags preserved (e.g., `<p>`, `<ul>`, etc.)
- Applied to: `description`, `remediation`, `evidence`

### Data Validation

The plugin automatically:

1. ✓ Converts severity to uppercase
2. ✓ Filters out 'Information' severity findings
3. ✓ Validates risk values (only CRITICAL, HIGH, MEDIUM, LOW allowed)
4. ✓ Returns empty DataFrame with correct schema if no valid findings

## Requirements

- Python 3.8 or higher
- Polars library: `pip install polars`

## Example Output

```
shape: (225, 9)
┌─────┬────────┬───────────────┬──────┬─────────────────────────────┬─────────────┬───────────┬──────────┬───────────┐
│ cve ┆ risk   ┆ host          ┆ port ┆ name                        ┆ description ┆ remediation ┆ evidence ┆ vpr_score │
├─────┼────────┼───────────────┼──────┼─────────────────────────────┼─────────────┼───────────┼──────────┼───────────┤
│     ┆ MEDIUM ┆ 54.169.144.186┆ 0    ┆ Strict Transport Security... ┆ <p>The H... ┆ <p>A Str... ┆ PUT /api...┆           │
│     ┆ HIGH   ┆ 54.169.144.186┆ 0    ┆ Cross-site scripting        ┆ Cross-sit...┆ In most s...┆ GET /vul...┆           │
│     ┆ LOW    ┆ 54.169.144.186┆ 0    ┆ Content Sniffing not disabled┆ <p>The r...┆ <p>The ap...┆ POST /ap...┆           │
└─────┴────────┴───────────────┴──────┴─────────────────────────────┴─────────────┴───────────┴──────────┴───────────┘
```

## Exporting from Burp Suite

To generate the XML file that this plugin can process:

1. Open Burp Suite Professional/Enterprise
2. Navigate to **Target > Site Map** or **Dashboard**
3. Right-click on the target or issue list
4. Select **"Report selected issues"** or **"Generate report"**
5. Choose **"XML"** as the report format
6. Save the file and upload it to ThreatVault

## Error Handling

The plugin will raise exceptions for:

- **Invalid file type**: If the MIME type is not an XML format
  ```
  ValueError: Unsupported file type: application/json. Expected XML format.
  ```

- **Malformed XML**: If the XML structure is invalid
  ```
  ET.ParseError: Failed to parse Burp Suite XML: ...
  ```

- **Empty results**: Returns empty DataFrame with correct schema (not an error)

## Implementation Details

### Processing Flow

```
1. Validate file type (XML)
2. Parse XML using ElementTree
3. Extract fields from each <issue> element
4. Build records list
5. Create Polars DataFrame
6. Transform text (newlines → <br/>)
7. Normalize risk to uppercase
8. Filter invalid risk values
9. Return DataFrame
```

### Performance

- **Lazy Evaluation**: No (uses DataFrame for XML parsing)
- **Memory Usage**: Loads full XML into memory
- **Processing Speed**: ~225 issues in < 1 second
- **Large Files**: Tested successfully with 4.8MB XML (234 issues)

## Limitations

- **No CVE mapping**: Burp Suite findings are not mapped to CVE IDs
- **No port information**: Port numbers are not included in Burp Suite XML exports
- **No VPR scores**: Burp Suite doesn't provide VPR (Vulnerability Priority Rating) scores
- **Base64 encoded data**: Request/response data may be base64 encoded (currently preserved as-is)
- **No confidence level**: Burp Suite confidence levels are not mapped to ThreatVault

## Troubleshooting

### Issue: "File type not supported: xml"

**Solution**: Clear Python cache and restart:
```bash
rm -rf __pycache__
python test_burpsuite.py your_file.xml
```

### Issue: No vulnerabilities in output

**Cause**: All findings may be 'Information' severity (filtered out)

**Solution**: Check the XML for severity values:
```bash
grep '<severity>' your_file.xml | sort | uniq -c
```

## Version History

- **v2.0** (2025) - Rebuilt following ThreatVault plugin standards
  - Improved code structure matching Semgrep/Trivy patterns
  - Better error handling and validation
  - Enhanced documentation
  - Added schema validation for empty results

- **v1.0** (2025) - Initial release
  - Support for Burp Suite XML exports
  - Field mapping to ThreatVault VAPT schema
  - Risk value validation and filtering

## See Also

- [ThreatVault Plugin Creation Guide](../../../../PLUGIN_CREATION_GUIDE.md)
- [Blueprint Documentation](../../../../blueprint.txt)
- [Semgrep Plugin](../../SAST/Semgrep/semgrep.py) - Similar JSON processing pattern
- [Trivy Plugin](../../VA/Trivy/trivy.py) - Similar structured data handling
