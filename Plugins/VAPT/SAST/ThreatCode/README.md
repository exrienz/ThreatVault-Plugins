# ThreatCode SAST Plugin

This plugin transforms ThreatCode AI security scan results into the standardized ThreatVault VAPT schema.

## Overview

ThreatCode is an AI-powered security scanner that analyzes source code to identify vulnerabilities using Large Language Models. This plugin processes CSV export files from ThreatCode scans and converts them into ThreatVault's standardized vulnerability format.

## Plugin Information

- **Tool**: ThreatCode (AI-Powered Security Scanner)
- **Category**: VAPT > SAST (Static Application Security Testing)
- **Input Format**: CSV (`.csv`)
- **Output Schema**: ThreatVault VAPT Schema
- **Plugin Type**: DataFrame (immediate processing)

## Field Mappings

| ThreatVault Field | ThreatCode Source | Mapping Details |
|------------------|-------------------|-----------------|
| `cve` | CVE column | CVE identifier if applicable (may be empty) |
| `risk` | Risk column | Mapped to CRITICAL, HIGH, MEDIUM, LOW |
| `host` | Host column | Repository name, domain, or service identifier |
| `port` | Plugin Output | Line number extracted from evidence (regex: `Line:\s*(\d+)`) |
| `name` | Name column | Vulnerability name/title |
| `description` | Description column | Detailed vulnerability description |
| `remediation` | Solution column | Fix recommendations and guidance |
| `evidence` | Plugin Output column | File paths, line numbers, code snippets |
| `vpr_score` | VPR Score column | VPR score (usually 0 for SAST) |

**Note**: The `host` field is populated with the value provided via the `--name` flag during scanning. This allows you to organize and filter scan results by project, environment, or domain in ThreatVault.

## CSV Input Format

The plugin accepts CSV files with the following MIME types:
- `csv` - Simple CSV format identifier
- `text/csv` - Standard CSV MIME type

### Required CSV Columns

| Column | Type | Description |
|--------|------|-------------|
| `CVE` | String | CVE identifier (optional, can be empty) |
| `Risk` | String | Severity level (Critical, High, Medium, Low) |
| `Host` | String | Application/repository name |
| `Port` | Integer | Port number (usually 0 for SAST) |
| `Name` | String | Vulnerability title |
| `Description` | String | Detailed description |
| `Solution` | String | Remediation guidance |
| `Plugin Output` | String | Evidence with file paths and line numbers |
| `VPR Score` | Integer | VPR score (usually 0) |

### CSV Structure Example

```csv
CVE,Risk,Host,Port,Name,Description,Solution,Plugin Output,VPR Score
,Critical,application-name,0,SQL Injection,"Vulnerability description...","1. Use parameterized queries...","File: src/auth.py
Line: 42
Code: query = f'SELECT...'
---",0
```

## Usage

### Quick Start with Docker

No installation needed! Just run the pre-built Docker image:

**1. Pull the Image**

```bash
docker pull exrienz/threatcode:latest
```

**2. Run a Scan**

Navigate to your project folder and run:

```bash
docker run --rm \
  -v $(pwd):/scan \
  -e LLM_PROVIDER=openrouter \
  -e OPENROUTER_API_KEY=YOUR_API_KEY \
  -e OPENROUTER_MODEL=anthropic/claude-3-haiku \
  exrienz/threatcode:latest scan \
  --input /scan \
  --output /scan \
  --name "your-domain.com"
```

**Tip**: Replace the `--name` value with your domain name (e.g., `api.example.com`) or repository name (e.g., `github.com/org/repo`) for better organization in ThreatVault.

### Python Import

```python
from threatcode import process

# Read CSV file as bytes
with open('scan_results.csv', 'rb') as f:
    file_bytes = f.read()

# Process the file
df = process(file_bytes, 'csv')

# Use the DataFrame
print(df)
print(f"Total findings: {df.shape[0]}")
```

### Integration with ThreatVault

Upload the processed CSV file to ThreatVault through:
- **Manual Upload**: ThreatVault web interface
- **API Upload**: ThreatVault REST API
- **CI/CD Pipeline**: Automated integration

## Output Schema

The plugin returns a Polars DataFrame with the following columns in exact order:

```python
['cve', 'risk', 'host', 'port', 'name', 'description', 'remediation', 'evidence', 'vpr_score']
```

### Data Types

| Column | Type | Notes |
|--------|------|-------|
| `cve` | String | Empty string if not applicable |
| `risk` | String | CRITICAL, HIGH, MEDIUM, or LOW (uppercase) |
| `host` | String | Repository/domain name from scan |
| `port` | Int64 | Line number extracted from Plugin Output |
| `name` | String | Vulnerability title |
| `description` | String | HTML formatted with `<br/>` for line breaks |
| `remediation` | String | HTML formatted with `<br/>` for line breaks |
| `evidence` | String | HTML formatted with `<br/>` for line breaks |
| `vpr_score` | String | VPR score as string |

## Data Processing

### Risk Level Mapping

ThreatCode severity values are normalized to ThreatVault risk levels:

| Input Severity | Output Risk | Action |
|----------------|-------------|--------|
| Critical | CRITICAL | Included |
| High | HIGH | Included |
| Medium | MEDIUM | Included |
| Low | LOW | Included |
| Informational | N/A | **Filtered out** |

### Line Number Extraction

The plugin extracts line numbers from the `Plugin Output` field using regex pattern:

```
Pattern: Line:\s*(\d+)
```

**Example**:
```
Input (Plugin Output):
  File: src/main.py
  Line: 42
  Code: ...
  ---

Output (port): 42
```

### HTML Formatting

All text fields are processed for better display:
- Newline characters (`\n`) → HTML line breaks (`<br/>`)
- Applied to: `description`, `remediation`, `evidence`

## Best Practices for Scanning

### Naming Convention for `--name` Flag

Use consistent naming to organize scan results:

- **Web Applications**: Domain names
  - `www.example.com`
  - `api.staging.example.com`
  - `app.production.example.com`

- **Repositories**: Repository paths
  - `github.com/organization/repository`
  - `gitlab.company.com/team/project`

- **Microservices**: Service names
  - `auth-service`
  - `payment-api`
  - `user-management`

- **Mobile Apps**: App identifiers
  - `com.company.mobile-app`
  - `ios-banking-app`

### Example Scan Commands

```bash
# Web application scan
threatcode scan /path/to/webapp \
  --name "www.example.com" \
  --output csv \
  --output-file scan_results.csv

# Repository scan
threatcode scan /path/to/repo \
  --name "github.com/org/project" \
  --output csv \
  --output-file scan_results.csv

# Microservice scan
threatcode scan /path/to/service \
  --name "payment-api" \
  --output csv \
  --output-file scan_results.csv
```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: ThreatCode Security Scan

on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Run ThreatCode Scan
        env:
          SCAN_API_KEY: ${{ secrets.SCAN_API_KEY }}
        run: |
          threatcode scan . \
            --name "${{ github.repository }}" \
            --output csv \
            --output-file scan_results.csv

      - name: Upload to ThreatVault
        run: |
          curl -X POST https://your-threatvault-instance/api/upload \
            -H "Authorization: Bearer ${{ secrets.THREATVAULT_TOKEN }}" \
            -F "file=@scan_results.csv"
```

### GitLab CI Example

```yaml
threatcode-scan:
  stage: security
  script:
    - threatcode scan .
        --name "$CI_PROJECT_PATH"
        --output csv
        --output-file scan_results.csv

    - curl -X POST https://your-threatvault-instance/api/upload
        -H "Authorization: Bearer $THREATVAULT_TOKEN"
        -F "file=@scan_results.csv"
  artifacts:
    paths:
      - scan_results.csv
    expire_in: 30 days
```

**Best Practices**:
- Use repository/project variables for `--name` flag
- Store credentials in CI/CD secrets
- Archive scan results as artifacts
- Run on specific branches to optimize resources

## Error Handling

### Supported Errors

| Error Type | Exception | Description |
|------------|-----------|-------------|
| Invalid file type | `ValueError` | File type is not CSV |
| Missing columns | `ColumnNotFoundError` | Required CSV column missing |
| Invalid risk values | N/A | Automatically filtered out |
| Empty CSV | N/A | Returns empty DataFrame with valid schema |

### Troubleshooting

**Issue**: No findings in output

**Solution**: Check CSV structure and risk values
```bash
# View risk column distribution
cut -d',' -f2 scan_results.csv | sort | uniq -c

# Validate CSV format
python3 -c "import polars as pl; print(pl.read_csv('scan_results.csv'))"
```

**Issue**: Line numbers showing as 0

**Cause**: Plugin Output field doesn't contain line information

**Solution**: This is expected when line numbers cannot be determined. File path information is still preserved in the evidence field.

**Issue**: CSV parsing errors

**Solution**: Check file encoding and structure
```bash
# Check file encoding
file -I scan_results.csv

# Validate CSV structure
head -5 scan_results.csv
```

## Data Validation

The plugin automatically:

1. ✓ Validates file type (CSV only)
2. ✓ Normalizes column names (lowercase, underscores)
3. ✓ Extracts line numbers from Plugin Output
4. ✓ Converts risk values to uppercase
5. ✓ Filters invalid risk levels
6. ✓ Replaces newlines with HTML breaks
7. ✓ Handles null/empty values appropriately
8. ✓ Returns empty DataFrame with correct schema if no valid findings

## Requirements

- Python 3.8 or higher
- Polars library: `pip install polars`

## Example Output

```
shape: (15, 9)
┌─────┬──────────┬────────────────┬──────┬─────────────────┬──────────────┬──────────────┬──────────────┬───────────┐
│ cve ┆ risk     ┆ host           ┆ port ┆ name            ┆ description  ┆ remediation  ┆ evidence     ┆ vpr_score │
├─────┼──────────┼────────────────┼──────┼─────────────────┼──────────────┼──────────────┼──────────────┼───────────┤
│     ┆ CRITICAL ┆ web-app        ┆ 42   ┆ SQL Injection   ┆ Detected...  ┆ Use param... ┆ File: src... ┆ 0         │
│     ┆ HIGH     ┆ web-app        ┆ 89   ┆ XSS             ┆ User input...┆ Sanitize...  ┆ File: src... ┆ 0         │
│     ┆ MEDIUM   ┆ web-app        ┆ 156  ┆ Weak Crypto     ┆ Insecure...  ┆ Use AES-256..┆ File: lib... ┆ 0         │
└─────┴──────────┴────────────────┴──────┴─────────────────┴──────────────┴──────────────┴──────────────┴───────────┘
```

## Security Considerations

When using ThreatCode:

- ✓ Store API credentials securely in environment variables or secrets managers
- ✓ Never commit API keys or tokens to version control
- ✓ Use role-based access control for scan results
- ✓ Sanitize code before sending to external LLM providers
- ✓ Consider self-hosted LLM models for highly sensitive codebases
- ✓ Implement proper access controls on scan results
- ✓ Regularly rotate API keys and credentials

## Performance

- **Processing Speed**: ~1000 findings per second
- **Memory Usage**: Efficient with Polars lazy evaluation
- **File Size**: Handles files up to 100MB
- **Scalability**: Tested with thousands of findings

## Version History

- **v1.0** (2025) - Initial release
  - CSV format support
  - Line number extraction from Plugin Output
  - VAPT schema compliance
  - HTML formatting for display
  - Risk value validation and filtering

## Contributing

To contribute improvements to this plugin:

1. Follow the plugin creation guidelines in the main repository
2. Ensure all tests pass with sample ThreatCode outputs
3. Update documentation for any new features
4. Submit a pull request with clear description of changes

## Support

For issues or questions:

- **Plugin Issues**: Open an issue in the ThreatVault-Plugins repository
- **ThreatVault Platform**: Contact your ThreatVault administrator

## License

This plugin is part of the ThreatVault-Plugins project. Refer to the main repository LICENSE file for licensing information.

---

**Note**: This plugin requires ThreatCode CSV output as input. Ensure ThreatCode is properly configured and has generated scan results before using this plugin.
