# Semgrep SAST Plugin

This plugin transforms Semgrep JSON scan results into the standardized ThreatVault VAPT schema.

## Overview

Semgrep is a fast, open-source static analysis tool for finding bugs and enforcing code standards. This plugin processes JSON export files from Semgrep scans and converts them into ThreatVault's standardized vulnerability format.

## Plugin Information

- **Tool**: Semgrep (Open Source / Pro)
- **Category**: VAPT > SAST (Static Application Security Testing)
- **Input Format**: JSON (`.json`)
- **Output Schema**: ThreatVault VAPT Schema
- **Plugin Type**: DataFrame (immediate processing)

## Field Mappings

| ThreatVault Field | Semgrep Source | Mapping Details |
|------------------|----------------|-----------------|
| `cve` | N/A | Empty (Semgrep findings are not CVE-based) |
| `risk` | N/A | Fixed value: "MEDIUM" (all findings default to Medium) |
| `host` | N/A | Fixed value: "semgrep" (static analysis tool) |
| `port` | `start.line` | Starting line number where issue was found |
| `name` | `check_id` | Rule identifier (e.g., "python.lang.security.audit.exec-used") |
| `description` | `extra.message` | Issue description/message from the rule |
| `remediation` | `extra.fix` | Suggested fix or remediation guidance |
| `evidence` | `path`, `start.line`, `end.line` | Format: "Line {start} - {end} in file : {path}" |
| `vpr_score` | N/A | Empty (Semgrep doesn't provide VPR scores) |

## Supported File Types

The plugin accepts JSON files with the following MIME types:

- `json` - Simple JSON format identifier
- `application/json` - Standard JSON MIME type

## Usage

### Python Import

```python
from semgrep import process

# Read JSON file as bytes
with open('semgrep_results.json', 'rb') as f:
    file_bytes = f.read()

# Process the file
df = process(file_bytes, 'json')

# Use the DataFrame
print(df)
print(f"Total findings: {df.shape[0]}")
```

### Testing

Run the test script to verify the plugin works with your JSON file:

```bash
python test_semgrep.py /path/to/semgrep_results.json
```

Example using sample data:

```bash
python test_semgrep.py ../../../../Test/semgrep_sample.json
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
| `risk` | String | Always "MEDIUM" |
| `host` | String | Always "semgrep" |
| `port` | Int64 | Line number where issue starts |
| `name` | String | Rule/check identifier |
| `description` | String | Rule message with `<br/>` for line breaks |
| `remediation` | String | Suggested fix with `<br/>` for line breaks |
| `evidence` | String | File location info with `<br/>` for line breaks |
| `vpr_score` | String | Always empty |

## Data Processing

### Risk Level

All Semgrep findings are assigned a fixed risk level of **MEDIUM**. Semgrep doesn't provide severity ratings in its standard output, so this plugin uses a consistent Medium risk level for all findings.

**Note**: Consider triaging findings based on rule categories or implementing custom risk mapping based on `check_id` patterns if needed.

### Text Formatting

All text fields are processed for better display in ThreatVault:

- Newline characters (`\n`) → HTML line breaks (`<br/>`)
- Applied to: `description`, `remediation`, `evidence`

### Evidence Format

The evidence field combines location information in a readable format:

```
Line 42 - 45 in file : src/auth/login.py
```

This shows:
- **Start line**: Where the issue begins
- **End line**: Where the issue ends
- **File path**: Full path to the source file

### Data Validation

The plugin automatically:

1. ✓ Handles missing `results` array gracefully
2. ✓ Returns empty DataFrame with correct schema if no findings
3. ✓ Preserves all rule identifiers and messages
4. ✓ Extracts line numbers for issue location tracking

## Requirements

- Python 3.8 or higher
- Polars library: `pip install polars`

## Example Output

```
shape: (12, 9)
┌─────┬────────┬─────────┬──────┬──────────────────────────┬──────────────┬──────────────┬──────────────┬───────────┐
│ cve ┆ risk   ┆ host    ┆ port ┆ name                     ┆ description  ┆ remediation  ┆ evidence     ┆ vpr_score │
├─────┼────────┼─────────┼──────┼──────────────────────────┼──────────────┼──────────────┼──────────────┼───────────┤
│     ┆ MEDIUM ┆ semgrep ┆ 42   ┆ python.lang.security.... ┆ Detected u...┆ Use paramet...┆ Line 42 - 45...│           │
│     ┆ MEDIUM ┆ semgrep ┆ 89   ┆ python.flask.security... ┆ Flask appl...┆ Ensure that...┆ Line 89 - 92...│           │
│     ┆ MEDIUM ┆ semgrep ┆ 156  ┆ python.crypto.insecure...┆ Weak crypt...┆ Use SHA-256...┆ Line 156 - ...│           │
└─────┴────────┴─────────┴──────┴──────────────────────────┴──────────────┴──────────────┴──────────────┴───────────┘
```

## Generating Semgrep JSON Output

To generate the JSON file that this plugin can process:

### Quick Start

Run Semgrep scan with auto-configuration and output JSON:

```bash
# Scan current directory with auto-config
semgrep scan --config auto --json ./ -o semgrep-results.json

# Scan specific directory
semgrep scan --config auto --json /path/to/code -o semgrep-results.json
```

**Upload to ThreatVault**:
- **Manual**: Upload `semgrep-results.json` through ThreatVault web interface
- **API**: Use ThreatVault API to programmatically upload scan results

### Command Line Options

```bash
# Scan with auto-configuration (recommended)
semgrep scan --config auto --json ./ -o semgrep-results.json

# Scan with specific rulesets
semgrep --config=p/security-audit --json > results.json /path/to/code

# Scan with custom rules
semgrep --config=/path/to/rules.yaml --json > results.json /path/to/code

# Scan with multiple rule sources
semgrep --config auto --config p/owasp-top-ten --json -o results.json .
```

### Semgrep CI/CD

```bash
# Use in CI/CD pipeline
semgrep ci --json > semgrep_results.json

# CI with auto-configuration
semgrep ci --config auto --json -o semgrep_results.json
```

### Semgrep App/Cloud

1. Run scan through Semgrep App
2. Navigate to findings page
3. Export results as JSON
4. Upload JSON file to ThreatVault (manually or via API)

## Expected JSON Structure

The plugin expects Semgrep JSON output with a `results` array:

```json
{
  "results": [
    {
      "check_id": "python.lang.security.audit.exec-used",
      "path": "src/utils.py",
      "start": {
        "line": 42,
        "col": 5
      },
      "end": {
        "line": 45,
        "col": 10
      },
      "extra": {
        "message": "Detected use of exec(). This is dangerous...",
        "fix": "Use safer alternatives like importlib..."
      }
    }
  ]
}
```

## Error Handling

The plugin will raise exceptions for:

- **Invalid file type**: If the MIME type is not JSON
  ```
  ValueError: Unsupported file type: text/csv. Expected JSON.
  ```

- **Malformed JSON**: If the JSON structure is invalid
  ```
  json.JSONDecodeError: Expecting value: line 1 column 1 (char 0)
  ```

- **Empty results**: Returns empty DataFrame with correct schema (not an error)

## Implementation Details

### Processing Flow

```
1. Validate file type (JSON)
2. Parse JSON data
3. Extract 'results' array
4. For each result:
   - Extract check_id, path, start/end lines
   - Extract message and fix from 'extra' object
   - Build evidence string with location info
5. Create Polars DataFrame
6. Transform text (newlines → <br/>)
7. Return DataFrame
```

### Performance

- **Lazy Evaluation**: No (uses DataFrame for JSON parsing)
- **Memory Usage**: Loads full JSON into memory
- **Processing Speed**: ~1000 findings in < 1 second
- **Large Files**: Handles large codebases efficiently

## Limitations

- **Fixed risk level**: All findings are Medium risk (no severity differentiation)
- **No CVE mapping**: Static analysis findings don't map to CVEs
- **No VPR scores**: Semgrep doesn't provide vulnerability priority ratings
- **Port field**: Uses line numbers instead of network ports (not applicable for SAST)
- **Host field**: Generic "semgrep" value (not a real host for static analysis)
- **No confidence level**: Semgrep confidence/severity metadata is not currently mapped

## Future Enhancements

Consider these potential improvements:

1. **Dynamic risk mapping**: Map rule categories or metadata to different risk levels
2. **Rule filtering**: Allow filtering by rule severity or categories
3. **Custom metadata**: Extract additional Semgrep metadata fields
4. **SARIF support**: Add support for SARIF format output

## Troubleshooting

### Issue: "Unsupported file type: application/json"

**Solution**: Ensure you're passing the correct MIME type:
```python
df = process(file_bytes, 'json')  # Use 'json' not 'application/json'
```

### Issue: No findings in output

**Cause**: The `results` array may be empty in the JSON file

**Solution**: Check the JSON structure:
```bash
cat semgrep_results.json | python -m json.tool | head -20
```

### Issue: Missing remediation text

**Cause**: Some Semgrep rules don't include fix suggestions

**Solution**: This is expected behavior. The `remediation` field will be empty for rules without fixes.

## Version History

- **v1.0** (2025) - Initial release
  - Support for Semgrep JSON exports
  - Field mapping to ThreatVault VAPT schema
  - Text formatting for HTML display
  - Empty result handling

## See Also

- [ThreatVault Plugin Creation Guide](../../../../PLUGIN_CREATION_GUIDE.md)
- [Blueprint Documentation](../../../../blueprint.txt)
- [Semgrep Documentation](https://semgrep.dev/docs/)
- [Trivy Plugin](../../VA/Trivy/trivy.py) - Similar JSON processing pattern
- [BurpSuite Plugin](../../DAST/BurpSuite/burpsuite.py) - Similar VAPT schema
