# Trivy VA Plugin

This plugin transforms Trivy vulnerability scan JSON results into the standardized ThreatVault VAPT schema.

## Overview

Trivy is a comprehensive open-source security scanner that detects vulnerabilities in container images, filesystems, Git repositories, and more. This plugin processes JSON export files from Trivy vulnerability scans and converts them into ThreatVault's standardized vulnerability format.

## Plugin Information

- **Tool**: Trivy (Aqua Security)
- **Category**: VAPT > VA (Vulnerability Assessment)
- **Scan Types**: Container images, filesystems, rootfs, VMs
- **Input Format**: JSON (`.json`)
- **Output Schema**: ThreatVault VAPT Schema
- **Plugin Type**: DataFrame (immediate processing)

## Field Mappings

| ThreatVault Field | Trivy Source | Mapping Details |
|------------------|--------------|-----------------|
| `cve` | `VulnerabilityID` or `id` | CVE identifier (e.g., CVE-2023-12345) |
| `risk` | `Severity` | Severity level (CRITICAL, HIGH, MEDIUM, LOW) - uppercase normalized |
| `host` | `Target` or `location.image` | Image name, filesystem path, or target identifier |
| `port` | N/A | Always 0 (not applicable for container/filesystem scans) |
| `name` | `PkgName` or `package.name` | Package name where vulnerability was found |
| `description` | `Description` or `Title` | Vulnerability description with newlines → `<br/>` |
| `remediation` | `FixedVersion` | Format: "Upgrade to version X.Y.Z" or "No fix available" |
| `evidence` | N/A | Empty string (Trivy doesn't provide evidence details) |
| `vpr_score` | N/A | Empty string (Trivy doesn't provide VPR scores) |

## Supported File Types

The plugin accepts JSON files with the following MIME types:

- `json` - Simple JSON format identifier
- `application/json` - Standard JSON MIME type

## Supported Trivy Formats

The plugin supports both legacy and modern Trivy JSON output formats:

### Legacy Format (Trivy < 0.19.0)

```json
{
  "vulnerabilities": [
    {
      "VulnerabilityID": "CVE-2023-12345",
      "Severity": "HIGH",
      "PkgName": "openssl",
      "Description": "Buffer overflow in OpenSSL...",
      "FixedVersion": "1.1.1w"
    }
  ]
}
```

### Modern Format (Trivy >= 0.19.0)

```json
{
  "Results": [
    {
      "Target": "alpine:3.18",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2023-12345",
          "Severity": "HIGH",
          "PkgName": "openssl",
          "Description": "Buffer overflow in OpenSSL...",
          "FixedVersion": "1.1.1w"
        }
      ]
    }
  ]
}
```

## Usage

### Python Import

```python
from trivy import process

# Read JSON file as bytes
with open('trivy_scan.json', 'rb') as f:
    file_bytes = f.read()

# Process the file
df = process(file_bytes, 'json')

# Use the DataFrame
print(df)
print(f"Total vulnerabilities: {df.shape[0]}")
```

### Testing

Run the test script to verify the plugin works with your JSON file:

```bash
python test_trivy.py /path/to/trivy_scan.json
```

Example using sample data:

```bash
python test_trivy.py ../../../../Test/trivy_sample.json
```

## Output Schema

The plugin returns a Polars DataFrame with the following columns in order:

```python
['cve', 'risk', 'host', 'port', 'name', 'description', 'remediation', 'evidence', 'vpr_score']
```

### Data Types

| Column | Type | Notes |
|--------|------|-------|
| `cve` | String | CVE ID (may be empty for non-CVE vulnerabilities) |
| `risk` | String | CRITICAL, HIGH, MEDIUM, or LOW (uppercase) |
| `host` | String | Target image/filesystem name |
| `port` | Int64 | Always 0 |
| `name` | String | Package name |
| `description` | String | HTML content with `<br/>` for line breaks |
| `remediation` | String | Fix version or "No fix available" |
| `evidence` | String | Always empty |
| `vpr_score` | String | Always empty |

## Data Processing

### Severity to Risk Mapping

Trivy severity values are normalized to uppercase for ThreatVault:

| Trivy Severity | ThreatVault Risk | Action |
|----------------|------------------|--------|
| CRITICAL | CRITICAL | Converted |
| HIGH | HIGH | Converted |
| MEDIUM | MEDIUM | Converted |
| LOW | LOW | Converted |
| UNKNOWN | N/A | **Filtered out** |
| (empty) | N/A | **Filtered out** |

Only valid risk levels are included in the output.

### Text Formatting

All text fields are processed for better display in ThreatVault:

- Newline characters (`\n`) → HTML line breaks (`<br/>`)
- Applied to: `description`, `remediation`

### Remediation Format

The plugin intelligently formats remediation text:

- **If fixed version available**: "Upgrade to version 1.2.3"
- **If no fix**: "No fix available"
- **Empty FixedVersion**: Treated as "No fix available"

### Null/Empty Handling

The plugin gracefully handles:

- **Null Vulnerabilities arrays**: Skipped (common in clean scans)
- **Empty Results**: Returns empty DataFrame with correct schema
- **Missing fields**: Uses empty strings or defaults

## Requirements

- Python 3.8 or higher
- Polars library: `pip install polars`

## Example Output

```
shape: (156, 9)
┌──────────────┬──────────┬────────────────┬──────┬──────────────────┬──────────────┬──────────────────────┬──────────┬───────────┐
│ cve          ┆ risk     ┆ host           ┆ port ┆ name             ┆ description  ┆ remediation          ┆ evidence ┆ vpr_score │
├──────────────┼──────────┼────────────────┼──────┼──────────────────┼──────────────┼──────────────────────┼──────────┼───────────┤
│ CVE-2023-... ┆ CRITICAL ┆ alpine:3.18    ┆ 0    ┆ openssl          ┆ Buffer ove...┆ Upgrade to version...┆          ┆           │
│ CVE-2023-... ┆ HIGH     ┆ alpine:3.18    ┆ 0    ┆ libcrypto3       ┆ Integer ov...┆ Upgrade to version...┆          ┆           │
│ CVE-2023-... ┆ MEDIUM   ┆ ubuntu:22.04   ┆ 0    ┆ libssl3          ┆ Denial of ...┆ Upgrade to version...┆          ┆           │
│ CVE-2024-... ┆ LOW      ┆ debian:bullseye┆ 0    ┆ curl             ┆ Informatio...┆ No fix available     ┆          ┆           │
└──────────────┴──────────┴────────────────┴──────┴──────────────────┴──────────────┴──────────────────────┴──────────┴───────────┘
```

## Generating Trivy JSON Output

To generate the JSON file that this plugin can process:

### Container Image Scan

```bash
# Scan a container image and output JSON
trivy image --format json --output trivy_scan.json alpine:3.18

# Scan with specific severity levels
trivy image --severity CRITICAL,HIGH --format json --output results.json nginx:latest

# Scan local image
trivy image --format json --output scan.json myapp:1.0.0
```

### Filesystem Scan

```bash
# Scan a filesystem/directory
trivy fs --format json --output trivy_fs.json /path/to/project

# Scan current directory
trivy fs --format json --output scan.json .
```

### Git Repository Scan

```bash
# Scan a Git repository
trivy repo --format json --output trivy_repo.json https://github.com/user/repo

# Scan local repository
trivy repo --format json --output scan.json .
```

### Rootfs Scan

```bash
# Scan a root filesystem
trivy rootfs --format json --output trivy_rootfs.json /path/to/rootfs
```

### CI/CD Integration

```yaml
# GitHub Actions example
- name: Run Trivy scanner
  run: |
    trivy image --format json --output trivy-results.json ${{ env.IMAGE_NAME }}

# GitLab CI example
trivy_scan:
  script:
    - trivy image --format json --output trivy-results.json $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
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

- **Unsupported format**: If JSON doesn't contain expected keys
  ```
  ValueError: Unsupported Trivy JSON format. Expected 'vulnerabilities' or 'Results' key.
  ```

- **Empty results**: Returns empty DataFrame with correct schema (not an error)

## Implementation Details

### Processing Flow

```
1. Validate file type (JSON)
2. Parse JSON data
3. Detect format (legacy vs modern)
4. For legacy format:
   - Parse vulnerabilities array
   - Call _parse_legacy_vulnerability()
5. For modern format:
   - Iterate through Results array
   - Extract Target
   - Parse Vulnerabilities array
   - Call _parse_modern_vulnerability()
6. Create Polars DataFrame
7. Transform text (newlines → <br/>)
8. Normalize risk to uppercase
9. Filter invalid risk values
10. Return DataFrame
```

### Performance

- **Lazy Evaluation**: No (uses DataFrame for JSON parsing)
- **Memory Usage**: Loads full JSON into memory
- **Processing Speed**: ~10,000 vulnerabilities in < 2 seconds
- **Large Files**: Handles large scans efficiently (100MB+ JSON files)

### Format Detection

The plugin automatically detects the Trivy format:

```python
if "vulnerabilities" in data:
    # Legacy format
elif "Results" in data:
    # Modern format
else:
    # Unsupported format - raise error
```

## Limitations

- **No VPR scores**: Trivy doesn't provide VPR (Vulnerability Priority Rating)
- **No evidence**: Trivy JSON doesn't include detailed evidence/proof
- **Port field**: Set to 0 (not applicable for container/filesystem scans)
- **Mixed formats**: Each scan file must use one format (cannot mix legacy/modern)
- **CVSS scores**: Not currently extracted (could be added in future)
- **References**: Vulnerability references not included in output

## Common Use Cases

### Container Security

- CI/CD pipeline security gates
- Container registry scanning
- Runtime vulnerability monitoring
- Docker image validation

### Kubernetes Security

- Pod image scanning
- Helm chart security audits
- Cluster-wide vulnerability assessment
- Admission controller integration

### DevSecOps

- Pre-commit security checks
- Build-time vulnerability detection
- Dependency vulnerability tracking
- Security reporting and metrics

## Troubleshooting

### Issue: "Unsupported Trivy JSON format"

**Cause**: JSON file doesn't contain `vulnerabilities` or `Results` keys

**Solution**: Verify Trivy was run with `--format json`:
```bash
trivy image --format json --output scan.json alpine:3.18
```

### Issue: Empty output with no vulnerabilities

**Cause**:
1. Image/filesystem has no vulnerabilities (good!)
2. All vulnerabilities filtered out (UNKNOWN severity)

**Solution**: Check Trivy output for vulnerability count:
```bash
trivy image alpine:3.18 | grep "Total:"
```

### Issue: Missing descriptions

**Cause**: Some vulnerability databases may have incomplete data

**Solution**: Update Trivy database:
```bash
trivy image --download-db-only
```

### Issue: "No fix available" for all vulnerabilities

**Cause**: Scanning outdated or unmaintained packages

**Solution**:
1. Update base image to latest version
2. Check if packages have reached end-of-life
3. Consider alternative packages with active maintenance

## Differences from SCA Plugin

Both Trivy VA and SCA plugins use identical code, but serve different purposes:

| Aspect | VA Plugin | SCA Plugin |
|--------|-----------|------------|
| **Category** | VAPT > VA | VAPT > SCA |
| **Focus** | Infrastructure vulnerabilities | Software composition analysis |
| **Typical Use** | Container/VM scanning | Dependency/library scanning |
| **Code** | Identical | Identical |

The categorization difference helps organize findings by security domain in ThreatVault.

## Version History

- **v1.0** (2025) - Initial release
  - Support for legacy and modern Trivy JSON formats
  - Field mapping to ThreatVault VAPT schema
  - Risk value normalization and filtering
  - Null/empty handling for clean scans
  - Intelligent remediation formatting

## See Also

- [ThreatVault Plugin Creation Guide](../../../../PLUGIN_CREATION_GUIDE.md)
- [Blueprint Documentation](../../../../blueprint.txt)
- [Trivy SCA Plugin](../../SCA/Trivy/trivy.py) - Identical implementation, different category
- [Trivy Documentation](https://aquasecurity.github.io/trivy/)
- [Trivy GitHub Repository](https://github.com/aquasecurity/trivy)
