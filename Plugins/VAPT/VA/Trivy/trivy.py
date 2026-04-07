"""
ThreatVault Plugin for Trivy JSON Results

This plugin converts Trivy JSON scan results to ThreatVault VAPT format.
It supports three formats:
- GitLab Container Scanning format: {"vulnerabilities": [...]}
- Modern Trivy format: {"Results": [...]}
- CycloneDX SBOM format: {"bomFormat": "CycloneDX", "vulnerabilities": [...]}
"""

import json
import polars as pl


def process(file: bytes, file_type: str) -> pl.DataFrame:
    """
    Process Trivy JSON results and convert to ThreatVault format.

    Supports three input formats:
        - CycloneDX SBOM: {"bomFormat": "CycloneDX", "vulnerabilities": [...]}
        - GitLab Container Scanning: {"vulnerabilities": [...]}
        - Modern Trivy: {"Results": [...]}

    Args:
        file: The uploaded file content as bytes
        file_type: MIME type of the uploaded file (expected: "application/json" or "json")

    Returns:
        pl.DataFrame: DataFrame with ThreatVault schema fields:
            - cve: CVE identifier
            - risk: Severity level (CRITICAL, HIGH, MEDIUM, LOW)
            - host: Target/image name
            - port: Port number (0 for container scans)
            - name: Package name or CVE ID
            - description: Vulnerability description
            - remediation: Fixed version or solution
            - evidence: Installed version (format: "Installed version : $version")
            - vpr_score: VPR score (empty string)

    Raises:
        ValueError: If file_type is not JSON or format is unsupported
    """
    # Validate file type
    if file_type not in ["application/json", "json"]:
        raise ValueError(f"Unsupported file type: {file_type}. Expected JSON.")

    # Parse JSON data
    data = json.loads(file.decode('utf-8'))

    # Prepare data for DataFrame
    records = []

    # Check for CycloneDX format: {"bomFormat": "CycloneDX", "vulnerabilities": [...]}
    if data.get("bomFormat") == "CycloneDX":
        image = data.get("metadata", {}).get("component", {}).get("name", "")
        vulnerabilities = data.get("vulnerabilities", [])
        for vuln in vulnerabilities:
            records.append(_parse_cyclonedx_vulnerability(vuln, image))

    # Check for GitLab Container Scanning format: {"vulnerabilities": [...]}
    elif "vulnerabilities" in data:
        for vuln in data["vulnerabilities"]:
            records.append(_parse_legacy_vulnerability(vuln, data))

    # Check for modern format: {"Results": [...]}
    elif "Results" in data:
        for result in data["Results"]:
            target = result.get("Target", "")
            vulnerabilities = result.get("Vulnerabilities", [])

            # Handle null/None vulnerabilities
            if vulnerabilities is None:
                continue

            for vuln in vulnerabilities:
                records.append(_parse_modern_vulnerability(vuln, target))

    else:
        raise ValueError(
            "Unsupported Trivy JSON format. Expected 'vulnerabilities', 'Results', or CycloneDX format."
        )

    # Create Polars DataFrame
    if not records:
        # Return empty DataFrame with correct schema
        return pl.DataFrame(
            schema={
                'cve': pl.Utf8,
                'risk': pl.Utf8,
                'host': pl.Utf8,
                'port': pl.Int64,
                'name': pl.Utf8,
                'description': pl.Utf8,
                'remediation': pl.Utf8,
                'evidence': pl.Utf8,
                'vpr_score': pl.Utf8,
            }
        )

    df = pl.DataFrame(records)

    # Handle newline replacement in text fields for better display
    df = df.with_columns(
        [
            pl.col("description").str.replace_all("\n", "<br/>"),
            pl.col("remediation").str.replace_all("\n", "<br/>"),
        ]
    )

    # Normalize risk values to uppercase
    df = df.with_columns(
        pl.col("risk").str.to_uppercase()
    )

    # Filter out invalid risk values
    valid_risks = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    df = df.filter(pl.col("risk").is_in(valid_risks))

    # Filter out findings with no solution provided
    df = df.filter(pl.col("remediation") != "No fix available")

    return df


def _parse_legacy_vulnerability(vuln: dict, data: dict) -> dict:
    """
    Parse a vulnerability from legacy Trivy format.

    Args:
        vuln: Individual vulnerability record
        data: Full scan data (for extracting image/target info)

    Returns:
        dict: Parsed vulnerability record
    """
    # Extract CVE ID
    cve_id = vuln.get("VulnerabilityID") or vuln.get("id") or vuln.get("cve", "")

    # Extract severity
    severity = vuln.get("Severity") or vuln.get("severity", "")

    # Extract target/image name from location
    location = vuln.get("location", {})
    image = location.get("image", "")

    # Extract package name
    package_name = ""
    if "location" in vuln and "dependency" in vuln["location"]:
        package_name = vuln["location"]["dependency"].get("package", {}).get("name", "")

    # Fallback to other name fields
    name = package_name or vuln.get("PkgName") or vuln.get("name") or vuln.get("message", "") or cve_id

    # Extract description
    description = vuln.get("Description") or vuln.get("description", "")

    # Extract solution/remediation
    solution = vuln.get("FixedVersion") or vuln.get("solution", "")
    if not solution or solution == "No solution provided":
        solution = "No fix available"

    # Extract version for evidence
    version = ""
    if "location" in vuln and "dependency" in vuln["location"]:
        version = vuln["location"]["dependency"].get("version", "")
    evidence = f"Installed version : {version}" if version else ""

    return {
        'cve': cve_id,
        'risk': severity,
        'host': image,
        'port': 0,
        'name': name,
        'description': description,
        'remediation': solution,
        'evidence': evidence,
        'vpr_score': ''
    }


def _parse_modern_vulnerability(vuln: dict, target: str) -> dict:
    """
    Parse a vulnerability from modern Trivy format (Results array).

    Args:
        vuln: Individual vulnerability record
        target: Target name from parent Result

    Returns:
        dict: Parsed vulnerability record
    """
    # Extract CVE ID
    cve_id = vuln.get("VulnerabilityID", "")

    # Extract severity
    severity = vuln.get("Severity", "")

    # Extract package name
    package_name = vuln.get("PkgName", "")

    # Extract description
    description = vuln.get("Description", "")
    if not description:
        description = vuln.get("Title", "")

    # Extract solution/remediation
    fixed_version = vuln.get("FixedVersion", "")
    if fixed_version:
        solution = f"Upgrade to version {fixed_version}"
    else:
        solution = "No fix available"

    # Extract installed version for evidence
    installed_version = vuln.get("InstalledVersion", "")
    evidence = f"Installed version : {installed_version}" if installed_version else ""

    return {
        'cve': cve_id,
        'risk': severity,
        'host': target,
        'port': 0,
        'name': package_name,
        'description': description,
        'remediation': solution,
        'evidence': evidence,
        'vpr_score': ''
    }


def _parse_purl(purl: str) -> tuple[str, str]:
    """
    Parse a Package URL (purl) to extract package name and version.

    Args:
        purl: Package URL string (e.g., "pkg:deb/debian/linux-libc-dev@6.1.159-1?arch=amd64")

    Returns:
        tuple: (package_name, version)
    """
    # Remove query string
    if '?' in purl:
        purl = purl.split('?')[0]

    # Extract version after @
    version = ""
    if '@' in purl:
        purl, version = purl.rsplit('@', 1)
        # URL decode the version (e.g., %2B -> +)
        from urllib.parse import unquote
        version = unquote(version)

    # Extract package name (last component after /)
    package_name = purl.rsplit('/', 1)[-1] if '/' in purl else purl

    return package_name, version


def _parse_cyclonedx_vulnerability(vuln: dict, image: str) -> dict:
    """
    Parse a vulnerability from CycloneDX SBOM format.

    Args:
        vuln: Individual vulnerability record from CycloneDX
        image: Container image name from metadata

    Returns:
        dict: Parsed vulnerability record
    """
    # Extract CVE ID
    cve_id = vuln.get("id", "")

    # Extract severity from ratings (prefer NVD, then first available)
    severity = ""
    ratings = vuln.get("ratings", [])
    for rating in ratings:
        source_name = rating.get("source", {}).get("name", "").lower()
        if source_name == "nvd":
            severity = rating.get("severity", "")
            break
    if not severity and ratings:
        severity = ratings[0].get("severity", "")

    # Extract description
    description = vuln.get("description", "")

    # Extract package name and version from affects
    package_name = ""
    version = ""
    affects = vuln.get("affects", [])
    if affects:
        ref = affects[0].get("ref", "")
        if ref:
            package_name, version = _parse_purl(ref)
        # Also check versions array
        versions = affects[0].get("versions", [])
        if versions and not version:
            version = versions[0].get("version", "")

    # Build evidence
    evidence = f"Installed version : {version}" if version else ""

    # Remediation - extract only the relevant recommendation for this package
    solution = "No fix available"
    recommendation = vuln.get("recommendation", "")
    if recommendation and package_name:
        # Recommendation format: "Upgrade pkg1 to version X; Upgrade pkg2 to version Y"
        # Extract only the part matching this package
        for part in recommendation.split("; "):
            if package_name in part:
                solution = part.strip()
                break
        # Fallback to full recommendation if no match found
        if solution == "No fix available" and recommendation:
            solution = recommendation

    return {
        'cve': cve_id,
        'risk': severity,
        'host': image,
        'port': 0,
        'name': package_name or cve_id,
        'description': description,
        'remediation': solution,
        'evidence': evidence,
        'vpr_score': ''
    }
