"""
ThreatVault Plugin for TruffleHog JSON Results

This plugin converts TruffleHog JSON scan results to ThreatVault VAPT format.
TruffleHog is a secrets scanning tool that finds and verifies leaked credentials
in git repositories, filesystems, and other sources.

GitHub: https://github.com/trufflesecurity/trufflehog
"""

import json
import polars as pl


def process(file: bytes, file_type: str) -> pl.DataFrame:
    """
    Process TruffleHog JSON results and convert to ThreatVault format.

    Args:
        file: The uploaded file content as bytes
        file_type: MIME type of the uploaded file (expected: "application/json" or "json")

    Returns:
        pl.DataFrame: DataFrame with ThreatVault schema fields:
            - cve: CVE identifier (N/A for secrets scanning)
            - risk: Severity level (all set to CRITICAL)
            - host: Repository URL or link (GitHub URL for GitHub sources, repository for Git sources)
            - port: Line number where secret was found
            - name: Detector name (e.g., "AWS", "GitHub Token")
            - description: Description based on detector and verification status
            - remediation: Generic secrets remediation advice
            - evidence: Location information with line, commit, file path, and secret value (formatted with <br/>)
            - vpr_score: VPR score (0 for SAST)

    Raises:
        ValueError: If file_type is not JSON
    """
    # Validate file type
    if file_type not in ["application/json", "json"]:
        raise ValueError(f"Unsupported file type: {file_type}. Expected JSON.")

    # Parse JSON data - TruffleHog outputs newline-delimited JSON
    content = file.decode('utf-8').strip()

    # Handle both single JSON object and newline-delimited JSON
    results = []
    if content.startswith('['):
        # Standard JSON array
        results = json.loads(content)
    else:
        # Newline-delimited JSON (default TruffleHog output)
        for line in content.split('\n'):
            line = line.strip()
            if line:
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    # Prepare data for DataFrame
    records = []

    for result in results:
        # Skip non-finding entries (log messages, etc.)
        # Valid findings must have SourceMetadata and DetectorName
        if 'SourceMetadata' not in result or 'DetectorName' not in result:
            continue

        # Extract detector information
        detector_name = result.get('DetectorName', 'Unknown Detector')
        verified = result.get('Verified', False)
        raw_v2 = result.get('RawV2', b'')

        # Decode RawV2 if it's bytes
        if isinstance(raw_v2, bytes):
            try:
                raw_v2_str = raw_v2.decode('utf-8')
            except:
                raw_v2_str = str(raw_v2)
        else:
            raw_v2_str = str(raw_v2)

        # Extract source metadata
        source_metadata = result.get('SourceMetadata', {})
        source_data = source_metadata.get('Data', {})

        # Initialize location variables
        line_number = 0
        commit = ''
        file_path = ''
        host_value = ''

        # Handle different source types (Git, GitHub, Filesystem, S3, Docker)
        if 'Git' in source_data:
            git_data = source_data['Git']
            line_number = git_data.get('line', 0)
            commit = git_data.get('commit', '') or 'Not Available'
            file_path = git_data.get('link', '') or git_data.get('file', '')
            # Host: Use link if available, otherwise repository
            host_value = git_data.get('link', '') or git_data.get('repository', '')
        elif 'Github' in source_data:
            github_data = source_data['Github']
            line_number = github_data.get('line', 0)
            commit = github_data.get('commit', '') or 'Not Available'
            # Use 'link' field for affected file (this is the GitHub URL to the exact line)
            file_path = github_data.get('link', '') or github_data.get('file', '')
            # Host: Use link if available, otherwise repository
            host_value = github_data.get('link', '') or github_data.get('repository', '')
        elif 'Filesystem' in source_data:
            fs_data = source_data['Filesystem']
            line_number = fs_data.get('line', 0)
            file_path = fs_data.get('file', '')
            host_value = 'Filesystem'
            commit = 'Not Available'
        elif 'S3' in source_data:
            s3_data = source_data['S3']
            file_path = f"{s3_data.get('bucket', '')}/{s3_data.get('key', '')}"
            host_value = s3_data.get('bucket', 'S3')
            line_number = 0
            commit = 'Not Available'
        elif 'Docker' in source_data:
            docker_data = source_data['Docker']
            file_path = f"{docker_data.get('image', '')}/{docker_data.get('layer', '')}"
            host_value = docker_data.get('image', 'Docker')
            line_number = 0
            commit = 'Not Available'

        # Build name based on detector and verification status
        verification_status = "Verified" if verified else "Unverified"
        name = f"{detector_name} - {verification_status} Secret"

        # Build description
        description = (
            f"TruffleHog detected a {verification_status.lower()} {detector_name} secret. "
            f"{'This credential has been verified and is active.' if verified else 'This credential could not be verified.'}"
        )

        # Generic remediation for secrets
        remediation = (
            "1. Immediately rotate the exposed credential<br/>"
            "2. Review access logs for any unauthorized usage<br/>"
            "3. Remove the secret from version control history using tools like git-filter-repo or BFG Repo-Cleaner<br/>"
            "4. Implement proper secret management using tools like HashiCorp Vault, AWS Secrets Manager, or Azure Key Vault<br/>"
            "5. Enable secret scanning in your CI/CD pipeline to prevent future leaks"
        )

        # Build evidence string as per user requirements:
        # "Line: {Line number}<br/>Commit: {commit}<br/>Affected file: {file}<br/>Value: {RawV2}"
        evidence = (
            f"Line: {line_number}<br/>"
            f"Commit: {commit}<br/>"
            f"Affected file: {file_path}<br/>"
            f"Value: {raw_v2_str}"
        )

        # Create the record with user-specified mappings
        record = {
            'cve': 'N/A',                    # CVE not applicable for secrets
            'risk': 'CRITICAL',               # All secrets set to CRITICAL as per user requirement
            'host': host_value,               # Repository URL or link
            'port': line_number,              # Line number where secret was found
            'name': name,                     # Detector name with verification status
            'description': description,       # Built from detector info
            'remediation': remediation,       # Generic secret remediation
            'evidence': evidence,             # Line, commit, file, value with <br/> tags
            'vpr_score': '0'                  # VPR score not applicable for SAST
        }

        records.append(record)

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

    # Handle newline replacement in text fields for better HTML display
    df = df.with_columns([
        pl.col("description").str.replace_all("\n", "<br/>"),
        pl.col("remediation").str.replace_all("\n", "<br/>"),
        pl.col("evidence").str.replace_all("\n", "<br/>"),
    ])

    return df
