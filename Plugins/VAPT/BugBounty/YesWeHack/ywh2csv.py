#!/usr/bin/env python3
"""
YesWeHack to CSV Exporter
Extracts bug bounty reports from YesWeHack API and exports to ThreatVault format
"""

import requests
import csv
import argparse
import logging
import sys
import os
from typing import List, Dict, Optional, Any

# Try to import dotenv, but make it optional
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    # dotenv not installed, environment variables must be set manually
    pass

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# API Configuration
BASE_URL = 'https://api.yeswehack.com'
API_KEY = os.getenv('YWH_API_KEY')

# Criticality mapping
CRITICALITY_MAP = {
    'critical': 'CRITICAL',
    'c': 'CRITICAL',
    'high': 'HIGH',
    'h': 'HIGH',
    'medium': 'MEDIUM',
    'm': 'MEDIUM',
    'low': 'LOW',
    'l': 'LOW'
}

# CSV Headers for ThreatVault format
CSV_HEADERS = [
    'CVE',
    'Risk',
    'Host',
    'Port',
    'Name',
    'Description',
    'Solution',
    'Plugin Output',
    'VPR Score'
]


def get_headers() -> Dict[str, str]:
    """Generate API request headers with authentication"""
    return {
        'X-AUTH-TOKEN': API_KEY,
        'Accept': 'application/json'
    }


def make_api_request(endpoint: str, method: str = 'GET', data: Optional[Dict] = None) -> Optional[Dict]:
    """
    Make API request to YesWeHack with error handling

    Args:
        endpoint: API endpoint path
        method: HTTP method (GET, POST, etc.)
        data: Optional JSON data for POST requests

    Returns:
        JSON response dict or None on failure
    """
    url = f"{BASE_URL}{endpoint}"
    headers = get_headers()

    try:
        if method == 'GET':
            response = requests.get(url, headers=headers, verify=True, timeout=30)
        elif method == 'POST':
            response = requests.post(url, headers=headers, json=data, verify=True, timeout=30)
        else:
            logger.error(f"Unsupported HTTP method: {method}")
            return None

        response.raise_for_status()
        return response.json()

    except requests.exceptions.HTTPError as http_err:
        logger.error(f'HTTP error occurred for {endpoint}: {http_err}')
        if hasattr(http_err.response, 'text'):
            logger.error(f'Response: {http_err.response.text}')
    except requests.exceptions.ConnectionError:
        logger.error(f'Connection error occurred for {endpoint}')
    except requests.exceptions.Timeout:
        logger.error(f'Request timeout for {endpoint}')
    except requests.exceptions.RequestException as err:
        logger.error(f'Request error occurred: {err}')
    except Exception as err:
        logger.error(f'Unexpected error: {err}')

    return None


def get_business_units() -> Optional[List[Dict]]:
    """Get all business units"""
    logger.info("Fetching business units...")
    response = make_api_request('/business-units')
    if response:
        return response.get('items', [])
    return None


def get_business_unit_programs(business_unit_slug: str) -> Optional[List[Dict]]:
    """Get all programs for a business unit"""
    logger.info(f"Fetching programs for business unit: {business_unit_slug}")

    # First get all business units to find the ID
    business_units = get_business_units()
    if not business_units:
        return None

    # Find the business unit by slug
    business_unit = next((bu for bu in business_units if bu.get('slug') == business_unit_slug), None)
    if not business_unit:
        logger.error(f"Business unit '{business_unit_slug}' not found")
        return None

    # Get programs from the business unit
    return business_unit.get('programs', [])


def get_program_reports(program_slug: str, limit: int = 100) -> Optional[List[Dict]]:
    """
    Get all reports for a program with pagination support

    Args:
        program_slug: Program slug identifier
        limit: Number of reports per page

    Returns:
        List of all reports or None on failure
    """
    logger.info(f"Fetching reports for program: {program_slug}")
    all_reports = []
    offset = 0

    while True:
        endpoint = f'/programs/{program_slug}/reports?limit={limit}&offset={offset}'
        response = make_api_request(endpoint)

        if not response:
            if offset == 0:
                return None
            break

        items = response.get('items', [])
        if not items:
            break

        all_reports.extend(items)
        logger.info(f"Retrieved {len(items)} reports (total: {len(all_reports)})")

        # Check if there are more pages
        pagination = response.get('pagination', {})
        total = pagination.get('total', 0)

        if len(all_reports) >= total:
            break

        offset += limit

    logger.info(f"Total reports retrieved for {program_slug}: {len(all_reports)}")
    return all_reports if all_reports else None


def get_report_details(report_id: str) -> Optional[Dict]:
    """
    Get detailed information for a specific report

    Args:
        report_id: Report ID (local_id or full ID)

    Returns:
        Full report details with description_html or None on failure
    """
    logger.debug(f"Fetching details for report: {report_id}")
    return make_api_request(f'/reports/{report_id}')


def get_program_info(program_slug: str) -> Optional[Dict]:
    """Get program information"""
    logger.info(f"Fetching program info: {program_slug}")
    return make_api_request(f'/programs/{program_slug}')


def convert_criticality(ywh_criticality: str) -> Optional[str]:
    """
    Convert YesWeHack criticality to ThreatVault risk level

    Args:
        ywh_criticality: YesWeHack criticality (c, h, m, l, i, etc.)

    Returns:
        ThreatVault risk level (CRITICAL, HIGH, MEDIUM, LOW) or None if invalid
    """
    if not ywh_criticality:
        return None

    criticality_lower = str(ywh_criticality).lower().strip()
    mapped = CRITICALITY_MAP.get(criticality_lower)

    if not mapped:
        logger.warning(f"Unknown criticality '{ywh_criticality}' - skipping")

    return mapped


def clean_scope(scope: str) -> str:
    """
    Clean scope URL to extract hostname for Host field

    Args:
        scope: Raw scope URL (e.g., "https://app.example.com/" or "https:\\/\\/app.example.com\\/")

    Returns:
        Cleaned hostname (e.g., "app.example.com")

    Examples:
        "https://app.example.com/" -> "app.example.com"
        "https:\\/\\/app.example.com\\/" -> "app.example.com"
        "http://example.com/path" -> "example.com"
        "https://sub.domain.com:8080/" -> "sub.domain.com"
    """
    if not scope:
        return ""

    # Convert to string and strip whitespace
    cleaned = str(scope).strip()

    # First, remove escaped slashes (\/) and replace with forward slashes
    cleaned = cleaned.replace('\\/', '/')

    # Remove protocol (http://, https://)
    cleaned = cleaned.replace('https://', '').replace('http://', '')

    # Split by '/' and take only the first part (hostname)
    if '/' in cleaned:
        cleaned = cleaned.split('/')[0]

    # Remove port number if present (e.g., :8080)
    if ':' in cleaned:
        cleaned = cleaned.split(':')[0]

    # Remove any remaining special characters except dots and hyphens
    # Keep only alphanumeric, dots, and hyphens
    import re
    cleaned = re.sub(r'[^a-zA-Z0-9.\-]', '', cleaned)

    return cleaned


def _format_table_for_pre(rows: List[List[str]]) -> str:
    """
    Format rows as a text table wrapped in <pre> tags.

    Each row is joined with ' | ' (pipe-space-pipe).
    No column-width alignment — ThreatVault collapses multi-space padding
    during CSV import anyway.

    Args:
        rows: List of rows, each row a list of cell strings (header row first).

    Returns:
        Text table inside <pre>...</pre>.
    """
    if not rows:
        return "<pre>\n</pre>"

    lines = []
    for row_idx, row in enumerate(rows):
        lines.append(" | ".join(row))
        if row_idx == 0:
            lines.append("")

    return "<pre>\n" + "\n".join(lines) + "\n</pre>"


def _convert_tables_to_pre(text: str) -> str:
    """
    Convert HTML tables to pre-formatted text blocks.

    ThreatVault bleach filter does NOT include table tags (<table>, <tr>, <td>, etc.)
    so they get stripped entirely. Instead of losing table structure, convert each row
    to a pipe-delimited line inside a <pre> block with proper column alignment.

    Args:
        text: HTML text potentially containing tables

    Returns:
        HTML with tables converted to <pre> blocks
    """
    import re

    def convert_table(m):
        """Callback to convert a single table HTML block to a pre-formatted text block."""
        table_html = m.group(0)

        # Remove all <br/> tags — they are just visual spacers in YesWeHack HTML
        # and they cause the header cell pattern to incorrectly span across tags.
        table_html = re.sub(r'<br\s*/?>', '', table_html)

        # Extract header cells using negative lookahead to prevent matching
        # 'th' inside tag names like <thead> or </thead>.
        header_cells = re.findall(r'<th(?![a-z/])([^>]*)>(.*?)</th>', table_html, re.DOTALL | re.IGNORECASE)
        clean_headers = []
        for attrs, content in header_cells:
            clean = re.sub(r'<[^>]+>', '', content, flags=re.DOTALL).strip()
            if clean:
                clean_headers.append(clean)

        # Extract all table rows
        rows = re.findall(r'<tr[^>]*>(.*?)</tr>', table_html, re.DOTALL | re.IGNORECASE)

        data_rows = []
        for row_content in rows:
            cells = re.findall(r'<td(?![a-z/])([^>]*)>(.*?)</td>', row_content, re.DOTALL | re.IGNORECASE)
            if cells:
                clean_cells = []
                for attrs, content in cells:
                    clean = re.sub(r'<[^>]+>', '', content, flags=re.DOTALL).strip()
                    if clean:
                        clean_cells.append(clean)
                if clean_cells:
                    data_rows.append(clean_cells)

        all_rows = [clean_headers] + data_rows if clean_headers else data_rows
        if not all_rows:
            return ''

        return _format_table_for_pre(all_rows)

    # Match full <table>...</table> blocks and replace with pre blocks.
    return re.sub(r'<table[^>]*>.*?</table>', convert_table, text, flags=re.DOTALL | re.IGNORECASE)


def _normalize_block_html(text: str) -> str:
    """
    Normalize HTML by removing newlines between block-level tags.

    YesWeHack HTML has \\n between every tag. Without cleanup, these become
    <br/> creating excessive spacing. This removes newlines that are purely
    structural (between block tags) while preserving meaningful whitespace.

    IMPORTANT: This function must NOT convert \\n to <br/> inside <pre> blocks,
    because _convert_tables_to_pre generates <pre> blocks with intentional \\n.

    Args:
        text: HTML text with potentially excessive newlines between tags

    Returns:
        HTML with normalized whitespace between block-level tags
    """
    import re

    # Split by <pre>...</pre> blocks and process non-pre parts separately
    parts = re.split(r'(<pre>.*?</pre>)', text, flags=re.DOTALL)
    result_parts = []

    for part in parts:
        if part.startswith('<pre>') and part.endswith('</pre>'):
            result_parts.append(part)
        else:
            for tag in ['</p>', '<p>', '</li>', '<li>', '</ol>', '<ol>', '</ul>', '<ul>',
                        '</h1>', '</h2>', '</h3>', '</h4>', '<h1>', '<h3>', '<h4>',
                        '</blockquote>', '<blockquote>', '</code>']:
                part = part.replace(f'\n{tag}', tag)
                part = part.replace(f'{tag}\n', tag)

            part = re.sub(r'\n{3,}', '\n\n', part)
            part = part.replace('\n', '<br/>')
            part = re.sub(r'(<br/>)+', '<br/>', part)
            part = re.sub(r'^<br/>', '', part)

            result_parts.append(part)

    text = ''.join(result_parts)
    text = text.strip()

    return text


def format_description(description: str) -> str:
    """
    Format description for CSV export.

    YesWeHack HTML has issues that cause visual problems after ThreatVault's
    bleach/safe_html_with_br filter:
    1. Tables (<table>, <tr>, <td>) are NOT in SAFE_TAGS — stripped entirely
    2. h2 and h3 are NOT in SAFE_TAGS — stripped, losing heading semantics
    3. Newlines between every tag create excessive <br/> after \\n→<br/> conversion

    This function:
    - Converts HTML tables to <pre> blocks with pipe-delimited columns
    - Replaces <h2> and <h3> with <p><strong> (both in SAFE_TAGS)
    - Removes newlines between block-level tags before <br/> conversion

    Args:
        description: Raw description text (HTML from YesWeHack)

    Returns:
        Formatted description safe for ThreatVault rendering
    """
    if not description:
        return ""

    text = str(description)

    # Convert HTML tables to pre-formatted blocks (bleach strips table tags)
    text = _convert_tables_to_pre(text)

    # Replace <h2> and <h3> with <p><strong> (both bleach-safe)
    # Use (.*?) with re.DOTALL to handle h2/h3 with nested HTML tags (e.g., <h3>text <code>code</code> text</h3>)
    import re
    text = re.sub(
        r'<h2>(.*?)</h2>',
        lambda m: f'<p><strong>{re.sub(r"<[^>]+>", "", m.group(1)).strip()}</strong></p>',
        text, flags=re.DOTALL
    )
    text = re.sub(
        r'<h3>(.*?)</h3>',
        lambda m: f'<p><strong>{re.sub(r"<[^>]+>", "", m.group(1)).strip()}</strong></p>',
        text, flags=re.DOTALL
    )

    # Normalize block-level tag whitespace and convert newlines
    text = _normalize_block_html(text)

    return text


def should_include_report(report: Dict) -> bool:
    """
    Check if report should be included based on workflow state and fix verification status

    IMPORTANT: This function requires data from /reports/{id} endpoint.
    The workflow_state and ask_for_fix_verification_status fields are NOT
    available in the /programs/{slug}/reports list endpoint.

    Args:
        report: YesWeHack report dict from /reports/{id} endpoint

    Returns:
        True if report should be included, False otherwise
    """
    # Get workflow_state (can be nested or at root level)
    # This field is only available from /reports/{id} endpoint
    workflow_state = report.get('workflow_state', '')

    # Try nested paths if not found at root
    if not workflow_state:
        # Try status.workflow_state (common structure)
        status = report.get('status', {})
        if isinstance(status, dict):
            workflow_state = status.get('workflow_state', '')

    if not workflow_state:
        # Try workflow.state (alternative structure)
        workflow = report.get('workflow', {})
        if isinstance(workflow, dict):
            workflow_state = workflow.get('state', '')

    # Get ask_for_fix_verification_status
    # This field is only available from /reports/{id} endpoint
    fix_verification_status = report.get('ask_for_fix_verification_status', '')

    # Check if workflow_state is "accepted" (case-insensitive)
    is_accepted = str(workflow_state).lower() == 'accepted'

    # Check if fix_verification_status is "PENDING" (case-sensitive)
    is_pending = str(fix_verification_status) == 'PENDING'

    # Include only if BOTH conditions are met
    if is_accepted and is_pending:
        return True
    else:
        logger.debug(
            f"Skipping report {report.get('local_id', 'unknown')} - "
            f"workflow_state={workflow_state}, fix_verification_status={fix_verification_status}"
        )
        return False


def extract_remediation(description_html: str, suggestions: Any, bug_type: Dict) -> str:
    """
    Extract per-report remediation from <h2>Remediation</h2> section in description.

    Only looks for the Remediation h2 section. Does NOT use suggestions or bug_type
    fallbacks as these provide generic/repeated information rather than per-report fixes.
    """
    import re

    # Try to extract <h2>...Remediation...</h2> section from description_html
    # Handles multilingual: English (Remediation) and French (Remédiation, Remèdiation)
    if description_html:
        pattern = r'<h2>[^<]*[Rr]em[eéè]d[iI]ation[^<]*</h2>(.*?)(?=<h2|$)'
        match = re.search(pattern, description_html, re.DOTALL | re.IGNORECASE)
        if match:
            remediation_html = match.group(1).strip()
            if remediation_html:
                return _normalize_block_html(remediation_html)

    # No Remediation h2 section found — return hardcoded message
    return 'No Remediation Provided by Hunter.'


def _build_report_metadata(source: Dict, program_slug: str = '') -> str:
    """
    Build a metadata block with Report ID, Report URL, and CVSS from YesWeHack report data.

    Args:
        source: YesWeHack report dict (from detailed or summary)
        program_slug: Program slug for constructing report URL if not provided in source

    Returns:
        HTML string with metadata fields, or empty string if no metadata available
    """
    parts = []

    # Report ID
    local_id = source.get('local_id', '')
    if local_id:
        parts.append(f'<p><strong>Report ID:</strong> {local_id}</p>')

    # Report URL — try direct field first, then construct from program slug
    # Priority: href > url > _program_slug + numeric id (NOT local_id)
    pg_slug = source.get('_program_slug') or program_slug or ''
    numeric_id = source.get('id', '')  # numeric YesWeHack id, e.g. '755474'
    report_url = ''
    if source.get('href'):
        report_url = source.get('href')
    elif source.get('url'):
        report_url = source.get('url')
    elif numeric_id:
        # YesWeHack uses vulnerability-center, not programs/{slug}
        report_url = f'https://yeswehack.com/vulnerability-center/reports/{numeric_id}'
    if report_url:
        if source.get('href'):
            parts.append(f'<p><strong>Report URL:</strong> <a href="{report_url}">{report_url}</a></p>')
        else:
            parts.append(f'<p><strong>Report URL:</strong> {report_url}</p>')

    # CVSS score and vector
    cvss = source.get('cvss', {})
    if isinstance(cvss, dict) and cvss:
        cvss_parts = []
        # Numeric score (e.g., 9.8)
        score = cvss.get('score') or cvss.get('cvss_score') or cvss.get('value')
        if score:
            cvss_parts.append(str(score))

        # Full vector string (e.g., CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N)
        vector = cvss.get('vector') or cvss.get('cvss_vector') or cvss.get('full_vector')
        if vector:
            cvss_parts.append(vector)
        elif score:
            # Construct vector from individual components if full vector not available
            abbrev = {
                'attack_vector': 'AV', 'attackcomplexity': 'AC',
                'privileges_required': 'PR', 'user_interaction': 'UI',
                'scope': 'S', 'confidentiality_impact': 'C',
                'integrity_impact': 'I', 'availability_impact': 'A',
            }
            metric_keys = ['attack_vector', 'attackcomplexity', 'privileges_required',
                          'user_interaction', 'scope', 'confidentiality_impact',
                          'integrity_impact', 'availability_impact']
            vector_parts = []
            for key in metric_keys:
                val = cvss.get(key, cvss.get(key.replace('_', ''), ''))
                if val:
                    ab = abbrev.get(key, key[:2].upper())
                    vector_parts.append(f'{ab}:{val[0].upper()}' if val else '')
            if vector_parts:
                vector_str = 'CVSS:3.1/' + '/'.join(vector_parts)
                cvss_parts.append(vector_str)

        if cvss_parts:
            parts.append(f'<p><strong>CVSS:</strong> {" ".join(cvss_parts)}</p>')

    return ''.join(parts)


def map_report_to_csv_row(report: Dict, detailed_report: Optional[Dict] = None, program_slug: str = '') -> Optional[Dict]:
    """
    Map YesWeHack report to ThreatVault CSV format

    Args:
        report: YesWeHack report dict (summary from list)
        detailed_report: Detailed report dict (from /reports/{id} endpoint)

    Returns:
        Mapped dict for CSV export or None if invalid
    """
    # Use detailed report if available, otherwise use summary
    source = detailed_report if detailed_report else report
    # Carry over _program_slug AND numeric id from summary report (needed for URL construction)
    if detailed_report:
        if report.get('_program_slug'):
            source = {**detailed_report, '_program_slug': report['_program_slug']}
        if report.get('id'):
            source = {**source, 'id': report['id']}

    # Extract fields from report
    local_id = source.get('local_id', '')

    # Try multiple paths for criticity
    criticity = source.get('criticity', '')
    if not criticity:
        cvss = source.get('cvss', {})
        if isinstance(cvss, dict):
            criticity = cvss.get('criticity', '')

    title = source.get('title', '')

    # Get description_html (preferred) or fall back to description
    description = source.get('description_html', '')
    if not description:
        description = source.get('description', '')

    # Extract per-report remediation (not generic bug_type link)
    # Uses: description_html <h2>Remediation</h2> section, then suggestions, then bug_type description
    suggestions = source.get('suggestions')
    bug_type = source.get('bug_type', {})
    if isinstance(bug_type, dict):
        remediation = extract_remediation(description, suggestions, bug_type)
    else:
        remediation = extract_remediation(description, suggestions, {})

    # Get scope for Host field
    scope = source.get('scope', '')
    host = clean_scope(scope) if scope else ''

    # Convert criticality
    risk = convert_criticality(criticity)
    if not risk:
        logger.debug(f"Skipping report {local_id} - invalid criticality: {criticity}")
        return None

    # Log if description is still empty
    if not description:
        logger.warning(f"Report {local_id} has no description_html or description field")

    # Build metadata block (Report ID, URL, CVSS) and prepend to description
    # Pass 'report' (has _program_slug) not 'source' (detailed_report) — _program_slug
    # is only set on the summary report, not the detailed response
    metadata = _build_report_metadata(source, program_slug)
    if not metadata:
        # Try getting _program_slug from the original report dict
        metadata = _build_report_metadata(report, program_slug)
    full_description = metadata + description if description else metadata

    # Map to ThreatVault format
    csv_row = {
        'CVE': local_id,  # Map bug bounty report ID to CVE field for tracking
        'Risk': risk,
        'Host': host,  # Extracted and cleaned from scope field
        'Port': '0',  # Use 0 for web applications (will be converted to int by plugin)
        'Name': title,
        'Description': format_description(full_description),
        'Solution': remediation,  # Per-report remediation: extracted from description_html, suggestions, or bug_type
        'Plugin Output': '',  # Leave empty as per requirement
        'VPR Score': ''  # Not provided by YesWeHack, empty string
    }

    return csv_row


def export_reports_to_csv(reports: List[Dict], output_file: str, fetch_details: bool = True, apply_filter: bool = True, program_slug: str = '') -> bool:
    """
    Export reports to CSV file in ThreatVault format

    Args:
        reports: List of YesWeHack report dicts (summary from list)
        output_file: Output CSV file path
        fetch_details: If True, fetch full details for each report (default: True)
        apply_filter: If True, filter by workflow_state and fix_verification_status (default: True)
        program_slug: Program slug for constructing report URLs (optional)

    Returns:
        True if successful, False otherwise
    """
    if not reports:
        logger.error("No reports to export")
        return False

    csv_rows = []
    skipped_criticality = 0
    skipped_status = 0
    failed_details = 0

    logger.info(f"Processing {len(reports)} reports...")

    for idx, report in enumerate(reports, 1):
        report_id = report.get('id') or report.get('local_id', '')

        # Fetch detailed report to get description_html and workflow state
        detailed_report = None
        if fetch_details and report_id:
            logger.info(f"[{idx}/{len(reports)}] Fetching details for report {report_id}...")
            detailed_report = get_report_details(report_id)
            if not detailed_report:
                logger.warning(f"Failed to fetch details for report {report_id}, using summary data")
                failed_details += 1
        else:
            logger.debug(f"[{idx}/{len(reports)}] Using summary data for report {report_id}")

        # Apply status filter if enabled
        if apply_filter:
            # Filtering requires detailed report from /reports/{id} endpoint
            # because workflow_state and ask_for_fix_verification_status are only available there
            if not detailed_report:
                logger.warning(
                    f"Cannot filter report {report_id} - detailed report not fetched. "
                    f"Filtering requires --no-details flag to be OFF."
                )
                skipped_status += 1
                continue

            # Filter by workflow_state and fix_verification_status
            if not should_include_report(detailed_report):
                skipped_status += 1
                continue

        # Map to CSV format
        csv_row = map_report_to_csv_row(report, detailed_report, program_slug)
        if csv_row:
            csv_rows.append(csv_row)
        else:
            skipped_criticality += 1

    if not csv_rows:
        logger.error("No valid reports to export after filtering")
        return False

    try:
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=CSV_HEADERS)
            writer.writeheader()
            writer.writerows(csv_rows)

        logger.info(f"\n{'='*60}")
        logger.info(f"Successfully exported {len(csv_rows)} reports to {output_file}")
        if skipped_criticality > 0:
            logger.info(f"Skipped {skipped_criticality} reports (invalid criticality)")
        if skipped_status > 0:
            logger.info(f"Skipped {skipped_status} reports (workflow_state != 'accepted' OR fix_verification_status != 'PENDING')")
        if failed_details > 0:
            logger.warning(f"Failed to fetch details for {failed_details} reports (using summary data)")
        logger.info(f"{'='*60}")
        return True

    except IOError as e:
        logger.error(f"Error writing to file {output_file}: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error during export: {e}")
        return False


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description='Extract YesWeHack bug bounty reports and export to ThreatVault CSV format',
        epilog='Example: ywh2csv.py program1 program2 -o reports.csv'
    )

    parser.add_argument(
        'programs',
        nargs='+',
        help='One or more program slug names to extract reports from'
    )

    parser.add_argument(
        '-o', '--output',
        required=True,
        help='Output CSV file path'
    )

    parser.add_argument(
        '-b', '--business-unit',
        help='Business unit slug (optional, for listing programs)'
    )

    parser.add_argument(
        '--list-business-units',
        action='store_true',
        help='List all available business units and exit'
    )

    parser.add_argument(
        '--list-programs',
        metavar='BUSINESS_UNIT',
        help='List all programs for a business unit and exit'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )

    parser.add_argument(
        '--no-details',
        action='store_true',
        help='Skip fetching individual report details (faster but may miss description_html)'
    )

    parser.add_argument(
        '--no-filter',
        action='store_true',
        help='Disable status filtering (export all reports regardless of workflow_state and fix_verification_status)'
    )

    args = parser.parse_args()

    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Handle list operations
    if args.list_business_units:
        business_units = get_business_units()
        if business_units:
            print("\nAvailable Business Units:")
            print("-" * 60)
            for bu in business_units:
                print(f"Slug: {bu.get('slug')}")
                print(f"Name: {bu.get('name')}")
                print(f"Programs: {len(bu.get('programs', []))}")
                print("-" * 60)
        return 0

    if args.list_programs:
        programs = get_business_unit_programs(args.list_programs)
        if programs:
            print(f"\nAvailable Programs in '{args.list_programs}':")
            print("-" * 60)
            for prog in programs:
                print(f"Slug: {prog.get('slug')}")
                print(f"Title: {prog.get('title')}")
                print(f"Status: {prog.get('status')}")
                print("-" * 60)
        return 0

    # Validate API key
    if not API_KEY:
        logger.error("API key not found. Set YWH_API_KEY environment variable or update .env file")
        return 1

    # Collect all reports from specified programs
    all_reports = []

    for program_slug in args.programs:
        logger.info(f"\n{'='*60}")
        logger.info(f"Processing program: {program_slug}")
        logger.info(f"{'='*60}")

        reports = get_program_reports(program_slug)
        if reports:
            # Tag each report with its program slug for URL construction
            for r in reports:
                r['_program_slug'] = program_slug
            all_reports.extend(reports)
            logger.info(f"Added {len(reports)} reports from {program_slug}")
        else:
            logger.warning(f"No reports found for program: {program_slug}")

    # Export to CSV
    if all_reports:
        logger.info(f"\n{'='*60}")
        logger.info(f"Total reports collected: {len(all_reports)}")
        logger.info(f"{'='*60}\n")

        # Apply filtering unless --no-filter flag is set
        apply_filter = not args.no_filter

        # Fetch details unless --no-details flag is set
        fetch_details = not args.no_details

        # IMPORTANT: Filtering requires detail fetching because workflow_state and
        # ask_for_fix_verification_status are only in /reports/{id} endpoint
        if apply_filter and not fetch_details:
            logger.warning("="*60)
            logger.warning("CONFLICT: Filtering enabled but --no-details flag is set")
            logger.warning("Filtering requires individual report details from /reports/{id}")
            logger.warning("FORCING detail fetching to enable filtering...")
            logger.warning("="*60)
            fetch_details = True

        if not fetch_details:
            logger.warning("Skipping individual report details (--no-details flag set)")
            logger.warning("Description fields may be empty or incomplete")

        if not apply_filter:
            logger.warning("Status filtering disabled (--no-filter flag set)")
            logger.warning("All reports will be exported regardless of workflow_state and fix_verification_status")
        else:
            logger.info("Filtering enabled: Only reports with workflow_state='accepted' AND fix_verification_status='PENDING' will be exported")
            logger.info("These fields are fetched from /reports/{id} endpoint")

        success = export_reports_to_csv(all_reports, args.output, fetch_details=fetch_details, apply_filter=apply_filter)
        return 0 if success else 1
    else:
        logger.error("No reports found for any of the specified programs")
        return 1


if __name__ == "__main__":
    sys.exit(main())
