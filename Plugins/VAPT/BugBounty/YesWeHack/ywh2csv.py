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
from typing import List, Dict, Optional

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


def format_description(description: str, max_length: int = 5000) -> str:
    """
    Format description for CSV export

    Args:
        description: Raw description text
        max_length: Maximum length for description

    Returns:
        Formatted description with newlines replaced
    """
    if not description:
        return ""

    # Replace newlines with <br/> for HTML display
    formatted = str(description).replace('\n', '<br/>')

    # Truncate if too long
    if len(formatted) > max_length:
        formatted = formatted[:max_length] + '...'

    return formatted


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


def map_report_to_csv_row(report: Dict, detailed_report: Optional[Dict] = None) -> Optional[Dict]:
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

    # Get remediation_link for Solution field
    # First try root level
    remediation_link = source.get('remediation_link', '')

    # If not found, try nested in bug_type object
    if not remediation_link:
        bug_type = source.get('bug_type', {})
        if isinstance(bug_type, dict):
            remediation_link = bug_type.get('remediation_link', '')

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

    # Map to ThreatVault format
    csv_row = {
        'CVE': local_id,  # Map bug bounty report ID to CVE field for tracking
        'Risk': risk,
        'Host': host,  # Extracted and cleaned from scope field
        'Port': '0',  # Use 0 for web applications (will be converted to int by plugin)
        'Name': title,
        'Description': format_description(description),
        'Solution': format_description(remediation_link) if remediation_link else format_description(description),  # Use remediation_link, fallback to description
        'Plugin Output': '',  # Leave empty as per requirement
        'VPR Score': ''  # Not provided by YesWeHack, empty string
    }

    return csv_row


def export_reports_to_csv(reports: List[Dict], output_file: str, fetch_details: bool = True, apply_filter: bool = True) -> bool:
    """
    Export reports to CSV file in ThreatVault format

    Args:
        reports: List of YesWeHack report dicts (summary from list)
        output_file: Output CSV file path
        fetch_details: If True, fetch full details for each report (default: True)
        apply_filter: If True, filter by workflow_state and fix_verification_status (default: True)

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
        csv_row = map_report_to_csv_row(report, detailed_report)
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
