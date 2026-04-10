#!/usr/bin/env python3
"""
ThreatVault Helper Scripts for YesWeHack Plugin Development

Provides utilities for:
- Cleaning up ThreatVault product data (findings, finding_names, upload logs)
- Uploading CSV files to ThreatVault via REST API
- Wiping and re-uploading in one shot

IMPORTANT: Authentication requires the API key from ThreatVault Manage API
(not the JWT from browser document.cookie). Create/get your API key from:
ThreatVault UI → Manage API

Usage:
    # Get API key from ThreatVault UI → Manage API
    # Use --token to pass the API key (or set THREATVAULT_API_TOKEN env var)

    # Clean up a product (deletes findings + finding_names + upload logs)
    python3 tv_helpers.py clean --product-name "NFP"

    # Upload CSV to ThreatVault (via /api/upload REST endpoint)
    python3 tv_helpers.py upload --file /tmp/nfp.csv --product-name "NFP" --plugin-id <uuid> --token <api_key>

    # Wipe + re-upload (full refresh)
    python3 tv_helpers.py refresh --file /tmp/nfp.csv --product-name "NFP" --plugin-id <uuid> --token <api_key>

    # List products (useful to find IDs)
    python3 tv_helpers.py list-products
"""

import argparse
import json
import subprocess
import sys
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    import requests
except ImportError:
    print("Error: 'requests' library is required. Install it with: pip install requests", file=sys.stderr)
    sys.exit(1)

# === Configuration ===
THREATVAULT_API_TOKEN = os.environ.get("THREATVAULT_API_TOKEN", "")
THREATVAULT_BASE_URL = os.environ.get("THREATVAULT_BASE_URL", "http://127.0.0.1:8000")
DB_URL = os.environ.get("THREATVAULT_DB_URL", "postgresql://root:secret@localhost:5432/sentinel")


def get_product_id_by_name(name: str) -> Optional[str]:
    """Find product UUID by name from the database."""
    try:
        result = subprocess.run(
            [
                "docker", "exec", "db",
                "psql", "-U", "root", "-d", "sentinel",
                "-t", "-c", f"SELECT id FROM product WHERE name = '{name}' LIMIT 1;"
            ],
            capture_output=True, text=True, check=True
        )
        product_id = result.stdout.strip()
        return product_id if product_id else None
    except subprocess.CalledProcessError:
        return None


def list_products() -> list:
    """List all products from the database."""
    try:
        result = subprocess.run(
            ["docker", "exec", "db", "psql", "-U", "root", "-d", "sentinel",
             "-t", "-c", "SELECT id, name, created_at FROM product ORDER BY created_at;"],
            capture_output=True, text=True, check=True
        )
        products = []
        for line in result.stdout.strip().split("\n"):
            if line.strip():
                parts = line.split("|")
                if len(parts) >= 2:
                    products.append({
                        "id": parts[0].strip(),
                        "name": parts[1].strip(),
                        "created_at": parts[2].strip() if len(parts) > 2 else ""
                    })
        return products
    except subprocess.CalledProcessError as e:
        print(f"Error listing products: {e.stderr}", file=sys.stderr)
        return []


def delete_findings(product_id: str) -> int:
    """Delete all findings for a product. Returns count deleted."""
    try:
        result = subprocess.run(
            ["docker", "exec", "db", "psql", "-U", "root", "-d", "sentinel",
             "-t", "-c", f"DELETE FROM finding WHERE product_id='{product_id}';"],
            capture_output=True, text=True, check=True
        )
        # Parse deleted count from output like "DELETE 16"
        deleted = result.stdout.strip().split(" ")[1] if result.stdout.strip() else "0"
        return int(deleted)
    except (subprocess.CalledProcessError, IndexError, ValueError) as e:
        print(f"Error deleting findings: {e}", file=sys.stderr)
        return 0


def delete_finding_names_for_product(product_id: str) -> int:
    """
    Delete all finding_names that were linked to a product's findings.

    Must be called BEFORE delete_findings() since the SQL join won't work after
    the finding records are deleted.

    Returns count deleted.
    """
    try:
        # First get the finding_name IDs that belong to this product
        result = subprocess.run(
            ["docker", "exec", "db", "psql", "-U", "root", "-d", "sentinel",
             "-t", "-c",
             f"SELECT DISTINCT finding_name_id FROM finding WHERE product_id='{product_id}';"],
            capture_output=True, text=True, check=True
        )
        ids = [line.strip() for line in result.stdout.strip().split("\n") if line.strip()]
        if not ids:
            print("No finding_names to delete (no findings existed for this product)")
            return 0

        # Now delete those finding_names directly
        id_list = ",".join(f"'{i}'" for i in ids)
        result = subprocess.run(
            ["docker", "exec", "db", "psql", "-U", "root", "-d", "sentinel",
             "-t", "-c", f"DELETE FROM finding_name WHERE id IN ({id_list});"],
            capture_output=True, text=True, check=True
        )
        deleted = result.stdout.strip().split(" ")[1] if result.stdout.strip() else "0"
        return int(deleted)
    except (subprocess.CalledProcessError, IndexError, ValueError) as e:
        print(f"Error deleting finding_names: {e}", file=sys.stderr)
        return 0


def clear_duckdb_snapshot():
    """Delete the DuckDB snapshot so ThreatVault re-initializes from fresh DB state."""
    try:
        # Find the snapshot path inside the app container
        result = subprocess.run(
            ["docker", "exec", "app", "ls", "/snapshots/shared.db"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            subprocess.run(["docker", "exec", "app", "rm", "-f", "/snapshots/shared.db"], check=True)
            print("DuckDB snapshot cleared")
        else:
            print("No DuckDB snapshot to clear")
    except subprocess.CalledProcessError as e:
        print(f"Warning: Could not clear DuckDB snapshot: {e}", file=sys.stderr)


def restart_app():
    """Restart the ThreatVault app container and wait for it to be ready."""
    try:
        subprocess.run(["docker", "restart", "app"], capture_output=True, text=True, check=True)
        # Wait for app to be ready by polling the health endpoint
        import time
        import requests as _requests
        max_wait = 60
        start = time.time()
        while time.time() - start < max_wait:
            try:
                resp = _requests.get(f"{THREATVAULT_BASE_URL}/", timeout=5)
                if resp.status_code < 500:
                    print(f"ThreatVault app restarted and ready (took {time.time()-start:.1f}s)")
                    return
            except Exception:
                pass
            time.sleep(2)
        print("Warning: App restart completed but may not be fully ready")
    except subprocess.CalledProcessError as e:
        print(f"Warning: Could not restart app: {e}", file=sys.stderr)


def init_fresh_snapshot():
    """Force-reinitialize the DuckDB snapshot from current PostgreSQL state."""
    try:
        subprocess.run(
            ["docker", "exec", "app", "python", "-c",
             "from src.application.utils.snapshot import init_fn_cve_snapshot; init_fn_cve_snapshot()"],
            capture_output=True, text=True, check=True
        )
        print("DuckDB snapshot re-initialized from PostgreSQL")
    except subprocess.CalledProcessError as e:
        print(f"Warning: Could not init snapshot: {e}", file=sys.stderr)
    except (subprocess.CalledProcessError, IndexError, ValueError) as e:
        print(f"Error deleting findings: {e.stderr if hasattr(e, 'stderr') else e}", file=sys.stderr)
        return 0


def delete_upload_logs(product_id: str) -> int:
    """Delete all file upload logs for a product. Returns count deleted."""
    try:
        result = subprocess.run(
            ["docker", "exec", "db", "psql", "-U", "root", "-d", "sentinel",
             "-t", "-c", f"DELETE FROM file_upload_log WHERE product_id='{product_id}';"],
            capture_output=True, text=True, check=True
        )
        deleted = result.stdout.strip().split(" ")[1] if result.stdout.strip() else "0"
        return int(deleted)
    except (subprocess.CalledProcessError, IndexError, ValueError) as e:
        print(f"Error deleting upload logs: {e.stderr if hasattr(e, 'stderr') else e}", file=sys.stderr)
        return 0


def delete_logs(product_id: str) -> int:
    """Delete all log entries for a product. Returns count deleted.

    ThreatVault dashboard counts (New Vulnerability, Aging, etc.) are sourced from
    the log table, not the finding table directly. Wiping only findings leaves
    stale log entries which keep dashboard counts showing old numbers even after
    findings are deleted.
    """
    try:
        result = subprocess.run(
            ["docker", "exec", "db", "psql", "-U", "root", "-d", "sentinel",
             "-t", "-c", f"DELETE FROM log WHERE product_id='{product_id}';"],
            capture_output=True, text=True, check=True
        )
        deleted = result.stdout.strip().split(" ")[1] if result.stdout.strip() else "0"
        return int(deleted)
    except (subprocess.CalledProcessError, IndexError, ValueError) as e:
        print(f"Error deleting logs: {e.stderr if hasattr(e, 'stderr') else e}", file=sys.stderr)
        return 0


def upload_csv(file_path: str, product_id: str, plugin_id: str, api_token: str = None, scan_date: str = None, label: str = "") -> bool:
    """Upload a CSV file to ThreatVault via the /api/upload REST endpoint.

    Uses Bearer token auth (JWT from document.cookie) — NOT the htmx Cookie-based upload.

    Args:
        file_path: Path to CSV file
        product_id: ThreatVault product UUID
        plugin_id: ThreatVault plugin UUID (e.g., YesWeHack plugin ID)
        api_token: Bearer token (JWT). Can pass raw token or "Bearer eyJ..." — the function
                   strips "Bearer " prefix if present.
        scan_date: ISO scan date string. Defaults to today's date YYYY-MM-DD.
        label: Optional label string.

    Returns:
        True on success (HTTP 200/201), False on failure.
    """
    if not api_token:
        api_token = THREATVAULT_API_TOKEN
    if not api_token:
        print("Error: No API token. Set THREATVAULT_API_TOKEN env var or pass --token", file=sys.stderr)
        return False

    # Strip "Bearer " prefix if present (token may come with or without it)
    if api_token.startswith("Bearer "):
        api_token = api_token[7:]

    if not Path(file_path).exists():
        print(f"Error: File not found: {file_path}", file=sys.stderr)
        return False

    base_url = THREATVAULT_BASE_URL.rstrip("/")
    url = f"{base_url}/api/upload"
    params = {"product_id": product_id}

    if not scan_date:
        scan_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    headers = {
        "accept": "application/json",
        "Authorization": api_token
    }
    data = {
        "plugin": plugin_id,
        "scan_date": scan_date,
        "process_new_finding": "true",
        "label": label,
    }

    print(f"Upload: POST {url}")
    print(f"  product_id={product_id}, plugin={plugin_id}, scan_date={scan_date}")

    try:
        with open(file_path, "rb") as f:
            files = {"formFile": (Path(file_path).name, f, "text/csv")}
            response = requests.post(
                url, params=params, headers=headers, data=data, files=files, timeout=120
            )

        if response.status_code in (200, 201):
            print(f"Upload successful (HTTP {response.status_code})")
            try:
                resp_json = response.json()
                print(f"  Response: {resp_json}")
            except Exception:
                print(f"  Response: {response.text[:200]}")
            return True

        print(f"Upload failed: HTTP {response.status_code} - {response.text}", file=sys.stderr)
        return False

    except requests.exceptions.Timeout:
        print("Upload timed out (120s)", file=sys.stderr)
        return False
    except Exception as exc:
        print(f"Upload error: {exc}", file=sys.stderr)
        return False


def wait_for_upload(timeout: int = 10) -> bool:
    """Wait briefly for background processing and check file_upload_log status."""
    import time
    time.sleep(timeout)
    try:
        result = subprocess.run(
            ["docker", "exec", "db", "psql", "-U", "root", "-d", "sentinel",
             "-t", "-c", "SELECT id, filename, status FROM file_upload_log ORDER BY created_at DESC LIMIT 1;"],
            capture_output=True, text=True, check=True
        )
        line = result.stdout.strip()
        if line:
            parts = line.split("|")
            if len(parts) >= 3:
                print(f"File upload log: id={parts[0].strip()}, filename={parts[1].strip()}, status={parts[2].strip()}")
                return parts[2].strip() == "SUCCESS"
        return False
    except subprocess.CalledProcessError:
        return False


def cmd_list_products(args):
    products = list_products()
    if not products:
        print("No products found")
        return
    print(f"\n{'ID':<42} | {'Name':<20} | Created At")
    print("-" * 80)
    for p in products:
        print(f"{p['id']:<42} | {p['name']:<20} | {p['created_at']}")


def cmd_clean(args):
    if not args.product_id and args.product_name:
        product_id = get_product_id_by_name(args.product_name)
        if not product_id:
            print(f"Product not found: {args.product_name}", file=sys.stderr)
            sys.exit(1)
        args.product_id = product_id

    print(f"Cleaning product: {args.product_id}")
    findings = delete_findings(args.product_id)
    print(f"Deleted {findings} findings")
    finding_names = delete_finding_names_for_product(args.product_id)
    print(f"Deleted {finding_names} finding_names")
    upload_logs = delete_upload_logs(args.product_id)
    print(f"Deleted {upload_logs} upload logs")
    logs = delete_logs(args.product_id)
    print(f"Deleted {logs} log entries")


def cmd_upload(args):
    if not args.product_id and args.product_name:
        product_id = get_product_id_by_name(args.product_name)
        if not product_id:
            print(f"Product not found: {args.product_name}", file=sys.stderr)
            sys.exit(1)
        args.product_id = product_id

    token = args.token or THREATVAULT_API_TOKEN
    if not token:
        print("Error: No API token. Use --token or set THREATVAULT_API_TOKEN", file=sys.stderr)
        sys.exit(1)

    print(f"Uploading {args.file} to product {args.product_id} with plugin {args.plugin_id}")
    success = upload_csv(args.file, args.product_id, args.plugin_id, token)
    if success and not args.no_wait:
        wait_for_upload()
    sys.exit(0 if success else 1)


def cmd_refresh(args):
    if not args.product_id and args.product_name:
        product_id = get_product_id_by_name(args.product_name)
        if not product_id:
            print(f"Product not found: {args.product_name}", file=sys.stderr)
            sys.exit(1)
        args.product_id = product_id

    print(f"REFRESH: Wiping product {args.product_id} then uploading {args.file}")
    # IMPORTANT: delete finding_names BEFORE findings (join won't work after findings deleted)
    finding_names = delete_finding_names_for_product(args.product_id)
    print(f"Deleted {finding_names} finding_names")
    findings = delete_findings(args.product_id)
    print(f"Deleted {findings} findings")
    logs = delete_logs(args.product_id)
    print(f"Deleted {logs} log entries")
    upload_logs = delete_upload_logs(args.product_id)
    print(f"Deleted {upload_logs} upload logs")
    print("Clearing DuckDB snapshot...")
    clear_duckdb_snapshot()
    print("Restarting app to clear cache...")
    restart_app()
    print("Uploading new data...")

    token = args.token or THREATVAULT_API_TOKEN
    if not token:
        print("Error: No API token. Use --token or set THREATVAULT_API_TOKEN", file=sys.stderr)
        sys.exit(1)

    success = upload_csv(args.file, args.product_id, args.plugin_id, token)
    if success and not args.no_wait:
        wait_for_upload()
    sys.exit(0 if success else 1)


def main():
    parser = argparse.ArgumentParser(
        description="ThreatVault helper scripts for YesWeHack workflow",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # List all products
  python3 tv_helpers.py list-products

  # Clean a product (delete findings + logs)
  python3 tv_helpers.py clean --product-name "NFP"

  # Upload CSV to ThreatVault
  python3 tv_helpers.py upload --file /tmp/nfp.csv --product-id <uuid> --plugin-id <uuid>

  # Wipe + re-upload in one shot
  python3 tv_helpers.py refresh --file /tmp/nfp.csv --product-name "NFP" --plugin-id <uuid>
        """
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # list-products
    subparsers.add_parser("list-products", help="List all products with IDs")

    # clean
    clean_parser = subparsers.add_parser("clean", help="Delete all findings and upload logs for a product")
    clean_parser.add_argument("--product-id", help="Product UUID")
    clean_parser.add_argument("--product-name", help="Product name (will look up UUID)")

    # upload
    upload_parser = subparsers.add_parser("upload", help="Upload a CSV file to ThreatVault")
    upload_parser.add_argument("--file", "-f", required=True, help="CSV file path to upload")
    upload_parser.add_argument("--product-id", help="Product UUID")
    upload_parser.add_argument("--product-name", help="Product name (will look up UUID)")
    upload_parser.add_argument("--plugin-id", "-p", required=True, help="Plugin UUID")
    upload_parser.add_argument("--token", "-t", help="API token (or set THREATVAULT_API_TOKEN)")
    upload_parser.add_argument("--no-wait", action="store_true", help="Don't wait for processing")

    # refresh
    refresh_parser = subparsers.add_parser("refresh", help="Wipe product data then upload CSV")
    refresh_parser.add_argument("--file", "-f", required=True, help="CSV file path to upload")
    refresh_parser.add_argument("--product-id", help="Product UUID")
    refresh_parser.add_argument("--product-name", help="Product name (will look up UUID)")
    refresh_parser.add_argument("--plugin-id", "-p", required=True, help="Plugin UUID")
    refresh_parser.add_argument("--token", "-t", help="API token (or set THREATVAULT_API_TOKEN)")
    refresh_parser.add_argument("--no-wait", action="store_true", help="Don't wait for processing")

    args = parser.parse_args()

    if args.command == "list-products":
        cmd_list_products(args)
    elif args.command == "clean":
        if not args.product_id and not args.product_name:
            parser.error("--product-id or --product-name required")
        cmd_clean(args)
    elif args.command == "upload":
        if not args.product_id and not args.product_name:
            parser.error("--product-id or --product-name required")
        cmd_upload(args)
    elif args.command == "refresh":
        if not args.product_id and not args.product_name:
            parser.error("--product-id or --product-name required")
        cmd_refresh(args)


if __name__ == "__main__":
    main()
