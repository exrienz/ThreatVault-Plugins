#!/usr/bin/env python3
"""
Test script for Burp Suite DAST plugin

Usage:
    python test_burpsuite.py <path_to_burp_xml_file>

Example:
    python test_burpsuite.py ../../../../Test/burp_sample.xml
"""

import sys
from pathlib import Path
import polars as pl
from burpsuite import process


def test_burpsuite_plugin(xml_file_path: str):
    """
    Test the Burp Suite plugin with a sample XML file

    Args:
        xml_file_path: Path to Burp Suite XML file
    """
    # Validate file exists
    xml_path = Path(xml_file_path)
    if not xml_path.exists():
        print(f"Error: File not found: {xml_file_path}")
        sys.exit(1)

    print(f"Testing Burp Suite plugin with: {xml_path}")
    print("=" * 80)

    # Read file as bytes
    with open(xml_path, 'rb') as f:
        file_bytes = f.read()

    # Determine MIME type
    file_type = "xml"

    print(f"\nFile type: {file_type}")
    print(f"File size: {len(file_bytes):,} bytes")

    # Process the file using the plugin
    try:
        df = process(file_bytes, file_type)
        print(f"\n✓ Plugin executed successfully!")
        print(f"\nDataFrame shape: {df.shape}")
        print(f"Total vulnerabilities: {df.shape[0]}")

        # Display schema
        print("\n" + "=" * 80)
        print("SCHEMA")
        print("=" * 80)
        print(f"Columns: {df.columns}")
        print("\nData types:")
        for col, dtype in zip(df.columns, df.dtypes):
            print(f"  {col}: {dtype}")

        # Display statistics
        print("\n" + "=" * 80)
        print("STATISTICS")
        print("=" * 80)

        # Risk distribution
        if 'risk' in df.columns and df.shape[0] > 0:
            print("\nRisk distribution:")
            risk_counts = df.group_by('risk').agg(
                pl.len().alias('count')
            ).sort('count', descending=True)
            print(risk_counts)

        # Top vulnerability types
        if 'name' in df.columns and df.shape[0] > 0:
            print("\nTop 10 vulnerability types:")
            name_counts = df.group_by('name').agg(
                pl.len().alias('count')
            ).sort('count', descending=True).head(10)
            print(name_counts)

        # Host information
        if 'host' in df.columns and df.shape[0] > 0:
            print("\nHost information:")
            host_counts = df.group_by('host').agg(
                pl.len().alias('count')
            ).sort('count', descending=True)
            print(host_counts)

        # Display sample data
        print("\n" + "=" * 80)
        print("SAMPLE DATA (First 3 rows)")
        print("=" * 80)
        print(df.head(3))

        # Verify schema
        print("\n" + "=" * 80)
        print("SCHEMA VERIFICATION")
        print("=" * 80)
        expected_columns = [
            'cve', 'risk', 'host', 'port', 'name',
            'description', 'remediation', 'evidence', 'vpr_score'
        ]

        missing_columns = set(expected_columns) - set(df.columns)
        extra_columns = set(df.columns) - set(expected_columns)

        if not missing_columns and not extra_columns:
            print("✓ Schema matches ThreatVault VAPT requirements")
        else:
            if missing_columns:
                print(f"✗ Missing columns: {missing_columns}")
            if extra_columns:
                print(f"✗ Extra columns: {extra_columns}")

        # Verify column order
        if df.columns == expected_columns:
            print("✓ Column order is correct")
        else:
            print(f"✗ Column order mismatch")
            print(f"  Expected: {expected_columns}")
            print(f"  Actual: {df.columns}")

        # Check for required data
        print("\n" + "=" * 80)
        print("DATA QUALITY CHECKS")
        print("=" * 80)

        if df.shape[0] > 0:
            # Check risk values
            valid_risks = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
            invalid_risks = df.filter(~pl.col('risk').is_in(valid_risks))
            if invalid_risks.shape[0] == 0:
                print("✓ All risk values are valid")
            else:
                print(f"✗ Found {invalid_risks.shape[0]} rows with invalid risk values")

            # Check for empty required fields
            required_fields = ['risk', 'host', 'name']
            for field in required_fields:
                empty_count = df.filter(
                    (pl.col(field) == "") | pl.col(field).is_null()
                ).height
                if empty_count == 0:
                    print(f"✓ No empty values in '{field}'")
                else:
                    print(f"⚠ Found {empty_count} empty values in '{field}'")

            # Verify host mapping (should be hostname, not IP)
            print("\n✓ Host mapping verification:")
            sample_host = df['host'][0]
            print(f"  Sample host value: {sample_host}")
            if 'https://' in sample_host or 'http://' in sample_host:
                print(f"  ✓ Using hostname (correct)")
            else:
                print(f"  ⚠ May be using IP address instead of hostname")

        print("\n" + "=" * 80)
        print("TEST COMPLETED SUCCESSFULLY")
        print("=" * 80)

    except Exception as e:
        print(f"\n✗ Error processing file: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python test_burpsuite.py <path_to_burp_xml_file>")
        print("\nExample:")
        print("  python test_burpsuite.py ../../../../Test/burp_sample.xml")
        sys.exit(1)

    xml_file = sys.argv[1]
    test_burpsuite_plugin(xml_file)
