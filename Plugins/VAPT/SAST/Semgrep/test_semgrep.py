#!/usr/bin/env python3
"""Test script for Semgrep plugin"""

import sys
from pathlib import Path

# Import the plugin
from semgrep import process

def main():
    # Read the test file
    test_file = Path("semgrep-results.json")

    if not test_file.exists():
        print(f"Error: {test_file} not found")
        sys.exit(1)

    print(f"Reading {test_file}...")
    file_bytes = test_file.read_bytes()
    print(f"File size: {len(file_bytes)} bytes")

    # Test processing
    print("\nProcessing with file_type='application/json'...")
    try:
        df = process(file_bytes, "application/json")
        print(f"✓ Success! Processed {len(df)} findings")
        print(f"\nDataFrame schema:")
        print(df.schema)
        print(f"\nFirst 3 rows:")
        print(df.head(3))
        print(f"\nLast 3 rows:")
        print(df.tail(3))

        # Check for any issues
        print("\n--- Data validation ---")
        print(f"Total rows: {len(df)}")
        print(f"Columns: {df.columns}")

        # Check for None/null values in critical fields
        for col in df.columns:
            null_count = df.select(col).null_count()[0, 0]
            if null_count > 0:
                print(f"Warning: {col} has {null_count} null values")

    except Exception as e:
        print(f"✗ Error processing file: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
