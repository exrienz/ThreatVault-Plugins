#!/usr/bin/env python3
"""Export Semgrep plugin output to CSV for debugging"""

from pathlib import Path
from semgrep import process

def main():
    # Read the test file
    test_file = Path("semgrep-results.json")

    print(f"Reading {test_file}...")
    file_bytes = test_file.read_bytes()

    # Process the data
    print("Processing with Semgrep plugin...")
    df = process(file_bytes, "application/json")

    # Export to CSV
    output_file = "semgrep-processed-output.csv"
    df.write_csv(output_file)

    print(f"✓ Exported {len(df)} findings to {output_file}")
    print(f"\nColumns: {', '.join(df.columns)}")
    print(f"\nFirst 5 rows preview:")
    print(df.head(5))

    # Show data statistics
    print(f"\n--- Data Statistics ---")
    print(f"Total findings: {len(df)}")
    print(f"\nRisk distribution:")
    print(df.group_by('risk').len().sort('risk'))

    # Check for empty/null values
    print(f"\n--- Field Validation ---")
    for col in df.columns:
        null_count = df.select(col).null_count()[0, 0]
        empty_count = len(df.filter((df[col] == '') | (df[col].is_null())))
        if null_count > 0 or empty_count > 0:
            print(f"⚠ {col}: {empty_count} empty values")
        else:
            print(f"✓ {col}: All values populated")

if __name__ == "__main__":
    main()
