import pandas as pd
from pathlib import Path

FILES = [
    "normalized_output/normalized_windows.parquet",
    "normalized_output/normalized_ids_ips.parquet",
    "normalized_output/cve_reference.parquet",
]

for file in FILES:
    path = Path(file)

    print("\n" + "=" * 80)
    print(f"FILE: {path.name}")
    print("=" * 80)

    df = pd.read_parquet(path)

    print(f"\nRows: {len(df)}")
    print(f"Columns: {len(df.columns)}")

    print("\nColumn Names")
    print("-" * 80)
    for col in df.columns:
        print(col)

    print("\nData Types")
    print("-" * 80)
    print(df.dtypes)

    print("\nMissing Values")
    print("-" * 80)
    print(df.isnull().sum())

    print("\nFirst 5 Rows")
    print("-" * 80)
    print(df.head())