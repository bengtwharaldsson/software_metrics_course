import csv
import sys
import math
from collections import defaultdict

# Robustly raise csv field size limit for very large fields (e.g., external_calls lists)
def increase_csv_field_size_limit():
    max_int = sys.maxsize
    while True:
        try:
            csv.field_size_limit(max_int)
            break
        except OverflowError:
            max_int = max_int // 10

def try_float(x):
    try:
        v = float(x)
        if math.isnan(v):
            return None
        return v
    except Exception:
        return None

# Columns in your header: path,ext,physical_loc,logical_loc,complexity_file,fan_in,fan_out,external_calls_count,external_calls
NUMERIC_COLUMNS = [
    "physical_loc",
    "logical_loc",
    "complexity_file",
    "fan_in",
    "fan_out",
    "external_calls_count",
]

def analyze_csv(file_path):
    increase_csv_field_size_limit()

    sums = defaultdict(float)
    counts = defaultdict(int)

    try:
        with open(file_path, "r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            # Validate headers once
            headers = reader.fieldnames or []
            missing = [c for c in NUMERIC_COLUMNS if c not in headers]
            if missing:
                print(f"[{file_path}] Missing columns: {missing}. Found: {headers}")
            # Stream rows; no need to load everything into memory
            for row in reader:
                for col in NUMERIC_COLUMNS:
                    if col in row:
                        v = try_float(row[col])
                        if v is not None:
                            sums[col] += v
                            counts[col] += 1
    except Exception as e:
        print(f"Error reading CSV file {file_path}: {e}")
        return

    if not any(counts.values()):
        print(f"[{file_path}] No numeric data found to analyze.")
        return

    print(f"\nAverages for {file_path}:")
    for col in NUMERIC_COLUMNS:
        if counts[col] > 0:
            avg = sums[col] / counts[col]
            print(f"  {col:21s} avg = {avg:.6f}  (n={counts[col]})")
        else:
            print(f"  {col:21s} avg = —        (n=0)")

if __name__ == "__main__":
    for fp in ["jdk_metrics.csv", "kernel_metrics.csv", "kibana_metrics.csv"]:
        analyze_csv(fp)
