import json
import sys
from pathlib import Path

def main():
    api_dir = Path(sys.argv[1] if len(sys.argv) > 1 else "data")

    if not api_dir.is_dir():
        print(f"error: API directory '{api_dir}' does not exist")
        return 1

    files = sorted(p for p in api_dir.rglob("*") if p.is_file())

    if not files:
        print(f"error: no files found in API directory '{api_dir}'")
        return 1

    invalid = 0
    for path in files:
        try:
            with open(path, "rb") as f:
                json.loads(f.read())
        except ValueError as e:
            invalid += 1
            print(f"error: {path} does not contain valid JSON: {e}")
        except OSError as e:
            invalid += 1
            print(f"error: failed to read {path}: {e}")

    print(f"Checked {len(files)} file(s) in '{api_dir}': {len(files) - invalid} valid, {invalid} invalid")

    return 1 if invalid else 0

if __name__ == "__main__":
    sys.exit(main())
