"""Validate SARIF files against the official OASIS SARIF 2.1.0 schema.

Usage: audit_validate_sarif.py SCHEMA.json FILE.sarif [FILE.sarif ...]
Download the schema first:
  curl -s -o sarif-2.1.0-schema.json https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/schemas/sarif-schema-2.1.0.json
"""

import json
import sys

import jsonschema


def main(argv: list[str]) -> int:
    schema = json.load(open(argv[0], encoding="utf-8"))
    validator = jsonschema.Draft7Validator(schema)
    failed = 0
    for path in argv[1:]:
        errors = sorted(validator.iter_errors(json.load(open(path, encoding="utf-8"))), key=lambda e: list(e.path))
        print(f"{path}: {'VALID' if not errors else f'INVALID ({len(errors)} errors)'}")
        for error in errors[:3]:
            print(f"    {list(error.path)} {error.message[:160]}")
        failed += bool(errors)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
