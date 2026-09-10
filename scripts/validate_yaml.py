#!/usr/bin/env python3
"""Validate all YAML files under skills/ directory."""
import yaml
import os
import sys

SKILLS_DIR = os.path.join(os.path.dirname(__file__), "..", "skills")

errors = []
count = 0

for root, dirs, files in os.walk(SKILLS_DIR):
    for fname in sorted(files):
        if not fname.endswith(".yaml"):
            continue
        fpath = os.path.join(root, fname)
        rel = os.path.relpath(fpath, SKILLS_DIR)
        count += 1
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            if data is None:
                errors.append(f"  WARN: {rel} - empty/null document")
            else:
                print(f"  OK: {rel}")
        except yaml.YAMLError as e:
            errors.append(f"  FAIL: {rel} - {e}")

print(f"\n{'='*60}")
print(f"Validated {count} YAML files")
if errors:
    print(f"\n{len(errors)} issues found:")
    for err in errors:
        print(err)
    sys.exit(1)
else:
    print("All files OK!")
