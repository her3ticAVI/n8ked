#!/usr/bin/env python3
import json, sys

def load(path):
    with open(path) as f:
        return json.load(f)

def find(obj, category, contains=None):
    for f in obj.get("findings", []):
        if f["category"] == category and (contains is None or contains in f["message"]):
            return f
    return None

def main():
    obj = load(sys.argv[1])
    checks = []

    def check(name, cond):
        checks.append((name, bool(cond)))

    check("target is set", obj.get("target"))
    check("version detected", obj.get("version") not in (None, "", "unknown"))
    check("no false-positive credential exposure",
          find(obj, "access-control", "/rest/credentials") is None)  # should be PROTECTED post-setup
    check("setup-complete finding absent", find(obj, "setup") is None)

    failed = [n for n, ok in checks if not ok]
    for n, ok in checks:
        print(f"{'PASS' if ok else 'FAIL'}: {n}")
    if failed:
        print(f"\n{len(failed)} check(s) failed", file=sys.stderr)
        sys.exit(1)
    print("\nall checks passed")

if __name__ == "__main__":
    main()
