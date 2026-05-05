import argparse
import sys
from .checks import CHECKS, REMEDIATIONS

def main():
    parser = argparse.ArgumentParser(description="Harduntu - Ubuntu Hardening Tool")
    parser.add_argument("--check", choices=CHECKS.keys(), help="The check to run")
    parser.add_argument("--remediate", choices=REMEDIATIONS.keys(), help="The remediation to run")
    args = parser.parse_args()

    if args.check in CHECKS:
        print(f"Running check: {args.check}")
        CHECKS[args.check]["check"]()
    if args.remediate in REMEDIATIONS:
        print(f"Running remediation: {args.remediate}")
        REMEDIATIONS[args.remediate]["remediate"]()
    else:
        print("Invalid check or remediation specified.")
        sys.exit(1)

if __name__ == "__main__":
    main()
