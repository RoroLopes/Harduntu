import argparse
import sys
import os
from .checks import CHECKS, REMEDIATIONS

def user_has_root_privileges():
    return os.geteuid() == 0

def main():
    parser = argparse.ArgumentParser(description="Harduntu - Ubuntu Hardening Tool")
    parser.add_argument("--check", choices=CHECKS.keys(), help="The check to run")
    parser.add_argument("--remediate", choices=REMEDIATIONS.keys(), help="The remediation to run")
    args = parser.parse_args()

    if not user_has_root_privileges():
        print("Warning: Running without root privileges may limit the effectiveness of checks and remediations.")
        sys.exit(1)
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
