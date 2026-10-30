"""Command line for signed updates.

    python -m engine.update_cli install --source DIR --target DIR --state DIR --key keys/publisher.pub
    python -m engine.update_cli rollback --target DIR --state DIR

The publisher key is passed explicitly and must be the key you pinned in the repository.
Nothing is fetched from the network: `--source` is a directory that already contains the
update's manifest.json, manifest.json.sig and the files it lists.
"""

import argparse
import sys
from pathlib import Path

from engine import updates


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="engine.update_cli", description="Signed update installer")
    sub = parser.add_subparsers(dest="command", required=True)

    install = sub.add_parser("install", help="Verify and install an update directory")
    install.add_argument("--source", type=Path, required=True)
    install.add_argument("--target", type=Path, required=True)
    install.add_argument("--state", type=Path, required=True)
    install.add_argument("--key", type=Path, required=True)

    roll = sub.add_parser("rollback", help="Restore the version installed before the current one")
    roll.add_argument("--target", type=Path, required=True)
    roll.add_argument("--state", type=Path, required=True)

    args = parser.parse_args(argv)
    try:
        if args.command == "install":
            key = updates.load_publisher_key(args.key)
            result = updates.install(args.source, args.target, args.state, key)
            print(f"installed {result['version']} (manifest sha256 {result['manifest_sha256']})")
        else:
            restored = updates.rollback(args.target, args.state)
            print(f"rolled back; installed version is now {restored}")
    except updates.UpdateError as exc:
        print(f"update rejected: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
