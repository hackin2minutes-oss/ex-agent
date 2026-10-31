"""Command line for one investigation.

  python -m engine.investigation --project-dir DIR --path app.py --line 6 --symbol eval [--title TEXT]
                                 [--planner offline|anthropic] [--max-steps N]

The result is printed as JSON on stdout. The planner comes from --planner, else SAWONE_PLANNER, else offline. The API
key is read from ANTHROPIC_API_KEY and is never printed.
"""

import argparse
import json
import sys
from pathlib import Path

from engine.investigation.investigate import DEFAULT_MAX_STEPS, investigate
from engine.investigation.planner import PlannerError, select_planner


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m engine.investigation", description=__doc__.split("\n")[0])
    parser.add_argument("--project-dir", required=True, type=Path)
    parser.add_argument("--path", required=True, help="file of the finding, relative to the project")
    parser.add_argument("--line", required=True, type=int)
    parser.add_argument("--symbol", default=None, help="the call or name the finding is about, e.g. eval")
    parser.add_argument("--title", default="finding")
    parser.add_argument("--planner", default=None, choices=["offline", "anthropic"])
    parser.add_argument("--max-steps", type=int, default=DEFAULT_MAX_STEPS)
    args = parser.parse_args(argv)

    finding = {"title": args.title, "path": args.path, "line": args.line, "symbol": args.symbol}
    try:
        planner = select_planner(args.planner)
    except PlannerError as error:
        print(json.dumps({"verdict": "ANALYSIS_INCOMPLETE", "reason": str(error)}, indent=2))
        return 2
    result = investigate(finding, args.project_dir, planner, max_steps=args.max_steps)
    print(json.dumps({"planner": planner.name, "finding": finding, **result.to_dict()}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
