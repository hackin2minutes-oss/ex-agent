# Investigation layer

This is the first slice of the agentic investigation layer. It is the part that decides whether a planner's conclusion can
be accepted. It is not yet an AI analyst.

## What already exists (and is reused, not rewritten)

| Module | Role |
| --- | --- |
| `engine/universal.py` | Verdict names, findings, assessments |
| `engine/evidence_graph.py` | Links findings and observations by exact keys, with provenance |
| `engine/callgraph.py` | Bounded Python call graph (same-module and direct imports only) |
| `engine/preconditions.py` | CVE-specific precondition checks |
| `engine/advisories.py` | GHSA and NVD normalisation |
| `engine/dast.py` | Reads recorded exchanges. Sends no traffic |
| `engine/iast.py` | Reads runtime observations from an agent |
| `engine/verdict.py` | Separates reachability from exploitability |

## What this slice adds

| Module | Role |
| --- | --- |
| `engine/investigation/evidence.py` | Evidence records with ids, kind, the tool that collected them, and the excerpt |
| `engine/investigation/tools.py` | Two read-only tools: `read_source` and `search_source`. Each lists its limits |
| `engine/investigation/citations.py` | Checks every cited id exists, and every source excerpt is the text of its file and line |
| `engine/investigation/planner.py` | Planner interface and a deterministic `OfflinePlanner` |
| `engine/investigation/investigate.py` | The loop, the step budget, the static-confirmation rule and the UNKNOWN gate |

## The rules the loop enforces, whatever the planner is

1. **Citations are checked.** A conclusion that cites a missing record, or a source excerpt that is not in the file at
   that line, is refused as `ANALYSIS_INCOMPLETE`.
2. **Static evidence cannot confirm.** `CONFIRMED_EXPLOITABLE` with only static evidence is reported as
   `POTENTIALLY_EXPLOITABLE`. Only evidence of kind `dynamic` or `runtime` (from running the application) can confirm.
3. **UNKNOWN is earned, not defaulted.** It needs at least two successful tool runs from two different tools, and a list
   of missing evidence. Each missing item says what would resolve it. Otherwise UNKNOWN is refused.
4. **Budgets are enforced.** The loop stops at its step budget and reports the steps taken.

## What is not built yet

- **No model provider.** The only planner is `OfflinePlanner`, which can't judge exploitability. Model providers will
  plug into the same `next_step` interface. Nothing is hardcoded to a vendor.
- **No attack-path tools.** Interprocedural data flow, route discovery and authorisation analysis are not implemented.
- **No dynamic testing.** The `dynamic` and `runtime` evidence kinds exist, but no tool produces them yet.
- **No advisory research tool, dependency tool or configuration tool** inside the loop.
- **No benchmark.** Precision and recall against ground truth are not measured yet.

## Known limits of this slice

- A blank line can't be cited. An excerpt must be the text of its line.
- `search_source` is a literal text search. It can't tell a call from a comment or a string.
- The offline planner always ends at UNKNOWN for a source finding. That is the correct result without a model, not a gap
  to hide.
