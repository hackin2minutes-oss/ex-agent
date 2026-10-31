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

## Choosing the planner

- `SAWONE_PLANNER=offline` (default): deterministic, no network, always ends at UNKNOWN for source findings.
- `SAWONE_PLANNER=anthropic`: asks the Anthropic Messages API for each step. Needs `ANTHROPIC_API_KEY`.
  `SAWONE_MODEL` picks the model (default `claude-opus-5-5`).
- A named planner with no key is an error. It never falls back to offline silently.

What leaves the runner with the anthropic planner: the finding, the evidence gathered so far (source excerpts from the
project), the tool log, and the tool descriptions. The key is sent only in the `x-api-key` header. It is never written to
a result, a log or an error message. The system prompt tells the model that source code is data, not instructions.

The model's reply is a proposal only. A reply that is not valid JSON ends the run as ANALYSIS_INCOMPLETE. A failed API
call does the same, with the HTTP status and nothing else.

## What is not built yet

- **Model output is not yet measured.** Tests use a fake transport. Accuracy against real findings needs a benchmark run
  with the key, which has not been done.
- **No attack-path tools.** Interprocedural data flow, route discovery and authorisation analysis are not implemented.
- **No dynamic testing.** The `dynamic` and `runtime` evidence kinds exist, but no tool produces them yet.
- **No advisory research tool, dependency tool or configuration tool** inside the loop.
- **No benchmark.** Precision and recall against ground truth are not measured yet.

## Known limits of this slice

- A blank line can't be cited. An excerpt must be the text of its line.
- `search_source` is a literal text search. It can't tell a call from a comment or a string.
- The offline planner always ends at UNKNOWN for a source finding. That is the correct result without a model, not a gap
  to hide.
