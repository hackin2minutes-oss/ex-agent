# Remediation performance report (F-01 call graph)

## What was measured

`engine.callgraph.build(root)` on synthetic Python projects from
`tests/test_callgraph_scale.make_project(files)`. Each file has 30 functions. The
project contains one Flask route, so a 4,000-file project has 120,001 candidate function
nodes.

- **Before**: the `engine/callgraph.py` at `HEAD` (commit `f240aee`), loaded from a copy
  in the scratchpad. Its node cap is 5,000.
- **After**: the working tree version in this change. Its limits are 50,000 nodes and
  250,000 edges.
- Each figure is the median of 3 runs, in one process, on the same machine. Peak memory
  is from `tracemalloc` for the build call only. Timings are wall-clock.

The measurement was an inline Python script, not committed. It imports `make_project`
from `tests/test_callgraph_scale.py`, loads the old module from `git show HEAD:engine/callgraph.py`,
and times `build()` with `time.perf_counter` and `tracemalloc`.

## Results

| Files | Version | Median time | Peak memory | Nodes | Edges | Complete | Reason |
|---|---|---|---|---|---|---|---|
| 100 | before | 0.24 s | 2.9 MB | 3,001 | 3,001 | yes | |
| 100 | after | 0.24 s | 2.9 MB | 3,001 | 3,001 | yes | |
| 1,000 | before | 2.36 s | 19.7 MB | 30,001 | **0** | (reported as complete) | edges dropped |
| 1,000 | after | 2.76 s | 28.2 MB | 30,001 | 30,001 | yes | |
| 4,000 | before | 10.37 s | 77.8 MB | 120,001 | **0** | (reported as complete) | edges dropped |
| 4,000 | after | 9.15 s | 48.1 MB | 50,000 | 49,999 | **no** | `node_limit`, 70,001 nodes skipped |

The old code set a `truncated` flag, but the flag never reached the evidence. Its output
therefore carried no incompleteness signal, and the "complete" entries above mean "no
signal", not "verified complete".

## Interpretation

- **Correctness is the main change.** Before, at ≥1,000 files, the call graph had no
  edges, so every path query returned "no path". After, the edges are kept, and an
  incomplete graph is labelled with the reason.
- **Time.** At 1,000 files the new build is about 17% slower (2.36 s to 2.76 s). Edge
  creation now runs for every retained call, where the old code stopped early. At 4,000
  files the new build is about 12% faster (10.37 s to 9.15 s), because it stops collecting
  nodes at the 50,000 cap. The old code built all 120,001 nodes.
- **Memory.** The new build uses less memory at 4,000 files (48 MB against 78 MB), because
  it stops at the node cap. At 1,000 files it uses about 43% more (28 MB against 20 MB),
  because it now stores 30,001 edges where the old code stored none.
- **Scale limit.** The 4,000-file case exceeds the 50,000-node default and is incomplete by
  design. The report states that. Raising `MAX_NODES` is a configuration decision with a
  memory cost. It is not required for correctness.

## Path search

`paths_to` is bounded by `MAX_DEPTH=8`, `MAX_PATHS=20` and `MAX_EXPANSIONS=200,000`. It
stops at any of these and reports `search_complete=false`. The scale tests run the search
on the 100-, 1,000- and 2,000-file projects. Timings for the search itself were not
separately recorded in this sprint, and the bound is a hard cap of 200,000 expansions.

## Caveats

- These are single-machine measurements on synthetic code with uniform fan-out. Real
  repositories have different call density. The numbers show the shape of the change,
  not a production benchmark.
- The earlier figures in the audit trail (60,000 nodes, 1.21 s before; 50,000 nodes,
  1.71 s after, on a 4,001-file project) used a different parameterisation. They are
  superseded by the table above. The 4,000-file case here has 120,001 nodes before
  because each file has 30 functions.
- GitHub-hosted runner timings are not measured. CI does not record a timing for this
  step.

## Not measured

- Precondition check time. The Python `ast` pass parses each matching file once per
  check. Each Go and JavaScript check reads each matching file once. Neither was timed.
- CodeQL query time. Not run.

## Second pass (final code, same machine)

Measured again after the verification pass. The graph code had not changed since the first
measurement. Only the reporting path changed. Three runs each, median time, peak memory
from `tracemalloc`:

| Files | Median time | Peak memory | Nodes | Edges | Complete | Reasons | Skipped nodes |
|---|---|---|---|---|---|---|---|
| 100 | 0.24 s | 2.9 MB | 3,001 | 3,001 | yes | none | 0 |
| 1,000 | 2.71 s | 28.2 MB | 30,001 | 30,001 | yes | none | 0 |
| 2,000 | 5.69 s | 47.7 MB | 50,000 | 49,999 | no | node_limit | 10,001 |
| 4,000 | 9.06 s | 48.0 MB | 50,000 | 49,999 | no | node_limit | 70,001 |

The scale test module (13 tests, 100 to 4,000 files) ran in 5.4 s of wall time.
The 2,000-file row is new in this report. Its build is bounded by the same 50,000-node cap
as the 4,000-file row, which is why the two peak-memory figures are close.
