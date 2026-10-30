# Remediation security review

Scope: the changes in this sprint (F-01 to F-08). The review asks what each change
trusts, what an attacker who controls the scanned repository or a pull request can do
through it, and what remains. It is a review of this change, not a penetration test.

## Trust boundaries

| Input | Who controls it | Used by |
|---|---|---|
| Scanned repository source (`*.py`, `*.go`, `*.js`, `*.ts`) | Any author of the analysed code, including a pull request author | Call graph, precondition checks, CodeQL database |
| Workflow inputs (`exposure`, `fail-on`, `rules-dir`) | Whoever edits the workflow file. A pull request can change it | Verdict gate, rule loading |
| Curated rules (`rules/*.json`) | Maintainers of this project, through review | Symbols, preconditions, affected ranges |
| Container user and image contents | This project | Runtime identity, write access to the workspace |
| Action references (`uses:`) | Upstream publishers, until pinned | Code executed in CI |

## Findings from this review

### 1. Exposure is an operator claim, and a pull request can make it

`exposure: internet` is what allows `confirmed_exploitable`. The value comes from the
workflow file. A pull request that edits the workflow can set it. That is the same trust
the repository already gives its workflow files, so it is not a new privilege. It does
mean that a pull request author can make the engine report a higher verdict, and the gate
can then fail or pass a build on that basis.

**Mitigation in place.** The default is `unknown`, which never yields the top verdict. The
README says exposure is the operator's declaration.

**Recommendation.** Set `exposure` in a workflow that is taken from the default branch, or
pass it through a protected environment, rather than leaving it to pull request content.
This is a configuration recommendation to the consuming repository and is not enforced by
the engine.

### 2. Precondition checks are not a sanitiser proof

The Python check treats `int()`, `secure_filename()`, `html.escape()` and similar calls as
`unknown`, never as `constant` or `request`. The Go and JavaScript checks are lexical. A
name assigned from a request accessor is treated as tainted for the whole file. Two
outcomes follow:

- **False negative (safe side).** A real flow through a helper function or a
  cross-function alias is `unverified`. It cannot produce a false `satisfied`.
- **False positive (unsafe side).** A same-named variable in another function of the same
  file can be tainted incorrectly. That can yield `satisfied`. Because `satisfied` alone
  does not produce `confirmed_exploitable`, the verdict still needs taint confirmed by
  CodeQL, an entry point, mitigation absent, and declared internet exposure. The
  false-positive path needs all of those to hold.

**Residual.** A false `satisfied` on the lexical path is possible. It is accepted because
the lexical path is the fallback when CodeQL is unavailable, and it can only contribute
to a verdict when the text-scan mode is not used for taint. Note: the text-scan path does
not set taint confirmed, so it cannot reach `confirmed_exploitable` regardless of
preconditions.

### 3. Hostile source files and the parser

The engine parses repository files with `ast.parse` and with regular expressions. A file
can be crafted to be expensive or to break the parser.

- **Syntax errors, NUL bytes.** Handled as `UNKNOWN`/parse errors in both the call graph
  and the precondition checks. Covered by tests (`test_unparseable_file_is_unverified`,
  `test_nul_byte_in_source_is_unverified_not_a_crash`).
- **Deep nesting.** A flat chain of 3,000 operators parses, and the classifier would
  recurse that deep. This was found by probing the parser and reading the classifier. The first
  version did not guard it. The classifier now catches `RecursionError` and returns `unknown`.
  Covered by `test_pathologically_deep_argument_is_unknown_not_a_crash`.
- **Call graph size.** Node and edge caps are enforced during construction. The path search
  has depth, path and expansion caps. A large or adversarial repository is reported as
  incomplete, not allowed to exhaust memory. Measured: 4,000 files stop at the node cap.
- **Regular expressions.** The lexical patterns are linear in line length, with no nested
  quantifiers. No backtracking test was run on the `_ASSIGN` or request-accessor patterns.

**Residual.** No fuzzing was run. Memory use of `ast.parse` on a very large single file is
bounded only by the runner's limits.

### 4. Non-root container

The container now runs as UID 1001. This limits what a compromised analysis can change on
the runner: it cannot write to system paths or install packages. It can still write to the
mounted workspace, which is the intended output location.

**Residual.** The container has not been run here, so this is a configuration claim until
the CI step passes. The image installs from `requirements.txt`. Hash pinning was not checked.

### 5. Action pinning

Actions are pinned to commit SHAs. The pins were resolved by `git ls-remote` against the
remote at the time of the change. Pinning protects against an upstream tag being moved. It
does not verify that the commit is trustworthy. Two references are not pinned:

- `hackin2minutes-oss/exploitability-agent@v1` in `examples/exploitability.yml`. This is
  this project's own wrapper. It is a tag and can move.
- `docker://ghcr.io/hackin2minutes-oss/exploitability-agent:v0.3.0` in the wrapper
  repository, which is a tag and not a digest.

**Residual.** Those two references. Digest pinning for the base image
`python:3.13-slim` is also not done.

### 6. Rules and placeholders

The placeholder rule was removed from `rules/` (F-06), and a test blocks future
placeholder identifiers there. The synthetic fixture is used only by tests, and its
location is declared in `tests/support.py`.

**Residual.** The four real rules were not re-verified against their advisories in this
change. A mistaken affected range would produce a wrong `not_affected` (F-04). The
curated fixed-version data is the trust anchor for that verdict.

### 7. Secrets

The repository was scanned for GitHub personal access token patterns (`ghp_`,
`github_pat_`) and AWS access key patterns (`AKIA`). No matches were found. The
token the user pasted earlier in the engagement was not written to the repository. The
user reports it deleted; the revocation has not been confirmed from here.

## Verification performed

- `yaml.safe_load` on all changed workflow and action files.
- Token-pattern scan on the tracked tree.
- Adversarial inputs: NUL byte, deep nesting, syntax errors, unclosed Go calls, and
  constant and sanitised arguments. All tests pass.
- Full unit suite, 246 tests, passing.

## Not verified

- CodeQL taint and call-site behaviour on the changed rules (CI only).
- Image build, non-root runtime and report writing in the container (CI only).
- Fuzzing of the parser and regex paths.
- Dependency pinning with hashes.

## Conclusion

No finding in this review changes the status recorded in `REMEDIATION_REPORT.md`. The
residual risks above are the reason F-02, F-03, F-07 and F-08 are PARTIALLY_FIXED rather
than FIXED.

## Follow-up PR 1: changes and residual risk

- **Hash-locked dependencies.** The engine, the image and CI install from
  `requirements.lock`, with SHA-256 hashes for every package. A changed or substituted
  artifact fails the install. The lock-currency check regenerates the lock in CI with a
  pinned `pip-tools` (7.6.2), so an edited `requirements.txt` without a matching lock fails
  the build.
- **Residual:** the lock-currency step installs `pip-tools` by version, not by hash. That
  tool runs in CI only and is not in the engine or the image. Pinning it by hash is a
  follow-up.
- **Summary and SARIF.** The new `analysis` block and the SARIF notifications only report
  completeness. They don't change what the engine decides, so they add no trust boundary.
  No custom SARIF properties are used.
- **Still open:** the Code Scanning result is unverified (HTTP 403 from the API), and the
  wrapper repository has not been checked.
