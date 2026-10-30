# Policy Engine

Pass a policy file with `--policy` or the action input `policy-file`. When a policy is supplied, it decides the gate, and `fail-on` is ignored.

```yaml
version: 1
exploitability:
  confirmed_exploitable:
    critical: block
    high: block
    medium: block
  potentially_exploitable:
    critical: block
    high: warn
    medium: warn
  reachable_preconditions_unknown:
    action: warn
  vulnerable_component_only:
    action: report
  not_reachable_within_analysed_scope:
    action: report
  unknown:
    action: warn
  analysis_failed:
    action: warn
intelligence:
  kev:
    increase_priority: true
```

## Rules

- Actions are `block`, `warn` or `report`.
- A classification can have one action for every severity, or a single `action`.
- Severity comes from the curated rule. A finding without a severity is treated as `unknown`, which defaults to `warn`.
- Any classification not listed defaults to `report`.
- Unknown top-level keys, unknown classifications, unknown severities and invalid actions are rejected. The run stops with an error.
- `block` on any finding fails the gate.

## Not implemented

- Suppressions and exceptions with expiry and justification.
- Repository and organisation policy layering, and workflow overrides.
- `intelligence.epss` and `intelligence.stale_data` are accepted by the validator but have no effect yet. `kev.increase_priority` sets `priority: elevated` on the finding; it does not change the action.
- Audit logs of policy decisions beyond the decision recorded in each finding.
