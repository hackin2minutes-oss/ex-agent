# Deployment and runtime context, `sawone-context-1`

SAWONE assesses the repository alone when no context is given. A context document adds what the repository cannot
show: where the application is exposed, what identities it runs as, which images it deploys, and what the runtime
observed. Each field is optional. A field that is not given is **unknown**, never assumed safe or exposed.

Pass a document with `--context <file>`. The formal shape is in
[`schemas/sawone-context-1.schema.json`](schemas/sawone-context-1.schema.json). The loader in
`engine/deployment_context.py` enforces the rules the engine depends on: the schema version, the allowed keys, the
exposure and outcome values, the required ids and locations, and duplicate ids.

## Example

This document is loaded by the tests, so it stays valid.

```json
{
  "schema": "sawone-context-1",
  "applications": [
    {"id": "mystore-web", "name": "MyStore web app", "repository": "hackin2minutes-oss/MyStore"}
  ],
  "environments": [
    {"id": "prod", "name": "production", "kind": "production"}
  ],
  "endpoints": [
    {
      "id": "ep-search",
      "application": "mystore-web",
      "route": "/search",
      "method": "GET",
      "exposure": "public",
      "handler": {"file": "Controllers/SearchController.cs", "symbol": "Search"},
      "authentication": {"required": false, "mechanism": "none"}
    }
  ],
  "workloads": [
    {
      "id": "wl-web",
      "environment": "prod",
      "kind": "container",
      "image": "mystore/web:1.4",
      "image_digest": "sha256:4f2c0b7d8e9a1c3f5b6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b",
      "running": true,
      "exposed_ports": [8080]
    }
  ],
  "identities": [
    {
      "id": "id-db",
      "kind": "service_account",
      "permissions": ["db:read"],
      "secret_refs": [{"file": "appsettings.json", "line": 12}]
    }
  ],
  "ci_workflows": [
    {"id": "ci-deploy", "path": ".github/workflows/deploy.yml", "deploy_credentials": ["AZURE_CREDENTIALS"]}
  ],
  "runtime_observations": [
    {
      "id": "obs-2026-10-29-1",
      "time": "2026-10-29T10:00:00Z",
      "source": "request tracer",
      "file": "Controllers/SearchController.cs",
      "line": 16,
      "symbol": "Search",
      "route": "/search",
      "outcome": "reached"
    }
  ],
  "runtime_protection_events": [
    {"id": "rasp-1", "time": "2026-10-29T10:00:01Z", "action": "blocked", "file": "Controllers/SearchController.cs", "line": 16, "rule": "sql-injection"}
  ],
  "x-acme-cmdb": {"owner": "store-team"}
}
```

## Sections

| Section | What it says | Used for |
|---|---|---|
| `applications`, `environments` | inventory and environment kind | labels only in this version |
| `endpoints` | a route, its handler file and symbol, `exposure` (`public`, `private`, `unknown`), authentication | exposure of a finding in that handler; the `handled_by` and `guarded_by` edges |
| `workloads` | a running container or VM, its environment, `image_digest` | `runs_in` edges to a container finding with the same digest |
| `resources` | a cloud or infrastructure resource and whether it is public | `configures` edges to an IaC finding with the same resource id |
| `identities` | a principal, its permissions, and the exact file and line of secrets it uses | `credential_of` edges to a secret finding at the same file and line |
| `ci_workflows` | a workflow file and the deploy credentials it uses | `deploys_with` edges to a CI/CD finding in the same file |
| `security_controls`, `mitigations` | controls that apply to endpoints, and mitigations recorded against findings | recorded; not yet used in verdicts |
| `runtime_observations` | a runtime event at a file and line, with `outcome` `reached`, `not_reached` or `error` | raises `reachable` and `runtime_observed` to CONFIRMED when `reached` |
| `runtime_protection_events` | an action a runtime protection tool took at a file and line | recorded; not yet used in verdicts |

## Rules

- A field that is not given is unknown. An undeclared endpoint does not make a finding internal or public.
- Exposure is `public` (reported as `internet`) or `private` (reported as `internal`). Anything else is `unknown`.
- A runtime observation only adds evidence. It cannot lower a verdict, and it cannot make a finding
  CONFIRMED_EXPLOITABLE on its own, because preconditions still need their own evidence.
- Links are made only on exact keys: the same file and line, the same image digest, the same resource identifier, the
  same handler file and symbol. A shared filename or package name is not a link.
- Keys that start with `x-` are kept and ignored. Any other unknown key is refused.

## Versioning

The version is the `schema` value. A new version adds a new value and a new loader; a version 1 document keeps
working. A document with another value is refused, not guessed at.
