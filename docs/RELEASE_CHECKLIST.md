# Release checklist

Nothing in this list has been run against production. Items marked **manual** need credentials or
approval that the engineering work does not have.

## 1. Verify the source (done in this branch)

- [ ] `python3 -m pytest -q` passes on the release commit. Last run: 491 passed.
- [ ] `python3 -m pyflakes engine tests` is clean for the modules this release adds.
- [ ] Repository secret scan: `gitleaks detect --source . --no-git --redact` reports no findings
      outside `.gitleaksignore`. The ignored findings are the fabricated key used by the secrets tests.
- [ ] SARIF produced by the release validates against the OASIS 2.1.0 schema
      (`python3 scripts/audit_validate_sarif.py SCHEMA.json universal-report/universal.sarif`).

## 2. Build the image

```sh
docker build -t sawone:RELEASE_TAG .
```

- Base image: `python:3.13-slim` pinned by digest in the `Dockerfile`. Dependencies are installed with
  `--require-hashes` from `requirements.lock`.
- Verified here (local, not a release): the build needed the sandbox proxy CA, so it was built from a
  test-only context that adds that CA. The repository Dockerfile was not changed. A build on a normal
  network needs no change.
- [ ] Run as non-root: `docker run --rm --entrypoint id sawone:RELEASE_TAG` shows uid 1001.
- [ ] Universal smoke test on a mounted workspace:
      `docker run --rm --user 1001:1001 -v "$PWD":/github/workspace -w /github/workspace --entrypoint python3 sawone:RELEASE_TAG -P -m engine.universal_run --inputs REPORT --project-dir . --output-dir out --offline true`
- [ ] SCA smoke test (default entry point, unchanged behaviour):
      `docker run --rm --user 1001:1001 -v "$PWD":/github/workspace -w /github/workspace sawone:RELEASE_TAG --project-dir . --output-dir out --offline true`

## 3. The action

- `action.yml` at the repository root is the SCA action, unchanged except for the rules-directory
  default, which now means the rules shipped with the image.
- `universal/action.yml` is the universal action. It uses `image: ../Dockerfile`.
  **Unverified:** whether GitHub accepts a relative `../` image path for an action in a subdirectory.
  If it does not, move the action definition or publish the image and reference it by digest.
- [ ] Run `universal/action.yml` in a test repository on GitHub. **Manual** (needs a GitHub run).

## 4. Publish (manual)

These steps need production credentials and the `production` environment approval. The engineering
work did not perform them.

- [ ] **Manual:** the `publish-image.yml` workflow runs on `workflow_dispatch` under the `production`
      environment. A reviewer must approve it.
- [ ] **Manual:** push the image to the registry with its digest recorded. Pin the digest in
      `action.yml` and `universal/action.yml`.
- [ ] **Manual:** create a Marketplace release. Do not move or delete an existing tag (see section 5).
- [ ] **Manual:** check the listing description and the usage example against the release.

## 5. The `v1` tag (inspect before any change)

`v1` on `hackin2minutes-oss/hackin2minutes-oss-exploitability-action` points at
`47398c26df0e688e73f817359c3fdce7c4ca6bcf`, the engine v0.3.0 release. Consumers who pin `@v1` get that
code. Changing it silently would change what they run.

Safest migration:
1. Keep `v1` as it is. Do not move or delete it.
2. Release the universal action under a new major tag (for example `v2`), with its own listing notes.
3. Say in the `v1` release notes that `v2` is the current action, and what changed.
4. Only if the owner decides to move `v1`, do it as an explicit, announced change, and never force-push
   a tag that consumers already use.

## 6. Credentials

- [ ] **User action:** a GitHub token pasted earlier in this project was reported deleted. Its
      revocation has not been confirmed from the session. Confirm it is revoked.

## 7. Known limits to state in the release notes

- SAST is call-site level, not dataflow. IaC has no resource graph. Container analysis does not look at
  runtime settings.
- IAST and RASP are implemented and tested on **synthetic** evidence only. No real agent output was
  assessed.
- Secret validity is not checked. Gitleaks findings say where a value is, not whether it works.
- Grype and Trivy vulnerability results depend on the database used. The databases came from public
  mirrors in the build environment.
- All reports in one run share one project directory.
