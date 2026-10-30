# Contributing

## Running the tests

```sh
pip install --require-hashes -r requirements.lock
PYTHONPATH=. python3 -P -m unittest discover -s tests -t .
```

Tests use recorded provider responses and never call the network. Fixtures live under `tests/fixtures/`.

## Changing the engine

- Keep the stage model and classification rules in `engine/exploitability.py` consistent with `docs/EXPLOITABILITY_MODEL.md`.
- A new classification or stage status needs a table test in `tests/test_exploitability.py`.
- UNKNOWN and ANALYSIS_FAILED must never map to "not reachable". Add a test if you touch that path.

## Adding a vulnerability rule

Rules are JSON files in `rules/`. Each rule needs a source for its symbols and preconditions. Do not add a symbol you cannot cite to an advisory, a patch or a published description.

## Changing CI

`.github/workflows/ci.yml` runs the unit tests, the Docker action and the CodeQL checks. Pin actions to a major version and keep permissions minimal.

## Dependency lock

`requirements.txt` lists the direct dependencies. `requirements.lock` pins every
installed package and its transitive dependencies to a version and SHA-256 hashes.
The image and CI install from the lock with `--require-hashes`.

To change a dependency:

```sh
python3 -m venv .lock-venv && .lock-venv/bin/pip install pip-tools
.lock-venv/bin/pip-compile --generate-hashes --allow-unsafe --strip-extras \
    --output-file requirements.lock requirements.txt
```

Commit `requirements.txt` and `requirements.lock` together. A hashed install without the
matching hashes fails, which is the intended check.
