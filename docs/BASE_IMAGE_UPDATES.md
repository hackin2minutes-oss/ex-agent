# Base image: digest pin and update process

The `Dockerfile` builds from `python:3.13-slim` pinned by digest:

```
FROM python:3.13-slim@sha256:2d44738ebf4ce5f63b9d9ea871e9c7cfdc0426f7b0c97cac915fd88ded1d86bb
```

The digest is the OCI image index from Docker Hub's official `library/python` repository. It
covers `linux/amd64` and `linux/arm64`. A tag such as `3.13-slim` can move to new content.
The digest cannot, which is why the build pins it.

## How the digest is verified

`scripts/verify_base_image.sh` reads the `FROM` line, fetches the manifest **by digest**
from `registry-1.docker.io` with an anonymous pull token, and recomputes its SHA-256. The
script passes only if the body hashes to the pinned digest. It needs no Docker daemon.
It fails if the `FROM` line has no digest, if the registry returns an error other than rate
limiting or a server error, or if the body does not match. Rate limits and 5xx responses are
retried with backoff.

CI runs the script in the Action job before the image is built. The same job then builds the
image, checks that it runs as UID 1001, checks that it runs Python 3.13, and checks that it
can write the report. Those checks confirm compatibility with the existing build.

## Updating the digest

Do this when you want a newer base image, for example for a security fix in Python or Debian.

1. Find the new digest. Either use `docker buildx imagetools inspect python:3.13-slim` and copy
   the manifest digest, or fetch the index for the tag and hash it as the script does.
2. Put the new digest in the `FROM` line. Keep the tag in the reference for readability.
3. Run `sh scripts/verify_base_image.sh` locally. It must print `OK`.
4. Open a pull request. CI runs the digest check, the image build, the UID check and the
   Python version check. Do not merge if any of them fails.
5. If the Python minor version changes, update the version check in
   `.github/workflows/ci.yml` as well. The check asserts `3.13`.

## Limits

- The script verifies that the pinned digest matches the content the registry serves for
  it. It does not check the registry's publisher signature. Docker Hub's official images are
  not signed by a key this repository verifies.
- Nothing alerts when the tag moves. Updates are manual, on the cadence above. Dependabot's
  Docker ecosystem can propose digest updates; it is not enabled by this change, because it
  needs repository settings.
- The script's test hook (`VERIFY_BODY_FILE`) is for tests only. It skips the registry and
  verifies a saved manifest body instead.
