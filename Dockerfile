FROM python:3.13-slim

# Optional CodeQL CLI. Leave CODEQL_VERSION empty to build without it; the engine
# then reports call sites through its text-scan fallback. Set it to a release tag
# you have tested (not verified in this repository's build environment).
ARG CODEQL_VERSION=""
RUN if [ -n "$CODEQL_VERSION" ]; then \
      apt-get update && apt-get install -y --no-install-recommends unzip curl ca-certificates \
      && curl -sSLf -o /tmp/codeql.zip \
         "https://github.com/github/codeql-cli-binaries/releases/download/v${CODEQL_VERSION}/codeql-linux64.zip" \
      && unzip -q /tmp/codeql.zip -d /opt \
      && rm -rf /tmp/codeql.zip /var/lib/apt/lists/*; \
    fi
ENV PATH="/opt/codeql:${PATH}"

# Run as a fixed non-root UID. 1001 matches the owner of the GitHub-hosted runner
# workspace, so the engine can write the report into it. The numeric USER lets
# Kubernetes-style runAsNonRoot checks verify it without resolving the name.
RUN groupadd --system --gid 1001 engine \
    && useradd --system --uid 1001 --gid 1001 --no-create-home --shell /usr/sbin/nologin engine

WORKDIR /opt/exploitability
COPY requirements.lock ./requirements.lock
# Installs only the pinned artifacts whose SHA-256 hashes are listed in requirements.lock.
RUN pip install --no-cache-dir --require-hashes -r requirements.lock
COPY engine ./engine
COPY queries ./queries
COPY rules ./rules

# The engine loads only from /opt/exploitability. -P stops Python from putting the
# scanned workspace on sys.path, so a file planted in the repository cannot shadow it.
ENV PYTHONPATH=/opt/exploitability
USER 1001:1001
ENTRYPOINT ["python3", "-P", "-m", "engine"]
