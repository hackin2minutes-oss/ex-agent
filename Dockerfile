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

WORKDIR /opt/exploitability
COPY engine ./engine
COPY queries ./queries
COPY rules ./rules

# The engine loads only from /opt/exploitability. -P stops Python from putting the
# scanned workspace on sys.path, so a file planted in the repository cannot shadow it.
ENV PYTHONPATH=/opt/exploitability
ENTRYPOINT ["python3", "-P", "-m", "engine"]
