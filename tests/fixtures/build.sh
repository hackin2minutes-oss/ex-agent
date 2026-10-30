#!/bin/sh
# Compiles the fixture sources so CodeQL can extract them. Spring jars are not on the
# classpath, so javac reports errors; extraction still records every file, so errors are ignored.
# CodeQL runs this from the project directory, so the script works from its own location.
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${TMPDIR:-/tmp}/fixture-classes"
mkdir -p "$OUT"
cd "$HERE/app" && javac -d "$OUT" $(find . -name '*.java') || true
