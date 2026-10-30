#!/bin/sh
# Compiles the fixture sources so CodeQL can extract them. Spring jars are not on the
# classpath, so javac reports errors; extraction still records every file, so errors are ignored.
OUT="${TMPDIR:-/tmp}/fixture-classes"
mkdir -p "$OUT"
javac -d "$OUT" $(find tests/fixtures/app -name '*.java') || true
