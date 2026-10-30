#!/bin/sh
# Compiles a fixture project so CodeQL can extract it. Usage: build.sh [app|taint-control]
# Spring jars are not on the classpath, so javac reports errors; extraction still records
# every file, so errors are ignored. CodeQL runs this from the project directory, so the
# script works from its own location.
HERE="$(cd "$(dirname "$0")" && pwd)"
TARGET="${1:-app}"
OUT="${TMPDIR:-/tmp}/fixture-classes-$TARGET"
mkdir -p "$OUT"
cd "$HERE/$TARGET" && javac -d "$OUT" $(find . -name '*.java') || true
