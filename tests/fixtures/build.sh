#!/bin/sh
# Compiles a fixture project so CodeQL can extract it. Usage: build.sh [app|taint-control]
# SPRING_LIBS, when set, is a directory of jars put on the classpath, so Spring
# annotations resolve and CodeQL can model remote input. CodeQL runs this from the
# project directory, so the script locates its own directory first.
HERE="$(cd "$(dirname "$0")" && pwd)"
TARGET="${1:-app}"
OUT="${TMPDIR:-/tmp}/fixture-classes-$TARGET"
mkdir -p "$OUT"
cd "$HERE/$TARGET" || exit 0
if [ -n "$SPRING_LIBS" ]; then
  javac -cp "$SPRING_LIBS/*" -d "$OUT" $(find . -name '*.java') || true
else
  javac -d "$OUT" $(find . -name '*.java') || true
fi
