#!/bin/sh
set -eu
cd "$(dirname "$0")"
PYTHON_BIN="${KANIT_PYTHON:-python3}"
if ! "$PYTHON_BIN" -c 'import reportlab' >/dev/null 2>&1; then
  BUNDLED_PYTHON="$HOME/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3"
  if [ -x "$BUNDLED_PYTHON" ] && "$BUNDLED_PYTHON" -c 'import reportlab' >/dev/null 2>&1; then
    PYTHON_BIN="$BUNDLED_PYTHON"
  else
    if [ ! -x .venv/bin/python ]; then
      "$PYTHON_BIN" -m venv .venv
    fi
    .venv/bin/python -m pip install --disable-pip-version-check -r requirements.txt
    PYTHON_BIN=".venv/bin/python"
  fi
fi
exec "$PYTHON_BIN" run.py "$@"
