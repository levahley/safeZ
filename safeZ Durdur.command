#!/bin/sh
cd "$(dirname "$0")" || exit 1
PYTHON_BIN="${KANIT_PYTHON:-python3}"
if "$PYTHON_BIN" launcher.py stop; then
  exit 0
fi
printf '\nPencereyi kapatmak için Enter tuşuna basın.\n'
read -r answer
exit 1
