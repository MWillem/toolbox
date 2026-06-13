#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$SCRIPT_DIR"

if [ ! -x ".venv/bin/python" ] ||
    ! .venv/bin/python -c 'import sys; raise SystemExit(sys.version_info < (3, 10))' >/dev/null 2>&1; then
    printf '%s\n' "La toolbox n'est pas encore installée. Lancement de install.sh..."
    sh install.sh
fi

exec .venv/bin/python -m cybertoolbox "$@"
