#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$SCRIPT_DIR"

printf '\n%s\n' "=========================================="
printf '%s\n' "  Installation Cyber Learning Toolbox"
printf '%s\n\n' "=========================================="

if command -v python3 >/dev/null 2>&1 &&
    python3 -c 'import sys; raise SystemExit(sys.version_info < (3, 10))'; then
    PYTHON=python3
elif command -v python >/dev/null 2>&1 &&
    python -c 'import sys; raise SystemExit(sys.version_info < (3, 10))'; then
    PYTHON=python
else
    printf '%s\n' "Python 3.10 ou plus récent est introuvable."
    if [ -n "${TERMUX_VERSION:-}" ] || printf '%s' "${PREFIX:-}" | grep -q 'com.termux'; then
        printf '%s\n' "Installez-le avec : pkg install python nmap"
    else
        printf '%s\n' "Installez Python 3.10 ou plus récent avec le gestionnaire de votre système."
    fi
    exit 1
fi

if [ -x ".venv/bin/python" ] && ! .venv/bin/python --version >/dev/null 2>&1; then
    printf '%s\n' "L'ancien environnement virtuel est inutilisable. Reconstruction..."
    rm -rf "$SCRIPT_DIR/.venv"
fi

if [ ! -x ".venv/bin/python" ]; then
    printf '%s\n' "Création de l'environnement virtuel..."
    "$PYTHON" -m venv .venv
fi

.venv/bin/python -m cybertoolbox --version

printf '\n%s\n' "Installation terminée."
printf '%s\n' "Lancez ensuite : ./run.sh"
