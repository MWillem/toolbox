#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$SCRIPT_DIR"

ensure_install() {
    if [ ! -x ".venv/bin/python" ] ||
        ! .venv/bin/python -c 'import sys; raise SystemExit(sys.version_info < (3, 10))' >/dev/null 2>&1; then
        sh install.sh
    fi
}

while :; do
    printf '\n%s\n' "=========================================="
    printf '%s\n' "  recon SC - lanceur local"
    printf '%s\n' "=========================================="
    printf '%s\n' "1. Ouvrir l'interface GUI"
    printf '%s\n' "2. Ouvrir le mode CLI"
    printf '%s\n' "3. Installer ou reparer"
    printf '%s\n' "4. Verifier les mises a jour Git"
    printf '%s\n' "0. Quitter"
    printf '\n%s' "Choix : "
    read -r choice

    case "$choice" in
        1)
            ensure_install
            sh gui.sh
            ;;
        2)
            ensure_install
            sh run.sh
            ;;
        3)
            sh install.sh
            ;;
        4)
            if ! command -v git >/dev/null 2>&1; then
                printf '%s\n' "Git n'est pas disponible sur ce systeme."
                continue
            fi
            git fetch
            git status -sb
            printf '%s' "Faire git pull maintenant ? [o/N] "
            read -r update_choice
            case "$update_choice" in
                o|O|oui|Oui|OUI) git pull ;;
            esac
            ;;
        0)
            exit 0
            ;;
    esac
done
