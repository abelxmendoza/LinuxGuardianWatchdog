#!/usr/bin/env bash
# Launcher used by the .desktop entry — ensures the module is run with the
# right working directory regardless of where it's invoked from.
cd "$(dirname "$(readlink -f "$0")")" || exit 1
exec python3 -m linuxguardian_ui.main "$@"
