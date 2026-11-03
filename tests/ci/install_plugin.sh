#!/usr/bin/env bash
# install_plugin.sh <dossier GLPI> <source du plugin> : copie, installe (ou met à jour) et active SecIncident.
set -euo pipefail
GLPI=$1; SRC=$2
rm -rf "$GLPI/plugins/secincident"
mkdir -p "$GLPI/plugins/secincident"
(cd "$SRC" && tar cf - --exclude=.git .) | tar xf - -C "$GLPI/plugins/secincident"
php "$GLPI/bin/console" --no-interaction plugin:install --force --username=glpi secincident
php "$GLPI/bin/console" --no-interaction plugin:activate secincident
php "$GLPI/bin/console" --no-interaction plugin:list | grep -i secincident
