#!/usr/bin/env bash
# install_plugin.sh <dossier GLPI> <source du plugin> : copie, installe (ou met à jour) et active SecIncident.
set -euo pipefail
GLPI=$1; SRC=$2
rm -rf "$GLPI/plugins/secincident"
mkdir -p "$GLPI/plugins/secincident"
(cd "$SRC" && tar cf - --exclude=.git .) | tar xf - -C "$GLPI/plugins/secincident"
php "$GLPI/bin/console" ${CONSOLE_FLAGS:-} --no-interaction plugin:install --force --username=glpi secincident
php "$GLPI/bin/console" ${CONSOLE_FLAGS:-} --no-interaction plugin:activate secincident
# Les gabarits Twig compilés de l'ancienne version restent en cache (constaté sous GLPI 11.0.4)
php "$GLPI/bin/console" ${CONSOLE_FLAGS:-} --no-interaction cache:clear
php "$GLPI/bin/console" ${CONSOLE_FLAGS:-} --no-interaction plugin:list | grep -i secincident
