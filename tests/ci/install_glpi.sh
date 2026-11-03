#!/usr/bin/env bash
# install_glpi.sh <version> <dossier> <base> : télécharge GLPI, installe la base (anglais, sans télémétrie).
set -euo pipefail
VERSION=$1; DIR=$2; DB=$3
DB_HOST=${DB_HOST:-127.0.0.1}; DB_USER=${DB_USER:-root}; DB_PASSWORD=${DB_PASSWORD:-root}
mkdir -p "$DIR"
curl -fsSL "https://github.com/glpi-project/glpi/releases/download/${VERSION}/glpi-${VERSION}.tgz" | tar xz -C "$DIR" --strip-components=1
php "$DIR/bin/console" database:install --no-interaction --no-telemetry \
  --db-host="$DB_HOST" --db-user="$DB_USER" --db-password="$DB_PASSWORD" --db-name="$DB" --default-language=en_GB
