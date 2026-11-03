#!/usr/bin/env bash
# start_server.sh <dossier GLPI> <port> : serveur web intégré de PHP (plusieurs workers pour les tests de concurrence).
set -euo pipefail
GLPI=$1; PORT=$2
HERE=$(cd "$(dirname "$0")/.." && pwd)
PHP_CLI_SERVER_WORKERS=6 nohup php -S "127.0.0.1:$PORT" -t "$GLPI/public" "$HERE/router.php" > "$GLPI/files/_log/php-server.log" 2>&1 &
echo $! > "$GLPI/files/_log/php-server.pid"
for _ in $(seq 1 30); do
  curl -fs -o /dev/null "http://127.0.0.1:$PORT/" && exit 0
  sleep 1
done
echo "GLPI ne répond pas sur le port $PORT" >&2; exit 1
