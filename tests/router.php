<?php
/**
 * Routeur du serveur web intégré de PHP pour les tests (php -S … -t <glpi>/public tests/router.php).
 * Sert les fichiers statiques, envoie tout le reste au contrôleur frontal de GLPI.
 */
$root = rtrim((string) $_SERVER['DOCUMENT_ROOT'], '/');
$path = (string) parse_url((string) $_SERVER['REQUEST_URI'], PHP_URL_PATH);
if ($path !== '/' && is_file($root . $path) && !str_ends_with($path, '.php')) {
    return false;
}
$_SERVER['SCRIPT_NAME']     = '/index.php';
$_SERVER['SCRIPT_FILENAME'] = $root . '/index.php';
require $root . '/index.php';
