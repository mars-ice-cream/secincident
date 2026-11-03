<?php
/**
 * Outil de test : recalcule toute la chaîne du journal d'audit, comme le ferait
 * un attaquant ayant accès à la base (même formule que AuditLog::computeHash()).
 * Entrée : une ligne par entrée, "id\tHEX(champ1)\t…\tHEX(champ15)" dans l'ordre des id.
 * Sortie : "id\tprev_hash\thash".
 */
$prev = str_repeat('0', 64);
foreach (preg_split('/\R/', trim((string) stream_get_contents(STDIN))) as $line) {
    if ($line === '') {
        continue;
    }
    $cols = explode("\t", $line);
    $id   = array_shift($cols);
    [$date_utc, $users_id, $user_name, $imp, $profiles_id, $profile_name, $rights, $privilege, $ip, $action, $result, $itemtype, $items_id, $incidents_id, $details]
        = array_map(fn ($h) => (string) hex2bin($h), $cols);
    $hash = hash('sha256', (string) json_encode([
        $prev, $date_utc, (int) $users_id, $user_name, (int) $imp, (int) $profiles_id, $profile_name, (int) $rights,
        $privilege, $ip, $action, $result, $itemtype, (int) $items_id, (int) $incidents_id, $details,
    ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
    echo $id, "\t", $prev, "\t", $hash, "\n";
    $prev = $hash;
}
