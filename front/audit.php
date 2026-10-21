<?php

/**
 * SecIncident — journal d'audit (lecture seule).
 */

use Glpi\Application\View\TemplateRenderer;
use GlpiPlugin\Secincident\AuditLog;
use GlpiPlugin\Secincident\I18n;
use GlpiPlugin\Secincident\Incident;
use Symfony\Component\HttpFoundation\Response;

global $CFG_GLPI;

AuditLog::checkPageAccess([Incident::AUDIT], I18n::instance('audit log'));

$filters = [
    'date_from'    => preg_match('/^\d{4}-\d{2}-\d{2}$/', (string) ($_GET['date_from'] ?? '')) ? $_GET['date_from'] : '',
    'date_to'      => preg_match('/^\d{4}-\d{2}-\d{2}$/', (string) ($_GET['date_to'] ?? '')) ? $_GET['date_to'] : '',
    'users_id'     => (int) ($_GET['users_id'] ?? 0),
    'action'       => (string) ($_GET['action'] ?? ''),
    'result'       => (string) ($_GET['result'] ?? ''),
    'incidents_id' => (int) ($_GET['incidents_id'] ?? 0),
    'ip'           => filter_var($_GET['ip'] ?? '', FILTER_VALIDATE_IP) ?: '',
];
$where = AuditLog::buildCriteria($filters);

// Export CSV (tracé)
if (($_GET['export'] ?? '') === 'csv') {
    $data = AuditLog::fetch($where, 0, 100000);
    AuditLog::record('export_audit', null, ['filtres' => array_filter($filters), 'lignes' => count($data['rows'])]);

    $out = fopen('php://temp', 'r+');
    fwrite($out, "\xEF\xBB\xBF");
    fputcsv($out, ['id', 'date_utc', 'utilisateur', 'users_id', 'identite_empruntee_par', 'profil', 'droits', 'privilege', 'ip', 'action', 'resultat', 'type', 'objet_id', 'incident_id', 'details', 'hash', 'hash_precedent'], ';', '"', '');
    foreach ($data['rows'] as $row) {
        fputcsv($out, [
            $row['id'], $row['date_utc'], $row['user_name'], $row['users_id'], $row['users_id_impersonator'],
            $row['profile_name'], $row['rights'], $row['privilege'], $row['ip'], $row['action'], $row['result'],
            $row['itemtype'], $row['items_id'], $row['incidents_id'], $row['details'], $row['hash'], $row['prev_hash'],
        ], ';', '"', '');
    }
    rewind($out);
    $csv = stream_get_contents($out);
    fclose($out);

    return new Response((string) $csv, 200, [
        'Content-Type'        => 'text/csv; charset=UTF-8',
        'Content-Disposition' => 'attachment; filename="secincident_audit_' . gmdate('Ymd_His') . '.csv"',
        'Cache-Control'       => 'no-store',
    ]);
}

$verification = null;
$data_check   = null;
if (!empty($_GET['verify_all'])) {
    // Journal + toutes les données + tous les fichiers de preuve
    $verification = AuditLog::verifyChain();
    $data_check   = ['incidents' => 0, 'ok' => 0, 'anomalies' => []];
    global $DB;
    $ids = array_merge(
        array_column(iterator_to_array($DB->request(['SELECT' => ['id'], 'FROM' => Incident::getTable()])), 'id'),
        array_column(iterator_to_array($DB->request([
            'SELECT'   => ['incidents_id'],
            'DISTINCT' => true,
            'FROM'     => AuditLog::getTable(),
            'WHERE'    => ['incidents_id' => ['>', 0]],
        ])), 'incidents_id')
    );
    foreach (array_unique(array_map('intval', $ids)) as $incidents_id) {
        $r = GlpiPlugin\Secincident\Integrity::verifyIncident($incidents_id, true);
        $data_check['incidents']++;
        if ($r['ok']) {
            $data_check['ok']++;
        } else {
            $data_check['anomalies'][] = [
                'incident'  => $incidents_id,
                'donnees'   => $r['summary'],
                'preuves'   => $r['evidence_problems'],
                'url'       => Incident::getFormURLWithID($incidents_id),
            ];
        }
    }
    AuditLog::record('verify_integrity', null, [
        'portee'   => 'globale',
        'journal'  => $verification,
        'incidents_verifies' => $data_check['incidents'],
        'incidents_en_anomalie' => array_column($data_check['anomalies'], 'incident'),
    ], ($verification['ok'] && $data_check['anomalies'] === []) ? AuditLog::RESULT_OK : AuditLog::RESULT_ERROR);
} elseif (!empty($_GET['verify'])) {
    $verification = AuditLog::verifyChain();
    AuditLog::record('verify_audit', null, $verification, $verification['ok'] ? AuditLog::RESULT_OK : AuditLog::RESULT_ERROR);
} else {
    AuditLog::record('view_audit', null, ['filtres' => array_filter($filters)]);
}

$limit = 50;
$start = max(0, (int) ($_GET['start'] ?? 0));
$data  = AuditLog::fetch($where, $start, $limit);

$actions = AuditLog::getActions();
$rows    = [];
foreach ($data['rows'] as $row) {
    $details = json_decode((string) $row['details'], true);
    $row['action_label'] = $actions[$row['action']] ?? $row['action'];
    $row['details_pretty'] = is_array($details) && $details !== []
        ? (string) json_encode($details, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)
        : '';
    $row['item_label'] = $row['itemtype'] !== ''
        ? (is_a($row['itemtype'], CommonGLPI::class, true) ? $row['itemtype']::getTypeName(1) : $row['itemtype']) . ($row['items_id'] > 0 ? ' #' . $row['items_id'] : '')
        : '';
    $row['incident_url'] = $row['incidents_id'] > 0 ? Incident::getFormURLWithID($row['incidents_id']) : '';
    $row['impersonator'] = $row['users_id_impersonator'] > 0 ? getUserName($row['users_id_impersonator']) : '';
    $rows[] = $row;
}

$base  = $CFG_GLPI['root_doc'] . '/plugins/secincident/front/audit.php';
$query = array_filter($filters);

Html::header(__('Audit log', 'secincident'), '', 'helpdesk', Incident::class, 'audit');

TemplateRenderer::getInstance()->display('@secincident/audit.html.twig', [
    'rows'         => $rows,
    'total'        => $data['total'],
    'start'        => $start,
    'limit'        => $limit,
    'filters'      => $filters,
    'actions'      => $actions,
    'base_url'     => $base,
    'query'        => $query,
    'prev_url'     => $start > 0 ? $base . '?' . http_build_query($query + ['start' => max(0, $start - $limit)]) : null,
    'next_url'     => $start + $limit < $data['total'] ? $base . '?' . http_build_query($query + ['start' => $start + $limit]) : null,
    'export_url'   => $base . '?' . http_build_query($query + ['export' => 'csv']),
    'verify_url'   => $base . '?' . http_build_query($query + ['verify' => 1]),
    'verify_all_url' => $base . '?' . http_build_query($query + ['verify_all' => 1]),
    'data_check'   => $data_check,
    'verification' => $verification,
]);

Html::footer();
