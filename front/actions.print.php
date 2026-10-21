<?php

/**
 * SecIncident — journal des actions d'investigation / intervention (imprimable).
 */

use Glpi\Application\View\TemplateRenderer;
use GlpiPlugin\Secincident\AuditLog;
use GlpiPlugin\Secincident\I18n;
use GlpiPlugin\Secincident\Incident;
use GlpiPlugin\Secincident\Playbook;
use GlpiPlugin\Secincident\RemediationTask;
use GlpiPlugin\Secincident\TimelineEvent;

AuditLog::checkPageAccess([READ, Incident::READALL], I18n::instance('printing the action log'));

$incident = new Incident();
$id       = (int) ($_GET['id'] ?? 0);
AuditLog::guard($incident, $id, READ, null, I18n::instance('printing the action log'));

global $DB;
$tools   = TimelineEvent::getTools();
$results = TimelineEvent::getResults();
$tasks   = TimelineEvent::getTaskChoices($id);
$actions = [];
$by_user = [];
$by_result = array_fill_keys(array_keys($results), 0);
foreach (
    $DB->request([
        'FROM'  => TimelineEvent::getTable(),
        'WHERE' => [Incident::getForeignKeyField() => $id, 'event_type' => 'action'],
        'ORDER' => ['date ASC', 'id ASC'],
    ]) as $row
) {
    $user = (int) $row['users_id'] > 0 ? getUserName((int) $row['users_id']) : '—';
    $by_user[$user] = ($by_user[$user] ?? 0) + 1;
    $by_result[$row['result']] = ($by_result[$row['result']] ?? 0) + 1;
    $row['user_name']    = $user;
    $row['tool_label']   = $tools[$row['tool']] ?? (string) $row['tool'];
    $row['result_label'] = $results[$row['result']] ?? (string) $row['result'];
    $row['task_name']    = $tasks[(int) $row['plugin_secincident_remediationtasks_id']] ?? '';
    $row['kind']         = 'action';
    $actions[] = $row;
}

// Tâches du plan de remédiation réalisées (ou jugées non applicables),
// qu'une action détaillée ait été consignée ou non
$phases       = Playbook::getPhases();
$task_status  = RemediationTask::getStatuses();
$remediations = 0;
foreach (
    $DB->request([
        'FROM'  => RemediationTask::getTable(),
        'WHERE' => [
            Incident::getForeignKeyField() => $id,
            'status'                       => [RemediationTask::STATUS_DONE, RemediationTask::STATUS_NA],
            'NOT'                          => ['date_done' => null],
        ],
    ]) as $row
) {
    $uid  = (int) $row['users_id_done'];
    $user = $uid > 0 ? getUserName($uid) : '—';
    $by_user[$user] = ($by_user[$user] ?? 0) + 1;
    $remediations++;
    $actions[] = [
        'kind'           => 'remediation',
        'id'             => (int) $row['id'],
        'integrity_hash' => $row['integrity_hash'] ?? '',
        'date'           => $row['date_done'],
        'users_id'       => $uid,
        'user_name'      => $user,
        'target'         => $phases[$row['phase']] ?? (string) $row['phase'],
        'tool'           => '',
        'tool_label'     => (int) $row['is_mandatory'] === 1 ? __('Mandatory step', 'secincident') : '',
        'name'           => (string) $row['name'],
        'command'        => '',
        'content'        => (string) ($row['comment'] ?? ''),
        'instructions'   => (string) ($row['instructions'] ?? ''),
        'result'         => (string) $row['status'],
        'result_label'   => $task_status[$row['status']] ?? (string) $row['status'],
        'detection_ref'  => '',
        'task_name'      => '',
    ];
}
usort($actions, fn ($a, $b) => [strtotime((string) $a['date']), $a['kind'], $a['id']] <=> [strtotime((string) $b['date']), $b['kind'], $b['id']]);
arsort($by_user);

// Empreinte du journal imprimé (contenu des actions, dans l'ordre)
$fingerprint = hash('sha256', (string) json_encode(array_map(
    fn ($a) => [$a['kind'], $a['id'], $a['integrity_hash'] ?? '', $a['date'], $a['users_id'], $a['target'], $a['tool'], $a['name'], $a['command'], $a['result'], $a['content']],
    $actions
), JSON_UNESCAPED_UNICODE));

AuditLog::record('print', $incident, [
    'document'  => I18n::instance('action log'),
    'actions'   => count($actions) - $remediations,
    'remediations' => $remediations,
    'empreinte' => $fingerprint,
]);

Html::popHeader(sprintf(__('Action log %s', 'secincident'), $incident->fields['reference']));

TemplateRenderer::getInstance()->display('@secincident/actions_print.html.twig', [
    'incident'    => $incident,
    'actions'     => $actions,
    'remediations' => $remediations,
    'by_user'     => $by_user,
    'by_result'   => $by_result,
    'results'     => $results,
    'category'    => Incident::getCategories()[$incident->fields['category']] ?? $incident->fields['category'],
    'severity'    => Incident::getSeverities()[(int) $incident->fields['severity']] ?? '',
    'status'      => Incident::getStatuses()[(int) $incident->fields['status']] ?? '',
    'printed_at'  => Session::getCurrentTime(),
    'printed_by'  => getUserName((int) Session::getLoginUserID()),
    'fingerprint' => $fingerprint,
]);

Html::popFooter();
