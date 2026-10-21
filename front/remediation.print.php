<?php

/**
 * SecIncident — plan de remédiation imprimable.
 */

use Glpi\Application\View\TemplateRenderer;
use GlpiPlugin\Secincident\AuditLog;
use GlpiPlugin\Secincident\I18n;
use GlpiPlugin\Secincident\Incident;
use GlpiPlugin\Secincident\RemediationTask;

AuditLog::checkPageAccess([READ, Incident::READALL], I18n::instance('printing the remediation plan'));

$incident = new Incident();
$id       = (int) ($_GET['id'] ?? 0);
AuditLog::guard($incident, $id, READ, null, I18n::instance('printing the remediation plan'));

$plan = RemediationTask::getPlanData($incident);

// Empreinte du plan imprimé : permet de prouver plus tard quelle version a été remise
$fingerprint = hash('sha256', (string) json_encode(array_map(
    fn ($t) => [$t['id'], $t['phase'], $t['name'], $t['status'], $t['date_done'], $t['users_id_done'], $t['comment']],
    $plan['tasks']
), JSON_UNESCAPED_UNICODE));

AuditLog::record('print', $incident, [
    'document'  => I18n::instance('remediation plan'),
    'taches'    => $plan['total'],
    'avancement' => $plan['percent'],
    'empreinte' => $fingerprint,
]);

Html::popHeader(sprintf(__('Remediation plan %s', 'secincident'), $incident->fields['reference']));

TemplateRenderer::getInstance()->display('@secincident/remediation_print.html.twig', [
    'incident'    => $incident,
    'plan'        => $plan,
    'category'    => Incident::getCategories()[$incident->fields['category']] ?? $incident->fields['category'],
    'severity'    => Incident::getSeverities()[(int) $incident->fields['severity']] ?? '',
    'status'      => Incident::getStatuses()[(int) $incident->fields['status']] ?? '',
    'tech'        => (int) $incident->fields['users_id_tech'] > 0 ? getUserName((int) $incident->fields['users_id_tech']) : '—',
    'printed_at'  => Session::getCurrentTime(),
    'printed_by'  => getUserName((int) Session::getLoginUserID()),
    'fingerprint' => $fingerprint,
]);

Html::popFooter();
