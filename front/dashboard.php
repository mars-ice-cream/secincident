<?php

/**
 * SecIncident — tableau de bord sécurité.
 */

use Glpi\Application\View\TemplateRenderer;
use GlpiPlugin\Secincident\AuditLog;
use GlpiPlugin\Secincident\I18n;
use GlpiPlugin\Secincident\Dashboard;
use GlpiPlugin\Secincident\Incident;

global $CFG_GLPI;

AuditLog::checkPageAccess([READ, Incident::READALL], I18n::instance('dashboard'));

$period = (int) ($_GET['period'] ?? 90);
if (!array_key_exists($period, Dashboard::getPeriods())) {
    $period = 90;
}

AuditLog::record('view_dashboard', null, [
    'periode_jours' => $period,
    'perimetre'     => Incident::canViewAll() ? 'tous' : 'siens',
]);

Html::header(__('Security dashboard', 'secincident'), '', 'helpdesk', Incident::class, 'dashboard');

TemplateRenderer::getInstance()->display('@secincident/dashboard.html.twig', [
    'stats'             => Dashboard::getStats($period),
    'period'            => $period,
    'periods'           => Dashboard::getPeriods(),
    'can_create'        => Incident::canCreate(),
    'incident_form_url' => Incident::getFormURL(),
    'import_url'        => $CFG_GLPI['root_doc'] . '/plugins/secincident/front/import.php',
]);

Html::footer();
