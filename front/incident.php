<?php

/**
 * SecIncident — liste des incidents de sécurité.
 * Le cloisonnement (ses incidents / tous) est appliqué par Incident::getSystemSQLCriteria().
 */

use GlpiPlugin\Secincident\AuditLog;
use GlpiPlugin\Secincident\I18n;
use GlpiPlugin\Secincident\Incident;

AuditLog::checkPageAccess([READ, Incident::READALL], I18n::instance('incident list'));
AuditLog::record('list', null, [
    'criteres' => $_GET['criteria'] ?? [],
    'perimetre' => Incident::canViewAll() ? 'tous' : 'siens',
]);

Html::header(
    Incident::getTypeName(Session::getPluralNumber()),
    '',
    'helpdesk',
    Incident::class
);

Search::show(Incident::class);

Html::footer();
