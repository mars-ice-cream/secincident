<?php

/**
 * SecIncident — configuration de l'accès (groupe sécurité, alertes).
 */

use GlpiPlugin\Secincident\AccessGuard;
use GlpiPlugin\Secincident\AuditLog;
use GlpiPlugin\Secincident\I18n;
use GlpiPlugin\Secincident\Incident;

AuditLog::checkPageAccess([Incident::AUDIT], I18n::instance('access settings'));

if (isset($_POST['save'])) {
    AccessGuard::saveConfig($_POST);
    Html::back();
}

Html::header(__('Access settings', 'secincident'), '', 'helpdesk', Incident::class, 'config');
AccessGuard::showConfigForm();
Html::footer();
