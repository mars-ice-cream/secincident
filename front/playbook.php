<?php

/**
 * SecIncident — bibliothèque des procédures de remédiation.
 */

use GlpiPlugin\Secincident\AuditLog;
use GlpiPlugin\Secincident\I18n;
use GlpiPlugin\Secincident\Incident;
use GlpiPlugin\Secincident\Playbook;

AuditLog::checkPageAccess([READ, Incident::READALL], I18n::instance('remediation playbooks'));
AuditLog::record('list', null, ['liste' => I18n::instance('remediation playbooks')]);

Html::header(Playbook::getTypeName(Session::getPluralNumber()), '', 'helpdesk', Incident::class, 'playbook');
Search::show(Playbook::class);
Html::footer();
