<?php

/**
 * SecIncident — procédure de remédiation type.
 */

use GlpiPlugin\Secincident\AuditLog;
use GlpiPlugin\Secincident\I18n;
use GlpiPlugin\Secincident\Incident;
use GlpiPlugin\Secincident\Playbook;

AuditLog::checkPageAccess([READ, Incident::READALL], I18n::instance('remediation playbook'));

$playbook = new Playbook();
$id       = (int) ($_POST['id'] ?? 0);

if (isset($_POST['add'])) {
    AuditLog::guard($playbook, -1, CREATE, $_POST, I18n::instance('playbook creation'));
    $newid = $playbook->add($_POST);
    if ($newid) {
        Html::redirect($playbook->getLinkURL());
    }
    Html::back();
} elseif (isset($_POST['update'])) {
    AuditLog::guard($playbook, $id, UPDATE, null, I18n::instance('playbook update'));
    $playbook->update($_POST);
    Html::back();
} elseif (isset($_POST['delete'])) {
    AuditLog::guard($playbook, $id, DELETE, null, I18n::instance('playbook moved to trash'));
    $playbook->delete($_POST);
    $playbook->redirectToList();
} elseif (isset($_POST['restore'])) {
    AuditLog::guard($playbook, $id, DELETE, null, I18n::instance('playbook restoration'));
    $playbook->restore($_POST);
    $playbook->redirectToList();
} elseif (isset($_POST['purge'])) {
    AuditLog::guard($playbook, $id, PURGE, null, I18n::instance('playbook deletion'));
    $playbook->delete($_POST, true);
    $playbook->redirectToList();
}

Playbook::displayFullPageForItem((int) ($_GET['id'] ?? 0), ['helpdesk', Incident::class, 'playbook']);
