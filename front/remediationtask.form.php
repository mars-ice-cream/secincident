<?php

/**
 * SecIncident — plan de remédiation d'un incident.
 */

use GlpiPlugin\Secincident\AuditLog;
use GlpiPlugin\Secincident\I18n;
use GlpiPlugin\Secincident\Incident;
use GlpiPlugin\Secincident\Playbook;
use GlpiPlugin\Secincident\RemediationTask;

AuditLog::checkPageAccess([READ, Incident::READALL], I18n::instance('remediation plan'));

$task = new RemediationTask();
$fk   = Incident::getForeignKeyField();
$id   = (int) ($_POST['id'] ?? 0);

if (isset($_POST['apply_playbook'])) {
    $incident = new Incident();
    AuditLog::guard($incident, (int) ($_POST[$fk] ?? 0), UPDATE, null, I18n::instance('playbook application'));
    $playbook = new Playbook();
    if (!$playbook->getFromDB((int) ($_POST[Playbook::getForeignKeyField()] ?? 0)) || !$playbook->canViewItem()) {
        Session::addMessageAfterRedirect(__s('Playbook not found', 'secincident'), false, ERROR);
        Html::back();
    }
    $created = RemediationTask::applyPlaybook($incident, $playbook);
    if ($created > 0) {
        Session::addMessageAfterRedirect(
            sprintf(__s('%d task(s) added to the remediation plan', 'secincident'), $created)
        );
    }
    Html::back();
} elseif (isset($_POST['add'])) {
    AuditLog::guard($task, -1, CREATE, $_POST, I18n::instance('remediation task addition'));
    $task->add($_POST);
    Html::back();
} elseif (isset($_POST['update'])) {
    AuditLog::guard($task, $id, UPDATE, null, I18n::instance('remediation task update'));
    $task->update($_POST);
    Html::back();
} elseif (isset($_POST['purge']) || isset($_POST['delete'])) {
    AuditLog::guard($task, $id, PURGE, null, I18n::instance('remediation task deletion'));
    $incidents_id = (int) $task->fields[$fk];
    $task->delete($_POST, true);
    Html::redirect(Incident::getFormURLWithID($incidents_id));
}

$get_id = (int) ($_GET['id'] ?? 0);
if ($get_id > 0) {
    AuditLog::guard($task, $get_id, READ, null, I18n::instance('remediation task consultation'));
}
$options = [];
if (!empty($_GET[$fk])) {
    $options[$fk] = (int) $_GET[$fk];
}
RemediationTask::displayFullPageForItem($get_id, ['helpdesk', Incident::class], $options);
