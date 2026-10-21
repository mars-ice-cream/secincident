<?php

/**
 * SecIncident — étape d'une procédure de remédiation.
 */

use GlpiPlugin\Secincident\AuditLog;
use GlpiPlugin\Secincident\I18n;
use GlpiPlugin\Secincident\Incident;
use GlpiPlugin\Secincident\Playbook;
use GlpiPlugin\Secincident\PlaybookStep;

AuditLog::checkPageAccess([READ, Incident::READALL], I18n::instance('playbook step'));

$step = new PlaybookStep();
$fk   = Playbook::getForeignKeyField();
$id   = (int) ($_POST['id'] ?? 0);

if (isset($_POST['add'])) {
    AuditLog::guard($step, -1, CREATE, $_POST, I18n::instance('playbook step addition'));
    $step->add($_POST);
    Html::back();
} elseif (isset($_POST['update'])) {
    AuditLog::guard($step, $id, UPDATE, null, I18n::instance('playbook step update'));
    $step->update($_POST);
    Html::back();
} elseif (isset($_POST['purge']) || isset($_POST['delete'])) {
    AuditLog::guard($step, $id, PURGE, null, I18n::instance('playbook step deletion'));
    $playbooks_id = (int) $step->fields[$fk];
    $step->delete($_POST, true);
    Html::redirect(Playbook::getFormURLWithID($playbooks_id));
}

$options = [];
if (!empty($_GET[$fk])) {
    $options[$fk] = (int) $_GET[$fk];
}
PlaybookStep::displayFullPageForItem((int) ($_GET['id'] ?? 0), ['helpdesk', Incident::class, 'playbook'], $options);
