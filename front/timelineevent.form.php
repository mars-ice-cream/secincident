<?php

/**
 * SecIncident — événement de chronologie.
 */

use GlpiPlugin\Secincident\AuditLog;
use GlpiPlugin\Secincident\I18n;
use GlpiPlugin\Secincident\Incident;
use GlpiPlugin\Secincident\TimelineEvent;

AuditLog::checkPageAccess([READ, Incident::READALL], I18n::instance('timeline event'));

$event = new TimelineEvent();
$fk    = Incident::getForeignKeyField();
$id    = (int) ($_POST['id'] ?? 0);

if (isset($_POST['add'])) {
    AuditLog::guard($event, -1, CREATE, $_POST, I18n::instance('event addition'));
    $event->add($_POST);
    Html::back();
} elseif (isset($_POST['update'])) {
    AuditLog::guard($event, $id, UPDATE, null, I18n::instance('event update'));
    $event->update($_POST);
    Html::back();
} elseif (isset($_POST['purge']) || isset($_POST['delete'])) {
    AuditLog::guard($event, $id, PURGE, null, I18n::instance('event deletion'));
    $incidents_id = (int) $event->fields[$fk];
    $event->delete($_POST, true);
    Html::redirect(Incident::getFormURLWithID($incidents_id));
}

$get_id = (int) ($_GET['id'] ?? 0);
if ($get_id > 0) {
    AuditLog::guard($event, $get_id, READ, null, I18n::instance('event consultation'));
}

$options = [];
if (!empty($_GET[$fk])) {
    $options[$fk] = (int) $_GET[$fk];
}
TimelineEvent::displayFullPageForItem($get_id, ['helpdesk', Incident::class], $options);
