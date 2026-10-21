<?php

/**
 * SecIncident — équipe d'intervention d'un incident.
 */

use Glpi\Exception\Http\BadRequestHttpException;
use GlpiPlugin\Secincident\AuditLog;
use GlpiPlugin\Secincident\I18n;
use GlpiPlugin\Secincident\Incident;
use GlpiPlugin\Secincident\TeamMember;

AuditLog::checkPageAccess([UPDATE], I18n::instance('response team'));

$member = new TeamMember();
$id     = (int) ($_POST['id'] ?? 0);

if (isset($_POST['add'])) {
    AuditLog::guard($member, -1, CREATE, $_POST, I18n::instance('addition to the team'));
    $member->add($_POST);
    Html::back();
} elseif (isset($_POST['update'])) {
    AuditLog::guard($member, $id, UPDATE, null, I18n::instance('team role change'));
    $member->update(['id' => $id, 'role' => (string) ($_POST['role'] ?? '')]);
    Html::back();
} elseif (isset($_POST['purge'])) {
    AuditLog::guard($member, $id, PURGE, null, I18n::instance('removal from the team'));
    $incidents_id = (int) $member->fields[Incident::getForeignKeyField()];
    $member->delete(['id' => $id], true);
    // Si l'utilisateur s'est retiré lui-même, il n'a plus accès à la fiche
    $incident = new Incident();
    if ($incident->getFromDB($incidents_id) && Incident::isVisibleFor($incident->fields)) {
        Html::back();
    }
    Html::redirect(Incident::getSearchURL());
}

throw new BadRequestHttpException();
