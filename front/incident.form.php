<?php

/**
 * SecIncident — formulaire d'un incident de sécurité.
 */

use Glpi\Exception\Http\BadRequestHttpException;
use GlpiPlugin\Secincident\AuditLog;
use GlpiPlugin\Secincident\I18n;
use GlpiPlugin\Secincident\Incident;

AuditLog::checkPageAccess([READ, Incident::READALL], I18n::instance('incident form'));

$incident = new Incident();
$id       = (int) ($_POST['id'] ?? 0);

if (isset($_POST['add'])) {
    AuditLog::guard($incident, -1, CREATE, $_POST, I18n::instance('creation'));
    $newid = $incident->add($_POST);
    if ($newid && $_SESSION['glpibackcreated']) {
        Html::redirect($incident->getLinkURL());
    }
    Html::back();
} elseif (isset($_POST['update'])) {
    AuditLog::guard($incident, $id, UPDATE, null, 'modification');
    $incident->update($_POST);
    Html::back();
} elseif (isset($_POST['delete'])) {
    AuditLog::guard($incident, $id, DELETE, null, I18n::instance('move to trash'));
    $incident->delete($_POST);
    $incident->redirectToList();
} elseif (isset($_POST['restore'])) {
    AuditLog::guard($incident, $id, DELETE, null, 'restauration');
    $incident->restore($_POST);
    $incident->redirectToList();
} elseif (isset($_POST['purge'])) {
    AuditLog::guard($incident, $id, PURGE, null, I18n::instance('permanent deletion'));
    $incident->delete($_POST, true);
    $incident->redirectToList();
} elseif (isset($_POST['verify_integrity'])) {
    AuditLog::guard($incident, $id, READ, null, I18n::instance('integrity check'));
    $result = GlpiPlugin\Secincident\Integrity::verifyIncident($id, true);
    AuditLog::record('verify_integrity', $incident, [
        'resultat'        => $result['ok'] ? I18n::instance('intact') : I18n::instance('anomalies'),
        'donnees'         => $result['summary'],
        'preuves'         => count($result['evidences']),
        'preuves_en_anomalie' => $result['evidence_problems'],
        'anomalies'       => array_values(array_map(
            fn ($i) => ['type' => $i['itemtype'], 'id' => $i['id'], 'etat' => $i['status']],
            array_filter($result['items'], fn ($i) => $i['status'] !== 'ok')
        )),
    ], $result['ok'] ? AuditLog::RESULT_OK : AuditLog::RESULT_ERROR);
    Session::addMessageAfterRedirect(
        $result['ok']
            ? __s('Check completed: data and evidence are intact.', 'secincident')
            : __s('Check completed: anomalies detected, see the Integrity & evidence tab.', 'secincident'),
        false,
        $result['ok'] ? INFO : ERROR
    );
    Html::back();
} elseif (isset($_POST['create_ticket'])) {
    AuditLog::guard($incident, $id, UPDATE, null, I18n::instance('linked ticket creation'));
    if (!Ticket::canCreate()) {
        AuditLog::recordDenied(I18n::instance('linked ticket creation (ticket right)'), Incident::class, $id);
        throw new BadRequestHttpException();
    }
    $tickets_id = $incident->createLinkedTicket();
    if ($tickets_id) {
        Session::addMessageAfterRedirect(
            sprintf(__s('Ticket %d created and linked to the incident', 'secincident'), $tickets_id)
        );
        Html::redirect(Ticket::getFormURLWithID($tickets_id));
    }
    Html::back();
}

$get_id = (int) ($_GET['id'] ?? 0);
if ($get_id > 0) {
    // Trace et bloque toute tentative d'ouvrir l'incident d'un autre technicien
    AuditLog::guard($incident, $get_id, READ, null, 'consultation');
}

$options = [
    'formoptions' => "data-track-changes='true'",
];
// Création depuis l'onglet d'un ticket / ordinateur : lien automatique
if (!empty($_GET['_link_itemtype']) && !empty($_GET['_link_items_id'])) {
    $options['_link_itemtype'] = (string) $_GET['_link_itemtype'];
    $options['_link_items_id'] = (int) $_GET['_link_items_id'];
}

Incident::displayFullPageForItem($get_id, ['helpdesk', Incident::class], $options);
