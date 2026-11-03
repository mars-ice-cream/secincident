<?php

/**
 * SecIncident — formulaire d'un incident de sécurité.
 */

use Glpi\Exception\Http\BadRequestHttpException;
use GlpiPlugin\Secincident\AuditLog;
use GlpiPlugin\Secincident\I18n;
use GlpiPlugin\Secincident\Incident;
use GlpiPlugin\Secincident\Integrity;

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
    $result = Integrity::verifyIncident($id, true);
    $verdict_labels = [
        Integrity::VERDICT_INTACT       => I18n::instance('intact'),
        Integrity::VERDICT_ALTERED      => I18n::instance('anomalies'),
        Integrity::VERDICT_UNVERIFIABLE => I18n::instance('not established: unsealed items'),
    ];
    AuditLog::record('verify_integrity', $incident, [
        'resultat'        => $verdict_labels[$result['verdict']],
        'donnees'         => $result['summary'],
        'preuves'         => count($result['evidences']),
        'preuves_en_anomalie' => $result['evidence_problems'],
        'preuves_non_scellees' => $result['evidence_unanchored'],
        'anomalies'       => array_values(array_map(
            fn ($i) => array_filter(['type' => $i['itemtype'], 'id' => $i['id'], 'etat' => $i['status'], 'motif' => $i['reason']]),
            array_filter($result['items'], fn ($i) => $i['status'] !== 'ok')
        )),
    ], $result['ok'] ? AuditLog::RESULT_OK : AuditLog::RESULT_ERROR);
    Session::addMessageAfterRedirect(
        match ($result['verdict']) {
            Integrity::VERDICT_INTACT  => __s('Check completed: data and evidence are intact.', 'secincident'),
            Integrity::VERDICT_ALTERED => __s('Check completed: anomalies detected, see the Integrity & evidence tab.', 'secincident'),
            default                    => __s('Check completed: integrity cannot be established, some items are not sealed (see the Integrity & evidence tab).', 'secincident'),
        },
        false,
        match ($result['verdict']) {
            Integrity::VERDICT_INTACT  => INFO,
            Integrity::VERDICT_ALTERED => ERROR,
            default                    => WARNING,
        }
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
