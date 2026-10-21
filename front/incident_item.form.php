<?php

/**
 * SecIncident — liaison incident ↔ éléments GLPI.
 */

use Glpi\Exception\Http\BadRequestHttpException;
use Glpi\Exception\ItemLinkException;
use GlpiPlugin\Secincident\AuditLog;
use GlpiPlugin\Secincident\I18n;
use GlpiPlugin\Secincident\Incident;
use GlpiPlugin\Secincident\Incident_Item;

Session::checkCentralAccess();
AuditLog::checkPageAccess([UPDATE], I18n::instance('item linking'));

$link = new Incident_Item();

if (isset($_POST['add'])) {
    $fk = Incident::getForeignKeyField();
    if (empty($_POST[$fk]) || empty($_POST['itemtype']) || empty($_POST['items_id'])) {
        Session::addMessageAfterRedirect(__s('Select an item to link', 'secincident'), false, ERROR);
        Html::back();
    }
    if (!in_array($_POST['itemtype'], Incident::getLinkableTypes(), true)) {
        throw new BadRequestHttpException();
    }
    try {
        AuditLog::guard($link, -1, CREATE, $_POST, 'liaison');
    } catch (ItemLinkException) {
        Html::back();
    }
    $link->add($_POST);
    Html::back();
} elseif (isset($_POST['delete'])) {
    foreach (($_POST['item'] ?? []) as $key => $val) {
        if ((int) $val === 1) {
            AuditLog::guard($link, (int) $key, UPDATE, null, I18n::instance('unlinking'));
            $link->delete(['id' => (int) $key]);
        }
    }
    Html::back();
}

throw new BadRequestHttpException();
