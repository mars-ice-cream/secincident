<?php

/**
 * SecIncident — indicateur de compromission.
 */

use GlpiPlugin\Secincident\AuditLog;
use GlpiPlugin\Secincident\I18n;
use GlpiPlugin\Secincident\Incident;
use GlpiPlugin\Secincident\Ioc;

AuditLog::checkPageAccess([READ, Incident::READALL], I18n::instance('indicator (IOC)'));

$ioc = new Ioc();
$fk  = Incident::getForeignKeyField();
$id  = (int) ($_POST['id'] ?? 0);

if (isset($_POST['add'])) {
    // Saisie en masse : une valeur par ligne
    $values = preg_split('/\R/', (string) ($_POST['values'] ?? $_POST['value'] ?? '')) ?: [];
    $values = array_values(array_filter(array_map('trim', $values), fn ($v) => $v !== ''));
    $added  = 0;
    foreach ($values as $value) {
        $input          = $_POST;
        $input['value'] = $value;
        unset($input['values']);
        AuditLog::guard($ioc, -1, CREATE, $input, I18n::instance('IOC addition'));
        if ((new Ioc())->add($input + ['_silent_duplicate' => count($values) > 1])) {
            $added++;
        }
    }
    if (count($values) > 1) {
        Session::addMessageAfterRedirect(
            sprintf(__s('%1$d indicator(s) added out of %2$d', 'secincident'), $added, count($values))
        );
    }
    Html::back();
} elseif (isset($_POST['update'])) {
    AuditLog::guard($ioc, $id, UPDATE, null, I18n::instance('IOC update'));
    $ioc->update($_POST);
    Html::back();
} elseif (isset($_POST['purge']) || isset($_POST['delete'])) {
    AuditLog::guard($ioc, $id, PURGE, null, I18n::instance('IOC deletion'));
    $incidents_id = (int) $ioc->fields[$fk];
    $ioc->delete($_POST, true);
    Html::redirect(Incident::getFormURLWithID($incidents_id));
}

$get_id = (int) ($_GET['id'] ?? 0);
if ($get_id > 0) {
    AuditLog::guard($ioc, $get_id, READ, null, I18n::instance('IOC consultation'));
}

$options = [];
if (!empty($_GET[$fk])) {
    $options[$fk] = (int) $_GET[$fk];
}
Ioc::displayFullPageForItem($get_id, ['helpdesk', Incident::class], $options);
