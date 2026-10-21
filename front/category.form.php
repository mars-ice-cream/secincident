<?php

/**
 * SecIncident — catégorie d'incident (création, modification réservées
 * au droit « Gérer les catégories »).
 */

use GlpiPlugin\Secincident\AuditLog;
use GlpiPlugin\Secincident\I18n;
use GlpiPlugin\Secincident\Category;
use GlpiPlugin\Secincident\Incident;

AuditLog::checkPageAccess([READ, Incident::READALL], I18n::instance('incident category'));

$category = new Category();
$id       = (int) ($_POST['id'] ?? 0);

if (isset($_POST['add'])) {
    AuditLog::guard($category, -1, CREATE, $_POST, I18n::instance('category creation'));
    $newid = $category->add($_POST);
    if ($newid) {
        Html::redirect($category->getLinkURL());
    }
    Html::back();
} elseif (isset($_POST['update'])) {
    AuditLog::guard($category, $id, UPDATE, null, I18n::instance('category update'));
    $category->update($_POST);
    Html::back();
} elseif (isset($_POST['purge']) || isset($_POST['delete'])) {
    AuditLog::guard($category, $id, PURGE, null, I18n::instance('category deletion'));
    if ($category->delete($_POST, true)) {
        $category->redirectToList();
    }
    Html::back();
}

Category::displayFullPageForItem((int) ($_GET['id'] ?? 0), ['helpdesk', Incident::class, 'category']);
