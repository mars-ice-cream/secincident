<?php

/**
 * SecIncident — liste des catégories d'incident.
 */

use GlpiPlugin\Secincident\AuditLog;
use GlpiPlugin\Secincident\I18n;
use GlpiPlugin\Secincident\Category;
use GlpiPlugin\Secincident\Incident;

AuditLog::checkPageAccess([READ, Incident::READALL], I18n::instance('incident categories'));
AuditLog::record('list', null, ['liste' => I18n::instance('incident categories')]);

Html::header(Category::getTypeName(Session::getPluralNumber()), '', 'helpdesk', Incident::class, 'category');
Search::show(Category::class);
Html::footer();
