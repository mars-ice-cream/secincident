<?php

/**
 * -------------------------------------------------------------------------
 * SecIncident — Suivi des incidents de sécurité pour GLPI 11
 * -------------------------------------------------------------------------
 * @license   GPLv3 https://www.gnu.org/licenses/gpl-3.0.html
 * -------------------------------------------------------------------------
 */

use Glpi\Plugin\Hooks;
use GlpiPlugin\Secincident\Evidence;
use GlpiPlugin\Secincident\Incident;
use GlpiPlugin\Secincident\Incident_Item;
use GlpiPlugin\Secincident\Profile;

define('PLUGIN_SECINCIDENT_VERSION', '1.9.0');
// Version minimale de GLPI (incluse)
define('PLUGIN_SECINCIDENT_MIN_GLPI', '11.0.0');
// Version maximale de GLPI (exclue)
define('PLUGIN_SECINCIDENT_MAX_GLPI', '11.0.99');

/**
 * Initialisation des hooks du plugin.
 */
function plugin_init_secincident(): void
{
    global $PLUGIN_HOOKS;

    if (!Plugin::isPluginActive('secincident')) {
        return;
    }

    // Objet principal : documents attachables, liens possibles, entrées de menu
    Plugin::registerClass(Incident::class, [
        'document_types' => true,
        'link_types'     => true,
    ]);

    // Onglet "Incidents de sécurité" sur les tickets, matériels, utilisateurs…
    Plugin::registerClass(Incident_Item::class, [
        'addtabon' => Incident::getLinkableTypes(),
    ]);

    // Onglet de droits sur les profils
    Plugin::registerClass(Profile::class, ['addtabon' => ['Profile']]);

    if (Incident::canView()) {
        $PLUGIN_HOOKS[Hooks::MENU_TOADD]['secincident'] = ['helpdesk' => Incident::class];
    }

    $PLUGIN_HOOKS[Hooks::ADD_CSS]['secincident'] = ['css/secincident.css'];

    // Nettoyage des liens quand un élément lié est purgé
    $purge = [];
    foreach (Incident::getLinkableTypes() as $itemtype) {
        $purge[$itemtype] = 'plugin_secincident_item_purge';
    }
    // Registre des preuves : empreinte SHA-256 de tout document joint à un incident
    $purge['Document_Item'] = [Evidence::class, 'onDocumentItemPurge'];
    $purge['Document']      = [Evidence::class, 'onDocumentPurge'];
    $PLUGIN_HOOKS[Hooks::ITEM_PURGE]['secincident'] = $purge;
    $PLUGIN_HOOKS[Hooks::ITEM_ADD]['secincident']   = ['Document_Item' => [Evidence::class, 'onDocumentItemAdd']];
    $PLUGIN_HOOKS[Hooks::ITEM_UPDATE]['secincident'] = ['Document' => [Evidence::class, 'onDocumentUpdate']];

    // Audit des changements de droits du plugin dans les profils
    // Audit des onglets standards GLPI (historique, documents) affichés sur nos objets
    $PLUGIN_HOOKS[Hooks::PRE_SHOW_TAB]['secincident'] = 'plugin_secincident_pre_show_tab';

    $PLUGIN_HOOKS[Hooks::PRE_ITEM_UPDATE]['secincident'] = [
        'Profile' => 'plugin_secincident_profile_pre_update',
    ];
}

/**
 * Informations du plugin.
 *
 * @return array<string, mixed>
 */
function plugin_version_secincident(): array
{
    return [
        'name'         => __('Security incidents', 'secincident'),
        'version'      => PLUGIN_SECINCIDENT_VERSION,
        'author'       => 'Gerome Le Duff',
        'license'      => 'GPLv3',
        'homepage'     => 'https://github.com/mars-ice-cream/secincident',
        'requirements' => [
            'glpi' => [
                'min' => PLUGIN_SECINCIDENT_MIN_GLPI,
                'max' => PLUGIN_SECINCIDENT_MAX_GLPI,
            ],
            'php'  => [
                'min' => '8.2',
            ],
        ],
    ];
}

function plugin_secincident_check_prerequisites(): bool
{
    return true;
}

function plugin_secincident_check_config($verbose = false): bool
{
    return true;
}
