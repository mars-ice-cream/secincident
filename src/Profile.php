<?php

/**
 * -------------------------------------------------------------------------
 * SecIncident — Suivi des incidents de sécurité pour GLPI 11
 * -------------------------------------------------------------------------
 * @license   GPLv3 https://www.gnu.org/licenses/gpl-3.0.html
 * -------------------------------------------------------------------------
 */

namespace GlpiPlugin\Secincident;

use CommonGLPI;
use Html;
use Session;

/**
 * Onglet "Incidents de sécurité" dans les profils GLPI.
 */
class Profile extends CommonGLPI
{
    public function getTabNameForItem(CommonGLPI $item, $withtemplate = 0)
    {
        if ($item instanceof \Profile && $item->getID() > 0 && $item->fields['interface'] === 'central') {
            return self::createTabEntry(__('Security incidents', 'secincident'), 0, null, Incident::getIcon());
        }
        return '';
    }

    public static function displayTabContentForItem(CommonGLPI $item, $tabnum = 1, $withtemplate = 0)
    {
        if ($item instanceof \Profile) {
            (new self())->showRights($item->getID());
        }
        return true;
    }

    public function showRights(int $profiles_id): void
    {
        $profile = new \Profile();
        if (!$profile->getFromDB($profiles_id) || !$profile->can($profiles_id, READ)) {
            return;
        }
        $canedit = Session::haveRight(\Profile::$rightname, UPDATE);

        echo '<div class="spaced">';
        if ($canedit) {
            echo '<form method="post" action="' . htmlescape(\Profile::getFormURL()) . '">';
        }

        $profile->displayRightsChoiceMatrix(
            [
                [
                    'itemtype' => Incident::class,
                    'label'    => Incident::getTypeName(Session::getPluralNumber()),
                    'field'    => Incident::$rightname,
                ],
            ],
            [
                'canedit' => $canedit,
                'title'   => __('Security incidents', 'secincident'),
            ]
        );

        if ($canedit) {
            echo '<div class="text-center mt-2">';
            echo Html::hidden('id', ['value' => $profiles_id]);
            echo Html::submit(_sx('button', 'Save'), ['name' => 'update', 'class' => 'btn btn-primary']);
            echo '</div>';
            Html::closeForm();
        }
        echo '</div>';

        echo '<div class="alert alert-info mt-3">';
        echo __s('Read: view incidents. Create: report an incident and import an EDR CSV. Update: qualify, complete the timeline, the IOCs and the GDPR/NIS2 section.', 'secincident');
        echo '</div>';
    }
}
