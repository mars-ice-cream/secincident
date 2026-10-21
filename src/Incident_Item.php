<?php

/**
 * -------------------------------------------------------------------------
 * SecIncident — Suivi des incidents de sécurité pour GLPI 11
 * -------------------------------------------------------------------------
 * @license   GPLv3 https://www.gnu.org/licenses/gpl-3.0.html
 * -------------------------------------------------------------------------
 */

namespace GlpiPlugin\Secincident;

use CommonDBRelation;
use CommonDBTM;
use CommonGLPI;
use Dropdown;
use Entity;
use Glpi\Application\View\TemplateRenderer;
use Html;
use Session;

/**
 * Lien entre un incident de sécurité et un élément GLPI
 * (ticket, problème, changement, ordinateur, utilisateur…).
 */
class Incident_Item extends CommonDBRelation
{
    use IntegerInputTrait;
    use IncidentChildTrait;

    protected static function getAuditAction(string $operation): string
    {
        return $operation === 'add' ? 'link' : 'unlink';
    }

    public static $itemtype_1         = Incident::class;
    public static $items_id_1         = 'plugin_secincident_incidents_id';
    public static $take_entity_1      = true;

    public static $itemtype_2         = 'itemtype';
    public static $items_id_2         = 'items_id';
    public static $take_entity_2      = false;
    // Lier un incident à un ticket ne doit pas exiger le droit de modifier le ticket
    public static $checkItem_2_Rights = self::HAVE_VIEW_RIGHT_ON_ITEM;

    public static $rightname = 'plugin_secincident_incident';

    public static function getTypeName($nb = 0)
    {
        return _n('Linked item', 'Linked items', $nb, 'secincident');
    }

    public function getForbiddenStandardMassiveAction()
    {
        $forbidden   = parent::getForbiddenStandardMassiveAction();
        $forbidden[] = 'update';
        return $forbidden;
    }

    public function getTabNameForItem(CommonGLPI $item, $withtemplate = 0)
    {
        if (!$item instanceof CommonDBTM || $withtemplate) {
            return '';
        }

        if ($item instanceof Incident) {
            if ($item->isNewItem()) {
                return '';
            }
            $nb = $_SESSION['glpishow_count_on_tabs']
                ? countElementsInTable(self::getTable(), [static::$items_id_1 => $item->getID()])
                : 0;
            return self::createTabEntry(self::getTypeName(Session::getPluralNumber()), $nb, null, 'ti ti-link');
        }

        if (in_array($item::class, Incident::getLinkableTypes(), true) && Incident::canView()) {
            $nb = $_SESSION['glpishow_count_on_tabs']
                ? countElementsInTable(self::getTable(), ['itemtype' => $item::class, 'items_id' => $item->getID()])
                : 0;
            return self::createTabEntry(
                Incident::getTypeName(Session::getPluralNumber()),
                $nb,
                null,
                Incident::getIcon()
            );
        }

        return '';
    }

    public static function displayTabContentForItem(CommonGLPI $item, $tabnum = 1, $withtemplate = 0)
    {
        if ($item instanceof Incident) {
            self::showForIncident($item);
        } elseif ($item instanceof CommonDBTM) {
            self::showForItem($item, (int) $withtemplate);
        }
        return true;
    }

    /**
     * Onglet "Éléments liés" d'un incident.
     */
    public static function showForIncident(Incident $incident): void
    {
        global $DB;

        $ID = $incident->getID();
        if (!$incident->can($ID, READ)) {
            AuditLog::recordDenied(I18n::instance('read linked items'), Incident::class, (int) $ID);
            return;
        }
        AuditLog::recordView($incident, I18n::instance('linked items'));
        $canedit = $incident->can($ID, UPDATE);

        if ($canedit) {
            self::showLinkFormForIncident($incident);
        }

        $iterator = $DB->request([
            'FROM'  => self::getTable(),
            'WHERE' => [static::$items_id_1 => $ID],
            'ORDER' => ['itemtype', 'items_id'],
        ]);

        $entries = [];
        foreach ($iterator as $row) {
            $itemtype = $row['itemtype'];
            $linked   = getItemForItemtype($itemtype);
            if (!$linked || !$linked->getFromDB((int) $row['items_id'])) {
                continue;
            }
            $status = '';
            if ($linked->canViewItem() && method_exists($linked, 'getStatus') && isset($linked->fields['status'])) {
                $status = htmlescape($linked::getStatus($linked->fields['status']));
            }
            $entry = [
                'itemtype' => self::class,
                'id'       => $row['id'],
                'type'     => htmlescape($linked::getTypeName(1)),
                // Pas de fuite du nom d'un élément que l'utilisateur ne peut pas voir
                'name'     => $linked->canViewItem() ? $linked->getLink() : htmlescape($linked::getTypeName(1) . ' #' . $linked->getID()),
                'status'   => $status,
            ];
            if (Session::isMultiEntitiesMode()) {
                $entry['entity'] = $linked->isEntityAssign()
                    ? htmlescape(Dropdown::getDropdownName('glpi_entities', $linked->getEntityID()))
                    : '-';
            }
            $entries[] = $entry;
        }

        $columns = [
            'type'   => _n('Type', 'Types', 1),
            'name'   => __('Name'),
            'status' => __('Status'),
        ];
        if (Session::isMultiEntitiesMode()) {
            $columns['entity'] = Entity::getTypeName(1);
        }

        TemplateRenderer::getInstance()->display('components/datatable.html.twig', [
            'is_tab'              => true,
            'nofilter'            => true,
            'nosort'              => true,
            'columns'             => $columns,
            'formatters'          => ['type' => 'raw_html', 'name' => 'raw_html', 'status' => 'raw_html', 'entity' => 'raw_html'],
            'entries'             => $entries,
            'total_number'        => count($entries),
            'filtered_number'     => count($entries),
            'showmassiveactions'  => $canedit,
            'massiveactionparams' => [
                'num_displayed' => count($entries),
                'container'     => 'mass' . str_replace('\\', '', self::class) . mt_rand(),
            ],
        ]);

        if ($canedit && \Ticket::canCreate()) {
            echo '<form method="post" action="' . htmlescape(Incident::getFormURL()) . '" class="mt-3">';
            echo Html::hidden('id', ['value' => $ID]);
            echo '<button type="submit" name="create_ticket" value="1" class="btn btn-outline-secondary">';
            echo '<i class="ti ti-ticket me-1"></i>' . __s('Create a ticket linked to this incident', 'secincident');
            echo '</button>';
            Html::closeForm();
        }
    }

    /**
     * Formulaire de liaison d'un élément GLPI à un incident.
     * Formulaire propre au plugin : le gabarit cœur link_existing_or_new
     * n'a pas la même API selon les versions 11.0.x.
     */
    private static function showLinkFormForIncident(Incident $incident): void
    {
        $rand = mt_rand();
        echo '<div class="firstbloc">';
        echo '<form method="post" action="' . htmlescape(self::getFormURL()) . '" class="d-flex flex-wrap align-items-center gap-2 mb-3">';
        echo Html::hidden(static::$items_id_1, ['value' => $incident->getID()]);
        echo '<div class="col-auto" style="min-width:32rem">';
        Dropdown::showSelectItemFromItemtypes([
            'itemtypes'       => Incident::getLinkableTypes(),
            'entity_restrict' => $incident->isRecursive()
                ? getSonsOf('glpi_entities', $incident->getEntityID())
                : $incident->getEntityID(),
            'checkright'      => true,
            'rand'            => $rand,
            'width'           => '100%',
        ]);
        echo '</div>';
        echo '<div class="col-auto"><button type="submit" name="add" value="1" class="btn btn-primary">';
        echo '<i class="ti ti-link me-1"></i>' . _sx('button', 'Associate') . '</button></div>';
        Html::closeForm();
        echo '</div>';
    }

    /**
     * Formulaire de liaison d'un incident existant depuis un ticket, un matériel…
     *
     * @param array<int, int> $used incidents déjà liés
     */
    private static function showLinkFormForItem(CommonDBTM $item, array $used): void
    {
        echo '<form method="post" action="' . htmlescape(self::getFormURL()) . '" class="d-flex flex-wrap align-items-center gap-2">';
        echo Html::hidden('itemtype', ['value' => $item::class]);
        echo Html::hidden('items_id', ['value' => $item->getID()]);
        echo '<div class="col-auto" style="min-width:20rem">';
        Dropdown::show(Incident::class, [
            'name'        => static::$items_id_1,
            'entity'      => $item->isEntityAssign() ? $item->getEntityID() : -1,
            'entity_sons' => $item->isEntityAssign() ? (bool) $item->isRecursive() : true,
            'used'        => $used,
            'displaywith' => ['reference'],
            'width'       => '100%',
        ]);
        echo '</div>';
        echo '<div class="col-auto"><button type="submit" name="add" value="1" class="btn btn-primary">';
        echo '<i class="ti ti-link me-1"></i>' . _sx('button', 'Associate') . '</button></div>';
        Html::closeForm();
    }

    /**
     * Onglet "Incidents de sécurité" sur un ticket, un ordinateur, un utilisateur…
     */
    public static function showForItem(CommonDBTM $item, int $withtemplate = 0): void
    {
        global $DB;

        $ID = $item->getID();
        if ($item->isNewID($ID) || !Incident::canView() || !$item->can($ID, READ)) {
            return;
        }

        $canlink = Incident::canUpdate() && $withtemplate < 2;
        AuditLog::recordView($item, I18n::instance('linked security incidents'));

        $iterator = $DB->request([
            'SELECT' => [
                self::getTable() . '.id AS linkid',
                Incident::getTable() . '.*',
            ],
            'FROM'       => self::getTable(),
            'INNER JOIN' => [
                Incident::getTable() => [
                    'ON' => [
                        self::getTable()     => static::$items_id_1,
                        Incident::getTable() => 'id',
                    ],
                ],
            ],
            'WHERE' => [
                self::getTable() . '.itemtype' => $item::class,
                self::getTable() . '.items_id' => $ID,
            ] + getEntitiesRestrictCriteria(Incident::getTable(), '', '', true)
              + Incident::getSystemSQLCriteria(Incident::getTable()),
            'ORDER' => [Incident::getTable() . '.date_detection DESC'],
        ]);

        $used    = [];
        $entries = [];
        $incident = new Incident();
        foreach ($iterator as $row) {
            $used[$row['id']] = $row['id'];
            $incident->getFromResultSet($row);
            $entries[] = [
                'itemtype'  => self::class,
                'id'        => $row['linkid'],
                'reference' => htmlescape($row['reference']),
                'name'      => $incident->getLink(),
                'status'    => Incident::getSpecificValueToDisplay('status', $row),
                'severity'  => Incident::getSpecificValueToDisplay('severity', $row),
                'category'  => Incident::getSpecificValueToDisplay('category', $row),
                'date'      => $row['date_detection'],
            ];
        }

        if ($canlink) {
            echo '<div class="d-flex flex-wrap align-items-start gap-2 mb-3">';
            self::showLinkFormForItem($item, $used);
            if (Incident::canCreate()) {
                $url = Incident::getFormURL() . '?' . http_build_query([
                    '_link_itemtype' => $item::class,
                    '_link_items_id' => $ID,
                ]);
                echo '<a class="btn btn-outline-danger" href="' . htmlescape($url) . '">';
                echo '<i class="ti ti-shield-plus me-1"></i>' . __s('Report a security incident', 'secincident');
                echo '</a>';
            }
            echo '</div>';
        }

        TemplateRenderer::getInstance()->display('components/datatable.html.twig', [
            'is_tab'      => true,
            'nofilter'    => true,
            'nosort'      => true,
            'columns'     => [
                'reference' => __('Reference', 'secincident'),
                'name'      => __('Title', 'secincident'),
                'status'    => __('Status', 'secincident'),
                'severity'  => __('Severity', 'secincident'),
                'category'  => __('Category', 'secincident'),
                'date'      => __('Detection date', 'secincident'),
            ],
            'formatters'  => [
                'reference' => 'raw_html',
                'name'      => 'raw_html',
                'status'    => 'raw_html',
                'severity'  => 'raw_html',
                'category'  => 'raw_html',
                'date'      => 'datetime',
            ],
            'entries'             => $entries,
            'total_number'        => count($entries),
            'filtered_number'     => count($entries),
            'showmassiveactions'  => $canlink,
            'massiveactionparams' => [
                'num_displayed' => count($entries),
                'container'     => 'mass' . str_replace('\\', '', self::class) . mt_rand(),
            ],
        ]);
    }
}
