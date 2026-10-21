<?php

/**
 * -------------------------------------------------------------------------
 * SecIncident — Suivi des incidents de sécurité pour GLPI 11
 * -------------------------------------------------------------------------
 * @license   GPLv3 https://www.gnu.org/licenses/gpl-3.0.html
 * -------------------------------------------------------------------------
 */

namespace GlpiPlugin\Secincident;

use CommonDBChild;
use CommonGLPI;
use Glpi\Application\View\TemplateRenderer;
use Session;
use User;

/**
 * Membre de l'équipe d'intervention d'un incident.
 *
 *  - intervenant : voit l'incident et peut agir (chronologie, IOC, remédiation…) ;
 *  - observateur : lecture seule.
 *
 * Seuls le responsable, le rédacteur, le groupe en charge ou un profil
 * « tous les incidents » peuvent composer l'équipe.
 */
class TeamMember extends CommonDBChild
{
    use IntegerInputTrait;
    use IncidentChildTrait {
        post_addItem as private traitPostAdd;
        post_updateItem as private traitPostUpdate;
        post_purgeItem as private traitPostPurge;
    }

    public static $itemtype = Incident::class;
    public static $items_id = 'plugin_secincident_incidents_id';

    public static $rightname = 'plugin_secincident_incident';

    public const ROLE_CONTRIBUTOR = 'contributor';
    public const ROLE_OBSERVER    = 'observer';

    /** Cache par requête : [incidents_id => [users_id => role]] */
    private static array $cache = [];

    public static function getTypeName($nb = 0)
    {
        return _n('Team member', 'Team', $nb, 'secincident');
    }

    public static function getIcon()
    {
        return 'ti ti-users-group';
    }

    /** @return array<string, string> */
    public static function getRoles(bool $instance = false): array
    {
        return [
            self::ROLE_CONTRIBUTOR => I18n::tr('Contributor (can act)', $instance),
            self::ROLE_OBSERVER    => I18n::tr('Observer (read only)', $instance),
        ];
    }

    public static function clearCache(): void
    {
        self::$cache = [];
    }

    /**
     * Rôle d'un utilisateur dans l'équipe d'un incident (null si absent).
     */
    public static function getRole(int $incidents_id, int $users_id): ?string
    {
        global $DB;

        if ($incidents_id <= 0 || $users_id <= 0) {
            return null;
        }
        if (!isset(self::$cache[$incidents_id])) {
            self::$cache[$incidents_id] = [];
            foreach (
                $DB->request([
                    'SELECT' => ['users_id', 'role'],
                    'FROM'   => self::getTable(),
                    'WHERE'  => [static::$items_id => $incidents_id],
                ]) as $row
            ) {
                self::$cache[$incidents_id][(int) $row['users_id']] = (string) $row['role'];
            }
        }
        return self::$cache[$incidents_id][$users_id] ?? null;
    }

    /**
     * Membres actifs d'un incident, responsable compris (pour l'assignation des tâches).
     *
     * @return array<int, string> users_id => libellé
     */
    public static function getAssignableUsers(Incident $incident): array
    {
        global $DB;

        $users = [];
        $tech  = (int) $incident->fields['users_id_tech'];
        if ($tech > 0) {
            $users[$tech] = getUserName($tech) . ' (' . __('owner', 'secincident') . ')';
        }
        foreach (
            $DB->request([
                'FROM'  => self::getTable(),
                'WHERE' => [static::$items_id => $incident->getID(), 'role' => self::ROLE_CONTRIBUTOR],
                'ORDER' => 'id',
            ]) as $row
        ) {
            $uid = (int) $row['users_id'];
            $users[$uid] ??= getUserName($uid);
        }
        return $users;
    }

    /**
     * L'utilisateur courant peut-il composer l'équipe de cet incident ?
     *
     * @param array<string, mixed> $incident_fields
     */
    public static function canManage(array $incident_fields): bool
    {
        if (!Session::haveRightsOr(Incident::$rightname, [UPDATE])) {
            return false;
        }
        if (Incident::canViewAll()) {
            return true;
        }
        $reasons = Incident::getOwnershipReasons($incident_fields);
        return array_intersect($reasons, ['tech', 'recipient', 'group']) !== [];
    }

    // ---------------------------------------------------------------------
    // Droits : composer l'équipe est réservé aux pilotes de l'incident
    // ---------------------------------------------------------------------

    private function getParentFields(?array $input = null): ?array
    {
        $id = (int) ($input[static::$items_id] ?? $this->fields[static::$items_id] ?? 0);
        $incident = new Incident();
        return $incident->getFromDB($id) ? $incident->fields : null;
    }

    public function canCreateItem(): bool
    {
        $fields = $this->getParentFields(is_array($this->input ?? null) ? $this->input : null);
        return $fields !== null && self::canManage($fields) && parent::canCreateItem();
    }

    public function canUpdateItem(): bool
    {
        $fields = $this->getParentFields();
        return $fields !== null && self::canManage($fields) && parent::canUpdateItem();
    }

    public function canPurgeItem(): bool
    {
        $fields = $this->getParentFields();
        return $fields !== null && self::canManage($fields) && parent::canPurgeItem();
    }

    public function canDeleteItem(): bool
    {
        return $this->canPurgeItem();
    }

    // ---------------------------------------------------------------------
    // Onglet
    // ---------------------------------------------------------------------

    public function getTabNameForItem(CommonGLPI $item, $withtemplate = 0)
    {
        if ($item instanceof Incident && !$item->isNewItem()) {
            $nb = countElementsInTable(self::getTable(), [static::$items_id => $item->getID()])
                + ((int) $item->fields['users_id_tech'] > 0 ? 1 : 0);
            return self::createTabEntry(self::getTypeName(2), $nb, null, self::getIcon());
        }
        return '';
    }

    public static function displayTabContentForItem(CommonGLPI $item, $tabnum = 1, $withtemplate = 0)
    {
        if ($item instanceof Incident) {
            self::showForIncident($item);
        }
        return true;
    }

    public static function showForIncident(Incident $incident): void
    {
        global $DB;

        if (!$incident->can($incident->getID(), READ)) {
            AuditLog::recordDenied(I18n::instance('read team'), Incident::class, (int) $incident->getID());
            return;
        }
        AuditLog::recordView($incident, I18n::instance('team'));

        $roles   = self::getRoles();
        $members = [];
        $used    = [];

        // Pilotes (champs de l'incident)
        $pilots = [];
        if ((int) $incident->fields['users_id_tech'] > 0) {
            $pilots[] = ['label' => __('Owner', 'secincident'), 'name' => getUserName((int) $incident->fields['users_id_tech'])];
            $used[]   = (int) $incident->fields['users_id_tech'];
        }
        if ((int) $incident->fields['users_id_recipient'] > 0) {
            $pilots[] = ['label' => __('Author', 'secincident'), 'name' => getUserName((int) $incident->fields['users_id_recipient'])];
        }
        if ((int) $incident->fields['groups_id_tech'] > 0) {
            $pilots[] = ['label' => __('Assigned group', 'secincident'), 'name' => \Dropdown::getDropdownName('glpi_groups', (int) $incident->fields['groups_id_tech'])];
        }

        foreach (
            $DB->request([
                'FROM'  => self::getTable(),
                'WHERE' => [static::$items_id => $incident->getID()],
                'ORDER' => ['role', 'id'],
            ]) as $row
        ) {
            $uid = (int) $row['users_id'];
            $used[] = $uid;
            $open = countElementsInTable(RemediationTask::getTable(), [
                static::$items_id => $incident->getID(),
                'users_id_assign' => $uid,
                'status'          => [RemediationTask::STATUS_TODO, RemediationTask::STATUS_IN_PROGRESS],
            ]);
            $members[] = [
                'id'         => (int) $row['id'],
                'name'       => getUserName($uid),
                'role'       => $row['role'],
                'role_label' => $roles[$row['role']] ?? $row['role'],
                'added_by'   => (int) $row['users_id_added'] > 0 ? getUserName((int) $row['users_id_added']) : '',
                'date_added' => $row['date_added'],
                'open_tasks' => $open,
            ];
        }

        TemplateRenderer::getInstance()->display('@secincident/team.html.twig', [
            'incident'    => $incident,
            'pilots'      => $pilots,
            'members'     => $members,
            'roles'       => $roles,
            'canmanage'   => self::canManage($incident->fields),
            'used'        => array_values(array_unique($used)),
            'fk'          => static::$items_id,
            'form_action' => self::getFormURL(),
        ]);
    }

    // ---------------------------------------------------------------------
    // Cycle de vie
    // ---------------------------------------------------------------------

    public function prepareInputForAdd($input)
    {
        $incidents_id = (int) ($input[static::$items_id] ?? 0);
        $users_id     = (int) ($input['users_id'] ?? 0);
        if ($incidents_id <= 0 || $users_id <= 0 || !(new User())->getFromDB($users_id)) {
            Session::addMessageAfterRedirect(__s('Select a user', 'secincident'), false, ERROR);
            return false;
        }
        if (self::getRole($incidents_id, $users_id) !== null) {
            Session::addMessageAfterRedirect(__s('This person is already part of the team', 'secincident'), false, WARNING);
            return false;
        }
        if (empty($input['role']) || !array_key_exists($input['role'], self::getRoles())) {
            $input['role'] = self::ROLE_CONTRIBUTOR;
        }
        $input['users_id_added'] = Session::getLoginUserID() ?: 0;
        $input['date_added']     = Session::getCurrentTime();
        return parent::prepareInputForAdd($input);
    }

    public function prepareInputForUpdate($input)
    {
        // Seul le rôle peut changer
        $input = array_intersect_key($input, array_flip(['id', 'role', '_no_audit']));
        if (isset($input['role']) && !array_key_exists($input['role'], self::getRoles())) {
            unset($input['role']);
        }
        return parent::prepareInputForUpdate($input);
    }

    public function post_addItem()
    {
        self::clearCache();
        $this->traitPostAdd();
        $this->addTimeline(sprintf(
            I18n::instance('%1$s added to the team (%2$s)'),
            getUserName((int) $this->fields['users_id']),
            mb_strtolower(strtok(self::getRoles(true)[$this->fields['role']] ?? '', ' ') ?: '')
        ));
    }

    public function post_updateItem($history = true)
    {
        self::clearCache();
        $this->traitPostUpdate($history);
        if (in_array('role', $this->updates, true)) {
            $this->addTimeline(sprintf(
                I18n::instance('%1$s: role changed (%2$s)'),
                getUserName((int) $this->fields['users_id']),
                self::getRoles(true)[$this->fields['role']] ?? $this->fields['role']
            ));
        }
    }

    public function post_purgeItem()
    {
        self::clearCache();
        $this->traitPostPurge();
        $this->addTimeline(sprintf(
            I18n::instance('%s removed from the team'),
            getUserName((int) $this->fields['users_id'])
        ));
    }

    private function addTimeline(string $label): void
    {
        (new TimelineEvent())->add([
            static::$items_id => $this->fields[static::$items_id],
            'date'            => Session::getCurrentTime(),
            'event_type'      => 'communication',
            'name'            => $label,
            'source'          => 'system',
            'users_id'        => Session::getLoginUserID() ?: 0,
            '_no_audit'       => AuditLog::silent(),
        ]);
        AuditLog::flushAnchors(I18n::instance('team'));
    }

    protected static function getAuditAction(string $operation): string
    {
        return $operation === 'add' ? 'team_add' : 'team_remove';
    }

    protected function getAuditSummary(): array
    {
        return [
            'membre'   => getUserName((int) ($this->fields['users_id'] ?? 0)),
            'users_id' => (int) ($this->fields['users_id'] ?? 0),
            'role'     => $this->fields['role'] ?? '',
        ];
    }
}
