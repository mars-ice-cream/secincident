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

/**
 * Tâche du plan de remédiation d'un incident (issue d'une procédure ou ajoutée à la main).
 */
class RemediationTask extends CommonDBChild
{
    use IntegerInputTrait;
    use IncidentChildTrait {
        post_updateItem as private childPostUpdateItem;
    }

    public static $itemtype = Incident::class;
    public static $items_id = 'plugin_secincident_incidents_id';

    public static $rightname = 'plugin_secincident_incident';

    public const STATUS_TODO        = 'todo';
    public const STATUS_IN_PROGRESS = 'in_progress';
    public const STATUS_DONE        = 'done';
    public const STATUS_NA          = 'na';

    /**
     * Champs qui définissent le plan (quoi faire, obligatoire ou non) :
     * réservés au droit « Gérer les procédures » (Super-Admin, RSSI).
     * Les intervenants ne renseignent que le statut, l'assignation et le compte rendu.
     */
    public const PLAN_FIELDS = ['name', 'instructions', 'phase', 'is_mandatory', 'position'];

    public static function canManagePlan(): bool
    {
        return Playbook::canCreate();
    }

    /** Ajout d'une tâche spécifique : droit « Gérer les procédures » + droit sur l'incident */
    public function canCreateItem(): bool
    {
        return self::canManagePlan() && parent::canCreateItem();
    }

    public function canDeleteItem(): bool
    {
        return self::canManagePlan() && parent::canDeleteItem();
    }

    public function canPurgeItem(): bool
    {
        return self::canManagePlan() && parent::canPurgeItem();
    }

    public static function getTypeName($nb = 0)
    {
        return _n('Remediation task', 'Remediation', $nb, 'secincident');
    }

    public static function getIcon()
    {
        return 'ti ti-list-check';
    }

    /** @return array<string, string> */
    public static function getStatuses(bool $instance = false): array
    {
        return [
            self::STATUS_TODO        => I18n::tr('To do', $instance),
            self::STATUS_IN_PROGRESS => I18n::tr('In progress', $instance),
            self::STATUS_DONE        => I18n::tr('Done', $instance),
            self::STATUS_NA          => I18n::tr('Not applicable', $instance),
        ];
    }

    public static function getStatusColor(string $status): string
    {
        return match ($status) {
            self::STATUS_DONE        => 'green',
            self::STATUS_IN_PROGRESS => 'blue',
            self::STATUS_NA          => 'secondary',
            default                  => 'yellow',
        };
    }

    /** Nombre d'étapes obligatoires non terminées d'un incident */
    public static function countPendingMandatory(int $incidents_id): int
    {
        return countElementsInTable(self::getTable(), [
            static::$items_id => $incidents_id,
            'is_mandatory'    => 1,
            'status'          => [self::STATUS_TODO, self::STATUS_IN_PROGRESS],
        ]);
    }

    // ---------------------------------------------------------------------
    // Onglet
    // ---------------------------------------------------------------------

    public function getTabNameForItem(CommonGLPI $item, $withtemplate = 0)
    {
        if ($item instanceof Incident && !$item->isNewItem()) {
            $total = countElementsInTable(self::getTable(), [static::$items_id => $item->getID()]);
            $done  = countElementsInTable(self::getTable(), [
                static::$items_id => $item->getID(),
                'status'          => [self::STATUS_DONE, self::STATUS_NA],
            ]);
            return self::createTabEntry(__('Remediation', 'secincident'), $total > 0 ? $done : 0, null, self::getIcon(), $total > 0 ? $total : null);
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

    /**
     * @return array<string, mixed>
     */
    public static function getPlanData(Incident $incident): array
    {
        global $DB;

        $phases   = Playbook::getPhases();
        $statuses = self::getStatuses();
        $users    = [];
        $tasks    = [];
        foreach (
            $DB->request([
                'FROM'  => self::getTable(),
                'WHERE' => [static::$items_id => $incident->getID()],
                'ORDER' => ['position ASC', 'id ASC'],
            ]) as $row
        ) {
            foreach (['users_id_assign', 'users_id_done'] as $field) {
                $uid = (int) $row[$field];
                $users[$uid] ??= $uid > 0 ? getUserName($uid) : '';
                $row[$field . '_name'] = $users[$uid];
            }
            $row['status_label'] = $statuses[$row['status']] ?? $row['status'];
            $row['status_color'] = self::getStatusColor((string) $row['status']);
            $row['phase_label']  = $phases[$row['phase']] ?? $row['phase'];
            $row['phase_color']  = Playbook::getPhaseColor((string) $row['phase']);
            $row['url']          = self::getFormURLWithID($row['id']);
            $tasks[] = $row;
        }

        $total = count($tasks);
        $done  = count(array_filter($tasks, fn ($t) => in_array($t['status'], [self::STATUS_DONE, self::STATUS_NA], true)));
        $pending_mandatory = count(array_filter(
            $tasks,
            fn ($t) => (int) $t['is_mandatory'] === 1 && in_array($t['status'], [self::STATUS_TODO, self::STATUS_IN_PROGRESS], true)
        ));

        // Regroupement par phase, dans l'ordre des phases
        $by_phase = [];
        foreach (array_keys($phases) as $phase) {
            $phase_tasks = array_values(array_filter($tasks, fn ($t) => $t['phase'] === $phase));
            if ($phase_tasks !== []) {
                $phase_done = count(array_filter($phase_tasks, fn ($t) => in_array($t['status'], [self::STATUS_DONE, self::STATUS_NA], true)));
                $by_phase[] = [
                    'key'   => $phase,
                    'label' => $phases[$phase],
                    'color' => Playbook::getPhaseColor($phase),
                    'tasks' => $phase_tasks,
                    'done'  => $phase_done,
                    'total' => count($phase_tasks),
                ];
            }
        }

        // Procédures déjà appliquées
        $applied = [];
        foreach (array_unique(array_filter(array_map('intval', array_column($tasks, 'plugin_secincident_playbooks_id')))) as $pid) {
            $playbook = new Playbook();
            $applied[$pid] = $playbook->getFromDB($pid) ? $playbook->fields['name'] : ('#' . $pid);
        }

        return [
            'tasks'             => $tasks,
            'by_phase'          => $by_phase,
            'total'             => $total,
            'done'              => $done,
            'percent'           => $total > 0 ? (int) round($done * 100 / $total) : 0,
            'pending_mandatory' => $pending_mandatory,
            'applied'           => $applied,
        ];
    }

    public static function showForIncident(Incident $incident): void
    {
        if (!$incident->can($incident->getID(), READ)) {
            AuditLog::recordDenied(I18n::instance('read remediation plan'), Incident::class, (int) $incident->getID());
            return;
        }
        AuditLog::recordView($incident, I18n::instance('remediation'));

        $plan     = self::getPlanData($incident);
        $choices  = Playbook::getChoicesForIncident($incident);
        foreach (array_keys($plan['applied']) as $pid) {
            unset($choices[$pid]);
        }

        TemplateRenderer::getInstance()->display('@secincident/remediation.html.twig', [
            'incident'     => $incident,
            'plan'         => $plan,
            'choices'      => $choices,
            'statuses'     => self::getStatuses(),
            'phases'       => Playbook::getPhases(),
            'canedit'      => $incident->can($incident->getID(), UPDATE),
            'fk'           => static::$items_id,
            'form_action'  => self::getFormURL(),
            'print_url'    => $GLOBALS['CFG_GLPI']['root_doc'] . '/plugins/secincident/front/remediation.print.php?id=' . $incident->getID(),
            'playbook_url' => Playbook::getSearchURL(),
            'assignables'  => TeamMember::getAssignableUsers($incident),
            'can_manage'   => Playbook::canCreate(),
            'can_add_task' => self::canManagePlan(),
            'journal_url'  => $GLOBALS['CFG_GLPI']['root_doc'] . '/plugins/secincident/front/actions.print.php?id=' . $incident->getID(),
        ]);
    }

    public function showForm($ID, array $options = [])
    {
        $this->initForm($ID, $options);
        if ($this->isNewItem() && !empty($options[static::$items_id])) {
            $this->fields[static::$items_id] = (int) $options[static::$items_id];
        }
        if (!$this->isNewItem()) {
            AuditLog::recordView($this, I18n::instance('remediation task'));
        }
        $incident = new Incident();
        $incident->getFromDB((int) ($this->fields[static::$items_id] ?? 0));
        TemplateRenderer::getInstance()->display('@secincident/remediationtask_form.html.twig', [
            'item'     => $this,
            'params'   => $options,
            'phases'   => Playbook::getPhases(),
            'statuses' => self::getStatuses(),
            'incident' => $incident,
            'can_plan' => self::canManagePlan(),
        ]);
        return true;
    }

    // ---------------------------------------------------------------------
    // Application d'une procédure
    // ---------------------------------------------------------------------

    /**
     * Copie les étapes d'une procédure dans le plan de l'incident.
     *
     * @return int nombre de tâches créées (0 si déjà appliquée)
     */
    public static function applyPlaybook(Incident $incident, Playbook $playbook): int
    {
        $already = countElementsInTable(self::getTable(), [
            static::$items_id                    => $incident->getID(),
            Playbook::getForeignKeyField()       => $playbook->getID(),
        ]);
        if ($already > 0) {
            Session::addMessageAfterRedirect(__s('This playbook is already applied to the incident.', 'secincident'), false, WARNING);
            return 0;
        }

        $base = (int) (countElementsInTable(self::getTable(), [static::$items_id => $incident->getID()]) * 10);
        $created = 0;
        foreach ($playbook->getSteps() as $step) {
            $task = new self();
            if (
                $task->add([
                    static::$items_id              => $incident->getID(),
                    Playbook::getForeignKeyField() => $playbook->getID(),
                    'position'                         => $base + (int) $step['position'],
                    'phase'                        => $step['phase'],
                    'name'                         => $step['name'],
                    'instructions'                 => $step['instructions'],
                    'is_mandatory'                 => (int) $step['is_mandatory'],
                    'status'                       => self::STATUS_TODO,
                    'users_id_assign'              => (int) $incident->fields['users_id_tech'],
                    '_no_audit'                    => AuditLog::silent(),
                ])
            ) {
                $created++;
            }
        }

        AuditLog::record('apply_playbook', $incident, [
            'procedure'      => $playbook->fields['name'],
            'procedure_id'   => $playbook->getID(),
            'taches_creees'  => $created,
        ]);

        (new TimelineEvent())->add([
            static::$items_id => $incident->getID(),
            'date'            => Session::getCurrentTime(),
            'event_type'      => 'analysis',
            'name'            => sprintf(I18n::instance('Playbook applied: %s'), $playbook->fields['name']),
            'source'          => 'system',
            'users_id'        => Session::getLoginUserID() ?: 0,
            '_no_audit'       => AuditLog::silent(),
        ]);
        AuditLog::flushAnchors(I18n::instance('playbook application'));

        return $created;
    }

    // ---------------------------------------------------------------------
    // Cycle de vie
    // ---------------------------------------------------------------------

    public function prepareInputForAdd($input)
    {
        if (empty($input['phase']) || !array_key_exists($input['phase'], Playbook::getPhases())) {
            $input['phase'] = 'containment';
        }
        if (empty($input['status']) || !array_key_exists($input['status'], self::getStatuses())) {
            $input['status'] = self::STATUS_TODO;
        }
        if (!isset($input['position'])) {
            $input['position'] = (countElementsInTable(self::getTable(), [static::$items_id => (int) ($input[static::$items_id] ?? 0)]) + 1) * 10;
        }
        $input = $this->stampCompletion($input, null);
        $input = $this->validateAssignee($input);
        return parent::prepareInputForAdd($input);
    }

    public function prepareInputForUpdate($input)
    {
        if (isset($input['phase']) && !array_key_exists($input['phase'], Playbook::getPhases())) {
            unset($input['phase']);
        }
        if (isset($input['status']) && !array_key_exists($input['status'], self::getStatuses())) {
            unset($input['status']);
        }
        // Origine non modifiable
        unset($input[Playbook::getForeignKeyField()]);
        // Définition du plan : réservée au droit « Gérer les procédures »
        if (!self::canManagePlan() && !AuditLog::isSilent($input)) {
            $blocked = [];
            foreach (self::PLAN_FIELDS as $field) {
                if (array_key_exists($field, $input) && (string) $input[$field] !== (string) ($this->fields[$field] ?? '')) {
                    $blocked[] = $field;
                }
                unset($input[$field]);
            }
            if ($blocked !== []) {
                AuditLog::record('update', $this, [
                    'tentative' => I18n::instance('change to the definition of a remediation task'),
                    'champs'    => $blocked,
                ], AuditLog::RESULT_DENIED);
                Session::addMessageAfterRedirect(
                    __s('Only profiles allowed to manage playbooks can change the definition of a task (action, instructions, phase, mandatory flag, order). Status, assignment and report have been saved.', 'secincident'),
                    false,
                    WARNING
                );
            }
        }
        $input = $this->stampCompletion($input, $this->fields['status'] ?? null);
        $input = $this->validateAssignee($input);
        return parent::prepareInputForUpdate($input);
    }

    /**
     * Une tâche ne peut être confiée qu'au responsable ou à un intervenant de l'équipe.
     * Si l'utilisateur courant pilote l'incident, la personne est ajoutée à l'équipe.
     *
     * @param array<string, mixed> $input
     * @return array<string, mixed>
     */
    private function validateAssignee(array $input): array
    {
        if (!array_key_exists('users_id_assign', $input)) {
            return $input;
        }
        $uid = (int) $input['users_id_assign'];
        if ($uid <= 0) {
            $input['users_id_assign'] = 0;
            return $input;
        }
        if ($uid === (int) ($this->fields['users_id_assign'] ?? -1)) {
            return $input;
        }
        $incidents_id = (int) ($input[static::$items_id] ?? $this->fields[static::$items_id] ?? 0);
        $incident     = new Incident();
        if (!$incident->getFromDB($incidents_id)) {
            return $input;
        }
        $role = TeamMember::getRole($incidents_id, $uid);
        if ((int) $incident->fields['users_id_tech'] === $uid || $role === TeamMember::ROLE_CONTRIBUTOR) {
            return $input;
        }
        if (TeamMember::canManage($incident->fields)) {
            $member = new TeamMember();
            if ($role === TeamMember::ROLE_OBSERVER) {
                $found = $member->find([static::$items_id => $incidents_id, 'users_id' => $uid], [], 1);
                $member->update(['id' => (int) array_key_first($found), 'role' => TeamMember::ROLE_CONTRIBUTOR]);
            } else {
                $member->add([static::$items_id => $incidents_id, 'users_id' => $uid, 'role' => TeamMember::ROLE_CONTRIBUTOR]);
            }
            Session::addMessageAfterRedirect(htmlescape(sprintf(
                __('%s has been added to the team as a contributor.', 'secincident'),
                getUserName($uid)
            )));
            return $input;
        }
        Session::addMessageAfterRedirect(
            __s('A task can only be assigned to a contributor of the team. Ask the owner to add them.', 'secincident'),
            false,
            WARNING
        );
        unset($input['users_id_assign']);
        return $input;
    }

    /**
     * Horodate et signe la réalisation d'une tâche.
     *
     * @param array<string, mixed> $input
     * @return array<string, mixed>
     */
    private function stampCompletion(array $input, ?string $previous): array
    {
        if (!isset($input['status']) || $input['status'] === $previous) {
            return $input;
        }
        if (in_array($input['status'], [self::STATUS_DONE, self::STATUS_NA], true)) {
            $input['date_done']     = Session::getCurrentTime();
            $input['users_id_done'] = Session::getLoginUserID() ?: 0;
        } else {
            $input['date_done']     = null;
            $input['users_id_done'] = 0;
        }
        return $input;
    }

    public function post_updateItem($history = true)
    {
        $this->childPostUpdateItem($history);

        if (in_array('status', $this->updates, true) && !AuditLog::isSilent($this->input)) {
            $statuses = self::getStatuses(true);
            $type     = match ($this->fields['phase']) {
                'containment', 'eradication', 'recovery', 'analysis', 'notification' => $this->fields['phase'],
                default => 'note',
            };
            (new TimelineEvent())->add([
                static::$items_id => $this->fields[static::$items_id],
                'date'            => Session::getCurrentTime(),
                'event_type'      => $type,
                'name'            => sprintf(
                    I18n::instance('Remediation — %1$s: %2$s'),
                    $statuses[$this->fields['status']] ?? $this->fields['status'],
                    $this->fields['name']
                ),
                'content'         => (string) ($this->fields['comment'] ?? ''),
                'source'          => 'system',
                'users_id'        => Session::getLoginUserID() ?: 0,
                '_no_audit'       => AuditLog::silent(),
            ]);
            AuditLog::flushAnchors(I18n::instance('remediation follow-up'));
        }
    }

    protected function getAuditSummary(): array
    {
        return array_intersect_key(
            $this->fields,
            array_flip(['name', 'phase', 'status', 'is_mandatory', 'plugin_secincident_playbooks_id'])
        );
    }
}
