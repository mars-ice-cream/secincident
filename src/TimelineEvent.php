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
 * Événement de la chronologie d'un incident
 * (détection, action de confinement, communication, import EDR…).
 */
class TimelineEvent extends CommonDBChild
{
    use IntegerInputTrait;
    use IncidentChildTrait;

    public static $itemtype = Incident::class;
    public static $items_id = 'plugin_secincident_incidents_id';

    public static $rightname = 'plugin_secincident_incident';

    public $dohistory = false;

    public static function getTypeName($nb = 0)
    {
        return _n('Event', 'Timeline', $nb, 'secincident');
    }

    public static function getIcon()
    {
        return 'ti ti-timeline-event';
    }

    /** @return array<string, string> */
    public static function getEventTypes(): array
    {
        return [
            'detection'     => __('Detection / alert', 'secincident'),
            'action'        => __('Investigation / response action', 'secincident'),
            'analysis'      => __('Analysis / investigation', 'secincident'),
            'containment'   => __('Containment', 'secincident'),
            'eradication'   => __('Eradication', 'secincident'),
            'recovery'      => __('Recovery', 'secincident'),
            'communication' => __('Communication', 'secincident'),
            'notification'  => __('Regulatory notification', 'secincident'),
            'status_change' => __('Status change', 'secincident'),
            'closure'       => __('Closure', 'secincident'),
            'note'          => __('Note', 'secincident'),
        ];
    }

    /** Icône Tabler par type d'événement */
    public static function getEventIcon(string $type): string
    {
        return match ($type) {
            'detection'     => 'ti ti-radar-2',
            'action'        => 'ti ti-tool',
            'analysis'      => 'ti ti-search',
            'containment'   => 'ti ti-lock',
            'eradication'   => 'ti ti-trash',
            'recovery'      => 'ti ti-refresh',
            'communication' => 'ti ti-message',
            'notification'  => 'ti ti-gavel',
            'status_change' => 'ti ti-arrows-exchange',
            'closure'       => 'ti ti-circle-check',
            default         => 'ti ti-note',
        };
    }

    public static function getEventColor(string $type): string
    {
        return match ($type) {
            'detection'     => 'red',
            'action'        => 'blue',
            'analysis'      => 'orange',
            'containment'   => 'yellow',
            'eradication'   => 'purple',
            'recovery'      => 'azure',
            'notification'  => 'pink',
            'closure'       => 'green',
            default         => 'secondary',
        };
    }

    /** Outils / moyens utilisés pour une action @return array<string, string> */
    public static function getTools(): array
    {
        return [
            'edr_console' => __('EDR / XDR console (remote response)', 'secincident'),
            'powershell' => 'PowerShell',
            'cmd'        => __('Command prompt / script', 'secincident'),
            'ad'         => __('Active Directory', 'secincident'),
            'm365'       => __('Microsoft 365 / Entra ID', 'secincident'),
            'firewall'   => __('Firewall / network', 'secincident'),
            'backup'     => __('Backup / restore', 'secincident'),
            'mail'       => __('Mail', 'secincident'),
            'edr_other'  => __('Antivirus / other security tool', 'secincident'),
            'forensic'   => __('Analysis tool (forensics)', 'secincident'),
            'physical'   => __('On-site physical intervention', 'secincident'),
            'phone'      => __('Phone call', 'secincident'),
            'other'      => __('Other', 'secincident'),
        ];
    }

    /** @return array<string, string> */
    public static function getResults(): array
    {
        return [
            'ok'       => __('Successful', 'secincident'),
            'partial'  => __('Partial', 'secincident'),
            'failed'   => __('Failed', 'secincident'),
            'to_check' => __('To be checked', 'secincident'),
        ];
    }

    public static function getResultColor(string $result): string
    {
        return match ($result) {
            'ok'      => 'green',
            'partial' => 'orange',
            'failed'  => 'red',
            default   => 'yellow',
        };
    }

    /**
     * Tâches du plan de remédiation de l'incident (pour rattacher une action).
     *
     * @return array<int, string>
     */
    public static function getTaskChoices(int $incidents_id): array
    {
        global $DB;
        $choices = [];
        foreach (
            $DB->request([
                'SELECT' => ['id', 'name', 'phase'],
                'FROM'   => RemediationTask::getTable(),
                'WHERE'  => [static::$items_id => $incidents_id],
                'ORDER'  => ['position ASC', 'id ASC'],
            ]) as $row
        ) {
            $choices[(int) $row['id']] = (Playbook::getPhases()[$row['phase']] ?? $row['phase']) . ' — ' . $row['name'];
        }
        return $choices;
    }

    public function getTabNameForItem(CommonGLPI $item, $withtemplate = 0)
    {
        if ($item instanceof Incident && !$item->isNewItem()) {
            $nb = 0;
            if ($_SESSION['glpishow_count_on_tabs']) {
                $nb = countElementsInTable(self::getTable(), [static::$items_id => $item->getID()]);
            }
            return self::createTabEntry(__('Timeline', 'secincident'), $nb, null, self::getIcon());
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
     * Affiche la chronologie (frise) d'un incident + formulaire d'ajout rapide.
     */
    public static function showForIncident(Incident $incident): void
    {
        global $DB;

        if (!$incident->can($incident->getID(), READ)) {
            AuditLog::recordDenied(I18n::instance('read timeline'), Incident::class, (int) $incident->getID());
            return;
        }
        AuditLog::recordView($incident, 'chronologie');
        $canedit = $incident->can($incident->getID(), UPDATE);

        $filter = $_GET['event_type'] ?? '';
        $where  = [static::$items_id => $incident->getID()];
        if ($filter !== '' && array_key_exists($filter, self::getEventTypes())) {
            $where['event_type'] = $filter;
        }

        $iterator = $DB->request([
            'FROM'  => self::getTable(),
            'WHERE' => $where,
            'ORDER' => ['date ASC', 'id ASC'],
        ]);

        $types   = self::getEventTypes();
        $tools   = self::getTools();
        $results = self::getResults();
        $tasks   = self::getTaskChoices((int) $incident->getID());
        $events  = [];
        foreach ($iterator as $row) {
            $row['tool_label']   = $tools[$row['tool'] ?? ''] ?? '';
            $row['result_label'] = $results[$row['result'] ?? ''] ?? '';
            $row['result_color'] = self::getResultColor((string) ($row['result'] ?? ''));
            $row['task_name']    = $tasks[(int) ($row['plugin_secincident_remediationtasks_id'] ?? 0)] ?? '';
            $row['type_label'] = $types[$row['event_type']] ?? $row['event_type'];
            $row['icon']       = self::getEventIcon((string) $row['event_type']);
            $row['color']      = self::getEventColor((string) $row['event_type']);
            $row['user_name']  = $row['users_id'] > 0 ? getUserName($row['users_id']) : '';
            $row['has_raw']    = !empty($row['raw_data']);
            $row['raw_pretty'] = '';
            if ($row['has_raw']) {
                $decoded           = json_decode((string) $row['raw_data'], true);
                $row['raw_pretty'] = is_array($decoded)
                    ? (string) json_encode($decoded, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)
                    : (string) $row['raw_data'];
            }
            unset($row['raw_data']);
            $row['form_url']   = self::getFormURLWithID($row['id']);
            $events[] = $row;
        }

        TemplateRenderer::getInstance()->display('@secincident/timeline.html.twig', [
            'incident'    => $incident,
            'events'      => $events,
            'types'       => $types,
            'filter'      => $filter,
            'canedit'     => $canedit,
            'fk'          => static::$items_id,
            'form_action' => self::getFormURL(),
            'now'         => Session::getCurrentTime(),
            'tools'       => $tools,
            'results'     => $results,
            'tasks'       => $tasks,
            'task_choices' => [0 => '—'] + $tasks,
            'print_url'   => $GLOBALS['CFG_GLPI']['root_doc'] . '/plugins/secincident/front/actions.print.php?id=' . $incident->getID(),
            'nb_actions'  => count(array_filter($events, fn ($e) => $e['event_type'] === 'action')),
            'nb_remediations' => countElementsInTable(RemediationTask::getTable(), [
                Incident::getForeignKeyField() => $incident->getID(),
                'status'                       => [RemediationTask::STATUS_DONE, RemediationTask::STATUS_NA],
            ]),
        ]);
    }

    public function showForm($ID, array $options = [])
    {
        $this->initForm($ID, $options);
        if (!$this->isNewItem()) {
            AuditLog::recordView($this, I18n::instance('event'));
        }

        $raw = null;
        if (!empty($this->fields['raw_data'])) {
            $decoded = json_decode($this->fields['raw_data'], true);
            $raw     = is_array($decoded) ? $decoded : null;
        }

        if ($this->isNewItem() && !empty($options[static::$items_id])) {
            $this->fields[static::$items_id] = (int) $options[static::$items_id];
        }
        $incident = new Incident();
        $incident->getFromDB((int) ($this->fields[static::$items_id] ?? 0));

        TemplateRenderer::getInstance()->display('@secincident/event_form.html.twig', [
            'item'     => $this,
            'params'   => $options,
            'types'    => self::getEventTypes(),
            'raw'      => $raw,
            'incident' => $incident,
            'tools'    => self::getTools(),
            'results'  => self::getResults(),
            'tasks'    => $tasks = self::getTaskChoices((int) ($this->fields[static::$items_id] ?? 0)),
            'task_choices' => [0 => '—'] + $tasks,
        ]);
        return true;
    }

    public function prepareInputForAdd($input)
    {
        if (empty($input['date'])) {
            $input['date'] = Session::getCurrentTime();
        }
        if (empty($input['event_type']) || !array_key_exists($input['event_type'], self::getEventTypes())) {
            $input['event_type'] = 'note';
        }
        if (!isset($input['users_id'])) {
            $input['users_id'] = Session::getLoginUserID() ?: 0;
        }
        if (isset($input['raw_data']) && is_array($input['raw_data'])) {
            $input['raw_data'] = json_encode($input['raw_data'], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        }
        $input = $this->normalizeAction($input, (int) ($input[static::$items_id] ?? 0), true);
        if ($input === false) {
            return false;
        }
        return parent::prepareInputForAdd($input);
    }

    public function prepareInputForUpdate($input)
    {
        if (isset($input['event_type']) && !array_key_exists($input['event_type'], self::getEventTypes())) {
            $input['event_type'] = 'note';
        }
        // Les données brutes importées ne sont pas modifiables (valeur probante)
        unset($input['raw_data'], $input['external_id'], $input['source']);
        $input = $this->normalizeAction($input, (int) ($this->fields[static::$items_id] ?? 0), false);
        if ($input === false) {
            return false;
        }
        return parent::prepareInputForUpdate($input);
    }

    /**
     * Contrôles d'une action d'investigation : cible obligatoire, outil et résultat
     * dans les listes, tâche liée appartenant au même incident.
     *
     * @param array<string, mixed> $input
     * @return array<string, mixed>|false
     */
    private function normalizeAction(array $input, int $incidents_id, bool $is_add): array|false
    {
        $current = $is_add ? [] : $this->fields;
        $type    = $input['event_type'] ?? ($current['event_type'] ?? '');
        foreach (['target', 'command', 'detection_ref'] as $field) {
            if (isset($input[$field])) {
                $input[$field] = trim((string) $input[$field]);
            }
        }
        if ($type !== 'action') {
            return $input;
        }
        $target = (string) ($input['target'] ?? ($current['target'] ?? ''));
        if ($target === '') {
            $target = (string) ($input['hostname'] ?? ($current['hostname'] ?? ''));
            if ($target !== '') {
                $input['target'] = $target;
            }
        }
        if ($target === '') {
            Session::addMessageAfterRedirect(__s('Action: specify the target (workstation, server, account…).', 'secincident'), false, ERROR);
            return false;
        }
        if (isset($input['tool']) && !array_key_exists($input['tool'], self::getTools())) {
            $input['tool'] = 'other';
        }
        if (array_key_exists('result', $input) && !array_key_exists((string) $input['result'], self::getResults())) {
            $input['result'] = 'to_check';
        }
        if ($is_add && empty($input['result'])) {
            $input['result'] = 'to_check';
        }
        $task_fk = 'plugin_secincident_remediationtasks_id';
        if (!empty($input[$task_fk])) {
            $ok = countElementsInTable(RemediationTask::getTable(), [
                'id'              => (int) $input[$task_fk],
                static::$items_id => $incidents_id,
            ]) === 1;
            if (!$ok) {
                $input[$task_fk] = 0;
            }
        }
        return $input;
    }

    public function rawSearchOptions()
    {
        $tab = [];
        $tab[] = ['id' => 'common', 'name' => self::getTypeName(1)];
        $tab[] = [
            'id'       => '1',
            'table'    => self::getTable(),
            'field'    => 'name',
            'name'     => __('Label', 'secincident'),
            'datatype' => 'itemlink',
        ];
        $tab[] = [
            'id'       => '2',
            'table'    => self::getTable(),
            'field'    => 'date',
            'name'     => __('Date'),
            'datatype' => 'datetime',
        ];
        $tab[] = [
            'id'       => '3',
            'table'    => self::getTable(),
            'field'    => 'hostname',
            'name'     => __('Host', 'secincident'),
            'datatype' => 'string',
        ];
        $tab[] = [
            'id'       => '4',
            'table'    => self::getTable(),
            'field'    => 'username',
            'name'     => __('User involved', 'secincident'),
            'datatype' => 'string',
        ];
        $tab[] = [
            'id'       => '5',
            'table'    => self::getTable(),
            'field'    => 'content',
            'name'     => __('Detail', 'secincident'),
            'datatype' => 'text',
        ];
        return $tab;
    }
}
