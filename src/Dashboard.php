<?php

/**
 * -------------------------------------------------------------------------
 * SecIncident — Suivi des incidents de sécurité pour GLPI 11
 * -------------------------------------------------------------------------
 * @license   GPLv3 https://www.gnu.org/licenses/gpl-3.0.html
 * -------------------------------------------------------------------------
 */

namespace GlpiPlugin\Secincident;

use DateTimeImmutable;
use Session;

/**
 * Indicateurs du tableau de bord sécurité.
 */
class Dashboard
{
    /** @return array<int, string> */
    public static function getPeriods(): array
    {
        return [
            30  => __('Last 30 days', 'secincident'),
            90  => __('Last 3 months', 'secincident'),
            365 => __('Last 12 months', 'secincident'),
            0   => __('Since the beginning', 'secincident'),
        ];
    }

    /**
     * @return array<string, mixed>
     */
    public static function getStats(int $days): array
    {
        global $DB;

        $table = Incident::getTable();
        $now   = new DateTimeImmutable(Session::getCurrentTime());
        $from  = $days > 0 ? $now->modify("-{$days} days")->format('Y-m-d H:i:s') : null;

        $where = ['is_deleted' => 0]
            + getEntitiesRestrictCriteria($table, '', '', true)
            + Incident::getSystemSQLCriteria($table);

        $iterator = $DB->request([
            'FROM'  => $table,
            'WHERE' => $where,
        ]);

        $statuses   = Incident::getStatuses();
        $severities = Incident::getSeverities();
        $categories = Incident::getCategories();
        $sources    = Incident::getSources();

        $kpi = [
            'open'           => 0,
            'open_critical'  => 0,
            'new_in_period'  => 0,
            'closed_period'  => 0,
            'overdue'        => 0,
            'personal_data'  => 0,
            'mttc_hours'     => null,
            'mttr_hours'     => null,
        ];
        $by_status   = array_fill_keys(array_keys($statuses), 0);
        $by_severity = array_fill_keys(array_keys($severities), 0);
        $by_category = array_fill_keys(array_keys($categories), 0);
        $by_source   = array_fill_keys(array_keys($sources), 0);
        $mitre_tactics = MitreAttack::getTactics();
        $by_tactic     = [];
        $by_technique  = [];

        // Tendance sur 12 mois glissants
        $months = [];
        for ($i = 11; $i >= 0; $i--) {
            $months[$now->modify("first day of -{$i} month")->format('Y-m')] = 0;
        }

        $containment_delays = [];
        $resolution_delays  = [];
        $open_list          = [];
        $deadline_list      = [];

        $incident = new Incident();
        foreach ($iterator as $row) {
            $is_open   = (int) $row['status'] !== Incident::STATUS_CLOSED;
            $detected  = $row['date_detection'];
            $in_period = $from === null || ($detected !== null && $detected >= $from);

            if ($is_open) {
                $kpi['open']++;
                if ((int) $row['severity'] >= 4) {
                    $kpi['open_critical']++;
                }
            }
            if ($in_period) {
                $kpi['new_in_period']++;
                $by_status[(int) $row['status']] = ($by_status[(int) $row['status']] ?? 0) + 1;
                $by_severity[(int) $row['severity']] = ($by_severity[(int) $row['severity']] ?? 0) + 1;
                $by_category[$row['category']] = ($by_category[$row['category']] ?? 0) + 1;
                $by_source[$row['source']] = ($by_source[$row['source']] ?? 0) + 1;
                if ((string) $row['mitre_tactic'] !== '') {
                    $by_tactic[$row['mitre_tactic']] = ($by_tactic[$row['mitre_tactic']] ?? 0) + 1;
                }
                if ((string) $row['mitre_technique'] !== '') {
                    $by_technique[$row['mitre_technique']] = ($by_technique[$row['mitre_technique']] ?? 0) + 1;
                }
                if ((int) $row['is_personal_data'] === 1) {
                    $kpi['personal_data']++;
                }
            }
            if ($row['date_closure'] !== null && ($from === null || $row['date_closure'] >= $from)) {
                $kpi['closed_period']++;
            }

            if ($detected !== null) {
                $month = substr($detected, 0, 7);
                if (isset($months[$month])) {
                    $months[$month]++;
                }
                if ($in_period && $row['date_containment'] !== null && $row['date_containment'] >= $detected) {
                    $containment_delays[] = (strtotime($row['date_containment']) - strtotime($detected)) / 3600;
                }
                if ($in_period && $row['date_closure'] !== null && $row['date_closure'] >= $detected) {
                    $resolution_delays[] = (strtotime($row['date_closure']) - strtotime($detected)) / 3600;
                }
            }

            // Échéances réglementaires (tous incidents, même clos, tant qu'une notification manque)
            $incident->getFromResultSet($row);
            foreach ($incident->getDeadlines() as $deadline) {
                if (in_array($deadline['state'], ['overdue', 'pending', 'unknown'], true)) {
                    if ($deadline['state'] === 'overdue') {
                        $kpi['overdue']++;
                    }
                    $deadline_list[] = $deadline + [
                        'incident_id'   => $row['id'],
                        'incident_ref'  => $row['reference'],
                        'incident_name' => $row['name'],
                        'incident_url'  => Incident::getFormURLWithID($row['id']),
                    ];
                }
            }

            if ($is_open) {
                $open_list[] = [
                    'id'             => $row['id'],
                    'reference'      => $row['reference'],
                    'name'           => $row['name'],
                    'url'            => Incident::getFormURLWithID($row['id']),
                    'status'         => $statuses[(int) $row['status']] ?? '',
                    'status_color'   => Incident::getStatusColor((int) $row['status']),
                    'severity'       => (int) $row['severity'],
                    'severity_label' => $severities[(int) $row['severity']] ?? '',
                    'severity_color' => Incident::getSeverityColor((int) $row['severity']),
                    'category'       => $categories[$row['category']] ?? $row['category'],
                    'date_detection' => $detected,
                    'age_days'       => $detected !== null ? (int) floor(($now->getTimestamp() - strtotime($detected)) / 86400) : null,
                ];
            }
        }

        usort($open_list, fn ($a, $b) => [$b['severity'], $a['date_detection']] <=> [$a['severity'], $b['date_detection']]);
        usort($deadline_list, function ($a, $b) {
            $order = ['overdue' => 0, 'pending' => 1, 'unknown' => 2];
            return [$order[$a['state']], $a['due'] ?? '9999'] <=> [$order[$b['state']], $b['due'] ?? '9999'];
        });

        if ($containment_delays !== []) {
            $kpi['mttc_hours'] = round(array_sum($containment_delays) / count($containment_delays), 1);
        }
        if ($resolution_delays !== []) {
            $kpi['mttr_hours'] = round(array_sum($resolution_delays) / count($resolution_delays), 1);
        }

        // Mes tâches de remédiation (tous incidents visibles)
        $my_tasks = [];
        $me       = (int) Session::getLoginUserID();
        if ($me > 0) {
            $rt = RemediationTask::getTable();
            $fk = Incident::getForeignKeyField();
            foreach (
                $DB->request([
                    'SELECT'     => ["$rt.id", "$rt.name", "$rt.phase", "$rt.status", "$rt.is_mandatory", "$table.id AS incidents_id", "$table.reference", "$table.name AS incident_name", "$table.severity"],
                    'FROM'       => $rt,
                    'INNER JOIN' => [$table => ['ON' => [$rt => $fk, $table => 'id']]],
                    'WHERE'      => [
                        "$rt.users_id_assign" => $me,
                        "$rt.status"          => [RemediationTask::STATUS_TODO, RemediationTask::STATUS_IN_PROGRESS],
                        "$table.is_deleted"   => 0,
                    ] + Incident::getSystemSQLCriteria($table),
                    'ORDER'      => ["$table.severity DESC", "$rt.position ASC"],
                    'LIMIT'      => 30,
                ]) as $row
            ) {
                $row['phase_label']  = Playbook::getPhases()[$row['phase']] ?? $row['phase'];
                $row['phase_color']  = Playbook::getPhaseColor((string) $row['phase']);
                $row['status_label'] = RemediationTask::getStatuses()[$row['status']] ?? $row['status'];
                $row['status_color'] = RemediationTask::getStatusColor((string) $row['status']);
                $row['url']          = Incident::getFormURLWithID((int) $row['incidents_id']) . '&forcetab=' . rawurlencode(RemediationTask::class . '$1');
                $my_tasks[] = $row;
            }
        }

        return [
            'my_tasks'    => $my_tasks,
            'kpi'         => $kpi,
            'by_status'   => self::toBars($by_status, $statuses, fn ($k) => Incident::getStatusColor((int) $k), 3),
            'by_severity' => self::toBars($by_severity, $severities, fn ($k) => Incident::getSeverityColor((int) $k), 4),
            'by_category' => self::toBars(array_filter($by_category), $categories, fn () => 'blue', 5, true),
            'by_source'   => self::toBars(array_filter($by_source), $sources, fn () => 'cyan', 9, true),
            'by_tactic'   => self::toBars($by_tactic, $mitre_tactics, fn () => 'purple', 10, true, 'contains'),
            'by_technique' => array_slice(self::toBars($by_technique, [], fn () => 'pink', 11, true, 'contains'), 0, 8),
            'months'      => $months,
            'months_max'  => max(1, ...array_values($months)),
            'open_list'   => array_slice($open_list, 0, 25),
            'deadlines'   => array_slice($deadline_list, 0, 25),
        ];
    }

    /**
     * @param array<string|int, int>    $counts
     * @param array<string|int, string> $labels
     * @return array<int, array<string, mixed>>
     */
    private static function toBars(array $counts, array $labels, callable $color, int $search_field, bool $sort = false, string $searchtype = 'equals'): array
    {
        $total = max(1, array_sum($counts));
        $bars  = [];
        foreach ($counts as $key => $count) {
            $bars[] = [
                'key'     => $key,
                'label'   => $labels[$key] ?? (string) $key,
                'count'   => $count,
                'percent' => round($count * 100 / $total),
                'color'   => $color($key),
                'url'     => Incident::getSearchURL() . '?' . http_build_query([
                    'criteria' => [[
                        'field'      => $search_field,
                        'searchtype' => $searchtype,
                        'value'      => $key,
                    ]],
                    'reset' => 'reset',
                ]),
            ];
        }
        if ($sort) {
            usort($bars, fn ($a, $b) => $b['count'] <=> $a['count']);
        }
        return $bars;
    }
}
