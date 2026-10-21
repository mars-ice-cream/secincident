<?php

/**
 * -------------------------------------------------------------------------
 * SecIncident — Suivi des incidents de sécurité pour GLPI 11
 * -------------------------------------------------------------------------
 * @license   GPLv3 https://www.gnu.org/licenses/gpl-3.0.html
 * -------------------------------------------------------------------------
 */

namespace GlpiPlugin\Secincident;

use CommonDBTM;
use Throwable;

/**
 * Empreintes SHA-256 de toutes les données du plugin.
 *
 * Principe :
 *  - chaque enregistrement (incident, événement, IOC, lien) porte une empreinte
 *    SHA-256 de son contenu, recalculée à chaque écriture légitime ;
 *  - cette empreinte est aussi ancrée dans le journal d'audit chaîné ;
 *  - la vérification recalcule l'empreinte du contenu actuel et la compare à la
 *    fois à la colonne et à la dernière ancre du journal. Une modification
 *    directe en base est donc détectée, même si l'auteur recalcule la colonne.
 */
class Integrity
{
    public const STATUS_OK       = 'ok';
    public const STATUS_ALTERED  = 'altered';
    public const STATUS_MISSING  = 'missing';
    public const STATUS_UNSEALED = 'unsealed';

    /** Champs exclus de l'empreinte (techniques, mis à jour par GLPI hors de nos hooks) */
    private const EXCLUDED = ['integrity_hash', 'date_mod'];

    /**
     * Classes dont les enregistrements sont scellés.
     *
     * @return array<int, class-string<CommonDBTM>>
     */
    public static function getSealedClasses(): array
    {
        return [Incident::class, TimelineEvent::class, Ioc::class, Incident_Item::class, RemediationTask::class, TeamMember::class];
    }

    /**
     * Empreinte du contenu d'une ligne, telle qu'elle est en base.
     * Les dates sont converties en timestamp Unix pour être indépendantes
     * du fuseau horaire de l'utilisateur qui lit la ligne.
     *
     * @param array<string, mixed> $row
     */
    public static function hashRow(string $itemtype, array $row, bool $legacy = false): string
    {
        $data = [];
        foreach ($row as $field => $value) {
            if (in_array($field, self::EXCLUDED, true) || is_int($field)) {
                continue;
            }
            // Depuis 1.5.0 les valeurs NULL sont ignorées : ajouter une colonne
            // facultative au schéma ne change pas l'empreinte des lignes existantes.
            if ($value === null && !$legacy) {
                continue;
            }
            if ($value !== null && self::isDateField($field) && $value !== '') {
                $ts    = strtotime((string) $value);
                $value = $ts !== false ? (string) $ts : (string) $value;
            } elseif ($value !== null) {
                $value = (string) $value;
            }
            $data[$field] = $value;
        }
        ksort($data);
        $canonical = json_encode([$itemtype, $data], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        return hash('sha256', (string) $canonical);
    }

    private static function isDateField(string $field): bool
    {
        return $field === 'date' || str_starts_with($field, 'date_') || str_ends_with($field, '_date');
    }

    /**
     * @return array<string, mixed>|null
     */
    public static function fetchRow(string $itemtype, int $id): ?array
    {
        global $DB;
        $row = $DB->request([
            'FROM'  => $itemtype::getTable(),
            'WHERE' => ['id' => $id],
            'LIMIT' => 1,
        ])->current();
        return $row ?: null;
    }

    /**
     * Scelle un enregistrement : calcule son empreinte à partir de la base,
     * la stocke et la renvoie (à ancrer dans le journal).
     */
    public static function seal(CommonDBTM $item): ?string
    {
        global $DB;

        try {
            $id  = (int) $item->getID();
            $row = $id > 0 ? self::fetchRow($item::class, $id) : null;
            if ($row === null) {
                return null;
            }
            $hash = self::hashRow($item::class, $row);
            $DB->update($item::getTable(), ['integrity_hash' => $hash], ['id' => $id]);
            $item->fields['integrity_hash'] = $hash;
            return $hash;
        } catch (Throwable $e) {
            trigger_error('SecIncident integrity seal failure: ' . $e->getMessage(), E_USER_WARNING);
            return null;
        }
    }

    // ---------------------------------------------------------------------
    // Vérification
    // ---------------------------------------------------------------------

    /**
     * Dernière empreinte ancrée dans le journal pour chaque élément d'un incident.
     *
     * @return array<string, array{hash: string, purged: bool}> clé "Classe#id"
     */
    public static function getAnchors(int $incidents_id): array
    {
        global $DB;

        $anchors  = [];
        $iterator = $DB->request([
            'SELECT' => ['action', 'itemtype', 'items_id', 'details'],
            'FROM'   => AuditLog::getTable(),
            'WHERE'  => [
                'incidents_id' => $incidents_id,
                'result'       => AuditLog::RESULT_OK,
                'action'       => ['create', 'update', 'trash', 'restore', 'link', 'purge', 'unlink', 'team_add', 'team_remove', 'integrity_anchor'],
            ],
            'ORDER'  => 'id ASC',
        ]);
        foreach ($iterator as $row) {
            $details = json_decode((string) $row['details'], true) ?: [];
            if ($row['action'] === 'integrity_anchor') {
                foreach (($details['empreintes'] ?? []) as $key => $hash) {
                    $anchors[$key] = ['hash' => (string) $hash, 'purged' => false];
                }
                continue;
            }
            if ($row['itemtype'] === '' || (int) $row['items_id'] <= 0) {
                continue;
            }
            $key = $row['itemtype'] . '#' . $row['items_id'];
            if (in_array($row['action'], ['purge', 'unlink', 'team_remove'], true)) {
                $anchors[$key] = ['hash' => $anchors[$key]['hash'] ?? '', 'purged' => true];
            } elseif (!empty($details['empreinte'])) {
                $anchors[$key] = ['hash' => (string) $details['empreinte'], 'purged' => false];
            }
        }
        return $anchors;
    }

    /**
     * Vérifie toutes les données et preuves d'un incident.
     *
     * @return array<string, mixed>
     */
    public static function verifyIncident(int $incidents_id, bool $with_files = true, bool $legacy = false): array
    {
        global $DB;

        $anchors = self::getAnchors($incidents_id);
        $fk      = Incident::getForeignKeyField();
        $items   = [];

        $check = function (string $itemtype, array $row) use (&$anchors, &$items, $legacy) {
            $key     = $itemtype . '#' . $row['id'];
            $current = self::hashRow($itemtype, $row, $legacy);
            $stored  = (string) ($row['integrity_hash'] ?? '');
            $anchor  = $anchors[$key]['hash'] ?? null;
            unset($anchors[$key]);

            if ($stored === '' && $anchor === null) {
                $status = self::STATUS_UNSEALED;
            } elseif ($current !== $stored || ($anchor !== null && $anchor !== $current)) {
                $status = self::STATUS_ALTERED;
            } else {
                $status = self::STATUS_OK;
            }
            $items[] = [
                'itemtype' => $itemtype,
                'id'       => (int) $row['id'],
                'label'    => self::describe($itemtype, $row),
                'status'   => $status,
                'current'  => $current,
                'stored'   => $stored,
                'anchor'   => $anchor,
            ];
        };

        $incident_row = self::fetchRow(Incident::class, $incidents_id);
        if ($incident_row !== null) {
            $check(Incident::class, $incident_row);
        }
        foreach ([TimelineEvent::class, Ioc::class, Incident_Item::class, RemediationTask::class, TeamMember::class] as $class) {
            foreach ($DB->request(['FROM' => $class::getTable(), 'WHERE' => [$fk => $incidents_id], 'ORDER' => 'id']) as $row) {
                $check($class, $row);
            }
        }

        // Ancres sans ligne correspondante : suppression hors application
        foreach ($anchors as $key => $anchor) {
            if ($anchor['purged'] || $anchor['hash'] === '') {
                continue;
            }
            [$itemtype, $id] = explode('#', $key) + ['', '0'];
            if (!in_array($itemtype, self::getSealedClasses(), true)) {
                continue;
            }
            $items[] = [
                'itemtype' => $itemtype,
                'id'       => (int) $id,
                'label'    => (is_a($itemtype, \CommonGLPI::class, true) ? $itemtype::getTypeName(1) : $itemtype) . ' #' . $id,
                'status'   => self::STATUS_MISSING,
                'current'  => null,
                'stored'   => null,
                'anchor'   => $anchor['hash'],
            ];
        }

        $evidences = $with_files ? Evidence::verifyForIncident($incidents_id) : Evidence::listForIncident($incidents_id);

        $summary = [self::STATUS_OK => 0, self::STATUS_ALTERED => 0, self::STATUS_MISSING => 0, self::STATUS_UNSEALED => 0];
        foreach ($items as $i) {
            $summary[$i['status']]++;
        }
        $evidence_problems = count(array_filter($evidences, fn ($e) => !in_array($e['check'], [Evidence::CHECK_OK, Evidence::CHECK_UNCHECKED, Evidence::CHECK_DETACHED], true)));

        return [
            'items'     => $items,
            'evidences' => $evidences,
            'summary'   => $summary,
            'ok'        => $summary[self::STATUS_ALTERED] === 0 && $summary[self::STATUS_MISSING] === 0 && $evidence_problems === 0,
            'evidence_problems' => $evidence_problems,
        ];
    }

    /**
     * @param array<string, mixed> $row
     */
    private static function describe(string $itemtype, array $row): string
    {
        return match ($itemtype) {
            Incident::class      => ($row['reference'] ?? '') . ' — ' . ($row['name'] ?? ''),
            TimelineEvent::class => ($row['date'] ?? '') . ' — ' . ($row['name'] ?? ''),
            Ioc::class           => ($row['ioc_type'] ?? '') . ' : ' . mb_strimwidth((string) ($row['value'] ?? ''), 0, 80, '…'),
            Incident_Item::class => ($row['itemtype'] ?? '') . ' #' . ($row['items_id'] ?? ''),
            RemediationTask::class => __('Remediation', 'secincident') . ' : ' . ($row['name'] ?? ''),
            TeamMember::class    => __('Team', 'secincident') . ' : ' . getUserName((int) ($row['users_id'] ?? 0)) . ' (' . ($row['role'] ?? '') . ')',
            default              => $itemtype . ' #' . ($row['id'] ?? ''),
        };
    }

    /**
     * Rescelle tous les enregistrements au format courant et ancre les empreintes.
     * À n'appeler qu'après une vérification tracée (migration de format).
     */
    public static function resealAll(string $reason): void
    {
        global $DB;

        $fk = Incident::getForeignKeyField();
        foreach (self::getSealedClasses() as $class) {
            if (!$DB->tableExists($class::getTable())) {
                continue;
            }
            foreach ($DB->request(['FROM' => $class::getTable()]) as $row) {
                $item = new $class();
                $item->fields = $row;
                $hash = self::seal($item);
                if ($hash !== null) {
                    $incidents_id = $class === Incident::class ? (int) $row['id'] : (int) $row[$fk];
                    AuditLog::anchor($class, (int) $row['id'], $incidents_id, $hash);
                }
            }
        }
        AuditLog::flushAnchors($reason);
    }

    /**
     * Scelle et ancre tous les enregistrements non scellés (installation / mise à jour).
     */
    public static function sealAll(): int
    {
        global $DB;

        $count = 0;
        $fk    = Incident::getForeignKeyField();
        foreach (self::getSealedClasses() as $class) {
            foreach ($DB->request(['FROM' => $class::getTable(), 'WHERE' => ['integrity_hash' => null]]) as $row) {
                $item = new $class();
                $item->fields = $row;
                $hash = self::seal($item);
                if ($hash !== null) {
                    $incidents_id = $class === Incident::class ? (int) $row['id'] : (int) $row[$fk];
                    AuditLog::anchor($class, (int) $row['id'], $incidents_id, $hash);
                    $count++;
                }
            }
        }
        AuditLog::flushAnchors(I18n::instance('initial sealing'));
        return $count;
    }
}
