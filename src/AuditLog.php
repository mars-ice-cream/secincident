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
use Session;
use Throwable;

/**
 * Journal d'audit infalsifiable du plugin.
 *
 * Chaque entrée enregistre qui (utilisateur, éventuel usurpateur via
 * "Prendre l'identité"), avec quel privilège (profil actif, droits du plugin,
 * périmètre tous / siens), quoi (action, résultat), sur quoi (type, id,
 * incident) et d'où (IP).
 *
 * Les entrées sont chaînées : hash = SHA-256(hash précédent + contenu).
 * Toute modification ou suppression d'une ligne casse la chaîne et est
 * détectée par verifyChain(). Aucune interface ne permet de modifier
 * ou supprimer une entrée.
 */
class AuditLog extends CommonDBTM
{
    public static $rightname = 'plugin_secincident_incident';

    public const RESULT_OK     = 'ok';
    public const RESULT_DENIED = 'denied';
    public const RESULT_ERROR  = 'error';

    private const GENESIS = '0000000000000000000000000000000000000000000000000000000000000000';
    private const LOCK    = 'plugin_secincident_audit';

    /** Évite d'auditer deux fois la même consultation dans une requête */
    private static array $viewed = [];

    /** Évite de tracer deux fois le même refus dans une requête */
    private static array $denied = [];

    /** Empreintes en attente d'ancrage, par incident */
    private static array $anchors = [];

    private static bool $shutdown_registered = false;

    private static bool $flushing = false;

    public static function getTypeName($nb = 0)
    {
        return __('Audit log', 'secincident');
    }

    public static function getIcon()
    {
        return 'ti ti-file-certificate';
    }

    public static function canView(): bool
    {
        return Incident::canAudit();
    }

    public static function canCreate(): bool
    {
        return false;
    }

    public static function canUpdate(): bool
    {
        return false;
    }

    public static function canDelete(): bool
    {
        return false;
    }

    public static function canPurge(): bool
    {
        return false;
    }

    /** @return array<string, string> */
    public static function getActions(): array
    {
        return [
            'view'            => __('Consultation', 'secincident'),
            'list'            => __('List / search', 'secincident'),
            'view_dashboard'  => __('Dashboard', 'secincident'),
            'create'          => __('Creation', 'secincident'),
            'update'          => __('Update', 'secincident'),
            'trash'           => __('Moved to trash', 'secincident'),
            'restore'         => __('Restoration', 'secincident'),
            'purge'           => __('Permanent deletion', 'secincident'),
            'link'            => __('Link', 'secincident'),
            'unlink'          => __('Unlink', 'secincident'),
            'import'          => __('CSV import', 'secincident'),
            'import_upload'   => __('File upload', 'secincident'),
            'create_ticket'   => __('Ticket creation', 'secincident'),
            'access_denied'   => __('Access denied', 'secincident'),
            'rights_change'   => __('Rights change', 'secincident'),
            'view_audit'      => __('Log consultation', 'secincident'),
            'export_audit'    => __('Log export', 'secincident'),
            'verify_audit'    => __('Log verification', 'secincident'),
            'verify_integrity' => __('Integrity check', 'secincident'),
            'integrity_anchor' => __('Fingerprint anchoring', 'secincident'),
            'evidence_add'     => __('Evidence added', 'secincident'),
            'apply_playbook'   => __('Playbook applied', 'secincident'),
            'team_add'         => __('Added to the team', 'secincident'),
            'team_remove'      => __('Removed from the team', 'secincident'),
            'print'            => __('Print', 'secincident'),
            'evidence_detach'  => __('Evidence removed', 'secincident'),
            'evidence_replaced' => __('Evidence file replaced', 'secincident'),
            'access_grant'     => __('Access granted', 'secincident'),
            'access_revoke'    => __('Access removed', 'secincident'),
            'config_change'    => __('Settings change', 'secincident'),
            'plugin_disable'   => __('Plugin deactivated', 'secincident'),
        ];
    }

    // ---------------------------------------------------------------------
    // Écriture
    // ---------------------------------------------------------------------

    /** Jeton interne de la requête, pour les écritures déjà tracées par ailleurs */
    private static ?string $silent_token = null;

    /**
     * Valeur à placer dans `_no_audit` pour une écriture interne déjà tracée.
     * Jeton aléatoire propre à la requête : un `_no_audit` envoyé par un
     * formulaire ou l'API ne peut pas désactiver l'audit.
     */
    public static function silent(): string
    {
        return self::$silent_token ??= bin2hex(random_bytes(16));
    }

    /**
     * @param array<string, mixed>|null $input
     */
    public static function isSilent(?array $input): bool
    {
        return self::$silent_token !== null
            && is_array($input)
            && is_string($input['_no_audit'] ?? null)
            && hash_equals(self::$silent_token, $input['_no_audit']);
    }

    /**
     * Enregistre une entrée. Ne lève jamais d'exception vers l'appelant
     * (un échec d'audit est tracé dans les logs PHP de GLPI).
     *
     * @param array<string, mixed> $details
     */
    public static function record(
        string $action,
        ?CommonDBTM $item = null,
        array $details = [],
        string $result = self::RESULT_OK,
        ?int $incidents_id = null
    ): void {
        global $DB;

        try {
            $incidents_id ??= self::resolveIncidentId($item);
            $incident_fields = null;
            if ($item instanceof Incident && array_key_exists('users_id_tech', $item->fields)) {
                $incident_fields = $item->fields;
            } elseif ($incidents_id > 0) {
                $incident = new Incident();
                // Lecture brute : pas de contrôle de droits ici, on veut tracer
                $row = $DB->request(['FROM' => Incident::getTable(), 'WHERE' => ['id' => $incidents_id], 'LIMIT' => 1])->current();
                $incident_fields = $row ?: null;
            }

            $privilege = self::getPrivilegeContext($incident_fields);

            $entry = [
                'date_utc'               => gmdate('Y-m-d H:i:s'),
                'users_id'               => (int) (Session::getLoginUserID() ?: 0),
                'user_name'              => (string) ($_SESSION['glpiname'] ?? (PHP_SAPI === 'cli' ? 'cli' : 'anonyme')),
                'users_id_impersonator'  => Session::isImpersonateActive() ? (int) ($_SESSION['impersonator_id'] ?? 0) : 0,
                'profiles_id'            => (int) ($_SESSION['glpiactiveprofile']['id'] ?? 0),
                'profile_name'           => (string) ($_SESSION['glpiactiveprofile']['name'] ?? ''),
                'rights'                 => $privilege['rights'],
                'privilege'              => $privilege['label'],
                'ip'                     => (string) ($_SERVER['REMOTE_ADDR'] ?? (PHP_SAPI === 'cli' ? 'cli' : '')),
                'action'                 => mb_substr($action, 0, 40),
                'result'                 => $result,
                'itemtype'               => $item !== null ? $item::class : '',
                'items_id'               => $item !== null ? max(0, (int) ($item->fields['id'] ?? 0)) : 0,
                'incidents_id'           => (int) ($incidents_id ?? 0),
                'details'                => self::encodeDetails($details),
            ];

            // Verrou global (API GLPI) : les entrées sont chaînées dans l'ordre, sans course
            $locked   = false;
            $deadline = microtime(true) + 10;
            do {
                $locked = $DB->getLock(self::LOCK);
                if (!$locked) {
                    usleep(20000);
                }
            } while (!$locked && microtime(true) < $deadline);
            try {
                $last = $DB->request([
                    'SELECT' => ['hash'],
                    'FROM'   => self::getTable(),
                    'ORDER'  => 'id DESC',
                    'LIMIT'  => 1,
                ])->current();
                $entry['prev_hash'] = $last['hash'] ?? self::GENESIS;
                $entry['hash']      = self::computeHash($entry);
                $entry['date']      = Session::getCurrentTime();
                $DB->insert(self::getTable(), $entry);
            } finally {
                if ($locked) {
                    $DB->releaseLock(self::LOCK);
                }
            }
        } catch (Throwable $e) {
            trigger_error('SecIncident audit failure: ' . $e->getMessage(), E_USER_WARNING);
        }
    }

    /**
     * Met en attente l'ancrage de l'empreinte d'un enregistrement écrit sans
     * entrée d'audit individuelle (import, événements automatiques).
     * Les ancres sont regroupées en une entrée par incident.
     */
    public static function anchor(string $itemtype, int $items_id, int $incidents_id, string $hash): void
    {
        self::$anchors[$incidents_id][$itemtype . '#' . $items_id] = $hash;
        if (!self::$shutdown_registered) {
            self::$shutdown_registered = true;
            register_shutdown_function([self::class, 'flushAnchors']);
        }
    }

    public static function flushAnchors(string $reason = ''): void
    {
        if (self::$flushing || self::$anchors === []) {
            return;
        }
        self::$flushing = true;
        $pending        = self::$anchors;
        self::$anchors  = [];
        foreach ($pending as $incidents_id => $hashes) {
            foreach (array_chunk($hashes, 500, true) as $chunk) {
                self::record('integrity_anchor', null, [
                    'motif'      => $reason !== '' ? $reason : I18n::instance('grouped writes'),
                    'empreintes' => $chunk,
                ], self::RESULT_OK, (int) $incidents_id);
            }
        }
        self::$flushing = false;
    }

    /**
     * Trace une consultation (une seule fois par élément et par requête).
     */
    public static function recordView(CommonDBTM $item, string $what = ''): void
    {
        $key = $item::class . '#' . ($item->fields['id'] ?? 0) . '#' . $what;
        if (isset(self::$viewed[$key])) {
            return;
        }
        self::$viewed[$key] = true;
        self::record('view', $item, $what !== '' ? ['vue' => $what] : []);
    }

    /**
     * Trace un refus d'accès. Les données sensibles de l'élément ne sont
     * pas recopiées : seulement son type et son identifiant.
     *
     * @param array<string, mixed> $details
     */
    public static function recordDenied(string $attempt, string $itemtype, int $items_id, array $details = [], ?int $incidents_id = null): void
    {
        $key = $itemtype . '#' . $items_id;
        if ($items_id > 0 && isset(self::$denied[$key])) {
            return;
        }
        self::$denied[$key] = true;

        $item = getItemForItemtype($itemtype);
        if ($item instanceof CommonDBTM) {
            $item->fields = ['id' => $items_id];
        }
        if ($incidents_id !== null) {
            // déjà connu (tentative de création rattachée à un incident)
        } elseif ($items_id > 0 && ($item instanceof TimelineEvent || $item instanceof Ioc || $item instanceof Incident_Item)) {
            global $DB;
            $row = $DB->request([
                'SELECT' => [Incident::getForeignKeyField()],
                'FROM'   => $item::getTable(),
                'WHERE'  => ['id' => $items_id],
            ])->current();
            $incidents_id = (int) ($row[Incident::getForeignKeyField()] ?? 0);
        } elseif ($item instanceof Incident) {
            $incidents_id = $items_id;
        }
        self::record('access_denied', $item instanceof CommonDBTM ? $item : null, ['tentative' => $attempt] + $details, self::RESULT_DENIED, $incidents_id);
    }

    /**
     * Vérifie un droit, trace un refus, puis laisse GLPI lever l'exception
     * habituelle (403) si l'accès n'est pas autorisé.
     *
     * @param array<string, mixed>|null $input
     */
    public static function guard(CommonDBTM $item, int $id, int $right, ?array $input = null, string $attempt = ''): void
    {
        $allowed = $input !== null ? $item->can($id, $right, $input) : $item->can($id, $right);
        if (!$allowed) {
            $fk = Incident::getForeignKeyField();
            $incidents_id = null;
            if ($id <= 0 && $input !== null) {
                $incidents_id = $item instanceof Incident ? 0 : (int) ($input[$fk] ?? 0);
            }
            self::recordDenied(
                $attempt !== '' ? $attempt : self::rightLabel($right),
                $item::class,
                max(0, $id),
                $id <= 0 ? ['creation' => true] : [],
                $incidents_id
            );
        }
        if ($input !== null) {
            $item->check($id, $right, $input);
        } else {
            $item->check($id, $right);
        }
    }

    /**
     * Contrôle d'accès à une page du plugin, avec trace en cas de refus.
     *
     * @param array<int, int> $rights Un des droits suffit
     */
    public static function checkPageAccess(array $rights, string $page): void
    {
        if (!Session::haveRightsOr(Incident::$rightname, $rights)) {
            self::record('access_denied', null, ['tentative' => I18n::instance('page access'), 'page' => $page], self::RESULT_DENIED);
        }
        Session::checkRightsOr(Incident::$rightname, $rights);
    }

    // ---------------------------------------------------------------------
    // Privilèges
    // ---------------------------------------------------------------------

    /**
     * Décrit le privilège avec lequel l'action est faite.
     *
     * @param array<string, mixed>|null $incident_fields
     * @return array{rights: int, label: string}
     */
    public static function getPrivilegeContext(?array $incident_fields = null): array
    {
        $rights = (int) ($_SESSION['glpiactiveprofile'][Incident::$rightname] ?? 0);

        $labels = [];
        foreach (self::getRightLabels() as $bit => $label) {
            if (($rights & $bit) === $bit) {
                $labels[] = $label;
            }
        }

        $scope = '';
        if ($incident_fields !== null && isset($incident_fields['id'])) {
            if (($rights & Incident::READALL) === Incident::READALL) {
                $scope = I18n::instance('scope: all incidents');
            } else {
                $reasons = Incident::getOwnershipReasons($incident_fields);
                $scope   = $reasons !== []
                    ? sprintf(I18n::instance('scope: own incidents (%s)'), implode(', ', array_map([self::class, 'reasonLabel'], $reasons)))
                    : I18n::instance('scope: outside own incidents');
            }
        }

        $parts = [$labels !== [] ? implode(', ', $labels) : I18n::instance('no plugin right')];
        if ($scope !== '') {
            $parts[] = $scope;
        }
        if (Session::isImpersonateActive()) {
            $parts[] = I18n::instance('impersonated identity');
        }
        if (($_SESSION['glpiactiveprofile']['interface'] ?? '') !== '') {
            $parts[] = sprintf(I18n::instance('interface %s'), $_SESSION['glpiactiveprofile']['interface']);
        }

        return ['rights' => $rights, 'label' => mb_substr(implode(' · ', $parts), 0, 500)];
    }

    /**
     * Libellés du journal, dans la langue de l'instance (indépendants de la langue de l'utilisateur).
     *
     * @return array<int, string>
     */
    public static function getRightLabels(): array
    {
        return [
            READ              => I18n::instance('read (own incidents)'),
            Incident::READALL => I18n::instance('all incidents'),
            CREATE            => I18n::instance('creation'),
            UPDATE            => I18n::instance('update'),
            DELETE            => I18n::instance('trash'),
            PURGE             => I18n::instance('permanent deletion'),
            Incident::AUDIT   => I18n::instance('audit log'),
            Incident::PLAYBOOK => I18n::instance('playbook management'),
            Incident::CATEGORY => I18n::instance('category management'),
        ];
    }

    private static function rightLabel(int $right): string
    {
        return match ($right) {
            READ    => I18n::instance('read'),
            CREATE  => I18n::instance('creation'),
            UPDATE  => I18n::instance('update'),
            DELETE  => I18n::instance('move to trash'),
            PURGE   => I18n::instance('permanent deletion'),
            default => sprintf(I18n::instance('right %d'), $right),
        };
    }

    /** Droits du plugin en clair (langue de l'instance), pour le journal et les alertes */
    public static function rightsToLabels(int $rights): string
    {
        $labels = [];
        foreach (self::getRightLabels() as $bit => $label) {
            if (($rights & $bit) === $bit) {
                $labels[] = $label;
            }
        }
        return $labels !== [] ? implode(', ', $labels) : I18n::instance('none');
    }

    /** Libellé d'un code de rattachement à un incident (Incident::getOwnershipReasons) */
    public static function reasonLabel(string $code): string
    {
        return match ($code) {
            'tech'        => I18n::instance('owner'),
            'recipient'   => I18n::instance('author'),
            'group'       => I18n::instance('assigned group'),
            'contributor' => I18n::instance('contributor'),
            'observer'    => I18n::instance('observer'),
            default       => $code,
        };
    }

    private static function resolveIncidentId(?CommonDBTM $item): ?int
    {
        if ($item instanceof Incident) {
            return (int) ($item->fields['id'] ?? 0);
        }
        if ($item !== null) {
            $fk = Incident::getForeignKeyField();
            if (isset($item->fields[$fk])) {
                return (int) $item->fields[$fk];
            }
        }
        return null;
    }

    /**
     * @param array<string, mixed> $details
     */
    private static function encodeDetails(array $details): string
    {
        array_walk_recursive($details, function (&$value) {
            if (is_string($value) && mb_strlen($value) > 1000) {
                $value = mb_substr($value, 0, 1000) . '…';
            }
        });
        return (string) json_encode($details, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PARTIAL_OUTPUT_ON_ERROR);
    }

    /**
     * Construit le détail d'une modification : ancien → nouveau, champ par champ.
     *
     * @param array<int, string>   $updates
     * @param array<string, mixed> $oldvalues
     * @param array<string, mixed> $fields
     * @return array<string, array{avant: mixed, apres: mixed}>
     */
    public static function diff(array $updates, array $oldvalues, array $fields): array
    {
        $diff = [];
        foreach ($updates as $field) {
            if (in_array($field, ['date_mod'], true)) {
                continue;
            }
            $diff[$field] = [
                'avant' => $oldvalues[$field] ?? null,
                'apres' => $fields[$field] ?? null,
            ];
        }
        return $diff;
    }

    // ---------------------------------------------------------------------
    // Intégrité
    // ---------------------------------------------------------------------

    /**
     * @param array<string, mixed> $entry
     */
    public static function computeHash(array $entry): string
    {
        $canonical = json_encode([
            (string) $entry['prev_hash'],
            (string) $entry['date_utc'],
            (int) $entry['users_id'],
            (string) $entry['user_name'],
            (int) $entry['users_id_impersonator'],
            (int) $entry['profiles_id'],
            (string) $entry['profile_name'],
            (int) $entry['rights'],
            (string) $entry['privilege'],
            (string) $entry['ip'],
            (string) $entry['action'],
            (string) $entry['result'],
            (string) $entry['itemtype'],
            (int) $entry['items_id'],
            (int) $entry['incidents_id'],
            (string) $entry['details'],
        ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        return hash('sha256', (string) $canonical);
    }

    /**
     * Rejoue toute la chaîne.
     *
     * @return array{ok: bool, count: int, broken_id: int|null, reason: string}
     */
    public static function verifyChain(): array
    {
        global $DB;

        $prev  = self::GENESIS;
        $count = 0;
        $last_id = 0;
        do {
            $iterator = $DB->request([
                'FROM'  => self::getTable(),
                'WHERE' => ['id' => ['>', $last_id]],
                'ORDER' => 'id ASC',
                'LIMIT' => 2000,
            ]);
            $batch = 0;
            foreach ($iterator as $row) {
                $batch++;
                $count++;
                $last_id = (int) $row['id'];
                if ($row['prev_hash'] !== $prev) {
                    return ['ok' => false, 'count' => $count, 'broken_id' => $last_id, 'reason' => I18n::instance('broken chain (row deleted or inserted)')];
                }
                if (self::computeHash($row) !== $row['hash']) {
                    return ['ok' => false, 'count' => $count, 'broken_id' => $last_id, 'reason' => I18n::instance('content modified')];
                }
                $prev = $row['hash'];
            }
        } while ($batch === 2000);

        return ['ok' => true, 'count' => $count, 'broken_id' => null, 'reason' => ''];
    }

    // ---------------------------------------------------------------------
    // Lecture (page d'audit)
    // ---------------------------------------------------------------------

    /**
     * @param array<string, mixed> $filters
     * @return array<mixed>
     */
    public static function buildCriteria(array $filters): array
    {
        $where = [];
        if (!empty($filters['date_from'])) {
            $where[] = ['date' => ['>=', $filters['date_from'] . ' 00:00:00']];
        }
        if (!empty($filters['date_to'])) {
            $where[] = ['date' => ['<=', $filters['date_to'] . ' 23:59:59']];
        }
        if (!empty($filters['users_id'])) {
            $where['users_id'] = (int) $filters['users_id'];
        }
        if (!empty($filters['action']) && array_key_exists($filters['action'], self::getActions())) {
            $where['action'] = $filters['action'];
        }
        if (!empty($filters['result']) && in_array($filters['result'], [self::RESULT_OK, self::RESULT_DENIED, self::RESULT_ERROR], true)) {
            $where['result'] = $filters['result'];
        }
        if (!empty($filters['incidents_id'])) {
            $where['incidents_id'] = (int) $filters['incidents_id'];
        }
        if (!empty($filters['ip'])) {
            $where['ip'] = (string) $filters['ip'];
        }
        return $where;
    }

    /**
     * @param array<mixed> $where
     * @return array{rows: array<int, array<string, mixed>>, total: int}
     */
    public static function fetch(array $where, int $start, int $limit): array
    {
        global $DB;

        $total = (int) ($DB->request([
            'COUNT' => 'cpt',
            'FROM'  => self::getTable(),
            'WHERE' => $where,
        ])->current()['cpt'] ?? 0);

        $rows = [];
        foreach (
            $DB->request([
                'FROM'  => self::getTable(),
                'WHERE' => $where,
                'ORDER' => 'id DESC',
                'START' => $start,
                'LIMIT' => $limit,
            ]) as $row
        ) {
            $rows[] = $row;
        }
        return ['rows' => $rows, 'total' => $total];
    }

    /**
     * Suppression interdite par l'API objet (seule la désinstallation y touche).
     */
    public function prepareInputForAdd($input)
    {
        return false;
    }

    public function prepareInputForUpdate($input)
    {
        return false;
    }

    public function pre_deleteItem()
    {
        return false;
    }
}
