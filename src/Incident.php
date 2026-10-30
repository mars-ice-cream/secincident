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
use CommonGLPI;
use DateInterval;
use DateTimeImmutable;
use Document_Item;
use Dropdown;
use Glpi\Application\View\TemplateRenderer;
use Html;
use Log;
use Session;
use Throwable;
use Ticket;

/**
 * Incident de sécurité.
 */
class Incident extends CommonDBTM
{
    use IntegerInputTrait;
    public $dohistory = true;

    public static $rightname = 'plugin_secincident_incident';

    // Cycle de vie (inspiré NIST SP 800-61)
    public const STATUS_NEW          = 1;
    public const STATUS_ANALYSIS     = 2;
    public const STATUS_CONTAINMENT  = 3;
    public const STATUS_ERADICATION  = 4;
    public const STATUS_RECOVERY     = 5;
    public const STATUS_CLOSED       = 6;

    public const GDPR_RISK_NONE = 0;
    public const GDPR_RISK      = 1;
    public const GDPR_RISK_HIGH = 2;

    /** Onglet RGPD / NIS2 (affiché via getTabNameForItem sur l'objet lui-même) */
    private const TAB_COMPLIANCE = 1;
    /** Onglet Intégrité (empreintes des données et des preuves) */
    private const TAB_INTEGRITY  = 2;

    // Droits spécifiques (bits libres de GLPI, comme Ticket::READALL)
    /** Voir et gérer tous les incidents (sinon : seulement les siens) */
    public const READALL = 1024;
    /** Consulter le journal d'audit */
    public const AUDIT   = 4096;
    /** Gérer la bibliothèque des procédures de remédiation */
    public const PLAYBOOK = 8192;
    /** Gérer les catégories d'incident */
    public const CATEGORY = 16384;

    /** Clé numérique peu commune pour fusionner nos critères sans collision */
    private const VISIBILITY_CRITERIA_KEY = 920130;

    // ---------------------------------------------------------------------
    // Droits et cloisonnement
    // ---------------------------------------------------------------------

    public function getRights($interface = 'central')
    {
        return [
            READ          => __('View own incidents', 'secincident'),
            self::READALL => __('View and manage all incidents', 'secincident'),
            CREATE        => __('Create'),
            UPDATE        => __('Update'),
            DELETE        => _x('button', 'Put in trashbin'),
            PURGE         => _x('button', 'Delete permanently'),
            self::AUDIT   => __('Audit log', 'secincident'),
            self::PLAYBOOK => __('Manage playbooks', 'secincident'),
            self::CATEGORY => __('Manage categories', 'secincident'),
        ];
    }

    public static function canView(): bool
    {
        return Session::haveRightsOr(static::$rightname, [READ, self::READALL]);
    }

    /** L'utilisateur voit-il tous les incidents (et pas seulement les siens) ? */
    public static function canViewAll(): bool
    {
        return Session::haveRight(static::$rightname, self::READALL);
    }

    public static function canAudit(): bool
    {
        return Session::haveRight(static::$rightname, self::AUDIT);
    }

    /**
     * Raisons pour lesquelles l'utilisateur courant est rattaché à un incident
     * (vide = pas son incident). Codes : tech, recipient, group, contributor, observer.
     *
     * @param array<string, mixed> $fields
     * @return array<int, string>
     */
    public static function getOwnershipReasons(array $fields): array
    {
        $me = (int) Session::getLoginUserID();
        if ($me <= 0) {
            return [];
        }
        $reasons = [];
        if ((int) ($fields['users_id_tech'] ?? 0) === $me) {
            $reasons[] = 'tech';
        }
        if ((int) ($fields['users_id_recipient'] ?? 0) === $me) {
            $reasons[] = 'recipient';
        }
        $group = (int) ($fields['groups_id_tech'] ?? 0);
        if ($group > 0 && in_array($group, array_map('intval', $_SESSION['glpigroups'] ?? []), true)) {
            $reasons[] = 'group';
        }
        $role = TeamMember::getRole((int) ($fields['id'] ?? 0), $me);
        if ($role === TeamMember::ROLE_CONTRIBUTOR) {
            $reasons[] = 'contributor';
        } elseif ($role === TeamMember::ROLE_OBSERVER) {
            $reasons[] = 'observer';
        }
        return $reasons;
    }

    /**
     * Peut agir sur l'incident (tout sauf observateur).
     *
     * @param array<string, mixed> $fields
     */
    public static function canActOn(array $fields): bool
    {
        return self::canViewAll() || array_diff(self::getOwnershipReasons($fields), ['observer']) !== [];
    }

    /**
     * Pilote de l'incident : responsable, rédacteur ou groupe en charge (ou RSSI).
     *
     * @param array<string, mixed> $fields
     */
    public static function isPilot(array $fields): bool
    {
        return self::canViewAll()
            || array_intersect(self::getOwnershipReasons($fields), ['tech', 'recipient', 'group']) !== [];
    }

    /**
     * @param array<string, mixed> $fields
     */
    public static function isVisibleFor(array $fields): bool
    {
        return self::canViewAll() || self::getOwnershipReasons($fields) !== [];
    }

    public function canViewItem(): bool
    {
        if (!parent::canViewItem()) {
            return false;
        }
        if (!self::isVisibleFor($this->fields)) {
            // Toute tentative d'accès à l'incident d'un autre (fiche, onglet, sous-objet) est tracée
            AuditLog::recordDenied(I18n::instance('read outside scope'), self::class, (int) ($this->fields['id'] ?? 0));
            return false;
        }
        return true;
    }

    /** Intervenants et pilotes peuvent modifier ; les observateurs non */
    public function canUpdateItem(): bool
    {
        return parent::canUpdateItem() && self::canActOn($this->fields);
    }

    /** Corbeille / suppression : réservées aux pilotes */
    public function canDeleteItem(): bool
    {
        return parent::canDeleteItem() && self::isPilot($this->fields);
    }

    public function canPurgeItem(): bool
    {
        return parent::canPurgeItem() && self::isPilot($this->fields);
    }

    /**
     * Restriction SQL appliquée par GLPI partout où il liste des incidents :
     * moteur de recherche, exports, listes déroulantes, API, tableaux de bord.
     */
    public static function getSystemSQLCriteria(?string $tablename = null): array
    {
        $visibility = self::getVisibilityCriteria($tablename ?? self::getTable());
        return $visibility === [] ? [] : [self::VISIBILITY_CRITERIA_KEY => $visibility];
    }

    /**
     * Critère "incidents visibles par l'utilisateur courant".
     *
     * @return array<mixed>
     */
    public static function getVisibilityCriteria(string $table): array
    {
        if (self::canViewAll()) {
            return [];
        }
        $me = (int) Session::getLoginUserID();
        if ($me <= 0) {
            // Pas de session (tâches CLI) : aucun cloisonnement, sinon rien
            return PHP_SAPI === 'cli' ? [] : ["$table.id" => -1];
        }
        $or = [
            "$table.users_id_tech"      => $me,
            "$table.users_id_recipient" => $me,
        ];
        $groups = array_map('intval', $_SESSION['glpigroups'] ?? []);
        if ($groups !== []) {
            $or["$table.groups_id_tech"] = $groups;
        }
        // Membres de l'équipe d'intervention (intervenants et observateurs)
        $or["$table.id"] = new \Glpi\DBAL\QuerySubQuery([
            'SELECT' => TeamMember::getTable() . '.' . self::getForeignKeyField(),
            'FROM'   => TeamMember::getTable(),
            'WHERE'  => [TeamMember::getTable() . '.users_id' => $me],
        ]);
        return ['OR' => $or];
    }

    /**
     * Sous-requête des identifiants d'incidents visibles (pour les sous-objets).
     */
    public static function getVisibleIdsSubQuery(): ?\Glpi\DBAL\QuerySubQuery
    {
        $criteria = self::getVisibilityCriteria(self::getTable());
        if ($criteria === []) {
            return null;
        }
        return new \Glpi\DBAL\QuerySubQuery([
            'SELECT' => self::getTable() . '.id',
            'FROM'   => self::getTable(),
            'WHERE'  => $criteria,
        ]);
    }

    // ---------------------------------------------------------------------
    // Libellés & référentiels
    // ---------------------------------------------------------------------

    public static function getTypeName($nb = 0)
    {
        return _n('Security incident', 'Security incidents', $nb, 'secincident');
    }

    public static function getIcon()
    {
        return 'ti ti-shield-exclamation';
    }

    public static function getMenuName()
    {
        return __('Security incidents', 'secincident');
    }

    /**
     * Types d'éléments qu'on peut lier à un incident.
     *
     * @return array<int, class-string<CommonDBTM>>
     */
    public static function getLinkableTypes(): array
    {
        return [
            'Ticket', 'Problem', 'Change',
            'Computer', 'Monitor', 'NetworkEquipment', 'Peripheral', 'Phone', 'Printer',
            'Software', 'User', 'Supplier',
        ];
    }

    /** @return array<string, string> */
    public static function getCategories(): array
    {
        return Category::getList();
    }

    /** @return array<int, string> */
    public static function getSeverities(): array
    {
        return [
            1 => __('Informational', 'secincident'),
            2 => __('Low', 'secincident'),
            3 => __('Medium', 'secincident'),
            4 => __('High', 'secincident'),
            5 => __('Critical', 'secincident'),
        ];
    }

    /** @return array<int, string> */
    public static function getStatuses(bool $instance = false): array
    {
        return [
            self::STATUS_NEW         => I18n::tr('New', $instance),
            self::STATUS_ANALYSIS    => I18n::tr('Qualification / analysis', $instance),
            self::STATUS_CONTAINMENT => I18n::tr('Containment', $instance),
            self::STATUS_ERADICATION => I18n::tr('Eradication', $instance),
            self::STATUS_RECOVERY    => I18n::tr('Recovery', $instance),
            self::STATUS_CLOSED      => I18n::tr('Closed', $instance),
        ];
    }

    /** @return array<int, string> */
    public static function getImpactLevels(): array
    {
        return [
            0 => __('None', 'secincident'),
            1 => __('Low', 'secincident'),
            2 => __('Moderate', 'secincident'),
            3 => __('Severe', 'secincident'),
            4 => __('Critical', 'secincident'),
        ];
    }

    /** @return array<string, string> */
    public static function getSources(): array
    {
        return [
            'manual'      => __('Manual entry', 'secincident'),
            'edr'         => __('EDR / XDR (import)', 'secincident'),
            'user_report' => __('User report', 'secincident'),
            'siem'        => __('SIEM / monitoring', 'secincident'),
            'edr_other'   => __('Antivirus / other security tool', 'secincident'),
            'third_party' => __('Third party (provider, CERT…)', 'secincident'),
            'other'       => __('Other', 'secincident'),
        ];
    }

    /** @return array<int, string> */
    public static function getGdprRiskLevels(): array
    {
        return [
            self::GDPR_RISK_NONE => __('No risk to individuals', 'secincident'),
            self::GDPR_RISK      => __('Risk to individuals', 'secincident'),
            self::GDPR_RISK_HIGH => __('High risk to individuals', 'secincident'),
        ];
    }

    /** Couleur Tabler associée à la gravité */
    public static function getSeverityColor(int $severity): string
    {
        return match ($severity) {
            5       => 'red',
            4       => 'orange',
            3       => 'yellow',
            2       => 'azure',
            default => 'secondary',
        };
    }

    /** Couleur Tabler associée au statut */
    public static function getStatusColor(int $status): string
    {
        return match ($status) {
            self::STATUS_NEW         => 'red',
            self::STATUS_ANALYSIS    => 'orange',
            self::STATUS_CONTAINMENT => 'yellow',
            self::STATUS_ERADICATION => 'purple',
            self::STATUS_RECOVERY    => 'azure',
            self::STATUS_CLOSED      => 'green',
            default                  => 'secondary',
        };
    }

    // ---------------------------------------------------------------------
    // Menu & onglets
    // ---------------------------------------------------------------------

    /**
     * Sous-menus (bouton « Ajouter » et recherche sur la page des procédures).
     *
     * @return array<string, mixed>|false
     */
    public static function getAdditionalMenuOptions()
    {
        if (!static::canView()) {
            return false;
        }
        $links = ['search' => Playbook::getSearchURL(false)];
        if (Playbook::canCreate()) {
            $links['add'] = Playbook::getFormURL(false);
        }
        $cat_links = ['search' => Category::getSearchURL(false)];
        if (Category::canCreate()) {
            $cat_links['add'] = Category::getFormURL(false);
        }
        return [
            'category' => [
                'title' => Category::getTypeName(Session::getPluralNumber()),
                'page'  => Category::getSearchURL(false),
                'icon'  => Category::getIcon(),
                'links' => $cat_links,
            ],
            'playbook' => [
                'title' => Playbook::getTypeName(Session::getPluralNumber()),
                'page'  => Playbook::getSearchURL(false),
                'icon'  => Playbook::getIcon(),
                'links' => $links,
            ],
        ];
    }

    public static function getAdditionalMenuLinks()
    {
        $links = [];
        if (static::canCreate()) {
            $links["<i class='ti ti-file-import'></i>" . __s('EDR CSV import', 'secincident')]
                = '/plugins/secincident/front/import.php';
        }
        if (static::canView()) {
            $links["<i class='ti ti-list-check'></i>" . __s('Playbooks', 'secincident')]
                = '/plugins/secincident/front/playbook.php';
            $links["<i class='ti ti-category'></i>" . __s('Categories', 'secincident')]
                = '/plugins/secincident/front/category.php';
            $links["<i class='ti ti-chart-bar'></i>" . __s('Dashboard', 'secincident')]
                = '/plugins/secincident/front/dashboard.php';
        }
        if (static::canAudit()) {
            $links["<i class='ti ti-file-certificate'></i>" . __s('Audit log', 'secincident')]
                = '/plugins/secincident/front/audit.php';
            $links["<i class='ti ti-lock-access'></i>" . __s('Access settings', 'secincident')]
                = '/plugins/secincident/front/config.form.php';
        }
        return $links;
    }

    public function defineTabs($options = [])
    {
        $ong = [];
        $this->addDefaultFormTab($ong);
        $this->addStandardTab(TimelineEvent::class, $ong, $options);
        $this->addStandardTab(TeamMember::class, $ong, $options);
        $this->addStandardTab(RemediationTask::class, $ong, $options);
        $this->addStandardTab(Ioc::class, $ong, $options);
        $this->addStandardTab(self::class, $ong, $options);
        $this->addStandardTab(Incident_Item::class, $ong, $options);
        $this->addStandardTab(Document_Item::class, $ong, $options);
        $this->addStandardTab(Log::class, $ong, $options);
        return $ong;
    }

    public function getTabNameForItem(CommonGLPI $item, $withtemplate = 0)
    {
        if ($item instanceof self && !$item->isNewItem()) {
            return [
                self::TAB_COMPLIANCE => self::createTabEntry(
                    __('GDPR / NIS2', 'secincident'),
                    0,
                    null,
                    'ti ti-gavel'
                ),
                self::TAB_INTEGRITY => self::createTabEntry(
                    __('Integrity & evidence', 'secincident'),
                    countElementsInTable(Evidence::getTable(), [self::getForeignKeyField() => $item->getID(), 'status' => 'active']),
                    null,
                    'ti ti-fingerprint'
                ),
            ];
        }
        return '';
    }

    public static function displayTabContentForItem(CommonGLPI $item, $tabnum = 1, $withtemplate = 0)
    {
        if ($item instanceof self && (int) $tabnum === self::TAB_COMPLIANCE) {
            $item->showComplianceForm();
        }
        if ($item instanceof self && (int) $tabnum === self::TAB_INTEGRITY) {
            $item->showIntegrity();
        }
        return true;
    }

    // ---------------------------------------------------------------------
    // Formulaires
    // ---------------------------------------------------------------------

    public function post_getEmpty()
    {
        $this->fields['status']         = self::STATUS_NEW;
        $this->fields['severity']       = 3;
        $this->fields['category']       = 'other';
        $this->fields['source']         = 'manual';
        $this->fields['date_detection'] = Session::getCurrentTime();
        $this->fields['date_awareness'] = Session::getCurrentTime();
        $this->fields['users_id_tech']  = Session::getLoginUserID() ?: 0;
    }

    public function showForm($ID, array $options = [])
    {
        $this->initForm($ID, $options);
        if (!$this->isNewItem()) {
            AuditLog::recordView($this, 'fiche');
        }

        // Référentiel MITRE ATT&CK ; une ancienne valeur libre reste proposée
        $mitre_tactics    = MitreAttack::getTactics();
        $mitre_techniques = MitreAttack::getTechniques();
        foreach (['mitre_tactic' => &$mitre_tactics, 'mitre_technique' => &$mitre_techniques] as $field => &$list) {
            $current = (string) ($this->fields[$field] ?? '');
            if ($current !== '' && !isset($list[$current])) {
                $list = [$current => $current . ' ' . __('(free text, not in the reference list)', 'secincident')] + $list;
            }
        }
        unset($list);

        TemplateRenderer::getInstance()->display('@secincident/incident_form.html.twig', [
            'item'       => $this,
            'mitre_tactics'    => $mitre_tactics,
            'mitre_techniques' => $mitre_techniques,
            'mitre_map'        => MitreAttack::getTechniqueTactics(),
            'mitre_version'    => MitreAttack::getVersion(),
            'params'     => $options,
            'categories' => self::getCategories(),
            'severities' => self::getSeverities(),
            'statuses'   => self::getStatuses(),
            'impacts'    => self::getImpactLevels(),
            'sources'    => self::getSources(),
            'deadlines'  => $this->isNewItem() ? [] : $this->getDeadlines(),
            'status_color'   => self::getStatusColor((int) $this->fields['status']),
            'severity_color' => self::getSeverityColor((int) $this->fields['severity']),
            'counts'     => $this->isNewItem() ? [] : [
                'events' => countElementsInTable(TimelineEvent::getTable(), [self::getForeignKeyField() => $this->getID()]),
                'iocs'   => countElementsInTable(Ioc::getTable(), [self::getForeignKeyField() => $this->getID()]),
                'items'  => countElementsInTable(Incident_Item::getTable(), [self::getForeignKeyField() => $this->getID()]),
            ],
            'can_create_ticket' => !$this->isNewItem() && Ticket::canCreate() && $this->canUpdateItem(),
        ]);

        return true;
    }

    /**
     * Onglet RGPD / NIS2.
     */
    public function showComplianceForm(): void
    {
        if (!$this->can($this->getID(), READ)) {
            AuditLog::recordDenied(I18n::instance('read GDPR / NIS2 tab'), self::class, (int) $this->getID());
            return;
        }
        AuditLog::recordView($this, I18n::instance('GDPR / NIS2'));

        TemplateRenderer::getInstance()->display('@secincident/compliance.html.twig', [
            'item'       => $this,
            'canedit'    => $this->can($this->getID(), UPDATE),
            'risks'      => self::getGdprRiskLevels(),
            'deadlines'  => $this->getDeadlines(),
        ]);
    }

    /**
     * Onglet Intégrité & preuves.
     */
    public function showIntegrity(): void
    {
        if (!$this->can($this->getID(), READ)) {
            AuditLog::recordDenied(I18n::instance('read integrity tab'), self::class, (int) $this->getID());
            return;
        }
        AuditLog::recordView($this, I18n::instance('integrity & evidence'));

        // Données : recalcul immédiat (rapide). Fichiers : dernier contrôle connu.
        $result = Integrity::verifyIncident((int) $this->getID(), false);

        $users = [];
        foreach ($result['evidences'] as &$evidence) {
            $uid = (int) $evidence['users_id'];
            $users[$uid] ??= $uid > 0 ? getUserName($uid) : '';
            $evidence['user_name']   = $users[$uid];
            $evidence['check_label'] = Evidence::getCheckLabels()[$evidence['check']] ?? $evidence['check'];
            $evidence['check_color'] = Evidence::getCheckColor($evidence['check']);
        }
        unset($evidence);

        TemplateRenderer::getInstance()->display('@secincident/integrity.html.twig', [
            'item'      => $this,
            'result'    => $result,
            'can_check' => $this->can($this->getID(), READ),
            'form_url'  => self::getFormURL(),
        ]);
    }

    // ---------------------------------------------------------------------
    // Échéances réglementaires
    // ---------------------------------------------------------------------

    /**
     * Calcule les échéances RGPD (art. 33/34) et NIS2 (art. 23) applicables.
     *
     * @return array<int, array<string, mixed>>
     */
    public function getDeadlines(): array
    {
        $deadlines = [];
        $awareness = $this->toDate($this->fields['date_awareness'] ?? null);
        $now       = $this->toDate(Session::getCurrentTime()) ?? new DateTimeImmutable();

        $make = function (string $label, ?DateTimeImmutable $due, ?string $done_field, string $hint) use ($now) {
            $done = $done_field !== null ? $this->toDate($this->fields[$done_field] ?? null) : null;
            if ($done !== null) {
                $state = ($due !== null && $done > $due) ? 'late' : 'done';
            } elseif ($due === null) {
                $state = 'unknown';
            } elseif ($now > $due) {
                $state = 'overdue';
            } else {
                $state = 'pending';
            }

            $remaining = null;
            if ($due !== null && $done === null) {
                $remaining = (int) round(($due->getTimestamp() - $now->getTimestamp()) / 3600);
            }

            return [
                'label'     => $label,
                'hint'      => $hint,
                'due'       => $due?->format('Y-m-d H:i:s'),
                'done'      => $done?->format('Y-m-d H:i:s'),
                'state'     => $state,
                'remaining' => $remaining,
            ];
        };

        if ((int) ($this->fields['is_personal_data'] ?? 0) === 1) {
            $risk = (int) ($this->fields['gdpr_risk'] ?? 0);
            if ($risk >= self::GDPR_RISK) {
                $deadlines[] = $make(
                    __('CNIL notification', 'secincident'),
                    $awareness?->add(new DateInterval('PT72H')),
                    'cnil_notified_date',
                    __('72 h after awareness (GDPR art. 33)', 'secincident')
                );
            }
            if ($risk === self::GDPR_RISK_HIGH) {
                $deadlines[] = $make(
                    __('Informing the people affected', 'secincident'),
                    $awareness,
                    'persons_informed_date',
                    __('Without undue delay (GDPR art. 34)', 'secincident')
                );
            }
        }

        if ((int) ($this->fields['is_nis2'] ?? 0) === 1 && (int) ($this->fields['is_significant'] ?? 0) === 1) {
            $deadlines[] = $make(
                __('ANSSI early warning', 'secincident'),
                $awareness?->add(new DateInterval('PT24H')),
                'anssi_warning_date',
                __('24 h after awareness (NIS2 art. 23)', 'secincident')
            );
            $notif_due = $awareness?->add(new DateInterval('PT72H'));
            $deadlines[] = $make(
                __('ANSSI incident notification', 'secincident'),
                $notif_due,
                'anssi_notification_date',
                __('72 h after awareness (NIS2 art. 23)', 'secincident')
            );
            $notif_done = $this->toDate($this->fields['anssi_notification_date'] ?? null) ?? $notif_due;
            $deadlines[] = $make(
                __('ANSSI final report', 'secincident'),
                $notif_done?->add(new DateInterval('P1M')),
                'anssi_final_report_date',
                __('1 month after notification (NIS2 art. 23)', 'secincident')
            );
        }

        return $deadlines;
    }

    private function toDate(mixed $value): ?DateTimeImmutable
    {
        if (empty($value)) {
            return null;
        }
        try {
            return new DateTimeImmutable((string) $value);
        } catch (Throwable) {
            return null;
        }
    }

    // ---------------------------------------------------------------------
    // Cycle de vie des données
    // ---------------------------------------------------------------------

    public function prepareInputForAdd($input)
    {
        $input = $this->checkInput($input);
        if ($input === false) {
            return false;
        }

        // Le rédacteur est toujours l'utilisateur connecté (non falsifiable)
        $input['users_id_recipient'] = Session::getLoginUserID() ?: 0;
        // Un technicien limité à ses incidents en devient responsable par défaut
        if (!self::canViewAll() && empty($input['users_id_tech']) && empty($input['groups_id_tech'])) {
            $input['users_id_tech'] = Session::getLoginUserID() ?: 0;
        }
        if (empty($input['date_detection'])) {
            $input['date_detection'] = Session::getCurrentTime();
        }
        if (empty($input['name'])) {
            $categories    = self::getCategories();
            $input['name'] = $categories[$input['category'] ?? 'other'] ?? __('Security incident', 'secincident');
        }

        return $this->fillPhaseDates($input, []);
    }

    public function prepareInputForUpdate($input)
    {
        $input = $this->checkInput($input);
        if ($input === false) {
            return false;
        }
        // Champs non modifiables après création
        unset($input['users_id_recipient'], $input['reference']);

        // Clôture impossible tant que des étapes obligatoires du plan de remédiation restent à faire
        if (
            isset($input['status'])
            && (int) $input['status'] === self::STATUS_CLOSED
            && (int) ($this->fields['status'] ?? 0) !== self::STATUS_CLOSED
        ) {
            $pending = RemediationTask::countPendingMandatory((int) $this->getID());
            if ($pending > 0) {
                Session::addMessageAfterRedirect(
                    htmlescape(sprintf(
                        __('Cannot close: %d mandatory step(s) of the remediation plan are still to do (or to mark as “not applicable”).', 'secincident'),
                        $pending
                    )),
                    false,
                    ERROR
                );
                AuditLog::record('update', $this, ['refus' => I18n::instance('closure with pending mandatory steps'), 'etapes_en_attente' => $pending], AuditLog::RESULT_ERROR);
                return false;
            }
        }
        return $this->fillPhaseDates($input, $this->fields);
    }

    /**
     * Valide les valeurs énumérées.
     *
     * @param array<string, mixed> $input
     * @return array<string, mixed>|false
     */
    private function checkInput(array $input): array|false
    {
        $input = MitreAttack::normalizeInput($input);
        if (isset($input['category']) && !array_key_exists($input['category'], self::getCategories())) {
            $input['category'] = 'other';
        }
        if (isset($input['source']) && !array_key_exists($input['source'], self::getSources())) {
            $input['source'] = 'other';
        }
        if (isset($input['severity'])) {
            $input['severity'] = max(1, min(5, (int) $input['severity']));
        }
        if (isset($input['status']) && !array_key_exists((int) $input['status'], self::getStatuses())) {
            Session::addMessageAfterRedirect(__s('Invalid status', 'secincident'), false, ERROR);
            return false;
        }
        foreach (['impact_confidentiality', 'impact_integrity', 'impact_availability'] as $field) {
            if (isset($input[$field])) {
                $input[$field] = max(0, min(4, (int) $input[$field]));
            }
        }
        if (isset($input['gdpr_risk'])) {
            $input['gdpr_risk'] = max(0, min(2, (int) $input['gdpr_risk']));
        }
        if (array_key_exists('persons_affected', $input)) {
            $input['persons_affected'] = ($input['persons_affected'] === '' || $input['persons_affected'] === null)
                ? null
                : max(0, (int) $input['persons_affected']);
        }
        // Les dates vides du formulaire doivent devenir NULL
        foreach ($input as $key => $value) {
            if (str_starts_with($key, 'date_') || str_ends_with($key, '_date')) {
                if ($value === '' || $value === 'NULL') {
                    $input[$key] = null;
                }
            }
        }
        return $input;
    }

    /**
     * Horodate automatiquement les phases quand le statut avance
     * et que la date correspondante n'est pas renseignée.
     *
     * @param array<string, mixed> $input
     * @param array<string, mixed> $current
     * @return array<string, mixed>
     */
    private function fillPhaseDates(array $input, array $current): array
    {
        if (!isset($input['status'])) {
            return $input;
        }
        $map = [
            self::STATUS_CONTAINMENT => 'date_containment',
            self::STATUS_ERADICATION => 'date_eradication',
            self::STATUS_RECOVERY    => 'date_recovery',
            self::STATUS_CLOSED      => 'date_closure',
        ];
        $status = (int) $input['status'];
        if (isset($map[$status])) {
            $field = $map[$status];
            if (empty($input[$field]) && empty($current[$field])) {
                $input[$field] = Session::getCurrentTime();
            }
        }
        return $input;
    }

    public function post_addItem()
    {
        global $DB;

        // Référence lisible : SEC-AAAA-0001
        $year      = substr((string) ($this->fields['date_creation'] ?? date('Y')), 0, 4);
        $reference = sprintf('SEC-%s-%04d', $year, $this->getID());
        $DB->update(self::getTable(), ['reference' => $reference], ['id' => $this->getID()]);
        $this->fields['reference'] = $reference;

        // Déclaration depuis un ticket / matériel : lien automatique
        if (
            !empty($this->input['_link_itemtype'])
            && !empty($this->input['_link_items_id'])
            && in_array($this->input['_link_itemtype'], self::getLinkableTypes(), true)
        ) {
            (new Incident_Item())->add([
                '_no_audit' => AuditLog::silent(),
                self::getForeignKeyField() => $this->getID(),
                'itemtype'                 => $this->input['_link_itemtype'],
                'items_id'                 => (int) $this->input['_link_items_id'],
            ]);
        }

        if (empty($this->input['_no_creation_event'])) {
            $event = new TimelineEvent();
            $event->add([
                '_no_audit' => AuditLog::silent(),
                self::getForeignKeyField() => $this->getID(),
                'date'                     => $this->fields['date_detection'] ?: Session::getCurrentTime(),
                'event_type'               => 'detection',
                'name'                     => I18n::instance('Incident created'),
                'source'                   => 'system',
                '_no_history'              => true,
            ]);
        }

        $empreinte = Integrity::seal($this);
        AuditLog::record('create', $this, [
            'empreinte' => $empreinte,
            'reference' => $this->fields['reference'],
            'titre'     => $this->fields['name'],
            'source'    => $this->fields['source'],
            'gravite'   => $this->fields['severity'],
            'entite'    => $this->fields['entities_id'],
        ]);

        AuditLog::flushAnchors();
        parent::post_addItem();
    }

    public function post_deleteItem()
    {
        AuditLog::record('trash', $this, ['reference' => $this->fields['reference'], 'empreinte' => Integrity::seal($this)]);
        parent::post_deleteItem();
    }

    public function post_restoreItem()
    {
        AuditLog::record('restore', $this, ['reference' => $this->fields['reference'], 'empreinte' => Integrity::seal($this)]);
        parent::post_restoreItem();
    }

    public function post_purgeItem()
    {
        AuditLog::record('purge', $this, [
            'reference' => $this->fields['reference'],
            'titre'     => $this->fields['name'],
        ]);
        parent::post_purgeItem();
    }

    public function post_updateItem($history = true)
    {
        $fk = self::getForeignKeyField();

        if (in_array('status', $this->updates, true)) {
            $statuses = self::getStatuses(true);
            $old      = $statuses[(int) ($this->oldvalues['status'] ?? 0)] ?? '?';
            $new      = $statuses[(int) $this->fields['status']] ?? '?';
            (new TimelineEvent())->add([
                '_no_audit' => AuditLog::silent(),
                $fk          => $this->getID(),
                'date'       => Session::getCurrentTime(),
                'event_type' => (int) $this->fields['status'] === self::STATUS_CLOSED ? 'closure' : 'status_change',
                'name'       => sprintf(I18n::instance('Status: %1$s → %2$s'), $old, $new),
                'source'     => 'system',
                'users_id'   => Session::getLoginUserID() ?: 0,
            ]);
        }

        // Trace automatique des notifications réglementaires
        $notifications = [
            'cnil_notified_date'      => I18n::instance('CNIL notification made'),
            'persons_informed_date'   => I18n::instance('People affected informed'),
            'anssi_warning_date'      => I18n::instance('ANSSI early warning sent'),
            'anssi_notification_date' => I18n::instance('ANSSI notification sent'),
            'anssi_final_report_date' => I18n::instance('ANSSI final report submitted'),
        ];
        foreach ($notifications as $field => $label) {
            if (in_array($field, $this->updates, true) && !empty($this->fields[$field])) {
                (new TimelineEvent())->add([
                '_no_audit' => AuditLog::silent(),
                    $fk          => $this->getID(),
                    'date'       => $this->fields[$field],
                    'event_type' => 'notification',
                    'name'       => $label,
                    'source'     => 'system',
                    'users_id'   => Session::getLoginUserID() ?: 0,
                ]);
            }
        }

        $empreinte = Integrity::seal($this);
        $diff      = AuditLog::diff($this->updates, $this->oldvalues, $this->fields);
        if (AuditLog::isSilent($this->input)) {
            if ($empreinte !== null) {
                AuditLog::anchor(self::class, (int) $this->getID(), (int) $this->getID(), $empreinte);
            }
        } elseif ($diff !== []) {
            AuditLog::record('update', $this, ['champs' => $diff, 'empreinte' => $empreinte]);
        }

        AuditLog::flushAnchors();
        parent::post_updateItem($history);
    }

    public function cleanDBonPurge()
    {
        $this->deleteChildrenAndRelationsFromDb([
            TimelineEvent::class,
            Ioc::class,
            Incident_Item::class,
            RemediationTask::class,
            TeamMember::class,
        ]);
    }

    // ---------------------------------------------------------------------
    // Ticket lié
    // ---------------------------------------------------------------------

    /**
     * Crée un ticket GLPI à partir de l'incident et le lie.
     */
    public function createLinkedTicket(): int|false
    {
        $content = sprintf(
            "<p>%s <a href=\"%s\">%s</a></p>%s",
            htmlescape(I18n::instance('Ticket created from the security incident')),
            htmlescape($this->getLinkURL()),
            htmlescape($this->fields['reference'] . ' — ' . $this->fields['name']),
            $this->fields['content'] ?? ''
        );

        $input = [
            'name'        => '[' . $this->fields['reference'] . '] ' . $this->fields['name'],
            'content'     => $content,
            'entities_id' => $this->fields['entities_id'],
            'type'        => Ticket::INCIDENT_TYPE,
            'urgency'     => min(5, max(1, (int) $this->fields['severity'])),
            'impact'      => min(5, max(1, (int) $this->fields['severity'])),
        ];
        if ((int) $this->fields['users_id_tech'] > 0) {
            $input['_users_id_assign'] = (int) $this->fields['users_id_tech'];
        }

        $ticket     = new Ticket();
        $tickets_id = $ticket->add($input);

        if (!$tickets_id) {
            return false;
        }

        (new Incident_Item())->add([
                '_no_audit' => AuditLog::silent(),
            self::getForeignKeyField() => $this->getID(),
            'itemtype'                 => Ticket::class,
            'items_id'                 => $tickets_id,
        ]);

        (new TimelineEvent())->add([
                '_no_audit' => AuditLog::silent(),
            self::getForeignKeyField() => $this->getID(),
            'date'       => Session::getCurrentTime(),
            'event_type' => 'communication',
            'name'       => sprintf(I18n::instance('Ticket %d created and linked'), $tickets_id),
            'source'     => 'system',
            'users_id'   => Session::getLoginUserID() ?: 0,
        ]);

        AuditLog::record('create_ticket', $this, ['tickets_id' => $tickets_id]);
        AuditLog::flushAnchors();

        return $tickets_id;
    }

    // ---------------------------------------------------------------------
    // Moteur de recherche
    // ---------------------------------------------------------------------

    public function rawSearchOptions()
    {
        $tab   = [];
        $table = self::getTable();

        $tab[] = [
            'id'   => 'common',
            'name' => self::getTypeName(1),
        ];

        $tab[] = [
            'id'            => '1',
            'table'         => $table,
            'field'         => 'name',
            'name'          => __('Title', 'secincident'),
            'datatype'      => 'itemlink',
            'massiveaction' => false,
        ];

        $tab[] = [
            'id'            => '2',
            'table'         => $table,
            'field'         => 'reference',
            'name'          => __('Reference', 'secincident'),
            'datatype'      => 'string',
            'massiveaction' => false,
        ];

        $tab[] = [
            'id'         => '3',
            'table'      => $table,
            'field'      => 'status',
            'name'       => __('Status', 'secincident'),
            'datatype'   => 'specific',
            'searchtype' => ['equals', 'notequals'],
        ];

        $tab[] = [
            'id'         => '4',
            'table'      => $table,
            'field'      => 'severity',
            'name'       => __('Severity', 'secincident'),
            'datatype'   => 'specific',
            'searchtype' => ['equals', 'notequals'],
        ];

        $tab[] = [
            'id'         => '5',
            'table'      => $table,
            'field'      => 'category',
            'name'       => __('Category', 'secincident'),
            'datatype'   => 'specific',
            'searchtype' => ['equals', 'notequals'],
        ];

        $tab[] = [
            'id'       => '6',
            'table'    => $table,
            'field'    => 'date_detection',
            'name'     => __('Detection date', 'secincident'),
            'datatype' => 'datetime',
        ];

        $tab[] = [
            'id'        => '7',
            'table'     => 'glpi_users',
            'field'     => 'name',
            'linkfield' => 'users_id_tech',
            'name'      => __('Owner', 'secincident'),
            'datatype'  => 'dropdown',
            'right'     => 'own_ticket',
        ];

        $tab[] = [
            'id'        => '8',
            'table'     => 'glpi_groups',
            'field'     => 'completename',
            'linkfield' => 'groups_id_tech',
            'name'      => __('Assigned group', 'secincident'),
            'datatype'  => 'dropdown',
            'condition' => ['is_assign' => 1],
        ];

        $tab[] = [
            'id'         => '9',
            'table'      => $table,
            'field'      => 'source',
            'name'       => __('Source', 'secincident'),
            'datatype'   => 'specific',
            'searchtype' => ['equals', 'notequals'],
        ];

        $tab[] = [
            'id'       => '10',
            'table'    => $table,
            'field'    => 'mitre_tactic',
            'name'     => __('MITRE ATT&CK tactic', 'secincident'),
            'datatype' => 'string',
        ];

        $tab[] = [
            'id'       => '11',
            'table'    => $table,
            'field'    => 'mitre_technique',
            'name'     => __('MITRE ATT&CK technique', 'secincident'),
            'datatype' => 'string',
        ];

        $tab[] = [
            'id'       => '12',
            'table'    => $table,
            'field'    => 'date_closure',
            'name'     => __('Closure date', 'secincident'),
            'datatype' => 'datetime',
        ];

        $tab[] = [
            'id'       => '13',
            'table'    => $table,
            'field'    => 'external_id',
            'name'     => __('External identifier', 'secincident'),
            'datatype' => 'string',
        ];

        $tab[] = [
            'id'       => '14',
            'table'    => $table,
            'field'    => 'content',
            'name'     => __('Description', 'secincident'),
            'datatype' => 'text',
            'htmltext' => true,
        ];

        $tab[] = [
            'id'       => '15',
            'table'    => $table,
            'field'    => 'date_awareness',
            'name'     => __('Awareness date', 'secincident'),
            'datatype' => 'datetime',
        ];

        $tab[] = [
            'id'       => '16',
            'table'    => $table,
            'field'    => 'date_containment',
            'name'     => __('Containment date', 'secincident'),
            'datatype' => 'datetime',
        ];

        $tab[] = [
            'id'        => '17',
            'table'     => 'glpi_users',
            'field'     => 'name',
            'linkfield' => 'users_id_recipient',
            'name'      => __('Author', 'secincident'),
            'datatype'  => 'dropdown',
            'massiveaction' => false,
        ];

        $tab[] = [
            'id'       => '19',
            'table'    => $table,
            'field'    => 'date_mod',
            'name'     => __('Last update'),
            'datatype' => 'datetime',
            'massiveaction' => false,
        ];

        $tab[] = [
            'id'       => '20',
            'table'    => $table,
            'field'    => 'id',
            'name'     => __('ID'),
            'datatype' => 'number',
            'massiveaction' => false,
        ];

        foreach (
            [
                '21' => ['impact_confidentiality', __('Confidentiality impact', 'secincident')],
                '22' => ['impact_integrity', __('Integrity impact', 'secincident')],
                '23' => ['impact_availability', __('Availability impact', 'secincident')],
            ] as $id => [$field, $label]
        ) {
            $tab[] = [
                'id'         => $id,
                'table'      => $table,
                'field'      => $field,
                'name'       => $label,
                'datatype'   => 'specific',
                'searchtype' => ['equals', 'notequals'],
            ];
        }

        // --- RGPD / NIS2 ---
        $tab[] = [
            'id'   => 'compliance',
            'name' => __('GDPR / NIS2', 'secincident'),
        ];

        $tab[] = [
            'id'       => '30',
            'table'    => $table,
            'field'    => 'is_personal_data',
            'name'     => __('Personal data involved', 'secincident'),
            'datatype' => 'bool',
        ];

        $tab[] = [
            'id'         => '31',
            'table'      => $table,
            'field'      => 'gdpr_risk',
            'name'       => __('Risk to individuals', 'secincident'),
            'datatype'   => 'specific',
            'searchtype' => ['equals', 'notequals'],
        ];

        $tab[] = [
            'id'       => '32',
            'table'    => $table,
            'field'    => 'cnil_notified_date',
            'name'     => __('CNIL notification date', 'secincident'),
            'datatype' => 'datetime',
        ];

        $tab[] = [
            'id'       => '33',
            'table'    => $table,
            'field'    => 'persons_affected',
            'name'     => __('Number of people affected', 'secincident'),
            'datatype' => 'integer',
        ];

        $tab[] = [
            'id'       => '34',
            'table'    => $table,
            'field'    => 'is_nis2',
            'name'     => __('Entity subject to NIS2', 'secincident'),
            'datatype' => 'bool',
        ];

        $tab[] = [
            'id'       => '35',
            'table'    => $table,
            'field'    => 'is_significant',
            'name'     => __('Significant incident (NIS2)', 'secincident'),
            'datatype' => 'bool',
        ];

        $tab[] = [
            'id'       => '36',
            'table'    => $table,
            'field'    => 'anssi_notification_date',
            'name'     => __('ANSSI notification date', 'secincident'),
            'datatype' => 'datetime',
        ];

        // --- Entité ---
        $tab[] = [
            'id'            => '80',
            'table'         => 'glpi_entities',
            'field'         => 'completename',
            'name'          => __('Entity'),
            'datatype'      => 'dropdown',
            'massiveaction' => false,
        ];

        $tab[] = [
            'id'       => '86',
            'table'    => $table,
            'field'    => 'is_recursive',
            'name'     => __('Child entities'),
            'datatype' => 'bool',
        ];

        return $tab;
    }

    /**
     * @return array<string|int, string>|null
     */
    private static function getValuesForField(string $field): ?array
    {
        return match ($field) {
            'status'   => self::getStatuses(),
            'severity' => self::getSeverities(),
            'category' => self::getCategories(),
            'source'   => self::getSources(),
            'gdpr_risk' => self::getGdprRiskLevels(),
            'impact_confidentiality', 'impact_integrity', 'impact_availability' => self::getImpactLevels(),
            default    => null,
        };
    }

    public static function getSpecificValueToDisplay($field, $values, array $options = [])
    {
        if (!is_array($values)) {
            $values = [$field => $values];
        }
        $list = self::getValuesForField($field);
        if ($list !== null) {
            $value = $values[$field] ?? '';
            $label = $list[$value] ?? (string) $value;
            if ($field === 'severity') {
                return sprintf(
                    '<span class="badge bg-%s-lt">%s</span>',
                    self::getSeverityColor((int) $value),
                    htmlescape($label)
                );
            }
            if ($field === 'status') {
                return sprintf(
                    '<span class="badge bg-%s-lt">%s</span>',
                    self::getStatusColor((int) $value),
                    htmlescape($label)
                );
            }
            return htmlescape($label);
        }
        return parent::getSpecificValueToDisplay($field, $values, $options);
    }

    public static function getSpecificValueToSelect($field, $name = '', $values = '', array $options = [])
    {
        if (!is_array($values)) {
            $values = [$field => $values];
        }
        $list = self::getValuesForField($field);
        if ($list !== null) {
            $options['display'] = false;
            $options['value']   = $values[$field] ?? '';
            return Dropdown::showFromArray($name, $list, $options);
        }
        return parent::getSpecificValueToSelect($field, $name, $values, $options);
    }
}
