<?php

/**
 * -------------------------------------------------------------------------
 * SecIncident — Suivi des incidents de sécurité pour GLPI 11
 * -------------------------------------------------------------------------
 * @license   GPLv3 https://www.gnu.org/licenses/gpl-3.0.html
 * -------------------------------------------------------------------------
 */

namespace GlpiPlugin\Secincident;

use CommonDropdown;
use Session;
use Toolbox;

/**
 * Catégories d'incident de sécurité, paramétrables.
 *
 * Les incidents et les procédures stockent le CODE de la catégorie (texte
 * stable), pas son id ni son libellé : renommer une catégorie ne modifie
 * aucune donnée scellée, et le code n'est jamais modifiable après création.
 */
class Category extends CommonDropdown
{
    use IntegerInputTrait;
    public $dohistory = true;

    public static $rightname = 'plugin_secincident_incident';

    /** Catégorie de repli, non supprimable */
    public const FALLBACK = 'other';

    /** @var array<string, string>|null */
    private static ?array $cache = null;

    public static function getTypeName($nb = 0)
    {
        return _n('Incident category', 'Incident categories', $nb, 'secincident');
    }

    public static function getIcon()
    {
        return 'ti ti-category';
    }

    // ---------------------------------------------------------------------
    // Droits : consultation pour tous les utilisateurs du plugin,
    // gestion réservée au droit « Gérer les catégories »
    // ---------------------------------------------------------------------

    public static function canView(): bool
    {
        return Incident::canView();
    }

    public static function canCreate(): bool
    {
        return Session::haveRight(static::$rightname, Incident::CATEGORY);
    }

    public static function canUpdate(): bool
    {
        return self::canCreate();
    }

    public static function canDelete(): bool
    {
        return self::canCreate();
    }

    public static function canPurge(): bool
    {
        return self::canCreate();
    }

    public function canCreateItem(): bool
    {
        return self::canCreate();
    }

    public function canUpdateItem(): bool
    {
        return self::canCreate();
    }

    public function canDeleteItem(): bool
    {
        return self::canCreate();
    }

    public function canPurgeItem(): bool
    {
        // Refus détaillé (catégorie utilisée, catégorie de repli) dans pre_deleteItem
        return self::canCreate();
    }

    public function getAdditionalFields()
    {
        return [
            [
                'name'  => 'code',
                'label' => __('Code (internal identifier, cannot be changed)', 'secincident'),
                'type'  => $this->isNewItem() ? 'text' : 'readonly_text',
                'list'  => true,
            ],
        ];
    }

    public function displaySpecificTypeField($ID, $field = [], array $options = [])
    {
        if (($field['type'] ?? '') === 'readonly_text') {
            echo '<code>' . htmlescape((string) ($this->fields[$field['name']] ?? '')) . '</code>';
        }
    }

    public function rawSearchOptions()
    {
        $tab = parent::rawSearchOptions();
        $tab[] = [
            'id'       => '9201',
            'table'    => $this->getTable(),
            'field'    => 'code',
            'name'     => __('Code', 'secincident'),
            'datatype' => 'string',
            'massiveaction' => false,
        ];
        return $tab;
    }

    // ---------------------------------------------------------------------
    // Code stable
    // ---------------------------------------------------------------------

    public static function makeCode(string $name): string
    {
        $code = strtolower(Toolbox::slugify($name, ''));
        $code = trim(preg_replace('/[^a-z0-9]+/', '_', $code) ?? '', '_');
        return substr($code !== '' ? $code : 'categorie', 0, 40);
    }

    public function prepareInputForAdd($input)
    {
        $input = parent::prepareInputForAdd($input);
        if ($input === false) {
            return false;
        }
        if (trim((string) ($input['name'] ?? '')) === '') {
            Session::addMessageAfterRedirect(__s('The category name is required', 'secincident'), false, ERROR);
            return false;
        }
        if (!$this->isNameAvailable((string) $input['name'], 0)) {
            return false;
        }
        $base = self::makeCode((string) (($input['code'] ?? '') !== '' ? $input['code'] : $input['name']));
        $code = $base;
        $i    = 2;
        while (countElementsInTable(self::getTable(), ['code' => $code]) > 0) {
            $code = substr($base, 0, 36) . '_' . $i++;
        }
        $input['code'] = $code;
        return $input;
    }

    public function prepareInputForUpdate($input)
    {
        // Le code est référencé par les incidents scellés : jamais modifié
        unset($input['code']);
        $input = parent::prepareInputForUpdate($input);
        if ($input === false) {
            return false;
        }
        if (array_key_exists('name', $input)) {
            if (trim((string) $input['name']) === '') {
                Session::addMessageAfterRedirect(__s('The category name is required', 'secincident'), false, ERROR);
                return false;
            }
            if (!$this->isNameAvailable((string) $input['name'], (int) $this->getID())) {
                return false;
            }
        }
        return $input;
    }

    /** Deux catégories ne peuvent pas porter le même nom (statistiques ambiguës) */
    private function isNameAvailable(string $name, int $except_id): bool
    {
        $criteria = ['name' => trim($name)];
        if ($except_id > 0) {
            $criteria['NOT'] = ['id' => $except_id];
        }
        if (countElementsInTable(self::getTable(), $criteria) > 0) {
            Session::addMessageAfterRedirect(
                htmlescape(sprintf(__('A category “%s” already exists.', 'secincident'), trim($name))),
                false,
                ERROR
            );
            return false;
        }
        return true;
    }

    public function post_addItem()
    {
        self::$cache = null;
        AuditLog::record('create', $this, ['categorie' => $this->fields['name'], 'code' => $this->fields['code']]);
        parent::post_addItem();
    }

    public function post_updateItem($history = true)
    {
        self::$cache = null;
        $diff = AuditLog::diff($this->updates, $this->oldvalues, $this->fields);
        if ($diff !== []) {
            AuditLog::record('update', $this, ['code' => $this->fields['code'], 'champs' => $diff]);
        }
        parent::post_updateItem($history);
    }

    // ---------------------------------------------------------------------
    // Suppression : interdite si la catégorie est utilisée
    // ---------------------------------------------------------------------

    public function countUses(): int
    {
        $code = (string) ($this->fields['code'] ?? '');
        if ($code === '') {
            return 0;
        }
        return countElementsInTable(Incident::getTable(), ['category' => $code])
            + countElementsInTable(Playbook::getTable(), ['category' => $code]);
    }

    public function canBePurged(): bool
    {
        return ($this->fields['code'] ?? '') !== self::FALLBACK && $this->countUses() === 0;
    }

    public function pre_deleteItem()
    {
        if (($this->fields['code'] ?? '') === self::FALLBACK) {
            Session::addMessageAfterRedirect(__s('The “Other” category is the fallback and cannot be deleted.', 'secincident'), false, ERROR);
            return false;
        }
        $uses = $this->countUses();
        if ($uses > 0) {
            Session::addMessageAfterRedirect(
                sprintf(__s('Category used by %d incident(s) or playbook(s): it cannot be deleted. Rename it instead.', 'secincident'), $uses),
                false,
                ERROR
            );
            AuditLog::record('purge', $this, ['categorie' => $this->fields['name'], 'motif' => I18n::instance('category in use')], AuditLog::RESULT_DENIED);
            return false;
        }
        return true;
    }

    public function post_purgeItem()
    {
        self::$cache = null;
        AuditLog::record('purge', $this, ['categorie' => $this->fields['name'], 'code' => $this->fields['code']]);
        parent::post_purgeItem();
    }

    // ---------------------------------------------------------------------
    // Liste des catégories (code => libellé)
    // ---------------------------------------------------------------------

    /**
     * @return array<string, string>
     */
    public static function getList(): array
    {
        global $DB;

        if (self::$cache !== null) {
            return self::$cache;
        }
        if (!$DB->tableExists(self::getTable())) {
            return self::getDefaults();
        }
        $list = [];
        foreach ($DB->request(['SELECT' => ['code', 'name'], 'FROM' => self::getTable(), 'ORDER' => 'name']) as $row) {
            $list[(string) $row['code']] = (string) $row['name'];
        }
        // « Autre » toujours en dernier
        if (isset($list[self::FALLBACK])) {
            $other = $list[self::FALLBACK];
            unset($list[self::FALLBACK]);
            $list[self::FALLBACK] = $other;
        }
        return self::$cache = ($list ?: self::getDefaults());
    }

    /**
     * Catégories installées par défaut.
     *
     * @return array<string, string>
     */
    public static function getDefaults(bool $instance = false): array
    {
        return [
            'malware'            => I18n::tr('Malware', $instance),
            'ransomware'         => I18n::tr('Ransomware', $instance),
            'phishing'           => I18n::tr('Phishing / social engineering', $instance),
            'account_compromise' => I18n::tr('Account compromise', $instance),
            'intrusion'          => I18n::tr('Intrusion / unauthorized access', $instance),
            'exploitation'       => I18n::tr('Vulnerability exploitation', $instance),
            'data_leak'          => I18n::tr('Data leak / exfiltration', $instance),
            'dos'                => I18n::tr('Denial of service', $instance),
            'fraud'              => I18n::tr('Fraud (CEO fraud, fake bank details…)', $instance),
            'insider'            => I18n::tr('Insider malice or internal error', $instance),
            'loss_theft'         => I18n::tr('Loss or theft of equipment', $instance),
            'policy_violation'   => I18n::tr('Security policy violation', $instance),
            self::FALLBACK       => I18n::tr('Other', $instance),
        ];
    }

    /**
     * Installe les catégories par défaut manquantes (sans audit individuel).
     */
    public static function installDefaults(): int
    {
        global $DB;

        $count = 0;
        foreach (self::getDefaults(true) as $code => $name) {
            if (countElementsInTable(self::getTable(), ['code' => $code]) === 0) {
                $DB->insert(self::getTable(), [
                    'name'          => $name,
                    'code'          => $code,
                    'date_creation' => $_SESSION['glpi_currenttime'] ?? date('Y-m-d H:i:s'),
                    'date_mod'      => $_SESSION['glpi_currenttime'] ?? date('Y-m-d H:i:s'),
                ]);
                $count++;
            }
        }
        self::$cache = null;
        return $count;
    }
}
