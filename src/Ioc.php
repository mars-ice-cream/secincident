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
 * Indicateur de compromission (hash, IP, domaine, chemin, ligne de commande…).
 */
class Ioc extends CommonDBChild
{
    use IntegerInputTrait;
    use IncidentChildTrait;

    public static $itemtype = Incident::class;
    public static $items_id = 'plugin_secincident_incidents_id';

    public static $rightname = 'plugin_secincident_incident';

    public const VERDICT_UNKNOWN    = 0;
    public const VERDICT_MALICIOUS  = 1;
    public const VERDICT_SUSPICIOUS = 2;
    public const VERDICT_BENIGN     = 3;

    public static function getTypeName($nb = 0)
    {
        return _n('Indicator (IOC)', 'Indicators (IOC)', $nb, 'secincident');
    }

    public static function getIcon()
    {
        return 'ti ti-fingerprint';
    }

    /** @return array<string, string> */
    public static function getIocTypes(): array
    {
        return [
            'sha256'   => 'SHA-256',
            'sha1'     => 'SHA-1',
            'md5'      => 'MD5',
            'ipv4'     => __('IPv4 address', 'secincident'),
            'ipv6'     => __('IPv6 address', 'secincident'),
            'domain'   => __('Domain', 'secincident'),
            'url'      => 'URL',
            'email'    => __('E-mail address', 'secincident'),
            'filepath' => __('File path', 'secincident'),
            'filename' => __('File name', 'secincident'),
            'cmdline'  => __('Command line', 'secincident'),
            'process'  => __('Process', 'secincident'),
            'registry' => __('Registry key', 'secincident'),
            'account'  => __('Account', 'secincident'),
            'other'    => __('Other', 'secincident'),
        ];
    }

    /** @return array<int, string> */
    public static function getVerdicts(): array
    {
        return [
            self::VERDICT_UNKNOWN    => __('Not assessed', 'secincident'),
            self::VERDICT_MALICIOUS  => __('Malicious', 'secincident'),
            self::VERDICT_SUSPICIOUS => __('Suspicious', 'secincident'),
            self::VERDICT_BENIGN     => __('Legitimate / false positive', 'secincident'),
        ];
    }

    public static function getVerdictColor(int $verdict): string
    {
        return match ($verdict) {
            self::VERDICT_MALICIOUS  => 'red',
            self::VERDICT_SUSPICIOUS => 'orange',
            self::VERDICT_BENIGN     => 'green',
            default                  => 'secondary',
        };
    }

    /**
     * Devine le type d'un indicateur à partir de sa valeur.
     */
    public static function guessType(string $value): string
    {
        $v = trim($value);
        return match (true) {
            (bool) preg_match('/^[a-f0-9]{64}$/i', $v)                       => 'sha256',
            (bool) preg_match('/^[a-f0-9]{40}$/i', $v)                       => 'sha1',
            (bool) preg_match('/^[a-f0-9]{32}$/i', $v)                       => 'md5',
            filter_var($v, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false   => 'ipv4',
            filter_var($v, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false   => 'ipv6',
            filter_var($v, FILTER_VALIDATE_EMAIL) !== false                  => 'email',
            (bool) preg_match('#^[a-z][a-z0-9+.-]*://#i', $v)                => 'url',
            (bool) preg_match('/^(HKLM|HKCU|HKEY_|\\\\REGISTRY\\\\)/i', $v)  => 'registry',
            (bool) preg_match('#^([a-z]:\\\\|\\\\\\\\|\\\\Device\\\\|/)#i', $v) => 'filepath',
            (bool) preg_match('/^(?=.{4,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$/i', $v) => 'domain',
            default                                                          => 'other',
        };
    }

    /**
     * Empreinte de dédoublonnage (type + valeur normalisée).
     */
    public static function computeHash(string $type, string $value): string
    {
        $normalized = trim($value);
        if (!in_array($type, ['filepath', 'cmdline', 'registry'], true)) {
            $normalized = mb_strtolower($normalized);
        }
        return hash('sha256', $type . '|' . $normalized);
    }

    public function getTabNameForItem(CommonGLPI $item, $withtemplate = 0)
    {
        if ($item instanceof Incident && !$item->isNewItem()) {
            $nb = 0;
            if ($_SESSION['glpishow_count_on_tabs']) {
                $nb = countElementsInTable(self::getTable(), [static::$items_id => $item->getID()]);
            }
            return self::createTabEntry(self::getTypeName(Session::getPluralNumber()), $nb, null, self::getIcon());
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
            AuditLog::recordDenied(I18n::instance('read IOCs'), Incident::class, (int) $incident->getID());
            return;
        }
        AuditLog::recordView($incident, 'IOC');
        $canedit = $incident->can($incident->getID(), UPDATE);

        $iterator = $DB->request([
            'FROM'  => self::getTable(),
            'WHERE' => [static::$items_id => $incident->getID()],
            'ORDER' => ['ioc_type ASC', 'id ASC'],
        ]);

        $types    = self::getIocTypes();
        $verdicts = self::getVerdicts();
        $entries  = [];
        foreach ($iterator as $row) {
            $value = (string) $row['value'];
            $entries[] = [
                'itemtype' => self::class,
                'id'       => $row['id'],
                'type'     => htmlescape($types[$row['ioc_type']] ?? $row['ioc_type']),
                'value'    => sprintf(
                    '<a href="%s"><code class="text-break">%s</code></a>',
                    htmlescape(self::getFormURLWithID($row['id'])),
                    htmlescape(mb_strimwidth($value, 0, 200, '…'))
                ),
                'verdict'  => sprintf(
                    '<span class="badge bg-%s-lt">%s</span>',
                    self::getVerdictColor((int) $row['verdict']),
                    htmlescape($verdicts[(int) $row['verdict']] ?? '')
                ),
                'source'   => htmlescape(Incident::getSources()[$row['source']] ?? $row['source']),
                'first'    => $row['date_first_seen'],
                'last'     => $row['date_last_seen'],
                'comment'  => $row['comment'],
            ];
        }

        TemplateRenderer::getInstance()->display('@secincident/iocs.html.twig', [
            'incident'    => $incident,
            'entries'     => $entries,
            'types'       => $types,
            'verdicts'    => $verdicts,
            'canedit'     => $canedit,
            'fk'          => static::$items_id,
            'form_action' => self::getFormURL(),
        ]);
    }

    public function showForm($ID, array $options = [])
    {
        $this->initForm($ID, $options);
        if (!$this->isNewItem()) {
            AuditLog::recordView($this, 'IOC');
        }
        if ($this->isNewItem() && !empty($options[static::$items_id])) {
            $this->fields[static::$items_id] = (int) $options[static::$items_id];
        }
        $incident = new Incident();
        $incident->getFromDB((int) ($this->fields[static::$items_id] ?? 0));

        TemplateRenderer::getInstance()->display('@secincident/ioc_form.html.twig', [
            'item'     => $this,
            'params'   => $options,
            'types'    => self::getIocTypes(),
            'verdicts' => self::getVerdicts(),
            'incident' => $incident,
        ]);
        return true;
    }

    /**
     * @param array<string, mixed> $input
     * @return array<string, mixed>|false
     */
    private function normalizeInput(array $input, bool $is_add): array|false
    {
        if (array_key_exists('value', $input)) {
            $input['value'] = trim((string) $input['value']);
            if ($input['value'] === '') {
                Session::addMessageAfterRedirect(__s('The indicator value is required', 'secincident'), false, ERROR);
                return false;
            }
        } elseif ($is_add) {
            return false;
        }

        $type = $input['ioc_type'] ?? ($this->fields['ioc_type'] ?? '');
        if ($type === '' || $type === 'auto' || !array_key_exists($type, self::getIocTypes())) {
            $type = self::guessType((string) ($input['value'] ?? $this->fields['value'] ?? ''));
        }
        $input['ioc_type'] = $type;

        if (isset($input['value']) || isset($input['ioc_type'])) {
            $input['value_hash'] = self::computeHash($type, (string) ($input['value'] ?? $this->fields['value']));
        }
        if (isset($input['verdict'])) {
            $input['verdict'] = max(0, min(3, (int) $input['verdict']));
        }
        foreach (['date_first_seen', 'date_last_seen'] as $field) {
            if (array_key_exists($field, $input) && ($input[$field] === '' || $input[$field] === 'NULL')) {
                $input[$field] = null;
            }
        }
        return $input;
    }

    public function prepareInputForAdd($input)
    {
        $input = $this->normalizeInput($input, true);
        if ($input === false) {
            return false;
        }
        // Dédoublonnage silencieux au sein d'un même incident
        if (
            !empty($input[static::$items_id])
            && countElementsInTable(self::getTable(), [
                static::$items_id => $input[static::$items_id],
                'value_hash'      => $input['value_hash'],
            ]) > 0
        ) {
            if (empty($input['_silent_duplicate'])) {
                Session::addMessageAfterRedirect(__s('This indicator already exists for this incident', 'secincident'), false, WARNING);
            }
            return false;
        }
        return parent::prepareInputForAdd($input);
    }

    public function prepareInputForUpdate($input)
    {
        $input = $this->normalizeInput($input, false);
        if ($input === false) {
            return false;
        }
        return parent::prepareInputForUpdate($input);
    }

    public function rawSearchOptions()
    {
        $tab = [];
        $tab[] = ['id' => 'common', 'name' => self::getTypeName(1)];
        $tab[] = [
            'id'       => '1',
            'table'    => self::getTable(),
            'field'    => 'value',
            'name'     => __('Value', 'secincident'),
            'datatype' => 'itemlink',
        ];
        $tab[] = [
            'id'       => '2',
            'table'    => self::getTable(),
            'field'    => 'ioc_type',
            'name'     => _n('Type', 'Types', 1),
            'datatype' => 'string',
        ];
        $tab[] = [
            'id'       => '3',
            'table'    => self::getTable(),
            'field'    => 'comment',
            'name'     => __('Comments'),
            'datatype' => 'text',
        ];
        return $tab;
    }

    public function getName($options = [])
    {
        $value = (string) ($this->fields['value'] ?? '');
        return $value === '' ? parent::getName($options) : mb_strimwidth($value, 0, 80, '…');
    }
}
