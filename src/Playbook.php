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
use Glpi\Application\View\TemplateRenderer;
use Log;
use Session;

/**
 * Procédure de remédiation type (playbook), applicable à un incident.
 */
class Playbook extends CommonDBTM
{
    use IntegerInputTrait;
    public $dohistory = true;

    public static $rightname = 'plugin_secincident_incident';

    public static function getTypeName($nb = 0)
    {
        return _n('Remediation playbook', 'Remediation playbooks', $nb, 'secincident');
    }

    public static function getIcon()
    {
        return 'ti ti-list-check';
    }

    /** Consultation : toute personne ayant accès aux incidents */
    public static function canView(): bool
    {
        return Incident::canView();
    }

    /** Gestion de la bibliothèque : droit dédié */
    public static function canCreate(): bool
    {
        return Session::haveRight(static::$rightname, Incident::PLAYBOOK);
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

    public function canUpdateItem(): bool
    {
        return self::canCreate() && parent::canViewItem();
    }

    public function canDeleteItem(): bool
    {
        return self::canCreate() && parent::canViewItem();
    }

    public function canPurgeItem(): bool
    {
        return self::canCreate() && parent::canViewItem();
    }

    public function canCreateItem(): bool
    {
        return self::canCreate();
    }

    /** @return array<string, string> */
    public static function getPhases(): array
    {
        return [
            'containment'   => __('Containment', 'secincident'),
            'analysis'      => __('Analysis / investigation', 'secincident'),
            'notification'  => __('Notification / communication', 'secincident'),
            'eradication'   => __('Eradication', 'secincident'),
            'recovery'      => __('Recovery', 'secincident'),
            'post_incident' => __('Post-incident / lessons learned', 'secincident'),
        ];
    }

    public static function getPhaseColor(string $phase): string
    {
        return match ($phase) {
            'containment'   => 'yellow',
            'analysis'      => 'orange',
            'notification'  => 'pink',
            'eradication'   => 'purple',
            'recovery'      => 'azure',
            'post_incident' => 'green',
            default         => 'secondary',
        };
    }

    public function defineTabs($options = [])
    {
        $ong = [];
        $this->addDefaultFormTab($ong);
        $this->addStandardTab(PlaybookStep::class, $ong, $options);
        $this->addStandardTab(Log::class, $ong, $options);
        return $ong;
    }

    public function post_getEmpty()
    {
        $this->fields['is_active'] = 1;
        $this->fields['category']  = '';
    }

    public function showForm($ID, array $options = [])
    {
        $this->initForm($ID, $options);
        if (!$this->isNewItem()) {
            AuditLog::recordView($this, I18n::instance('playbook'));
        }
        TemplateRenderer::getInstance()->display('@secincident/playbook_form.html.twig', [
            'item'       => $this,
            'params'     => $options,
            'categories' => ['' => __('All categories', 'secincident')] + Incident::getCategories(),
        ]);
        return true;
    }

    public function prepareInputForAdd($input)
    {
        if (isset($input['category']) && $input['category'] !== '' && !array_key_exists($input['category'], Incident::getCategories())) {
            $input['category'] = '';
        }
        return $input;
    }

    public function prepareInputForUpdate($input)
    {
        return $this->prepareInputForAdd($input);
    }

    public function post_addItem()
    {
        AuditLog::record('create', $this, ['procedure' => $this->fields['name'], 'categorie' => $this->fields['category']]);
        parent::post_addItem();
    }

    public function post_updateItem($history = true)
    {
        $diff = AuditLog::diff($this->updates, $this->oldvalues, $this->fields);
        if ($diff !== []) {
            AuditLog::record('update', $this, ['champs' => $diff]);
        }
        parent::post_updateItem($history);
    }

    public function post_purgeItem()
    {
        AuditLog::record('purge', $this, ['procedure' => $this->fields['name']]);
        parent::post_purgeItem();
    }

    public function cleanDBonPurge()
    {
        $this->deleteChildrenAndRelationsFromDb([PlaybookStep::class]);
    }

    /**
     * Procédures actives proposées pour un incident (celles de sa catégorie en premier).
     *
     * @return array<int, string>
     */
    public static function getChoicesForIncident(Incident $incident): array
    {
        global $DB;

        $category = (string) $incident->fields['category'];
        $choices  = [];
        $iterator = $DB->request([
            'FROM'  => self::getTable(),
            'WHERE' => ['is_active' => 1, 'is_deleted' => 0]
                + getEntitiesRestrictCriteria(self::getTable(), '', $incident->getEntityID(), true),
            'ORDER' => 'name',
        ]);
        $suggested = [];
        $others    = [];
        foreach ($iterator as $row) {
            $nb    = countElementsInTable(PlaybookStep::getTable(), [self::getForeignKeyField() => $row['id']]);
            $label = $row['name'] . ' (' . sprintf(_n('%d step', '%d steps', $nb, 'secincident'), $nb) . ')';
            if ($row['category'] !== '' && $row['category'] === $category) {
                $suggested[(int) $row['id']] = '★ ' . $label;
            } else {
                $others[(int) $row['id']] = $label;
            }
        }
        return $suggested + $others;
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    public function getSteps(): array
    {
        global $DB;
        $steps = [];
        foreach (
            $DB->request([
                'FROM'  => PlaybookStep::getTable(),
                'WHERE' => [self::getForeignKeyField() => $this->getID()],
                'ORDER' => ['position ASC', 'id ASC'],
            ]) as $row
        ) {
            $steps[] = $row;
        }
        return $steps;
    }

    public function rawSearchOptions()
    {
        $tab   = [];
        $table = self::getTable();
        $tab[] = ['id' => 'common', 'name' => self::getTypeName(1)];
        $tab[] = [
            'id'            => '1',
            'table'         => $table,
            'field'         => 'name',
            'name'          => __('Name'),
            'datatype'      => 'itemlink',
            'massiveaction' => false,
        ];
        $tab[] = [
            'id'         => '2',
            'table'      => $table,
            'field'      => 'category',
            'name'       => __('Category', 'secincident'),
            'datatype'   => 'specific',
            'searchtype' => ['equals', 'notequals'],
        ];
        $tab[] = [
            'id'       => '3',
            'table'    => $table,
            'field'    => 'is_active',
            'name'     => __('Active'),
            'datatype' => 'bool',
        ];
        $tab[] = [
            'id'       => '4',
            'table'    => $table,
            'field'    => 'description',
            'name'     => __('Description'),
            'datatype' => 'text',
        ];
        $tab[] = [
            'id'            => '19',
            'table'         => $table,
            'field'         => 'date_mod',
            'name'          => __('Last update'),
            'datatype'      => 'datetime',
            'massiveaction' => false,
        ];
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

    public static function getSpecificValueToDisplay($field, $values, array $options = [])
    {
        if (!is_array($values)) {
            $values = [$field => $values];
        }
        if ($field === 'category') {
            $value = (string) ($values[$field] ?? '');
            return htmlescape($value === '' ? __('All categories', 'secincident') : (Incident::getCategories()[$value] ?? $value));
        }
        return parent::getSpecificValueToDisplay($field, $values, $options);
    }

    public static function getSpecificValueToSelect($field, $name = '', $values = '', array $options = [])
    {
        if (!is_array($values)) {
            $values = [$field => $values];
        }
        if ($field === 'category') {
            $options['display'] = false;
            $options['value']   = $values[$field] ?? '';
            return \Dropdown::showFromArray($name, ['' => __('All categories', 'secincident')] + Incident::getCategories(), $options);
        }
        return parent::getSpecificValueToSelect($field, $name, $values, $options);
    }

    /**
     * Procédures fournies à l'installation.
     *
     * @return array<int, array{name: string, category: string, description: string, steps: array<int, array{0: string, 1: string, 2: string, 3: bool}>}>
     */
    public static function getDefaultPlaybooks(): array
    {
        return [
            [
                'name'        => I18n::noop('Ransomware'),
                'category'    => 'ransomware',
                'description' => I18n::noop('Data encryption, ransom note, deletion of shadow copies.'),
                'steps'       => [
                    ['containment', I18n::noop('Isolate the affected workstations and servers'), I18n::noop('Isolate from the network (network containment from the EDR console, or cable/Wi-Fi cut). Do NOT shut the machines down: memory may hold keys and traces.'), true],
                    ['containment', I18n::noop('Cut remote access'), I18n::noop('Suspend VPN, exposed RDP, provider access and network shares while the scope is being assessed.'), true],
                    ['containment', I18n::noop('Disable the compromised accounts'), I18n::noop('Disable the accounts used by the attacker and revoke their sessions and tokens.'), true],
                    ['analysis', I18n::noop('Preserve the evidence'), I18n::noop('Export EDR detections, Windows/firewall/proxy logs, memory capture if possible. Attach the files to the incident (Documents tab): their SHA-256 is recorded.'), true],
                    ['analysis', I18n::noop('Determine the scope'), I18n::noop('Search for the same hash / command line across the whole fleet (EDR console), list the affected hosts and accounts and link the computers to the incident.'), true],
                    ['analysis', I18n::noop('Check the state of the backups'), I18n::noop('Confirm that a clean backup — offline or immutable, prior to the compromise — exists and can be restored.'), true],
                    ['notification', I18n::noop('Assess GDPR / NIS2 obligations'), I18n::noop('Fill in the GDPR / NIS2 tab (72 h CNIL, 24 h / 72 h ANSSI where applicable).'), true],
                    ['notification', I18n::noop('File a complaint and inform'), I18n::noop('Complaint (police, online), cyber insurer, management. Resources: cybermalveillance.gouv.fr. Do not pay the ransom without legal advice.'), false],
                    ['eradication', I18n::noop('Identify and close the initial vector'), I18n::noop('Phishing, exposed RDP, unpatched vulnerability, provider account… Fix it before any return to service.'), true],
                    ['eradication', I18n::noop('Remove persistence'), I18n::noop('Scheduled tasks, services, Run keys, modified GPOs, accounts added by the attacker.'), true],
                    ['eradication', I18n::noop('Reset passwords'), I18n::noop('All privileged accounts, service accounts, and the krbtgt account twice if Active Directory is affected.'), true],
                    ['recovery', I18n::noop('Restore from a clean backup'), I18n::noop('Reinstall or restore the systems, check for the absence of indicators (incident IOCs) before reconnecting.'), true],
                    ['recovery', I18n::noop('Return to service under monitoring'), I18n::noop('Reconnect step by step, with reinforced EDR monitoring for at least 2 weeks.'), true],
                    ['post_incident', I18n::noop('Lessons learned'), I18n::noop('Root cause and corrective actions in the incident form, update this playbook if needed.'), true],
                ],
            ],
            [
                'name'        => I18n::noop('Phishing'),
                'category'    => 'phishing',
                'description' => I18n::noop('Fraudulent e-mail received, link clicked or credentials entered.'),
                'steps'       => [
                    ['containment', I18n::noop('Retrieve the original message'), I18n::noop('Obtain the full e-mail (.eml with headers) and attach it to the incident.'), true],
                    ['containment', I18n::noop('Block the sender, links and domains'), I18n::noop('Mail gateway, proxy / DNS filtering, firewall. Add the URLs and domains as IOCs.'), true],
                    ['containment', I18n::noop('Purge the message from other mailboxes'), I18n::noop('Find and delete the same message for all recipients.'), true],
                    ['analysis', I18n::noop('Identify the users who clicked or entered credentials'), I18n::noop('Proxy / mail logs, talks with the recipients. Link the users involved.'), true],
                    ['eradication', I18n::noop('Reset the exposed credentials'), I18n::noop('Change passwords, revoke sessions, check mailbox forwarding and access rules.'), true],
                    ['eradication', I18n::noop('Analyse the workstations involved'), I18n::noop('Full EDR scan if an attachment was opened.'), false],
                    ['notification', I18n::noop('Assess GDPR obligations'), I18n::noop('If personal data may have been exposed, fill in the GDPR / NIS2 tab.'), false],
                    ['post_incident', I18n::noop('Raise awareness'), I18n::noop('Feedback to the users involved, reminder of the signs of phishing.'), false],
                ],
            ],
            [
                'name'        => I18n::noop('Account compromise'),
                'category'    => 'account_compromise',
                'description' => I18n::noop('Illegitimate sign-in, credential theft, privilege escalation.'),
                'steps'       => [
                    ['containment', I18n::noop('Block the account and revoke sessions'), I18n::noop('Disable or reset the account, revoke tokens and active sessions (mail, VPN, cloud).'), true],
                    ['analysis', I18n::noop('Trace the account\'s activity'), I18n::noop('Sign-ins (dates, IP, country), actions performed, data viewed or exported. Attach the logs.'), true],
                    ['analysis', I18n::noop('Search for other affected accounts'), I18n::noop('Same source IP, same technique (LSASS dump, brute force…).'), true],
                    ['eradication', I18n::noop('Remove the access added by the attacker'), I18n::noop('Mailbox rules, authorized applications, API keys, added MFA methods, created accounts.'), true],
                    ['recovery', I18n::noop('Re-enable with MFA'), I18n::noop('New strong password, multi-factor authentication required.'), true],
                    ['notification', I18n::noop('Assess GDPR / NIS2 obligations'), I18n::noop('Depending on the data reachable from the account.'), false],
                    ['post_incident', I18n::noop('Lessons learned'), I18n::noop('Cause (password reuse, phishing, no MFA…) and corrective actions.'), true],
                ],
            ],
            [
                'name'        => I18n::noop('Malware'),
                'category'    => 'malware',
                'description' => I18n::noop('EDR / antivirus detection of a malicious file or behaviour.'),
                'steps'       => [
                    ['containment', I18n::noop('Isolate the workstation'), I18n::noop('Network containment through the EDR if execution is confirmed.'), true],
                    ['analysis', I18n::noop('Qualify the detection'), I18n::noop('True or false positive, file executed or only blocked, parent process, user.'), true],
                    ['analysis', I18n::noop('Search for the same indicator across the fleet'), I18n::noop('Hash, file name, command line: add as an IOC and search in the EDR console.'), true],
                    ['eradication', I18n::noop('Clean or reinstall'), I18n::noop('Removal by the EDR and persistence check, or reinstallation if in doubt.'), true],
                    ['recovery', I18n::noop('Lift the isolation'), I18n::noop('After verification, reconnect and monitor.'), true],
                    ['post_incident', I18n::noop('Identify the origin'), I18n::noop('Download, USB key, attachment… and preventive actions.'), false],
                ],
            ],
            [
                'name'        => I18n::noop('Data leak'),
                'category'    => 'data_leak',
                'description' => I18n::noop('Exfiltration, sent by mistake, public share, lost media.'),
                'steps'       => [
                    ['containment', I18n::noop('Stop the leak'), I18n::noop('Remove the public share, block the exfiltration channel, ask the unauthorized recipient to delete the data.'), true],
                    ['analysis', I18n::noop('Identify the data and the people affected'), I18n::noop('Type of data, volume, number of people: to be entered in the GDPR / NIS2 tab.'), true],
                    ['analysis', I18n::noop('Preserve the evidence'), I18n::noop('Access logs, copies of the exchanges, screenshots. Attach them to the incident.'), true],
                    ['notification', I18n::noop('CNIL notification within 72 h if there is a risk'), I18n::noop('Document the risk analysis in all cases (breach register).'), true],
                    ['notification', I18n::noop('Inform the people if the risk is high'), I18n::noop('Clear message: nature of the breach, consequences, measures taken, contact.'), false],
                    ['eradication', I18n::noop('Fix the cause'), I18n::noop('Access rights, configuration, media encryption, sending procedure.'), true],
                    ['post_incident', I18n::noop('Lessons learned'), I18n::noop('Update the procedures and raise awareness.'), true],
                ],
            ],
        ];
    }

    /**
     * Installe les procédures par défaut (sans audit individuel).
     */
    public static function installDefaults(): int
    {
        global $DB;

        $count = 0;
        $fk    = self::getForeignKeyField();
        foreach (self::getDefaultPlaybooks() as $playbook) {
            $DB->insert(self::getTable(), [
                'entities_id'   => 0,
                'is_recursive'  => 1,
                'name'          => I18n::instance($playbook['name']),
                'category'      => $playbook['category'],
                'description'   => I18n::instance($playbook['description']),
                'is_active'     => 1,
                'date_creation' => $_SESSION['glpi_currenttime'] ?? date('Y-m-d H:i:s'),
                'date_mod'      => $_SESSION['glpi_currenttime'] ?? date('Y-m-d H:i:s'),
            ]);
            $id = (int) $DB->insertId();
            foreach ($playbook['steps'] as $rank => [$phase, $name, $instructions, $mandatory]) {
                $DB->insert(PlaybookStep::getTable(), [
                    $fk            => $id,
                    'position'         => ($rank + 1) * 10,
                    'phase'        => $phase,
                    'name'         => I18n::instance($name),
                    'instructions' => I18n::instance($instructions),
                    'is_mandatory' => $mandatory ? 1 : 0,
                ]);
            }
            $count++;
        }
        return $count;
    }
}
