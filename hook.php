<?php

/**
 * -------------------------------------------------------------------------
 * SecIncident — Suivi des incidents de sécurité pour GLPI 11
 * -------------------------------------------------------------------------
 * @license   GPLv3 https://www.gnu.org/licenses/gpl-3.0.html
 * -------------------------------------------------------------------------
 */

use GlpiPlugin\Secincident\AccessGuard;
use GlpiPlugin\Secincident\AuditLog;
use GlpiPlugin\Secincident\I18n;
use GlpiPlugin\Secincident\Category;
use GlpiPlugin\Secincident\Evidence;
use GlpiPlugin\Secincident\Integrity;
use GlpiPlugin\Secincident\Incident;
use GlpiPlugin\Secincident\Incident_Item;
use GlpiPlugin\Secincident\Ioc;
use GlpiPlugin\Secincident\Playbook;
use GlpiPlugin\Secincident\PlaybookStep;
use GlpiPlugin\Secincident\RemediationTask;
use GlpiPlugin\Secincident\TeamMember;
use GlpiPlugin\Secincident\TimelineEvent;

/**
 * Installation / mise à jour du plugin.
 */
function plugin_secincident_install(): bool
{
    /** @var DBmysql $DB */
    global $DB;

    $migration = new Migration(PLUGIN_SECINCIDENT_VERSION);
    // Installation neuve : aucune attribution automatique de droits
    $fresh_install = !$DB->tableExists(Incident::getTable());

    $charset   = DBConnection::getDefaultCharset();
    $collation = DBConnection::getDefaultCollation();
    $sign      = DBConnection::getDefaultPrimaryKeySignOption();
    $options   = "ENGINE=InnoDB DEFAULT CHARSET={$charset} COLLATE={$collation} ROW_FORMAT=DYNAMIC";

    // ---------------------------------------------------------------------
    // Incidents
    // ---------------------------------------------------------------------
    $table = Incident::getTable();
    if (!$DB->tableExists($table)) {
        $migration->displayMessage(sprintf(__('Creating table %s', 'secincident'), $table));
        $DB->doQuery("CREATE TABLE `$table` (
            `id`                       int {$sign} NOT NULL AUTO_INCREMENT,
            `entities_id`              int {$sign} NOT NULL DEFAULT '0',
            `is_recursive`             tinyint NOT NULL DEFAULT '0',
            `name`                     varchar(255) DEFAULT NULL,
            `reference`                varchar(50) DEFAULT NULL,
            `content`                  longtext,
            `category`                 varchar(50) NOT NULL DEFAULT 'other',
            `severity`                 tinyint NOT NULL DEFAULT '3',
            `status`                   tinyint NOT NULL DEFAULT '1',
            `impact_confidentiality`   tinyint NOT NULL DEFAULT '0',
            `impact_integrity`         tinyint NOT NULL DEFAULT '0',
            `impact_availability`      tinyint NOT NULL DEFAULT '0',
            `source`                   varchar(50) NOT NULL DEFAULT 'manual',
            `external_id`              varchar(255) DEFAULT NULL,
            `mitre_tactic`             varchar(255) DEFAULT NULL,
            `mitre_technique`          varchar(255) DEFAULT NULL,
            `users_id_tech`            int {$sign} NOT NULL DEFAULT '0',
            `groups_id_tech`           int {$sign} NOT NULL DEFAULT '0',
            `users_id_recipient`       int {$sign} NOT NULL DEFAULT '0',
            `date_detection`           timestamp NULL DEFAULT NULL,
            `date_awareness`           timestamp NULL DEFAULT NULL,
            `date_containment`         timestamp NULL DEFAULT NULL,
            `date_eradication`         timestamp NULL DEFAULT NULL,
            `date_recovery`            timestamp NULL DEFAULT NULL,
            `date_closure`             timestamp NULL DEFAULT NULL,
            `root_cause`               text,
            `lessons_learned`          text,
            `is_personal_data`         tinyint NOT NULL DEFAULT '0',
            `personal_data_categories` text,
            `persons_affected`         int DEFAULT NULL,
            `gdpr_risk`                tinyint NOT NULL DEFAULT '0',
            `gdpr_justification`       text,
            `cnil_notified_date`       timestamp NULL DEFAULT NULL,
            `cnil_reference`           varchar(255) DEFAULT NULL,
            `persons_informed_date`    timestamp NULL DEFAULT NULL,
            `is_nis2`                  tinyint NOT NULL DEFAULT '0',
            `is_significant`           tinyint NOT NULL DEFAULT '0',
            `anssi_warning_date`       timestamp NULL DEFAULT NULL,
            `anssi_notification_date`  timestamp NULL DEFAULT NULL,
            `anssi_final_report_date`  timestamp NULL DEFAULT NULL,
            `anssi_reference`          varchar(255) DEFAULT NULL,
            `is_deleted`               tinyint NOT NULL DEFAULT '0',
            `date_mod`                 timestamp NULL DEFAULT NULL,
            `date_creation`            timestamp NULL DEFAULT NULL,
            PRIMARY KEY (`id`),
            KEY `entities_id` (`entities_id`),
            KEY `is_recursive` (`is_recursive`),
            KEY `name` (`name`),
            KEY `reference` (`reference`),
            KEY `category` (`category`),
            KEY `severity` (`severity`),
            KEY `status` (`status`),
            KEY `source` (`source`),
            KEY `external_id` (`external_id`),
            KEY `users_id_tech` (`users_id_tech`),
            KEY `groups_id_tech` (`groups_id_tech`),
            KEY `users_id_recipient` (`users_id_recipient`),
            KEY `date_detection` (`date_detection`),
            KEY `is_deleted` (`is_deleted`),
            KEY `date_mod` (`date_mod`),
            KEY `date_creation` (`date_creation`)
        ) {$options}");
    }

    // ---------------------------------------------------------------------
    // Chronologie
    // ---------------------------------------------------------------------
    $table = TimelineEvent::getTable();
    $fk    = Incident::getForeignKeyField();
    if (!$DB->tableExists($table)) {
        $migration->displayMessage(sprintf(__('Creating table %s', 'secincident'), $table));
        $DB->doQuery("CREATE TABLE `$table` (
            `id`            int {$sign} NOT NULL AUTO_INCREMENT,
            `$fk`           int {$sign} NOT NULL DEFAULT '0',
            `date`          timestamp NULL DEFAULT NULL,
            `event_type`    varchar(30) NOT NULL DEFAULT 'note',
            `name`          varchar(255) DEFAULT NULL,
            `content`       text,
            `hostname`      varchar(255) DEFAULT NULL,
            `username`      varchar(255) DEFAULT NULL,
            `source`        varchar(50) NOT NULL DEFAULT 'manual',
            `external_id`   varchar(255) DEFAULT NULL,
            `raw_data`      longtext,
            `users_id`      int {$sign} NOT NULL DEFAULT '0',
            `date_mod`      timestamp NULL DEFAULT NULL,
            `date_creation` timestamp NULL DEFAULT NULL,
            PRIMARY KEY (`id`),
            KEY `$fk` (`$fk`),
            KEY `date` (`date`),
            KEY `event_type` (`event_type`),
            KEY `external_id` (`external_id`),
            KEY `users_id` (`users_id`),
            KEY `date_mod` (`date_mod`),
            KEY `date_creation` (`date_creation`)
        ) {$options}");
    }

    // ---------------------------------------------------------------------
    // Indicateurs de compromission
    // ---------------------------------------------------------------------
    $table = Ioc::getTable();
    if (!$DB->tableExists($table)) {
        $migration->displayMessage(sprintf(__('Creating table %s', 'secincident'), $table));
        $DB->doQuery("CREATE TABLE `$table` (
            `id`              int {$sign} NOT NULL AUTO_INCREMENT,
            `$fk`             int {$sign} NOT NULL DEFAULT '0',
            `ioc_type`        varchar(30) NOT NULL DEFAULT 'other',
            `value`           text,
            `value_hash`      char(64) DEFAULT NULL,
            `verdict`         tinyint NOT NULL DEFAULT '0',
            `comment`         text,
            `source`          varchar(50) NOT NULL DEFAULT 'manual',
            `date_first_seen` timestamp NULL DEFAULT NULL,
            `date_last_seen`  timestamp NULL DEFAULT NULL,
            `date_mod`        timestamp NULL DEFAULT NULL,
            `date_creation`   timestamp NULL DEFAULT NULL,
            PRIMARY KEY (`id`),
            UNIQUE KEY `unicity` (`$fk`, `value_hash`),
            KEY `ioc_type` (`ioc_type`),
            KEY `value_hash` (`value_hash`),
            KEY `verdict` (`verdict`),
            KEY `date_mod` (`date_mod`),
            KEY `date_creation` (`date_creation`)
        ) {$options}");
    }

    // ---------------------------------------------------------------------
    // Éléments liés (tickets, matériels, utilisateurs…)
    // ---------------------------------------------------------------------
    $table = Incident_Item::getTable();
    if (!$DB->tableExists($table)) {
        $migration->displayMessage(sprintf(__('Creating table %s', 'secincident'), $table));
        $DB->doQuery("CREATE TABLE `$table` (
            `id`       int {$sign} NOT NULL AUTO_INCREMENT,
            `$fk`      int {$sign} NOT NULL DEFAULT '0',
            `itemtype` varchar(100) NOT NULL,
            `items_id` int {$sign} NOT NULL DEFAULT '0',
            PRIMARY KEY (`id`),
            UNIQUE KEY `unicity` (`$fk`, `itemtype`, `items_id`),
            KEY `item` (`itemtype`, `items_id`)
        ) {$options}");
    }

    // ---------------------------------------------------------------------
    // Catégories d'incident paramétrables (1.6.0)
    // ---------------------------------------------------------------------
    $categories_table = Category::getTable();
    $categories_new   = !$DB->tableExists($categories_table);
    if ($categories_new) {
        $migration->displayMessage(sprintf(__('Creating table %s', 'secincident'), $categories_table));
        $DB->doQuery("CREATE TABLE `$categories_table` (
            `id`            int {$sign} NOT NULL AUTO_INCREMENT,
            `name`          varchar(255) DEFAULT NULL,
            `code`          varchar(50) NOT NULL,
            `comment`       text,
            `date_mod`      timestamp NULL DEFAULT NULL,
            `date_creation` timestamp NULL DEFAULT NULL,
            PRIMARY KEY (`id`),
            UNIQUE KEY `code` (`code`),
            KEY `name` (`name`),
            KEY `date_mod` (`date_mod`),
            KEY `date_creation` (`date_creation`)
        ) {$options}");
    }

    // ---------------------------------------------------------------------
    // Procédures de remédiation (bibliothèque) et plans par incident
    // ---------------------------------------------------------------------
    $pb_fk           = Playbook::getForeignKeyField();
    $playbooks_table = Playbook::getTable();
    $playbooks_new   = !$DB->tableExists($playbooks_table);
    if ($playbooks_new) {
        $migration->displayMessage(sprintf(__('Creating table %s', 'secincident'), $playbooks_table));
        $DB->doQuery("CREATE TABLE `$playbooks_table` (
            `id`            int {$sign} NOT NULL AUTO_INCREMENT,
            `entities_id`   int {$sign} NOT NULL DEFAULT '0',
            `is_recursive`  tinyint NOT NULL DEFAULT '1',
            `name`          varchar(255) DEFAULT NULL,
            `category`      varchar(50) NOT NULL DEFAULT '',
            `description`   text,
            `is_active`     tinyint NOT NULL DEFAULT '1',
            `is_deleted`    tinyint NOT NULL DEFAULT '0',
            `date_mod`      timestamp NULL DEFAULT NULL,
            `date_creation` timestamp NULL DEFAULT NULL,
            PRIMARY KEY (`id`),
            KEY `entities_id` (`entities_id`),
            KEY `is_recursive` (`is_recursive`),
            KEY `name` (`name`),
            KEY `category` (`category`),
            KEY `is_active` (`is_active`),
            KEY `is_deleted` (`is_deleted`),
            KEY `date_mod` (`date_mod`),
            KEY `date_creation` (`date_creation`)
        ) {$options}");
    }
    $table = PlaybookStep::getTable();
    if (!$DB->tableExists($table)) {
        $migration->displayMessage(sprintf(__('Creating table %s', 'secincident'), $table));
        $DB->doQuery("CREATE TABLE `$table` (
            `id`            int {$sign} NOT NULL AUTO_INCREMENT,
            `$pb_fk`        int {$sign} NOT NULL DEFAULT '0',
            `position`          int NOT NULL DEFAULT '0',
            `phase`         varchar(30) NOT NULL DEFAULT 'containment',
            `name`          varchar(255) DEFAULT NULL,
            `instructions`  text,
            `is_mandatory`  tinyint NOT NULL DEFAULT '0',
            `date_mod`      timestamp NULL DEFAULT NULL,
            `date_creation` timestamp NULL DEFAULT NULL,
            PRIMARY KEY (`id`),
            KEY `$pb_fk` (`$pb_fk`),
            KEY `position` (`position`),
            KEY `date_mod` (`date_mod`),
            KEY `date_creation` (`date_creation`)
        ) {$options}");
    }
    $table = RemediationTask::getTable();
    if (!$DB->tableExists($table)) {
        $migration->displayMessage(sprintf(__('Creating table %s', 'secincident'), $table));
        $DB->doQuery("CREATE TABLE `$table` (
            `id`              int {$sign} NOT NULL AUTO_INCREMENT,
            `$fk`             int {$sign} NOT NULL DEFAULT '0',
            `$pb_fk`          int {$sign} NOT NULL DEFAULT '0',
            `position`            int NOT NULL DEFAULT '0',
            `phase`           varchar(30) NOT NULL DEFAULT 'containment',
            `name`            varchar(255) DEFAULT NULL,
            `instructions`    text,
            `is_mandatory`    tinyint NOT NULL DEFAULT '0',
            `status`          varchar(20) NOT NULL DEFAULT 'todo',
            `users_id_assign` int {$sign} NOT NULL DEFAULT '0',
            `users_id_done`   int {$sign} NOT NULL DEFAULT '0',
            `date_done`       timestamp NULL DEFAULT NULL,
            `comment`         text,
            `date_mod`        timestamp NULL DEFAULT NULL,
            `date_creation`   timestamp NULL DEFAULT NULL,
            PRIMARY KEY (`id`),
            KEY `$fk` (`$fk`),
            KEY `$pb_fk` (`$pb_fk`),
            KEY `status` (`status`),
            KEY `users_id_assign` (`users_id_assign`),
            KEY `position` (`position`),
            KEY `date_mod` (`date_mod`),
            KEY `date_creation` (`date_creation`)
        ) {$options}");
    }

    // ---------------------------------------------------------------------
    // 1.5.0 : actions d'investigation structurées dans la chronologie.
    // Si les données sont déjà scellées, on vérifie tout avec l'ancien format
    // d'empreinte AVANT de toucher au schéma, puis on rescelle (tracé).
    // ---------------------------------------------------------------------
    $events_table = TimelineEvent::getTable();
    $needs_format_migration = $DB->tableExists($events_table)
        && $DB->fieldExists($events_table, 'integrity_hash')
        && !$DB->fieldExists($events_table, 'tool')
        && $DB->tableExists(AuditLog::getTable());
    if ($DB->tableExists($events_table) && !$DB->fieldExists($events_table, 'tool')) {
        $pre_verified = false;
        if ($needs_format_migration) {
            $migration->displayMessage(__('Integrity check before migration', 'secincident'));
            // Vérification au format historique (valeurs NULL incluses) avant ALTER
            $ids = [];
            foreach ($DB->request(['SELECT' => ['id'], 'FROM' => Incident::getTable()]) as $row) {
                $ids[] = (int) $row['id'];
            }
            $anomalies = [];
            foreach ($ids as $incidents_id) {
                $r = Integrity::verifyIncident($incidents_id, false, true);
                if (!$r['ok']) {
                    $anomalies[$incidents_id] = $r['summary'];
                }
            }
            AuditLog::record('verify_integrity', null, [
                'portee'                => I18n::instance('global, before schema migration (1.5.0)'),
                'incidents_verifies'    => count($ids),
                'incidents_en_anomalie' => $anomalies,
            ], $anomalies === [] ? AuditLog::RESULT_OK : AuditLog::RESULT_ERROR);
            $pre_verified = true;
        }
        $rt_fk = RemediationTask::getForeignKeyField();
        $migration->addField($events_table, 'target', 'varchar(255) DEFAULT NULL', ['nodefault' => true]);
        $migration->addField($events_table, 'tool', 'varchar(30) DEFAULT NULL', ['nodefault' => true]);
        $migration->addField($events_table, 'command', 'text', ['nodefault' => true]);
        $migration->addField($events_table, 'result', 'varchar(20) DEFAULT NULL', ['nodefault' => true]);
        $migration->addField($events_table, 'detection_ref', 'varchar(255) DEFAULT NULL', ['nodefault' => true]);
        $migration->addField($events_table, $rt_fk, "int {$sign} NOT NULL DEFAULT '0'");
        $migration->addKey($events_table, $rt_fk);
        $migration->addKey($events_table, 'result');
        $migration->migrationOneTable($events_table);
        if ($pre_verified) {
            $reseal_after_migration = true;
        }
    }

    // ---------------------------------------------------------------------
    // Équipe d'intervention
    // ---------------------------------------------------------------------
    $table = TeamMember::getTable();
    if (!$DB->tableExists($table)) {
        $migration->displayMessage(sprintf(__('Creating table %s', 'secincident'), $table));
        $DB->doQuery("CREATE TABLE `$table` (
            `id`             int {$sign} NOT NULL AUTO_INCREMENT,
            `$fk`            int {$sign} NOT NULL DEFAULT '0',
            `users_id`       int {$sign} NOT NULL DEFAULT '0',
            `role`           varchar(20) NOT NULL DEFAULT 'contributor',
            `users_id_added` int {$sign} NOT NULL DEFAULT '0',
            `date_added`     timestamp NULL DEFAULT NULL,
            `date_mod`       timestamp NULL DEFAULT NULL,
            `date_creation`  timestamp NULL DEFAULT NULL,
            PRIMARY KEY (`id`),
            UNIQUE KEY `unicity` (`$fk`, `users_id`),
            KEY `users_id` (`users_id`),
            KEY `role` (`role`)
        ) {$options}");
    }

    // ---------------------------------------------------------------------
    // Empreintes d'intégrité sur toutes les tables de données
    // ---------------------------------------------------------------------
    foreach ([Incident::getTable(), TimelineEvent::getTable(), Ioc::getTable(), Incident_Item::getTable(), RemediationTask::getTable(), TeamMember::getTable()] as $table) {
        if (!$DB->fieldExists($table, 'integrity_hash')) {
            $migration->addField($table, 'integrity_hash', 'char(64) DEFAULT NULL', ['nodefault' => true]);
            $migration->migrationOneTable($table);
        }
    }

    // ---------------------------------------------------------------------
    // Registre des preuves (conservé même après désinstallation)
    // ---------------------------------------------------------------------
    $table = Evidence::getTable();
    if (!$DB->tableExists($table)) {
        $migration->displayMessage(sprintf(__('Creating table %s', 'secincident'), $table));
        $DB->doQuery("CREATE TABLE `$table` (
            `id`                 int {$sign} NOT NULL AUTO_INCREMENT,
            `$fk`                int {$sign} NOT NULL DEFAULT '0',
            `documents_id`       int {$sign} NOT NULL DEFAULT '0',
            `documents_items_id` int {$sign} NOT NULL DEFAULT '0',
            `filename`           varchar(255) NOT NULL DEFAULT '',
            `filepath`           varchar(255) NOT NULL DEFAULT '',
            `mime`               varchar(255) NOT NULL DEFAULT '',
            `filesize`           bigint NOT NULL DEFAULT '0',
            `sha256`             char(64) NOT NULL DEFAULT '',
            `sha1_glpi`          char(40) NOT NULL DEFAULT '',
            `users_id`           int {$sign} NOT NULL DEFAULT '0',
            `date_added`         timestamp NULL DEFAULT NULL,
            `status`             varchar(20) NOT NULL DEFAULT 'active',
            `date_detached`      timestamp NULL DEFAULT NULL,
            `check_status`       varchar(20) NOT NULL DEFAULT 'unchecked',
            `date_last_check`    timestamp NULL DEFAULT NULL,
            `last_sha256`        char(64) NOT NULL DEFAULT '',
            PRIMARY KEY (`id`),
            KEY `$fk` (`$fk`),
            KEY `documents_id` (`documents_id`),
            KEY `documents_items_id` (`documents_items_id`),
            KEY `sha256` (`sha256`),
            KEY `status` (`status`)
        ) {$options}");
    }

    // ---------------------------------------------------------------------
    // Journal d'audit (chaîné, conservé même après désinstallation)
    // ---------------------------------------------------------------------
    $audit_table   = AuditLog::getTable();
    $audit_existed = $DB->tableExists($audit_table);
    if (!$audit_existed) {
        $migration->displayMessage(sprintf(__('Creating table %s', 'secincident'), $audit_table));
        $DB->doQuery("CREATE TABLE `$audit_table` (
            `id`                    int {$sign} NOT NULL AUTO_INCREMENT,
            `date`                  timestamp NULL DEFAULT NULL,
            `date_utc`              varchar(19) NOT NULL,
            `users_id`              int {$sign} NOT NULL DEFAULT '0',
            `user_name`             varchar(255) NOT NULL DEFAULT '',
            `users_id_impersonator` int {$sign} NOT NULL DEFAULT '0',
            `profiles_id`           int {$sign} NOT NULL DEFAULT '0',
            `profile_name`          varchar(255) NOT NULL DEFAULT '',
            `rights`                int NOT NULL DEFAULT '0',
            `privilege`             varchar(500) NOT NULL DEFAULT '',
            `ip`                    varchar(64) NOT NULL DEFAULT '',
            `action`                varchar(40) NOT NULL,
            `result`                varchar(10) NOT NULL DEFAULT 'ok',
            `itemtype`              varchar(100) NOT NULL DEFAULT '',
            `items_id`              int {$sign} NOT NULL DEFAULT '0',
            `incidents_id`          int {$sign} NOT NULL DEFAULT '0',
            `details`               mediumtext,
            `prev_hash`             char(64) NOT NULL,
            `hash`                  char(64) NOT NULL,
            PRIMARY KEY (`id`),
            KEY `date` (`date`),
            KEY `users_id` (`users_id`),
            KEY `action` (`action`),
            KEY `result` (`result`),
            KEY `item` (`itemtype`, `items_id`),
            KEY `incidents_id` (`incidents_id`),
            KEY `ip` (`ip`)
        ) {$options}");
    }

    // ---------------------------------------------------------------------
    // Droits : AUCUN profil n'a accès par défaut, pas même Super-Admin.
    // L'accès s'attribue volontairement (Administration > Profils > onglet
    // « Security incidents »), et chaque attribution est tracée et alertée.
    // Les profils créés après l'installation reçoivent eux aussi « aucun droit ».
    // ---------------------------------------------------------------------
    $fresh_rights = countElementsInTable('glpi_profilerights', ['name' => Incident::$rightname]) === 0;
    foreach (
        $DB->request([
            'SELECT'    => ['glpi_profiles.id'],
            'FROM'      => 'glpi_profiles',
            'LEFT JOIN' => [
                'glpi_profilerights' => [
                    'ON' => [
                        'glpi_profilerights' => 'profiles_id',
                        'glpi_profiles'      => 'id',
                        ['AND' => ['glpi_profilerights.name' => Incident::$rightname]],
                    ],
                ],
            ],
            'WHERE'     => ['glpi_profilerights.id' => null],
        ]) as $row
    ) {
        $DB->insert('glpi_profilerights', ['profiles_id' => (int) $row['id'], 'name' => Incident::$rightname, 'rights' => 0]);
    }
    if ($fresh_rights) {
        $migration->displayMessage(__('No profile has access to the plugin yet: grant it in Administration > Profiles > "Security incidents" tab.', 'secincident'));
    }

    if (!$audit_existed && !$fresh_install) {
        // Mise à jour depuis 1.0.0 : ajoute les nouveaux droits aux profils administrateurs
        foreach (
            $DB->request([
                'SELECT' => ['profiles_id'],
                'FROM'   => 'glpi_profilerights',
                'WHERE'  => [
                    'name' => 'config',
                    new \Glpi\DBAL\QueryExpression('(' . $DB::quoteName('rights') . ' & ' . (READ | UPDATE) . ') = ' . (READ | UPDATE)),
                ],
            ]) as $row
        ) {
            $DB->update(
                'glpi_profilerights',
                ['rights' => new \Glpi\DBAL\QueryExpression($DB::quoteName('rights') . ' | ' . (Incident::READALL | Incident::AUDIT))],
                ['name' => Incident::$rightname, 'profiles_id' => $row['profiles_id']]
            );
        }
    }

    // Préférences d'affichage par défaut de la liste
    $migration->updateDisplayPrefs([
        Incident::class => [2, 3, 4, 5, 6, 7, 8],
        Playbook::class => [2, 3, 19],
    ]);

    // Configuration (mapping d'import mémorisé)
    $config = Config::getConfigurationValues('plugin:secincident');
    if (!array_key_exists('csv_mapping', $config)) {
        Config::setConfigurationValues('plugin:secincident', ['csv_mapping' => '']);
    }

    $migration->executeMigration();

    if ($playbooks_new) {
        if (!$fresh_install) {
            // Nouveauté 1.3.0 : droit de gestion des procédures pour les profils administrateurs
            foreach (
                $DB->request([
                    'SELECT' => ['profiles_id'],
                    'FROM'   => 'glpi_profilerights',
                    'WHERE'  => [
                        'name' => 'config',
                        new \Glpi\DBAL\QueryExpression('(' . $DB::quoteName('rights') . ' & ' . (READ | UPDATE) . ') = ' . (READ | UPDATE)),
                    ],
                ]) as $row
            ) {
                $DB->update(
                    'glpi_profilerights',
                    ['rights' => new \Glpi\DBAL\QueryExpression($DB::quoteName('rights') . ' | ' . Incident::PLAYBOOK)],
                    ['name' => Incident::$rightname, 'profiles_id' => $row['profiles_id']]
                );
            }
        }
        $installed_playbooks = Playbook::installDefaults();
        $migration->displayMessage(sprintf(__('%d remediation playbooks installed', 'secincident'), $installed_playbooks));
    }

    if ($categories_new) {
        $installed_categories = Category::installDefaults();
        $migration->displayMessage(sprintf(__('%d incident categories installed', 'secincident'), $installed_categories));
        // Nouveauté 1.6.0 : la gestion des catégories est donnée aux profils
        // qui gèrent déjà les procédures (Super-Admin, RSSI…)
        $DB->update(
            'glpi_profilerights',
            ['rights' => new \Glpi\DBAL\QueryExpression($DB::quoteName('rights') . ' | ' . Incident::CATEGORY)],
            [
                'name' => Incident::$rightname,
                new \Glpi\DBAL\QueryExpression('(' . $DB::quoteName('rights') . ' & ' . Incident::PLAYBOOK . ') = ' . Incident::PLAYBOOK),
            ]
        );
    }

    // Rescellement au nouveau format après migration (vérification faite avant)
    if (!empty($reseal_after_migration)) {
        Integrity::resealAll(I18n::instance('migration 1.5.0: new fingerprint format, prior check logged'));
    }

    // ---------------------------------------------------------------------
    // 1.8.0 : plugin neutre vis-à-vis de l'éditeur d'EDR.
    // Clés « crowdstrike » / « falcon_rtr » renommées en « edr » / « edr_console ».
    // Vérification d'intégrité des incidents concernés AVANT, puis rescellement
    // des seules lignes modifiées, le tout tracé dans le journal d'audit.
    // ---------------------------------------------------------------------
    $legacy_keys = [
        [Incident::getTable(), 'source', 'crowdstrike', 'edr', Incident::class],
        [TimelineEvent::getTable(), 'source', 'crowdstrike', 'edr', TimelineEvent::class],
        [TimelineEvent::getTable(), 'tool', 'falcon_rtr', 'edr_console', TimelineEvent::class],
    ];
    $legacy_rows = [];
    foreach ($legacy_keys as [$ltable, $lfield, $old, $new, $lclass]) {
        if ($DB->tableExists($ltable) && $DB->fieldExists($ltable, $lfield)) {
            foreach ($DB->request(['FROM' => $ltable, 'WHERE' => [$lfield => $old]]) as $row) {
                $legacy_rows[] = [$ltable, $lfield, $new, $lclass, $row];
            }
        }
    }
    if ($legacy_rows !== []) {
        $migration->displayMessage(__('Renaming former vendor keys to generic EDR', 'secincident'));
        $fk_inc   = Incident::getForeignKeyField();
        $affected = [];
        foreach ($legacy_rows as [, , , $lclass, $row]) {
            $affected[$lclass === Incident::class ? (int) $row['id'] : (int) $row[$fk_inc]] = true;
        }
        $anomalies = [];
        $intact    = [];
        foreach (array_keys($affected) as $incidents_id) {
            $r = Integrity::verifyIncident($incidents_id, false);
            if (!$r['ok']) {
                $anomalies[$incidents_id] = $r['summary'];
            }
            foreach ($r['items'] as $checked) {
                if ($checked['status'] === Integrity::STATUS_OK) {
                    $intact[$checked['itemtype'] . '#' . $checked['id']] = true;
                }
            }
        }
        AuditLog::record('verify_integrity', null, [
            'portee'                => I18n::instance('affected incidents, before renaming EDR keys (1.8.0)'),
            'incidents_verifies'    => count($affected),
            'incidents_en_anomalie' => $anomalies,
        ], $anomalies === [] ? AuditLog::RESULT_OK : AuditLog::RESULT_ERROR);

        foreach ($legacy_rows as [$ltable, $lfield, $new, $lclass, $row]) {
            $DB->update($ltable, [$lfield => $new], ['id' => (int) $row['id']]);
            // Une ligne déjà altérée n'est PAS rescellée : l'anomalie reste visible
            if (!isset($intact[$lclass . '#' . $row['id']])) {
                continue;
            }
            $item = new $lclass();
            $item->fields = $row;
            $hash = Integrity::seal($item);
            if ($hash !== null) {
                AuditLog::anchor($lclass, (int) $row['id'], $lclass === Incident::class ? (int) $row['id'] : (int) $row[$fk_inc], $hash);
            }
        }
        AuditLog::flushAnchors(I18n::instance('migration 1.8.0: keys “crowdstrike” / “falcon_rtr” renamed to “edr” / “edr_console”'));
    }
    // Textes des procédures par défaut (bibliothèque, non scellée)
    if ($DB->tableExists(PlaybookStep::getTable())) {
        foreach (
            [
                '(confinement réseau Falcon ou câble/Wi-Fi coupé)' => '(confinement réseau depuis la console EDR, ou câble/Wi-Fi coupé)',
                'sur tout le parc (CrowdStrike)'                   => 'sur tout le parc (console EDR)',
                'ajouter en IOC et chercher dans CrowdStrike.'     => 'ajouter en IOC et chercher dans la console EDR.',
            ] as $old_text => $new_text
        ) {
            $DB->update(
                PlaybookStep::getTable(),
                ['instructions' => new \Glpi\DBAL\QueryExpression('REPLACE(' . $DB::quoteName('instructions') . ', ' . $DB->quoteValue($old_text) . ', ' . $DB->quoteValue($new_text) . ')')],
                ['instructions' => ['LIKE', '%' . $old_text . '%']]
            );
        }
    }

    // Scelle les données existantes et inscrit les documents déjà joints
    $sealed    = Integrity::sealAll();
    $evidences = Evidence::registerExisting();

    AuditLog::record('update', null, [
        'enregistrements_scelles' => $sealed,
        'preuves_inscrites'       => $evidences,
        'evenement' => $audit_existed ? I18n::instance('plugin update') : I18n::instance('plugin installation / audit activation'),
        'version'   => PLUGIN_SECINCIDENT_VERSION,
    ]);

    return true;
}

/**
 * Désinstallation : supprime tables, droits, préférences et configuration.
 */
/**
 * Désactivation : tracée et alertée (le journal reste en base).
 */
function plugin_secincident_deactivate(): bool
{
    AccessGuard::alert('plugin_disable', I18n::instance('SecIncident plugin deactivated'), [
        'evenement' => I18n::instance('plugin deactivated: security incidents are no longer accessible or logged'),
    ]);
    return true;
}

function plugin_secincident_uninstall(): bool
{
    /** @var DBmysql $DB */
    global $DB;

    $tables = [
        Incident::getTable(),
        TimelineEvent::getTable(),
        Ioc::getTable(),
        Incident_Item::getTable(),
        RemediationTask::getTable(),
        TeamMember::getTable(),
        Playbook::getTable(),
        PlaybookStep::getTable(),
        Category::getTable(),
    ];
    foreach ($tables as $table) {
        $DB->dropTable($table, true);
    }
    // Le journal d'audit et le registre des preuves sont volontairement CONSERVÉS
    // (valeur probante). Pour les supprimer :
    // DROP TABLE glpi_plugin_secincident_auditlogs, glpi_plugin_secincident_evidences;
    AccessGuard::alert('plugin_disable', I18n::instance('SecIncident plugin uninstalled'), ['evenement' => I18n::instance('plugin uninstallation (data deleted, log kept)')]);

    $itemtypes = [Incident::class, TimelineEvent::class, Ioc::class, Incident_Item::class, RemediationTask::class, TeamMember::class, Playbook::class, PlaybookStep::class, Category::class];
    foreach (['glpi_displaypreferences', 'glpi_documents_items', 'glpi_logs', 'glpi_savedsearches'] as $table) {
        $DB->delete($table, ['itemtype' => $itemtypes]);
    }

    ProfileRight::deleteProfileRights([Incident::$rightname]);
    Config::deleteConfigurationValues('plugin:secincident', ['csv_mapping']);

    return true;
}

/**
 * Supprime les liens quand un ticket / matériel / utilisateur lié est purgé.
 */
function plugin_secincident_item_purge(CommonDBTM $item): void
{
    $link = new Incident_Item();
    $link->deleteByCriteria([
        'itemtype' => $item::class,
        'items_id' => $item->getID(),
    ]);
}

/**
 * Trace toute modification des droits du plugin sur un profil.
 * Appelé avant l'enregistrement : on compare la valeur actuelle à la valeur demandée.
 */
function plugin_secincident_profile_pre_update(Profile $profile): void
{
    /** @var DBmysql $DB */
    global $DB;

    $key = '_' . Incident::$rightname;
    if (!isset($profile->input[$key])) {
        return;
    }

    $requested = $profile->input[$key];
    if (!is_array($requested)) {
        $requested = ['1' => $requested];
    }
    $new = 0;
    foreach ($requested as $value => $valid) {
        if ($valid) {
            $value = (string) $value;
            if (($pos = strpos($value, '_')) !== false) {
                $value = substr($value, 0, $pos);
            }
            $new += (int) $value;
        }
    }

    $old = (int) ($DB->request([
        'SELECT' => ['rights'],
        'FROM'   => 'glpi_profilerights',
        'WHERE'  => ['profiles_id' => $profile->getID(), 'name' => Incident::$rightname],
    ])->current()['rights'] ?? 0);

    if ($old === $new) {
        return;
    }

    $labels = static function (int $value): array {
        $out = [];
        foreach (AuditLog::getRightLabels() as $bit => $label) {
            if (($value & $bit) === $bit) {
                $out[] = $label;
            }
        }
        return $out;
    };

    $target = new Profile();
    $target->getFromDB($profile->getID());
    AuditLog::record('rights_change', $target, [
        'profil' => $target->fields['name'] ?? $profile->getID(),
        'avant'  => ['valeur' => $old, 'droits' => $labels($old)],
        'apres'  => ['valeur' => $new, 'droits' => $labels($new)],
    ]);
    AccessGuard::onProfileRightsChange((string) ($target->fields['name'] ?? $profile->getID()), $old, $new);
}

/**
 * Trace la consultation des onglets standards (historique, documents) d'un incident.
 *
 * @param array{item: CommonGLPI, options: array<string, mixed>} $params
 */
function plugin_secincident_pre_show_tab(array $params): void
{
    $item    = $params['item'] ?? null;
    $tabtype = $params['options']['itemtype'] ?? '';
    if (!$item instanceof Incident) {
        return;
    }
    $labels = [
        'Log'           => 'historique',
        'Document_Item' => 'documents',
    ];
    if (isset($labels[$tabtype])) {
        AuditLog::recordView($item, $labels[$tabtype]);
    }
}
