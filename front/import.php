<?php

/**
 * SecIncident — import d'un export CSV d'EDR / XDR.
 *
 * Étape 1 : dépôt du fichier.
 * Étape 2 : vérification du mapping des colonnes + options.
 * Étape 3 : import et compte rendu.
 */

use Glpi\Application\View\TemplateRenderer;
use GlpiPlugin\Secincident\AuditLog;
use GlpiPlugin\Secincident\I18n;
use GlpiPlugin\Secincident\CsvImporter;
use GlpiPlugin\Secincident\Incident;

global $CFG_GLPI;

AuditLog::checkPageAccess([CREATE], I18n::instance('import of a CSV file'));

$session_key = 'plugin_secincident_import';

/**
 * Supprime les fichiers temporaires de plus d'une heure.
 */
$cleanup = static function () use ($session_key): void {
    foreach ($_SESSION[$session_key] ?? [] as $token => $info) {
        if (($info['time'] ?? 0) < time() - 3600) {
            if (is_file($info['path'])) {
                @unlink($info['path']);
            }
            unset($_SESSION[$session_key][$token]);
        }
    }
};
$cleanup();

$renderer = TemplateRenderer::getInstance();
$saved    = json_decode((string) (Config::getConfigurationValues('plugin:secincident', ['csv_mapping'])['csv_mapping'] ?? ''), true);
$saved    = is_array($saved) ? $saved : [];

Html::header(__('EDR CSV import', 'secincident'), '', 'helpdesk', Incident::class, 'import');

$step   = 'upload';
$params = [
    'form_url' => $CFG_GLPI['root_doc'] . '/plugins/secincident/front/import.php',
    'targets'  => CsvImporter::getTargets(),
];

try {
    if (isset($_POST['upload'])) {
        $file = $_FILES['csvfile'] ?? null;
        if (!is_array($file) || ($file['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
            throw new RuntimeException(__('No file received (check the maximum size allowed by PHP).', 'secincident'));
        }
        $ext = strtolower(pathinfo((string) $file['name'], PATHINFO_EXTENSION));
        if (!in_array($ext, ['csv', 'txt', 'tsv'], true)) {
            throw new RuntimeException(__('The file must be in CSV format.', 'secincident'));
        }
        if ((int) $file['size'] > CsvImporter::MAX_BYTES) {
            throw new RuntimeException(__('File too large.', 'secincident'));
        }

        $token = bin2hex(random_bytes(16));
        $path  = GLPI_TMP_DIR . '/secincident_' . $token . '.csv';
        if (!move_uploaded_file($file['tmp_name'], $path)) {
            throw new RuntimeException(__('Unable to save the temporary file.', 'secincident'));
        }
        $_SESSION[$session_key][$token] = [
            'path' => $path,
            'name' => (string) $file['name'],
            'time' => time(),
        ];

        $parsed  = CsvImporter::parse($path);
        $mapping = CsvImporter::autoMap($parsed['headers'], $saved['mapping'] ?? []);
        $_SESSION[$session_key][$token]['sha256'] = hash_file('sha256', $path);

        AuditLog::record('import_upload', null, [
            'fichier' => (string) $file['name'],
            'taille'  => (int) $file['size'],
            'sha256'  => $_SESSION[$session_key][$token]['sha256'],
            'lignes'  => count($parsed['rows']),
        ]);

        $step   = 'mapping';
        $params += [
            'token'       => $token,
            'filename'    => (string) $file['name'],
            'headers'     => $parsed['headers'],
            'mapping'     => $mapping,
            'preview'     => array_slice($parsed['rows'], 0, 5),
            'total_rows'  => count($parsed['rows']),
            'truncated'   => $parsed['truncated'],
            'max_rows'    => CsvImporter::MAX_ROWS,
            'groups'      => [
                CsvImporter::GROUP_BY_DETECTION => count(CsvImporter::group($parsed['rows'], $mapping, CsvImporter::GROUP_BY_DETECTION)),
                CsvImporter::GROUP_BY_HOST      => count(CsvImporter::group($parsed['rows'], $mapping, CsvImporter::GROUP_BY_HOST)),
                CsvImporter::GROUP_SINGLE       => 1,
                CsvImporter::GROUP_PER_ROW      => count($parsed['rows']),
            ],
            'group_by'    => $saved['group_by'] ?? (isset($mapping['external_id']) ? CsvImporter::GROUP_BY_DETECTION : CsvImporter::GROUP_SINGLE),
            'timezone'    => $saved['timezone'] ?? 'UTC',
            'local_tz'    => date_default_timezone_get(),
            'link_assets' => $saved['link_assets'] ?? true,
            'create_iocs' => $saved['create_iocs'] ?? true,
            'multi_entity' => Session::isMultiEntitiesMode(),
            'active_entity' => Session::getActiveEntity(),
        ];
    } elseif (isset($_POST['import'])) {
        $token = (string) ($_POST['token'] ?? '');
        $info  = $_SESSION[$session_key][$token] ?? null;
        if ($info === null || !is_file($info['path'])) {
            throw new RuntimeException(__('File expired: please upload it again.', 'secincident'));
        }

        $parsed  = CsvImporter::parse($info['path']);
        $mapping = [];
        foreach (array_keys(CsvImporter::getTargets()) as $target) {
            $column = (string) ($_POST['mapping'][$target] ?? '');
            if ($column !== '' && in_array($column, $parsed['headers'], true)) {
                $mapping[$target] = $column;
            }
        }
        if ($mapping === []) {
            throw new RuntimeException(__('No column has been mapped.', 'secincident'));
        }

        $entities_id = (int) ($_POST['entities_id'] ?? Session::getActiveEntity());
        if (!Session::haveAccessToEntity($entities_id)) {
            $entities_id = Session::getActiveEntity();
        }

        $group_by = (string) ($_POST['group_by'] ?? CsvImporter::GROUP_BY_DETECTION);
        if (!in_array($group_by, [CsvImporter::GROUP_BY_DETECTION, CsvImporter::GROUP_BY_HOST, CsvImporter::GROUP_SINGLE, CsvImporter::GROUP_PER_ROW], true)) {
            $group_by = CsvImporter::GROUP_BY_DETECTION;
        }
        $timezone = (string) ($_POST['timezone'] ?? 'UTC');
        if (!in_array($timezone, ['UTC', date_default_timezone_get()], true)) {
            $timezone = 'UTC';
        }

        $options = [
            'entities_id'     => $entities_id,
            'group_by'        => $group_by,
            'target_incident' => (int) ($_POST['target_incident'] ?? 0),
            'timezone'        => $timezone,
            'link_assets'     => !empty($_POST['link_assets']),
            'create_iocs'     => !empty($_POST['create_iocs']),
        ];

        $importer = new CsvImporter();
        $stats    = $importer->import($parsed['rows'], $mapping, $options);

        // Le fichier d'origine est conservé comme preuve sur chaque incident concerné
        // (document GLPI → inscrit au registre des preuves avec son SHA-256)
        $documents_id = 0;
        $targets      = array_values(array_unique(array_merge($stats['created'], $stats['updated'])));
        if ($targets !== []) {
            $safe_name = preg_replace('/[^A-Za-z0-9._-]+/', '_', basename((string) $info['name'])) ?: 'import.csv';
            if (!preg_match('/\.(csv|txt)$/i', $safe_name)) {
                $safe_name .= '.csv';
            }
            $prefix   = 'secincident' . bin2hex(random_bytes(6)) . '_';
            $tmp_name = $prefix . $safe_name;
            if (@copy($info['path'], GLPI_TMP_DIR . '/' . $tmp_name)) {
                $document     = new Document();
                $documents_id = (int) $document->add([
                    'name'              => sprintf(I18n::instance('Imported EDR export — %s'), $safe_name),
                    'entities_id'       => $entities_id,
                    'is_recursive'      => 1,
                    '_filename'         => [$tmp_name],
                    '_prefix_filename'  => [$prefix],
                    'itemtype'          => Incident::class,
                    'items_id'          => $targets[0],
                    'comment'           => 'SHA-256 : ' . ($info['sha256'] ?? ''),
                ]);
                @unlink(GLPI_TMP_DIR . '/' . $tmp_name);
                foreach (array_slice($targets, 1) as $incidents_id) {
                    (new Document_Item())->add([
                        'documents_id' => $documents_id,
                        'itemtype'     => Incident::class,
                        'items_id'     => $incidents_id,
                    ]);
                }
            }
        }

        // Une entrée récapitulative : les lignes importées ne sont pas tracées une à une
        AuditLog::record('import', null, [
            'fichier'            => $info['name'],
            'sha256'             => $info['sha256'] ?? hash_file('sha256', $info['path']),
            'lignes'             => count($parsed['rows']),
            'options'            => $options,
            'mapping'            => $mapping,
            'incidents_crees'    => $stats['created'],
            'incidents_completes' => $stats['updated'],
            'evenements'         => $stats['events_added'],
            'doublons'           => $stats['events_skipped'],
            'ioc'                => $stats['iocs_added'],
            'liens'              => $stats['links_added'],
            'erreurs'            => $stats['errors'],
            'document_preuve'    => $documents_id,
        ], $stats['errors'] === [] ? AuditLog::RESULT_OK : AuditLog::RESULT_ERROR);

        if (!empty($_POST['remember'])) {
            Config::setConfigurationValues('plugin:secincident', [
                'csv_mapping' => json_encode([
                    'mapping'     => $mapping,
                    'group_by'    => $group_by,
                    'timezone'    => $timezone,
                    'link_assets' => $options['link_assets'],
                    'create_iocs' => $options['create_iocs'],
                ], JSON_UNESCAPED_UNICODE),
            ]);
        }

        @unlink($info['path']);
        unset($_SESSION[$session_key][$token]);

        $incidents = [];
        foreach (['created' => $stats['created'], 'updated' => $stats['updated']] as $kind => $ids) {
            foreach ($ids as $id) {
                $incident = new Incident();
                if ($incident->getFromDB((int) $id)) {
                    $incidents[] = [
                        'kind'      => $kind,
                        'reference' => $incident->fields['reference'],
                        'name'      => $incident->fields['name'],
                        'url'       => Incident::getFormURLWithID($id),
                        'severity'  => Incident::getSeverities()[(int) $incident->fields['severity']] ?? '',
                        'color'     => Incident::getSeverityColor((int) $incident->fields['severity']),
                    ];
                }
            }
        }

        $step   = 'result';
        $params += [
            'filename'  => $info['name'],
            'stats'     => $stats,
            'incidents' => $incidents,
            'list_url'  => Incident::getSearchURL(),
        ];
    }
} catch (Throwable $e) {
    $params['error'] = $e->getMessage();
    $step            = 'upload';
}

$renderer->display('@secincident/import.html.twig', $params + [
    'step'           => $step,
    'saved_mapping'  => $saved !== [],
    'max_upload'     => ini_get('upload_max_filesize'),
]);

Html::footer();
