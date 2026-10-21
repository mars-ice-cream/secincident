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
use Document;
use Document_Item;
use Session;
use Throwable;

/**
 * Registre des preuves : chaque document joint à un incident reçoit à l'ajout
 * une empreinte SHA-256 de référence, ancrée dans le journal d'audit.
 * Le registre n'est jamais supprimé ni réécrit : un document retiré ou
 * remplacé reste tracé avec son empreinte d'origine.
 */
class Evidence extends CommonDBTM
{
    public static $rightname = 'plugin_secincident_incident';

    public const CHECK_OK                = 'ok';
    public const CHECK_MODIFIED          = 'modified';
    public const CHECK_MISSING           = 'missing';
    public const CHECK_REPLACED          = 'replaced';
    public const CHECK_REFERENCE_ALTERED = 'reference_altered';
    public const CHECK_UNCHECKED         = 'unchecked';
    public const CHECK_DETACHED          = 'detached';

    public static function getTypeName($nb = 0)
    {
        return _n('Evidence', 'Evidence', $nb, 'secincident');
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
    public static function getCheckLabels(): array
    {
        return [
            self::CHECK_OK                => __('Intact', 'secincident'),
            self::CHECK_MODIFIED          => __('File modified', 'secincident'),
            self::CHECK_MISSING           => __('File not found', 'secincident'),
            self::CHECK_REPLACED          => __('File replaced in GLPI', 'secincident'),
            self::CHECK_REFERENCE_ALTERED => __('Reference fingerprint altered', 'secincident'),
            self::CHECK_UNCHECKED         => __('Never checked', 'secincident'),
            self::CHECK_DETACHED          => __('Removed from the incident', 'secincident'),
        ];
    }

    public static function getCheckColor(string $check): string
    {
        return match ($check) {
            self::CHECK_OK        => 'green',
            self::CHECK_UNCHECKED => 'secondary',
            self::CHECK_DETACHED  => 'secondary',
            self::CHECK_REPLACED  => 'orange',
            default               => 'red',
        };
    }

    public static function getFilePath(Document $doc): ?string
    {
        $relative = (string) ($doc->fields['filepath'] ?? '');
        if ($relative === '' || str_contains($relative, '..')) {
            return null;
        }
        return GLPI_DOC_DIR . '/' . $relative;
    }

    // ---------------------------------------------------------------------
    // Enregistrement
    // ---------------------------------------------------------------------

    /**
     * Inscrit un document comme preuve d'un incident.
     */
    public static function register(int $incidents_id, Document $doc, int $documents_items_id, string $reason = 'ajout'): void
    {
        global $DB;

        try {
            $path   = self::getFilePath($doc);
            $exists = $path !== null && is_file($path);
            $sha256 = $exists ? (string) hash_file('sha256', $path) : '';
            $size   = $exists ? (int) filesize($path) : 0;

            $DB->insert(self::getTable(), [
                Incident::getForeignKeyField() => $incidents_id,
                'documents_id'       => (int) $doc->getID(),
                'documents_items_id' => $documents_items_id,
                'filename'           => (string) ($doc->fields['filename'] ?? ''),
                'filepath'           => (string) ($doc->fields['filepath'] ?? ''),
                'mime'               => (string) ($doc->fields['mime'] ?? ''),
                'filesize'           => $size,
                'sha256'             => $sha256,
                'sha1_glpi'          => (string) ($doc->fields['sha1sum'] ?? ''),
                'users_id'           => (int) (Session::getLoginUserID() ?: 0),
                'date_added'         => Session::getCurrentTime(),
                'status'             => 'active',
                'check_status'       => $exists ? self::CHECK_OK : self::CHECK_MISSING,
                'date_last_check'    => Session::getCurrentTime(),
                'last_sha256'        => $sha256,
            ]);
            $evidence_id = (int) $DB->insertId();

            $evidence = new self();
            $evidence->fields = ['id' => $evidence_id, Incident::getForeignKeyField() => $incidents_id];
            AuditLog::record('evidence_add', $evidence, [
                'motif'        => $reason,
                'document'     => (int) $doc->getID(),
                'fichier'      => (string) ($doc->fields['filename'] ?? ''),
                'taille'       => $size,
                'sha256'       => $sha256,
                'sha1_glpi'    => (string) ($doc->fields['sha1sum'] ?? ''),
                'fichier_absent' => !$exists,
            ], $exists ? AuditLog::RESULT_OK : AuditLog::RESULT_ERROR, $incidents_id);
        } catch (Throwable $e) {
            trigger_error('SecIncident evidence failure: ' . $e->getMessage(), E_USER_WARNING);
        }
    }

    /**
     * Hook : document lié à un incident.
     */
    public static function onDocumentItemAdd(Document_Item $link): void
    {
        if (($link->fields['itemtype'] ?? '') !== Incident::class) {
            return;
        }
        $doc = new Document();
        if ($doc->getFromDB((int) $link->fields['documents_id'])) {
            self::register((int) $link->fields['items_id'], $doc, (int) $link->getID());
        }
    }

    /**
     * Hook : document retiré d'un incident.
     */
    public static function onDocumentItemPurge(Document_Item $link): void
    {
        if (($link->fields['itemtype'] ?? '') !== Incident::class) {
            return;
        }
        self::detach(['documents_items_id' => (int) $link->getID()], I18n::instance('document removed from the incident'));
    }

    /**
     * Hook : document supprimé de GLPI.
     */
    public static function onDocumentPurge(Document $doc): void
    {
        self::detach(['documents_id' => (int) $doc->getID()], I18n::instance('document deleted from GLPI'));
    }

    /**
     * Hook : fichier d'un document remplacé (nouvelle version).
     * L'empreinte d'origine est conservée ; la nouvelle version est inscrite à part.
     */
    public static function onDocumentUpdate(Document $doc): void
    {
        global $DB;

        if (!in_array('filepath', $doc->updates, true) && !in_array('sha1sum', $doc->updates, true)) {
            return;
        }
        $rows = $DB->request([
            'FROM'  => self::getTable(),
            'WHERE' => ['documents_id' => (int) $doc->getID(), 'status' => 'active'],
        ]);
        $by_link = [];
        foreach ($rows as $row) {
            $by_link[(int) $row['documents_items_id']] = $row;
        }
        foreach ($by_link as $documents_items_id => $row) {
            $DB->update(self::getTable(), [
                'status'       => 'superseded',
                'check_status' => self::CHECK_REPLACED,
            ], ['id' => $row['id']]);

            $evidence = new self();
            $evidence->fields = $row;
            AuditLog::record('evidence_replaced', $evidence, [
                'document'        => (int) $doc->getID(),
                'ancien_fichier'  => $row['filename'],
                'ancien_sha256'   => $row['sha256'],
                'nouveau_fichier' => (string) $doc->fields['filename'],
            ], AuditLog::RESULT_OK, (int) $row[Incident::getForeignKeyField()]);

            self::register((int) $row[Incident::getForeignKeyField()], $doc, $documents_items_id, I18n::instance('new version of the file'));
        }
    }

    /**
     * @param array<string, int> $where
     */
    private static function detach(array $where, string $reason): void
    {
        global $DB;

        $rows = $DB->request([
            'FROM'  => self::getTable(),
            'WHERE' => $where + ['status' => 'active'],
        ]);
        foreach ($rows as $row) {
            $DB->update(self::getTable(), [
                'status'        => 'detached',
                'date_detached' => Session::getCurrentTime(),
            ], ['id' => $row['id']]);

            $evidence = new self();
            $evidence->fields = $row;
            AuditLog::record('evidence_detach', $evidence, [
                'motif'   => $reason,
                'fichier' => $row['filename'],
                'sha256'  => $row['sha256'],
            ], AuditLog::RESULT_OK, (int) $row[Incident::getForeignKeyField()]);
        }
    }

    // ---------------------------------------------------------------------
    // Vérification
    // ---------------------------------------------------------------------

    /**
     * Empreintes de référence telles qu'ancrées dans le journal (par id de preuve).
     *
     * @return array<int, string>
     */
    private static function getAnchoredHashes(int $incidents_id): array
    {
        global $DB;

        $hashes = [];
        foreach (
            $DB->request([
                'SELECT' => ['items_id', 'details'],
                'FROM'   => AuditLog::getTable(),
                'WHERE'  => ['incidents_id' => $incidents_id, 'action' => 'evidence_add', 'itemtype' => self::class],
            ]) as $row
        ) {
            $details = json_decode((string) $row['details'], true) ?: [];
            $hashes[(int) $row['items_id']] = (string) ($details['sha256'] ?? '');
        }
        return $hashes;
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    public static function listForIncident(int $incidents_id): array
    {
        global $DB;

        $out = [];
        foreach (
            $DB->request([
                'FROM'  => self::getTable(),
                'WHERE' => [Incident::getForeignKeyField() => $incidents_id],
                'ORDER' => 'id ASC',
            ]) as $row
        ) {
            $row['check'] = $row['status'] === 'detached'
                ? self::CHECK_DETACHED
                : ($row['status'] === 'superseded' ? self::CHECK_REPLACED : (string) $row['check_status']);
            $out[] = $row;
        }
        return $out;
    }

    /**
     * Recalcule l'empreinte de chaque preuve active et la compare à la référence.
     *
     * @return array<int, array<string, mixed>>
     */
    public static function verifyForIncident(int $incidents_id): array
    {
        global $DB;

        $anchored = self::getAnchoredHashes($incidents_id);
        $rows     = self::listForIncident($incidents_id);

        foreach ($rows as &$row) {
            $anchor = $anchored[(int) $row['id']] ?? null;
            if ($anchor !== null && $anchor !== $row['sha256']) {
                $row['check'] = self::CHECK_REFERENCE_ALTERED;
            } elseif ($row['status'] !== 'active') {
                // retirée ou remplacée : on garde l'état, pas de recalcul
                continue;
            } else {
                $doc  = new Document();
                $path = null;
                if ($doc->getFromDB((int) $row['documents_id'])) {
                    $path = self::getFilePath($doc);
                    if ((string) $doc->fields['filepath'] !== (string) $row['filepath']) {
                        $row['check'] = self::CHECK_REPLACED;
                        $path = null;
                    }
                }
                if ($row['check'] !== self::CHECK_REPLACED) {
                    if ($path === null || !is_file($path)) {
                        $row['check'] = self::CHECK_MISSING;
                        $row['last_sha256'] = '';
                    } else {
                        $current            = (string) hash_file('sha256', $path);
                        $row['last_sha256'] = $current;
                        $row['check']       = hash_equals((string) $row['sha256'], $current) ? self::CHECK_OK : self::CHECK_MODIFIED;
                    }
                }
            }

            $row['date_last_check'] = Session::getCurrentTime();
            $DB->update(self::getTable(), [
                'check_status'    => $row['check'],
                'last_sha256'     => (string) ($row['last_sha256'] ?? ''),
                'date_last_check' => $row['date_last_check'],
            ], ['id' => $row['id']]);
        }
        unset($row);

        return $rows;
    }

    /**
     * Inscrit les documents déjà joints aux incidents (mise à jour du plugin).
     */
    public static function registerExisting(): int
    {
        global $DB;

        $count = 0;
        foreach (
            $DB->request([
                'FROM'  => Document_Item::getTable(),
                'WHERE' => ['itemtype' => Incident::class],
            ]) as $link
        ) {
            $already = countElementsInTable(self::getTable(), ['documents_items_id' => $link['id']]);
            $doc     = new Document();
            if ($already === 0 && $doc->getFromDB((int) $link['documents_id'])) {
                self::register((int) $link['items_id'], $doc, (int) $link['id'], I18n::instance('initial registration (document already attached)'));
                $count++;
            }
        }
        return $count;
    }

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
