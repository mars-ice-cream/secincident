<?php

/**
 * -------------------------------------------------------------------------
 * SecIncident — Suivi des incidents de sécurité pour GLPI 11
 * -------------------------------------------------------------------------
 * @license   GPLv3 https://www.gnu.org/licenses/gpl-3.0.html
 * -------------------------------------------------------------------------
 */

namespace GlpiPlugin\Secincident;

use Computer;
use DateTimeImmutable;
use DateTimeZone;
use RuntimeException;
use Session;
use Throwable;
use User;

/**
 * Import d'exports CSV d'EDR / XDR (détections, alertes).
 *
 * Les en-têtes varient d'un éditeur et d'une console à l'autre : on détecte
 * automatiquement les colonnes usuelles et l'utilisateur peut corriger le
 * mapping avant import (mapping mémorisé pour les imports suivants).
 */
class CsvImporter
{
    public const MAX_ROWS  = 20000;
    public const MAX_BYTES = 30 * 1024 * 1024;

    public const GROUP_BY_DETECTION = 'external_id';
    public const GROUP_BY_HOST      = 'hostname';
    public const GROUP_SINGLE       = 'single';
    public const GROUP_PER_ROW      = 'row';

    /** @var array<string, mixed> */
    private array $stats = [];

    /**
     * Champs cibles proposés dans l'écran de mapping.
     *
     * @return array<string, string>
     */
    public static function getTargets(bool $instance = false): array
    {
        return [
            'external_id'    => I18n::tr('Detection identifier (grouping)', $instance),
            'timestamp'      => I18n::tr('Timestamp', $instance),
            'name'           => I18n::tr('Detection name', $instance),
            'description'    => I18n::tr('Description', $instance),
            'severity'       => I18n::tr('Severity', $instance),
            'tactic'         => I18n::tr('MITRE tactic', $instance),
            'technique'      => I18n::tr('MITRE technique', $instance),
            'objective'      => I18n::tr('Objective', $instance),
            'status'         => I18n::tr('Status in the EDR', $instance),
            'action'         => I18n::tr('Action / disposition', $instance),
            'hostname'       => I18n::tr('Hostname', $instance),
            'username'       => I18n::tr('User', $instance),
            'local_ip'       => I18n::tr('Host local IP', $instance),
            'external_ip'    => I18n::tr('Host public IP', $instance),
            'filename'       => I18n::tr('File name', $instance),
            'filepath'       => I18n::tr('File path', $instance),
            'cmdline'        => I18n::tr('Command line', $instance),
            'parent_cmdline' => I18n::tr('Parent command line', $instance),
            'sha256'         => 'SHA-256',
            'md5'            => 'MD5',
            'remote_ip'      => I18n::tr('Remote IP (IOC)', $instance),
            'domain'         => I18n::tr('Domain (IOC)', $instance),
            'url'            => I18n::tr('URL (IOC)', $instance),
            'ioc_value'      => I18n::tr('Generic IOC value', $instance),
            'link'           => I18n::tr('Link to the EDR console', $instance),
        ];
    }

    /**
     * Noms de colonnes connus (normalisés : minuscules, sans accents ni ponctuation).
     *
     * @return array<string, array<int, string>>
     */
    public static function getSynonyms(): array
    {
        return [
            'external_id'    => ['iddetection', 'identifiantdetection', 'identifiant', 'compositeid', 'detectionid', 'detectid', 'alertid', 'incidentid', 'id', 'aggregateid', 'detection', 'ldtid', 'threatid', 'eventid', 'uuid'],
            'timestamp'      => ['horodatage', 'dateheure', 'datededetection', 'heurededetection', 'timestamp', 'detecttime', 'detectiontime', 'time', 'date', 'createdtimestamp', 'firstbehavior', 'firstseen', 'processstarttime', 'contextimestamp', 'eventtime', 'datetime', 'lastbehavior', 'created', 'detectdate', 'detectedat', 'detected', 'alerttime', 'alertcreationtime', 'identifiedat', 'createdat', 'firstactivity'],
            'name'           => ['nomdeladetection', 'nom', 'titre', 'displayname', 'detectname', 'detectionname', 'name', 'alertname', 'patternname', 'scenario', 'title', 'alerttitle', 'threatname', 'rulename', 'signature', 'threat'],
            'description'    => ['description', 'detectdescription', 'alertdescription', 'details'],
            'severity'       => ['gravite', 'severite', 'criticite', 'severity', 'maxseverity', 'maxseveritydisplayname', 'severityname', 'severitydisplayname', 'criticality'],
            'tactic'         => ['tactique', 'tactiques', 'tactic', 'tactics', 'behaviorstactic', 'mitretactic', 'mitretactics', 'attacktactic'],
            'technique'      => ['technique', 'techniques', 'behaviorstechnique', 'mitretechnique', 'mitretechniques', 'techniqueid', 'tacticandtechnique', 'attacktechnique'],
            'objective'      => ['objective', 'behaviorsobjective'],
            'status'         => ['statut', 'etat', 'status', 'detectionstatus', 'alertstatus'],
            'action'         => ['actionentreprise', 'patterndisposition', 'patterndispositiondescription', 'actiontaken', 'action', 'disposition', 'preventionaction', 'mitigationstatus', 'remediation', 'response'],
            'hostname'       => ['hote', 'nomdhote', 'poste', 'machine', 'nomdumachine', 'hostname', 'host', 'devicehostname', 'computername', 'devicename', 'machinename', 'computer', 'endpointname', 'endpoint', 'agentname', 'device', 'assetname'],
            'username'       => ['utilisateur', 'nomdutilisateur', 'compte', 'username', 'user', 'behaviorsusername', 'accountname', 'userid', 'loggedonuser'],
            'local_ip'       => ['iplocale', 'adresseip', 'localip', 'devicelocalip', 'hostip', 'ipaddress', 'ip'],
            'external_ip'    => ['externalip', 'deviceexternalip', 'publicip'],
            'filename'       => ['nomdufichier', 'fichier', 'filename', 'imagefilename', 'processname', 'behaviorsfilename', 'file'],
            'filepath'       => ['chemin', 'chemindufichier', 'filepath', 'behaviorsfilepath', 'imagefilepath', 'path', 'fullpath'],
            'cmdline'        => ['lignedecommande', 'commandline', 'cmdline', 'behaviorscmdline', 'processcommandline'],
            'parent_cmdline' => ['parentcommandline', 'parentcmdline', 'parentdetailsparentcmdline', 'parentprocesscommandline'],
            'sha256'         => ['sha256', 'sha256hash', 'filesha256', 'behaviorssha256', 'hashsha256'],
            'md5'            => ['md5', 'md5hash', 'filemd5', 'behaviorsmd5', 'hashmd5'],
            'remote_ip'      => ['remoteip', 'remoteaddress', 'destinationip', 'remoteaddressip4', 'connectionremoteip'],
            'domain'         => ['domain', 'domainname', 'dnsdomain', 'requesteddomain'],
            'url'            => ['url', 'requesturl'],
            'ioc_value'      => ['iocvalue', 'indicator', 'indicatorvalue', 'ioc'],
            'link'           => ['consolelink', 'link', 'detectionlink', 'alertlink', 'alerturl', 'consoleurl', 'falconlink'],
        ];
    }

    public static function normalizeHeader(string $header): string
    {
        $h = mb_strtolower(trim($header));
        $h = strtr($h, [
            'à' => 'a', 'â' => 'a', 'ä' => 'a', 'é' => 'e', 'è' => 'e', 'ê' => 'e', 'ë' => 'e',
            'î' => 'i', 'ï' => 'i', 'ô' => 'o', 'ö' => 'o', 'ù' => 'u', 'û' => 'u', 'ü' => 'u', 'ç' => 'c',
        ]);
        return (string) preg_replace('/[^a-z0-9]/', '', $h);
    }

    // ---------------------------------------------------------------------
    // Lecture du fichier
    // ---------------------------------------------------------------------

    /**
     * Lit un CSV et renvoie en-têtes + lignes associatives.
     *
     * @return array{headers: array<int, string>, rows: array<int, array<string, string>>, delimiter: string, truncated: bool}
     */
    public static function parse(string $path): array
    {
        if (!is_readable($path)) {
            throw new RuntimeException(__('Unreadable file', 'secincident'));
        }
        if (filesize($path) > self::MAX_BYTES) {
            throw new RuntimeException(sprintf(__('File too large (max %d MB)', 'secincident'), self::MAX_BYTES / 1024 / 1024));
        }

        $content = (string) file_get_contents($path);
        // BOM UTF-8 / UTF-16
        if (str_starts_with($content, "\xEF\xBB\xBF")) {
            $content = substr($content, 3);
        } elseif (str_starts_with($content, "\xFF\xFE") || str_starts_with($content, "\xFE\xFF")) {
            $content = (string) mb_convert_encoding($content, 'UTF-8', 'UTF-16');
        }
        if (!mb_check_encoding($content, 'UTF-8')) {
            $content = (string) mb_convert_encoding($content, 'UTF-8', 'Windows-1252');
        }

        $first_line = strtok($content, "\n") ?: '';
        $delimiter  = self::detectDelimiter($first_line);

        $handle = fopen('php://temp', 'r+');
        fwrite($handle, $content);
        rewind($handle);

        $headers = fgetcsv($handle, null, $delimiter, '"', '');
        if (!is_array($headers) || count(array_filter($headers, fn ($h) => trim((string) $h) !== '')) === 0) {
            fclose($handle);
            throw new RuntimeException(__('No header found in the file', 'secincident'));
        }
        $headers = array_map(fn ($h) => trim((string) $h), $headers);
        // En-têtes dupliqués : on les suffixe pour ne rien perdre
        $seen = [];
        foreach ($headers as $i => $h) {
            $key = $h === '' ? 'colonne_' . ($i + 1) : $h;
            if (isset($seen[$key])) {
                $seen[$key]++;
                $key .= ' (' . $seen[$key] . ')';
            } else {
                $seen[$key] = 1;
            }
            $headers[$i] = $key;
        }

        $rows      = [];
        $truncated = false;
        while (($data = fgetcsv($handle, null, $delimiter, '"', '')) !== false) {
            if ($data === [null] || (count($data) === 1 && trim((string) $data[0]) === '')) {
                continue;
            }
            if (count($rows) >= self::MAX_ROWS) {
                $truncated = true;
                break;
            }
            $row = [];
            foreach ($headers as $i => $h) {
                $row[$h] = isset($data[$i]) ? trim((string) $data[$i]) : '';
            }
            $rows[] = $row;
        }
        fclose($handle);

        return [
            'headers'   => $headers,
            'rows'      => $rows,
            'delimiter' => $delimiter,
            'truncated' => $truncated,
        ];
    }

    private static function detectDelimiter(string $line): string
    {
        $best  = ',';
        $count = 0;
        foreach ([',', ';', "\t", '|'] as $candidate) {
            $c = substr_count($line, $candidate);
            if ($c > $count) {
                $best  = $candidate;
                $count = $c;
            }
        }
        return $best;
    }

    /**
     * Propose un mapping cible → colonne à partir des en-têtes.
     *
     * @param array<int, string>   $headers
     * @param array<string, string> $saved Mapping mémorisé (prioritaire si la colonne existe)
     * @return array<string, string>
     */
    public static function autoMap(array $headers, array $saved = []): array
    {
        $normalized = [];
        foreach ($headers as $h) {
            $normalized[self::normalizeHeader($h)] ??= $h;
        }

        $mapping = [];
        $used    = [];
        foreach (self::getSynonyms() as $target => $synonyms) {
            if (isset($saved[$target]) && in_array($saved[$target], $headers, true)) {
                $mapping[$target] = $saved[$target];
                $used[$saved[$target]] = true;
                continue;
            }
            foreach ($synonyms as $synonym) {
                $synonym = self::normalizeHeader($synonym);
                if (isset($normalized[$synonym]) && !isset($used[$normalized[$synonym]])) {
                    $mapping[$target] = $normalized[$synonym];
                    $used[$normalized[$synonym]] = true;
                    break;
                }
            }
        }
        // Repli : correspondance partielle pour les colonnes « device.hostname », « behaviors.0.tactic »…
        foreach (self::getSynonyms() as $target => $synonyms) {
            if (isset($mapping[$target])) {
                continue;
            }
            foreach ($normalized as $norm => $original) {
                if (isset($used[$original])) {
                    continue;
                }
                foreach (array_slice($synonyms, 0, 2) as $synonym) {
                    $synonym = self::normalizeHeader($synonym);
                    if (strlen($synonym) >= 5 && str_ends_with($norm, $synonym)) {
                        $mapping[$target] = $original;
                        $used[$original]  = true;
                        continue 3;
                    }
                }
            }
        }
        return $mapping;
    }

    // ---------------------------------------------------------------------
    // Conversion des valeurs
    // ---------------------------------------------------------------------

    public static function mapSeverity(string $value): ?int
    {
        $v = self::normalizeHeader($value);
        if ($v === '') {
            return null;
        }
        if (is_numeric($value)) {
            $n = (float) $value;
            if ($n <= 5) {
                return max(1, (int) round($n));
            }
            // Échelle 0-100 de certains EDR : 10 info, 30 low, 50 medium, 70 high, 90 critical
            return match (true) {
                $n >= 90 => 5,
                $n >= 70 => 4,
                $n >= 50 => 3,
                $n >= 30 => 2,
                default  => 1,
            };
        }
        return match (true) {
            str_contains($v, 'critic')                                   => 5,
            str_contains($v, 'high') || str_contains($v, 'elev') || str_contains($v, 'haut') => 4,
            str_contains($v, 'medium') || str_contains($v, 'moyen')     => 3,
            str_contains($v, 'low') || str_contains($v, 'faible') || str_contains($v, 'bas') => 2,
            str_contains($v, 'info')                                     => 1,
            default                                                      => null,
        };
    }

    /**
     * Devine une catégorie d'incident à partir du texte de la détection.
     */
    public static function guessCategory(string $text): string
    {
        $t = mb_strtolower($text);
        $rules = [
            'ransomware'         => ['ransom', 'rançon', 'shadow cop', 'vssadmin', 'encrypt'],
            'account_compromise' => ['credential', 'password', 'mimikatz', 'lsass', 'brute', 'kerberoast', 'pass-the', 'identity'],
            'data_leak'          => ['exfiltrat', 'exfil', 'data staged', 'collection'],
            'phishing'           => ['phish', 'malicious document', 'office macro', 'spearphish'],
            'exploitation'       => ['exploit', 'vulnerab', 'cve-', 'webshell', 'web shell'],
            'malware'            => ['malware', 'machine learning', 'trojan', 'virus', 'worm', 'miner', 'adware', 'pup', 'backdoor', 'known malicious', 'intel detection'],
            'intrusion'          => ['lateral', 'remote access', 'initial access', 'persistence', 'privilege', 'defense evasion', 'discovery', 'command and control', 'execution'],
        ];
        foreach ($rules as $category => $needles) {
            foreach ($needles as $needle) {
                if (str_contains($t, $needle)) {
                    return $category;
                }
            }
        }
        return 'other';
    }

    /**
     * Convertit un horodatage CSV en date GLPI (fuseau du serveur).
     */
    public static function parseDate(string $value, string $naive_tz = 'UTC'): ?string
    {
        $value = trim($value);
        if ($value === '') {
            return null;
        }
        $local = new DateTimeZone(date_default_timezone_get());
        try {
            $tz = new DateTimeZone($naive_tz);
        } catch (Throwable) {
            $tz = new DateTimeZone('UTC');
        }

        try {
            if (preg_match('/^\d{10}(\d{3})?$/', $value)) {
                $seconds = strlen($value) === 13 ? intdiv((int) $value, 1000) : (int) $value;
                $date    = (new DateTimeImmutable('@' . $seconds));
            } else {
                // Formats français JJ/MM/AAAA
                if (preg_match('#^(\d{2})/(\d{2})/(\d{4})(.*)$#', $value, $m)) {
                    $value = sprintf('%s-%s-%s%s', $m[3], $m[2], $m[1], $m[4]);
                }
                // « Oct. 12, 2026 08:15:32 »
                $value = str_replace('.', '', preg_replace('/^([A-Za-z]{3})\. /', '$1 ', $value) ?? $value);
                $date  = new DateTimeImmutable($value, $tz);
            }
            return $date->setTimezone($local)->format('Y-m-d H:i:s');
        } catch (Throwable) {
            $ts = strtotime($value);
            return $ts !== false ? date('Y-m-d H:i:s', $ts) : null;
        }
    }

    // ---------------------------------------------------------------------
    // Regroupement
    // ---------------------------------------------------------------------

    /**
     * @param array<int, array<string, string>> $rows
     * @param array<string, string>             $mapping
     * @return array<string, array<int, array<string, string>>>
     */
    public static function group(array $rows, array $mapping, string $mode): array
    {
        $groups = [];
        foreach ($rows as $i => $row) {
            $key = match ($mode) {
                self::GROUP_SINGLE  => 'all',
                self::GROUP_PER_ROW => 'row' . $i,
                self::GROUP_BY_HOST => mb_strtolower(self::get($row, $mapping, 'hostname')) ?: 'unknown',
                default             => self::get($row, $mapping, 'external_id') ?: ('row' . $i),
            };
            $groups[$key][] = $row;
        }
        return $groups;
    }

    /**
     * @param array<string, string> $row
     * @param array<string, string> $mapping
     */
    public static function get(array $row, array $mapping, string $target): string
    {
        if (empty($mapping[$target])) {
            return '';
        }
        return trim((string) ($row[$mapping[$target]] ?? ''));
    }

    // ---------------------------------------------------------------------
    // Import
    // ---------------------------------------------------------------------

    /**
     * @param array<int, array<string, string>> $rows
     * @param array<string, string>             $mapping
     * @param array<string, mixed>              $options
     * @return array<string, mixed> Statistiques
     */
    public function import(array $rows, array $mapping, array $options): array
    {
        $this->stats = [
            'created'        => [],
            'updated'        => [],
            'events_added'   => 0,
            'events_skipped' => 0,
            'iocs_added'     => 0,
            'links_added'    => 0,
            'errors'         => [],
        ];

        $mode        = (string) ($options['group_by'] ?? self::GROUP_BY_DETECTION);
        $entities_id = (int) ($options['entities_id'] ?? Session::getActiveEntity());
        $target_id   = (int) ($options['target_incident'] ?? 0);
        $naive_tz    = (string) ($options['timezone'] ?? 'UTC');
        $link_assets = !empty($options['link_assets']);
        $create_iocs = !empty($options['create_iocs']);

        $fk     = Incident::getForeignKeyField();
        $groups = $target_id > 0 ? ['target' => $rows] : self::group($rows, $mapping, $mode);

        foreach ($groups as $key => $group_rows) {
            try {
                $incident = $this->resolveIncident(
                    $target_id,
                    $mode === self::GROUP_BY_DETECTION ? (string) $key : '',
                    $group_rows,
                    $mapping,
                    $entities_id,
                    $naive_tz
                );
                if ($incident === null) {
                    continue;
                }

                $hosts = [];
                $users = [];
                $max_severity = (int) $incident->fields['severity'];
                $min_date     = $incident->fields['date_detection'];

                foreach ($group_rows as $row) {
                    $date = self::parseDate(self::get($row, $mapping, 'timestamp'), $naive_tz) ?? Session::getCurrentTime();
                    if ($min_date === null || $date < $min_date) {
                        $min_date = $date;
                    }
                    $severity = self::mapSeverity(self::get($row, $mapping, 'severity'));
                    if ($severity !== null && $severity > $max_severity) {
                        $max_severity = $severity;
                    }

                    $hostname = self::get($row, $mapping, 'hostname');
                    $username = self::get($row, $mapping, 'username');
                    if ($hostname !== '') {
                        $hosts[mb_strtolower($hostname)] = $hostname;
                    }
                    if ($username !== '') {
                        $users[mb_strtolower($username)] = $username;
                    }

                    $this->addEvent($incident, $row, $mapping, $date, $hostname, $username);

                    if ($create_iocs) {
                        $this->addIocs($incident, $row, $mapping, $date);
                    }
                }

                // Mise à jour de l'incident (gravité max, date de détection la plus ancienne)
                $update = ['id' => $incident->getID()];
                if ($max_severity > (int) $incident->fields['severity']) {
                    $update['severity'] = $max_severity;
                }
                if ($min_date !== null && $min_date !== $incident->fields['date_detection']) {
                    $update['date_detection'] = $min_date;
                }
                if (count($update) > 1) {
                    $update['_no_audit'] = AuditLog::silent();
                    $incident->update($update);
                }

                if ($link_assets) {
                    $this->linkAssets($incident, $hosts, $users);
                }
            } catch (Throwable $e) {
                $this->stats['errors'][] = sprintf('%s : %s', $key, $e->getMessage());
            }
        }

        AuditLog::flushAnchors(I18n::instance('import of a CSV file'));

        $this->stats['created'] = array_values(array_unique($this->stats['created']));
        $this->stats['updated'] = array_values(array_diff(array_unique($this->stats['updated']), $this->stats['created']));
        return $this->stats;
    }

    /**
     * Retrouve (dédoublonnage par identifiant externe) ou crée l'incident d'un groupe.
     *
     * @param array<int, array<string, string>> $rows
     * @param array<string, string>             $mapping
     */
    private function resolveIncident(
        int $target_id,
        string $external_id,
        array $rows,
        array $mapping,
        int $entities_id,
        string $naive_tz
    ): ?Incident {
        $incident = new Incident();

        if ($target_id > 0) {
            if (!$incident->getFromDB($target_id) || !$incident->can($target_id, UPDATE)) {
                AuditLog::recordDenied(I18n::instance('import into existing incident'), Incident::class, $target_id);
                throw new RuntimeException(__('Target incident not found or not editable', 'secincident'));
            }
            $this->stats['updated'][] = $incident->getID();
            return $incident;
        }

        if ($external_id !== '' && !str_starts_with($external_id, 'row')) {
            $found = $incident->find([
                'source'      => 'edr',
                'external_id' => $external_id,
                'entities_id' => $entities_id,
                'is_deleted'  => 0,
            ], [], 1);
            if (count($found) === 1) {
                $existing_id = (int) array_key_first($found);
                $incident->getFromDB($existing_id);
                if (!$incident->can($existing_id, UPDATE)) {
                    // La détection existe déjà dans un incident qui n'est pas le sien :
                    // on ne le complète pas et on ne révèle rien de son contenu.
                    AuditLog::recordDenied(I18n::instance('import into another technician\'s incident'), Incident::class, $existing_id);
                    throw new RuntimeException(__('Detection already attached to an incident you cannot access', 'secincident'));
                }
                $this->stats['updated'][] = $incident->getID();
                return $incident;
            }
        }

        // Pré-remplissage à partir de la première ligne exploitable
        $first     = $rows[0];
        $name      = self::get($first, $mapping, 'name');
        $desc      = self::get($first, $mapping, 'description');
        $tactic    = self::get($first, $mapping, 'tactic');
        $technique = self::get($first, $mapping, 'technique');
        $hostname  = self::get($first, $mapping, 'hostname');

        $title = $name !== '' ? $name : ($technique !== '' ? $technique : ($desc !== '' ? mb_strimwidth($desc, 0, 120, '…') : __('EDR detection', 'secincident')));
        if ($hostname !== '') {
            $title .= ' — ' . $hostname;
        }

        $severity = null;
        $dates    = [];
        $texts    = [];
        foreach ($rows as $row) {
            $s = self::mapSeverity(self::get($row, $mapping, 'severity'));
            if ($s !== null) {
                $severity = max($s, $severity ?? 0);
            }
            $d = self::parseDate(self::get($row, $mapping, 'timestamp'), $naive_tz);
            if ($d !== null) {
                $dates[] = $d;
            }
            $texts[] = implode(' ', [
                self::get($row, $mapping, 'name'),
                self::get($row, $mapping, 'description'),
                self::get($row, $mapping, 'tactic'),
                self::get($row, $mapping, 'technique'),
                self::get($row, $mapping, 'objective'),
            ]);
        }
        sort($dates);

        $content = '<p>' . htmlescape(sprintf(
            I18n::instance('Incident created by EDR CSV import (%d row(s)).'),
            count($rows)
        )) . '</p>';
        if ($desc !== '') {
            $content .= '<p>' . nl2br(htmlescape($desc)) . '</p>';
        }
        $link = self::get($first, $mapping, 'link');
        if ($link !== '' && preg_match('#^https://#i', $link)) {
            $content .= '<p><a href="' . htmlescape($link) . '" target="_blank" rel="noopener">'
                . htmlescape(I18n::instance('Open in the EDR console')) . '</a></p>';
        }

        $id = $incident->add([
            'name'               => mb_strimwidth($title, 0, 250, '…'),
            'content'            => $content,
            'entities_id'        => $entities_id,
            'category'           => self::guessCategory(implode(' ', $texts)),
            'severity'           => $severity ?? 3,
            'status'             => Incident::STATUS_NEW,
            'source'             => 'edr',
            'external_id'        => ($external_id !== '' && !str_starts_with($external_id, 'row')) ? mb_strimwidth($external_id, 0, 250) : null,
            'mitre_tactic'       => $tactic !== '' ? mb_strimwidth($tactic, 0, 250) : null,
            'mitre_technique'    => $technique !== '' ? mb_strimwidth($technique, 0, 250) : null,
            'date_detection'     => $dates[0] ?? Session::getCurrentTime(),
            'users_id_tech'      => Session::getLoginUserID() ?: 0,
            '_no_creation_event' => true,
        ]);

        if (!$id) {
            throw new RuntimeException(__('Unable to create the incident', 'secincident'));
        }
        $this->stats['created'][] = $id;
        return $incident;
    }

    /**
     * @param array<string, string> $row
     * @param array<string, string> $mapping
     */
    private function addEvent(Incident $incident, array $row, array $mapping, string $date, string $hostname, string $username): void
    {
        $fk = Incident::getForeignKeyField();

        // Empreinte de la ligne pour éviter les doublons en cas de ré-import
        $fingerprint = hash('sha256', json_encode($row, JSON_UNESCAPED_UNICODE) ?: '');
        $exists = countElementsInTable(TimelineEvent::getTable(), [
            $fk           => $incident->getID(),
            'external_id' => $fingerprint,
        ]);
        if ($exists > 0) {
            $this->stats['events_skipped']++;
            return;
        }

        $name = self::get($row, $mapping, 'name');
        if ($name === '') {
            $parts = array_filter([self::get($row, $mapping, 'tactic'), self::get($row, $mapping, 'technique')]);
            $name  = $parts !== [] ? implode(' / ', $parts) : I18n::instance('EDR detection');
        }

        $lines = [];
        foreach (['description', 'severity', 'tactic', 'technique', 'objective', 'action', 'status', 'filepath', 'filename', 'cmdline', 'parent_cmdline', 'sha256', 'local_ip', 'external_ip'] as $target) {
            $value = self::get($row, $mapping, $target);
            if ($value !== '') {
                $lines[] = self::getTargets(true)[$target] . ' : ' . $value;
            }
        }

        $event = new TimelineEvent();
        $ok = $event->add([
            $fk           => $incident->getID(),
            'date'        => $date,
            'event_type'  => 'detection',
            'name'        => mb_strimwidth($name, 0, 250, '…'),
            'content'     => implode("\n", $lines),
            'hostname'    => $hostname !== '' ? mb_strimwidth($hostname, 0, 250) : null,
            'username'    => $username !== '' ? mb_strimwidth($username, 0, 250) : null,
            'source'      => 'edr',
            'external_id' => $fingerprint,
            'raw_data'    => $row,
            '_no_audit'   => AuditLog::silent(),
            'users_id'    => 0,
        ]);
        if ($ok) {
            $this->stats['events_added']++;
        }
    }

    /**
     * @param array<string, string> $row
     * @param array<string, string> $mapping
     */
    private function addIocs(Incident $incident, array $row, array $mapping, string $date): void
    {
        $fk = Incident::getForeignKeyField();

        $candidates = [
            'sha256'   => self::get($row, $mapping, 'sha256'),
            'md5'      => self::get($row, $mapping, 'md5'),
            'filepath' => self::get($row, $mapping, 'filepath'),
            'cmdline'  => self::get($row, $mapping, 'cmdline'),
            'domain'   => self::get($row, $mapping, 'domain'),
            'url'      => self::get($row, $mapping, 'url'),
            'auto_ip'  => self::get($row, $mapping, 'remote_ip'),
            'auto'     => self::get($row, $mapping, 'ioc_value'),
        ];
        if ($candidates['filepath'] === '') {
            $candidates['filename'] = self::get($row, $mapping, 'filename');
        }

        foreach ($candidates as $type => $value) {
            if ($value === '' || in_array(mb_strtolower($value), ['n/a', 'na', '-', 'none', 'null'], true)) {
                continue;
            }
            $ioc_type = str_starts_with($type, 'auto') ? Ioc::guessType($value) : $type;
            $hash     = Ioc::computeHash($ioc_type, $value);

            $existing = (new Ioc())->find([$fk => $incident->getID(), 'value_hash' => $hash], [], 1);
            if (count($existing) === 1) {
                $current = reset($existing);
                if ($current['date_last_seen'] === null || $date > $current['date_last_seen']) {
                    (new Ioc())->update(['id' => $current['id'], 'date_last_seen' => $date, '_no_audit' => AuditLog::silent()]);
                }
                continue;
            }

            $ioc = new Ioc();
            if (
                $ioc->add([
                    $fk                 => $incident->getID(),
                    'ioc_type'          => $ioc_type,
                    'value'             => $value,
                    'verdict'           => Ioc::VERDICT_UNKNOWN,
                    'source'            => 'edr',
                    'date_first_seen'   => $date,
                    'date_last_seen'    => $date,
                    '_silent_duplicate' => true,
                    '_no_audit'         => AuditLog::silent(),
                ])
            ) {
                $this->stats['iocs_added']++;
            }
        }
    }

    /**
     * Lie les ordinateurs (par nom d'hôte) et les utilisateurs (par identifiant) trouvés dans GLPI.
     *
     * @param array<string, string> $hosts
     * @param array<string, string> $users
     */
    private function linkAssets(Incident $incident, array $hosts, array $users): void
    {
        $fk   = Incident::getForeignKeyField();
        $link = new Incident_Item();

        foreach ($hosts as $hostname) {
            $short = explode('.', $hostname)[0];
            $found = (new Computer())->find([
                'is_deleted'  => 0,
                'is_template' => 0,
                'OR'          => [['name' => $hostname], ['name' => $short]],
                'entities_id' => getSonsOf('glpi_entities', $incident->getEntityID()),
            ], [], 2);
            if (count($found) === 1) {
                $this->addLink($link, $fk, $incident->getID(), Computer::class, (int) array_key_first($found));
            }
        }

        foreach ($users as $username) {
            // DOMAINE\login ou login@domaine
            $login = $username;
            if (str_contains($login, '\\')) {
                $login = substr($login, strrpos($login, '\\') + 1);
            }
            $candidates = array_unique([$login, explode('@', $login)[0], $username]);
            $found = (new User())->find(['name' => $candidates, 'is_deleted' => 0], [], 2);
            if (count($found) === 1) {
                $this->addLink($link, $fk, $incident->getID(), User::class, (int) array_key_first($found));
            }
        }
    }

    private function addLink(Incident_Item $link, string $fk, int $incidents_id, string $itemtype, int $items_id): void
    {
        $exists = countElementsInTable(Incident_Item::getTable(), [
            $fk        => $incidents_id,
            'itemtype' => $itemtype,
            'items_id' => $items_id,
        ]);
        if ($exists === 0 && $link->add([$fk => $incidents_id, 'itemtype' => $itemtype, 'items_id' => $items_id, '_no_audit' => AuditLog::silent()])) {
            $this->stats['links_added']++;
        }
    }
}
