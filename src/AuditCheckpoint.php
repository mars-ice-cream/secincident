<?php

/**
 * -------------------------------------------------------------------------
 * SecIncident — Suivi des incidents de sécurité pour GLPI
 * -------------------------------------------------------------------------
 * @license   GPLv3 https://www.gnu.org/licenses/gpl-3.0.html
 * -------------------------------------------------------------------------
 */

namespace GlpiPlugin\Secincident;

use Config;
use Throwable;

/**
 * Point de contrôle externe du journal d'audit.
 *
 * Le chaînage détecte une modification, une insertion ou une suppression au
 * milieu du journal, mais pas la suppression des dernières entrées, ni une
 * réécriture complète de la chaîne par quelqu'un qui a accès à la base. Le
 * point de contrôle fige l'état du journal (identifiant de l'instance, dernière
 * entrée, son empreinte, nombre d'entrées). Conservé hors de la base GLPI, avec
 * des droits d'écriture distincts, il permet de prouver que les entrées qu'il
 * couvre sont toujours là, inchangées.
 */
class AuditCheckpoint
{
    public const FORMAT = 'secincident-audit-checkpoint/1';

    public const ANOMALY_FORMAT    = 'format_invalid';
    public const ANOMALY_INSTANCE  = 'instance_mismatch';
    public const ANOMALY_MISSING   = 'entry_missing';
    public const ANOMALY_TRUNCATED = 'log_truncated';
    public const ANOMALY_HASH      = 'hash_changed';
    public const ANOMALY_COUNT     = 'count_mismatch';
    public const ANOMALY_CHAIN     = 'chain_broken';

    /**
     * Identifiant aléatoire de l'instance, créé une fois (installation ou premier export).
     * S'il est supprimé ou modifié en base, les points de contrôle existants ne
     * correspondent plus : l'anomalie est signalée.
     */
    public static function getInstanceId(): string
    {
        $conf = Config::getConfigurationValues('plugin:secincident', ['instance_id']);
        $id   = (string) ($conf['instance_id'] ?? '');
        if (preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/', $id)) {
            return $id;
        }
        $bytes    = random_bytes(16);
        $bytes[6] = chr((ord($bytes[6]) & 0x0f) | 0x40);
        $bytes[8] = chr((ord($bytes[8]) & 0x3f) | 0x80);
        $id       = vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($bytes), 4));
        Config::setConfigurationValues('plugin:secincident', ['instance_id' => $id]);
        return $id;
    }

    /**
     * État actuel du journal, sous forme de point de contrôle.
     *
     * @return array<string, mixed>
     */
    public static function build(): array
    {
        global $DB, $CFG_GLPI;

        $chain = AuditLog::verifyChain();
        $last  = $DB->request([
            'SELECT' => ['id', 'hash', 'date_utc'],
            'FROM'   => AuditLog::getTable(),
            'ORDER'  => 'id DESC',
            'LIMIT'  => 1,
        ])->current();
        $last_id = (int) ($last['id'] ?? 0);

        return [
            'format'           => self::FORMAT,
            'instance_id'      => self::getInstanceId(),
            'instance_url'     => (string) ($CFG_GLPI['url_base'] ?? ''),
            'plugin_version'   => defined('PLUGIN_SECINCIDENT_VERSION') ? PLUGIN_SECINCIDENT_VERSION : '',
            'generated_at_utc' => gmdate('Y-m-d H:i:s'),
            'last_id'          => $last_id,
            'last_hash'        => (string) ($last['hash'] ?? AuditLog::GENESIS),
            'last_date_utc'    => (string) ($last['date_utc'] ?? ''),
            'count'            => self::countUpTo($last_id),
            'chain_ok'         => (bool) $chain['ok'],
        ];
    }

    /**
     * Exporte un point de contrôle et trace l'export dans le journal.
     *
     * @return array<string, mixed>
     */
    public static function export(string $channel): array
    {
        $checkpoint = self::build();
        AuditLog::record('checkpoint_export', null, [
            'canal'       => $channel,
            'derniere_entree' => $checkpoint['last_id'],
            'empreinte'   => $checkpoint['last_hash'],
            'entrees'     => $checkpoint['count'],
            'chainage_ok' => $checkpoint['chain_ok'],
        ], $checkpoint['chain_ok'] ? AuditLog::RESULT_OK : AuditLog::RESULT_ERROR);
        return $checkpoint;
    }

    public static function encode(array $checkpoint): string
    {
        return (string) json_encode($checkpoint, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    }

    /**
     * Lit un point de contrôle : objet JSON, ou fichier JSON Lines dont on prend
     * la dernière ligne non vide (un fichier en ajout seul en contient plusieurs).
     *
     * @return array<string, mixed>|null
     */
    public static function parse(string $raw): ?array
    {
        $raw = trim($raw);
        if ($raw === '') {
            return null;
        }
        $data = json_decode($raw, true);
        if (!is_array($data)) {
            $lines = array_values(array_filter(array_map('trim', preg_split('/\R/', $raw) ?: []), fn ($l) => $l !== ''));
            $data  = $lines !== [] ? json_decode((string) end($lines), true) : null;
        }
        return is_array($data) ? $data : null;
    }

    /**
     * Compare le journal actuel à un point de contrôle conservé à l'extérieur.
     *
     * @param array<string, mixed>|null $checkpoint
     * @return array<string, mixed>
     */
    public static function verify(?array $checkpoint, bool $log = true): array
    {
        global $DB;

        $result = [
            'ok'         => false,
            'anomalies'  => [],
            'checkpoint' => null,
            'covered'    => null,
            'newer'      => null,
            'chain'      => null,
        ];

        if (
            !is_array($checkpoint)
            || ($checkpoint['format'] ?? '') !== self::FORMAT
            || !isset($checkpoint['last_id'], $checkpoint['last_hash'], $checkpoint['count'], $checkpoint['instance_id'])
            || !is_int($checkpoint['last_id']) || $checkpoint['last_id'] < 0
            || !is_int($checkpoint['count']) || $checkpoint['count'] < 0
            || !is_string($checkpoint['last_hash']) || !preg_match('/^[0-9a-f]{64}$/', $checkpoint['last_hash'])
        ) {
            $result['anomalies'][] = ['code' => self::ANOMALY_FORMAT, 'message' => I18n::instance('invalid or unreadable checkpoint')];
            return self::finish($result, $log);
        }

        $last_id = (int) $checkpoint['last_id'];
        $result['checkpoint'] = [
            'instance_id'      => (string) $checkpoint['instance_id'],
            'generated_at_utc' => (string) ($checkpoint['generated_at_utc'] ?? ''),
            'last_id'          => $last_id,
            'last_hash'        => (string) $checkpoint['last_hash'],
            'last_date_utc'    => (string) ($checkpoint['last_date_utc'] ?? ''),
            'count'            => (int) $checkpoint['count'],
        ];

        if (!hash_equals(self::getInstanceId(), (string) $checkpoint['instance_id'])) {
            $result['anomalies'][] = ['code' => self::ANOMALY_INSTANCE, 'message' => I18n::instance('the checkpoint belongs to another instance, or the instance identifier was changed')];
        }

        $chain = AuditLog::verifyChain();
        $result['chain'] = $chain;
        if (!$chain['ok']) {
            $result['anomalies'][] = [
                'code'    => self::ANOMALY_CHAIN,
                'message' => sprintf(I18n::instance('chain broken at entry #%d: %s'), (int) $chain['broken_id'], $chain['reason']),
                'id'      => (int) $chain['broken_id'],
                // rupture dans la partie couverte par le point de contrôle, ou après
                'zone'    => (int) $chain['broken_id'] <= (int) $checkpoint['last_id'] ? 'covered' : 'newer',
            ];
        }

        $max_id = (int) ($DB->request(['SELECT' => ['MAX' => 'id AS m'], 'FROM' => AuditLog::getTable()])->current()['m'] ?? 0);

        if ($last_id > 0) {
            $row = $DB->request(['SELECT' => ['id', 'hash', 'date_utc'], 'FROM' => AuditLog::getTable(), 'WHERE' => ['id' => $last_id], 'LIMIT' => 1])->current();
            if (!$row) {
                $result['anomalies'][] = $max_id < $last_id
                    ? ['code' => self::ANOMALY_TRUNCATED, 'message' => sprintf(I18n::instance('log truncated: the checkpoint covers up to entry #%d, the log now ends at #%d'), $last_id, $max_id), 'id' => $last_id]
                    : ['code' => self::ANOMALY_MISSING, 'message' => sprintf(I18n::instance('entry #%d referenced by the checkpoint has disappeared'), $last_id), 'id' => $last_id];
            } elseif (!hash_equals((string) $checkpoint['last_hash'], (string) $row['hash'])) {
                $result['anomalies'][] = ['code' => self::ANOMALY_HASH, 'message' => sprintf(I18n::instance('fingerprint of entry #%d differs from the checkpoint (entry or chain rewritten)'), $last_id), 'id' => $last_id];
            }
        }

        $count = self::countUpTo($last_id);
        if ($count !== (int) $checkpoint['count']) {
            $result['anomalies'][] = ['code' => self::ANOMALY_COUNT, 'message' => sprintf(I18n::instance('%d entries up to #%d, the checkpoint records %d'), $count, $last_id, (int) $checkpoint['count'])];
        }

        $covered_row = $last_id > 0
            ? $DB->request(['SELECT' => ['date_utc'], 'FROM' => AuditLog::getTable(), 'WHERE' => ['id' => $last_id], 'LIMIT' => 1])->current()
            : null;
        $result['covered'] = [
            'until_id'       => $last_id,
            'until_date_utc' => (string) ($covered_row['date_utc'] ?? $checkpoint['last_date_utc'] ?? ''),
            'count'          => $count,
        ];

        $newer = $DB->request([
            'SELECT' => ['COUNT' => 'id AS n', 'MIN' => 'id AS fid', 'MAX' => 'id AS lid'],
            'FROM'   => AuditLog::getTable(),
            'WHERE'  => ['id' => ['>', $last_id]],
        ])->current();
        $newer_last = (int) ($newer['lid'] ?? 0);
        $result['newer'] = [
            'count'         => (int) ($newer['n'] ?? 0),
            'from_id'       => (int) ($newer['fid'] ?? 0),
            'to_id'         => $newer_last,
            'last_date_utc' => $newer_last > 0
                ? (string) ($DB->request(['SELECT' => ['date_utc'], 'FROM' => AuditLog::getTable(), 'WHERE' => ['id' => $newer_last]])->current()['date_utc'] ?? '')
                : '',
        ];

        $result['ok'] = $result['anomalies'] === [];
        return self::finish($result, $log);
    }

    /**
     * @param array<string, mixed> $result
     * @return array<string, mixed>
     */
    private static function finish(array $result, bool $log): array
    {
        if ($log) {
            AuditLog::record('checkpoint_verify', null, [
                'resultat'    => $result['ok'] ? I18n::instance('consistent') : I18n::instance('anomalies'),
                'anomalies'   => array_column($result['anomalies'], 'code'),
                'couvert_jusqu_a' => $result['covered']['until_id'] ?? null,
                'entrees_plus_recentes' => $result['newer']['count'] ?? null,
            ], $result['ok'] ? AuditLog::RESULT_OK : AuditLog::RESULT_ERROR);
        }
        return $result;
    }

    private static function countUpTo(int $last_id): int
    {
        global $DB;
        if ($last_id <= 0) {
            return 0;
        }
        try {
            return (int) ($DB->request(['COUNT' => 'n', 'FROM' => AuditLog::getTable(), 'WHERE' => ['id' => ['<=', $last_id]]])->current()['n'] ?? 0);
        } catch (Throwable $e) {
            return -1;
        }
    }
}
