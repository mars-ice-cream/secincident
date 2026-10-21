<?php

/**
 * -------------------------------------------------------------------------
 * SecIncident — Suivi des incidents de sécurité pour GLPI 11
 * -------------------------------------------------------------------------
 * @license   GPLv3 https://www.gnu.org/licenses/gpl-3.0.html
 * -------------------------------------------------------------------------
 */

namespace GlpiPlugin\Secincident;

/**
 * Comportements communs aux sous-objets d'un incident
 * (chronologie, IOC, éléments liés) : cloisonnement SQL et audit.
 *
 * Mettre `_no_audit => AuditLog::silent()` (jeton interne, non falsifiable) dans l'input pour les écritures déjà couvertes
 * par une entrée d'audit globale (import CSV, événements automatiques).
 */
trait IncidentChildTrait
{
    /**
     * Les sous-objets ne sont visibles que si l'incident parent l'est.
     */
    public static function getSystemSQLCriteria(?string $tablename = null): array
    {
        $subquery = Incident::getVisibleIdsSubQuery();
        if ($subquery === null) {
            return [];
        }
        $table = $tablename ?? static::getTable();
        return [920131 => [$table . '.' . Incident::getForeignKeyField() => $subquery]];
    }

    public function post_addItem()
    {
        parent::post_addItem();
        $empreinte = Integrity::seal($this);
        if (!AuditLog::isSilent($this->input)) {
            AuditLog::record(static::getAuditAction('add'), $this, $this->getAuditSummary() + ['empreinte' => $empreinte]);
        } elseif ($empreinte !== null) {
            AuditLog::anchor(static::class, (int) $this->getID(), (int) $this->fields[Incident::getForeignKeyField()], $empreinte);
        }
    }

    public function post_updateItem($history = true)
    {
        parent::post_updateItem($history);
        $empreinte = Integrity::seal($this);
        $diff      = AuditLog::diff($this->updates, $this->oldvalues, $this->fields);
        if (AuditLog::isSilent($this->input)) {
            if ($empreinte !== null) {
                AuditLog::anchor(static::class, (int) $this->getID(), (int) $this->fields[Incident::getForeignKeyField()], $empreinte);
            }
        } elseif ($diff !== []) {
            AuditLog::record('update', $this, ['champs' => $diff, 'empreinte' => $empreinte]);
        }
    }

    public function post_purgeItem()
    {
        parent::post_purgeItem();
        AuditLog::record(static::getAuditAction('purge'), $this, $this->getAuditSummary());
    }

    protected static function getAuditAction(string $operation): string
    {
        return $operation === 'add' ? 'create' : 'purge';
    }

    /**
     * @return array<string, mixed>
     */
    protected function getAuditSummary(): array
    {
        return array_intersect_key(
            $this->fields,
            array_flip(['name', 'event_type', 'date', 'target', 'tool', 'command', 'result', 'detection_ref', 'ioc_type', 'value', 'verdict', 'itemtype', 'items_id', 'source'])
        );
    }
}
