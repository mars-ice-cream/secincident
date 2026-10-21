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
 * Une valeur vide envoyée (formulaire, API) pour une colonne entière devient 0
 * (ou NULL si la colonne l'accepte) au lieu de provoquer une erreur SQL.
 */
trait IntegerInputTrait
{
    /**
     * @param array<string, mixed> $values
     * @param array<int, string>|null $only
     * @return array<string, mixed>
     */
    private function castEmptyIntegers(array $values, ?array $only = null): array
    {
        global $DB;

        foreach ($DB->listFields(static::getTable()) as $name => $column) {
            if ($only !== null && !in_array($name, $only, true)) {
                continue;
            }
            if (!array_key_exists($name, $values) || $values[$name] !== '') {
                continue;
            }
            if (preg_match('/^(tiny|small|medium|big)?int/i', (string) $column['Type'])) {
                $values[$name] = strtoupper((string) $column['Null']) === 'YES' ? null : 0;
            }
        }
        return $values;
    }

    public function pre_addInDB()
    {
        if (is_array($this->input)) {
            $this->input = $this->castEmptyIntegers($this->input);
        }
        parent::pre_addInDB();
    }

    public function pre_updateInDB()
    {
        $this->fields = $this->castEmptyIntegers($this->fields, $this->updates);
        parent::pre_updateInDB();
    }
}
