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
 * Référentiel MITRE ATT&CK (Enterprise) embarqué dans data/mitre_attack.json.
 *
 * Valeurs enregistrées dans l'incident :
 *  - tactique  : nom anglais officiel (« Credential Access »), comme dans les exports EDR ;
 *  - technique : « T1003 – OS Credential Dumping » (identifiant + nom officiel).
 * Une ancienne valeur saisie librement et non reconnue est conservée telle quelle.
 *
 * © The MITRE Corporation. This work is reproduced and distributed with the
 * permission of The MITRE Corporation.
 */
class MitreAttack
{
    /** @var array<string, mixed>|null */
    private static ?array $data = null;

    /**
     * Noms des tactiques, pour l'extraction gettext (traduits dynamiquement dans getTactics).
     *
     * @return array<int, string>
     */
    public static function getTacticNamesForTranslation(): array
    {
        return [
            I18n::noop('Reconnaissance'), I18n::noop('Resource Development'), I18n::noop('Initial Access'),
            I18n::noop('Execution'), I18n::noop('Persistence'), I18n::noop('Privilege Escalation'),
            I18n::noop('Stealth'), I18n::noop('Defense Impairment'), I18n::noop('Credential Access'),
            I18n::noop('Discovery'), I18n::noop('Lateral Movement'), I18n::noop('Collection'),
            I18n::noop('Command and Control'), I18n::noop('Exfiltration'), I18n::noop('Impact'),
        ];
    }

    /** Noms français des tactiques, acceptés en saisie (normalisation) */
    private const TACTICS_FR = [
        'Reconnaissance'       => 'Reconnaissance',
        'Resource Development' => 'Développement de ressources',
        'Initial Access'       => 'Accès initial',
        'Execution'            => 'Exécution',
        'Persistence'          => 'Persistance',
        'Privilege Escalation' => 'Élévation de privilèges',
        'Stealth'              => 'Furtivité',
        'Defense Impairment'   => 'Neutralisation des défenses',
        'Credential Access'    => 'Accès aux identifiants',
        'Discovery'            => 'Découverte',
        'Lateral Movement'     => 'Mouvement latéral',
        'Collection'           => 'Collecte',
        'Command and Control'  => 'Commande et contrôle',
        'Exfiltration'         => 'Exfiltration',
        'Impact'               => 'Impact',
    ];

    /** Anciens noms encore employés par certains outils (EDR, SIEM) */
    private const TACTIC_ALIASES = [
        'defense evasion' => 'Stealth',
        'evasion'         => 'Stealth',
        'c2'              => 'Command and Control',
    ];

    /**
     * @return array<string, mixed>
     */
    private static function data(): array
    {
        if (self::$data === null) {
            $file = dirname(__DIR__) . '/data/mitre_attack.json';
            $json = is_readable($file) ? json_decode((string) file_get_contents($file), true) : null;
            self::$data = is_array($json) ? $json : ['version' => '', 'tactics' => [], 'techniques' => []];
        }
        return self::$data;
    }

    public static function getVersion(): string
    {
        return (string) (self::data()['version'] ?? '');
    }

    /**
     * Tactiques dans l'ordre de la matrice : nom anglais => libellé affiché.
     *
     * @return array<string, string>
     */
    public static function getTactics(): array
    {
        $list = [];
        foreach (self::data()['tactics'] as $tactic) {
            // Nom officiel (anglais) + traduction dans la langue de l'utilisateur si elle diffère
            $translated = __($tactic['name'], 'secincident');
            $list[$tactic['name']] = $tactic['id'] . ' · ' . $tactic['name'] . ($translated !== $tactic['name'] ? ' — ' . $translated : '');
        }
        return $list;
    }

    /**
     * Techniques et sous-techniques : valeur enregistrée => libellé.
     *
     * @return array<string, string>
     */
    public static function getTechniques(): array
    {
        $list = [];
        foreach (self::data()['techniques'] as $technique) {
            $value = self::techniqueValue($technique);
            $list[$value] = $value;
        }
        return $list;
    }

    /**
     * Tactiques de chaque technique (pour filtrer la liste dans le formulaire).
     *
     * @return array<string, array<int, string>> valeur de technique => noms anglais des tactiques
     */
    public static function getTechniqueTactics(): array
    {
        $short = [];
        foreach (self::data()['tactics'] as $tactic) {
            $short[$tactic['short']] = $tactic['name'];
        }
        $map = [];
        foreach (self::data()['techniques'] as $technique) {
            $map[self::techniqueValue($technique)] = array_values(array_filter(array_map(
                fn ($s) => $short[$s] ?? null,
                $technique['tactics']
            )));
        }
        return $map;
    }

    /**
     * @param array{id: string, name: string} $technique
     */
    private static function techniqueValue(array $technique): string
    {
        return $technique['id'] . ' – ' . $technique['name'];
    }

    // ---------------------------------------------------------------------
    // Normalisation (formulaire, API, import CSV)
    // ---------------------------------------------------------------------

    /**
     * Ramène une tactique saisie (nom, identifiant TA…, nom français, ancien nom)
     * à son nom officiel. Valeur inconnue : renvoyée telle quelle.
     */
    public static function normalizeTactic(?string $value): ?string
    {
        $value = trim((string) $value);
        // « 0 » = choix vide de la liste déroulante GLPI
        if ($value === '' || $value === '0') {
            return null;
        }
        $index = [];
        foreach (self::data()['tactics'] as $tactic) {
            foreach ([$tactic['id'], $tactic['name'], $tactic['short'], self::TACTICS_FR[$tactic['name']] ?? ''] as $key) {
                if ($key !== '') {
                    $index[mb_strtolower($key)] = $tactic['name'];
                }
            }
        }
        foreach (self::TACTIC_ALIASES as $alias => $name) {
            $index[$alias] = $name;
        }
        // Valeur exacte, ou première tactique reconnue d'une liste « A, B » / « A; B »
        foreach (array_merge([$value], preg_split('/\s*[,;|\/]\s*/', $value) ?: []) as $candidate) {
            $key = mb_strtolower(trim($candidate));
            if (preg_match('/^(TA\d{4})\b/i', $candidate, $m)) {
                $key = mb_strtolower($m[1]);
            }
            if (isset($index[$key])) {
                return $index[$key];
            }
        }
        // Libellé de la liste déroulante (« TA0006 · Credential Access — … »)
        if (preg_match('/^(TA\d{4})/i', $value, $m) && isset($index[mb_strtolower($m[1])])) {
            return $index[mb_strtolower($m[1])];
        }
        return mb_strimwidth($value, 0, 250);
    }

    /**
     * Ramène une technique saisie (« T1566 », « T1566.001 », « Phishing »,
     * « OS Credential Dumping »…) à la valeur canonique « Txxxx – Nom ».
     * Valeur inconnue : renvoyée telle quelle.
     */
    public static function normalizeTechnique(?string $value): ?string
    {
        $value = trim((string) $value);
        // « 0 » = choix vide de la liste déroulante GLPI
        if ($value === '' || $value === '0') {
            return null;
        }
        $by_id   = [];
        $by_name = [];
        $sub_names = [];
        foreach (self::data()['techniques'] as $technique) {
            $canonical = self::techniqueValue($technique);
            $by_id[strtoupper($technique['id'])] = $canonical;
            $by_name[mb_strtolower($technique['name'])] ??= $canonical;
            // Nom court d'une sous-technique (« Spearphishing Attachment ») si non ambigu
            if (str_contains($technique['name'], ' : ')) {
                $short = mb_strtolower(substr($technique['name'], strrpos($technique['name'], ' : ') + 3));
                $sub_names[$short][] = $canonical;
            }
        }
        if (preg_match('/\b(T\d{4}(?:\.\d{3})?)\b/i', $value, $m)) {
            $id = strtoupper($m[1]);
            if (isset($by_id[$id])) {
                return $by_id[$id];
            }
            // Sous-technique inconnue : on retombe sur la technique parente
            $parent = substr($id, 0, 5);
            if (isset($by_id[$parent])) {
                return $by_id[$parent];
            }
        }
        $key = mb_strtolower($value);
        if (isset($by_name[$key])) {
            return $by_name[$key];
        }
        if (isset($sub_names[$key]) && count($sub_names[$key]) === 1) {
            return $sub_names[$key][0];
        }
        return mb_strimwidth($value, 0, 250);
    }

    /**
     * Normalise les deux champs d'un input et complète la tactique si la
     * technique n'en a qu'une.
     *
     * @param array<string, mixed> $input
     * @return array<string, mixed>
     */
    public static function normalizeInput(array $input): array
    {
        if (array_key_exists('mitre_tactic', $input)) {
            $input['mitre_tactic'] = self::normalizeTactic((string) $input['mitre_tactic']);
        }
        if (array_key_exists('mitre_technique', $input)) {
            $input['mitre_technique'] = self::normalizeTechnique((string) $input['mitre_technique']);
            $tactics = self::getTechniqueTactics()[$input['mitre_technique'] ?? ''] ?? [];
            if (
                count($tactics) === 1
                && array_key_exists('mitre_tactic', $input)
                && ($input['mitre_tactic'] === null || $input['mitre_tactic'] === '')
            ) {
                $input['mitre_tactic'] = $tactics[0];
            }
        }
        return $input;
    }
}
