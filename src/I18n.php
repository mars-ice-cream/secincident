<?php

/**
 * -------------------------------------------------------------------------
 * SecIncident — Suivi des incidents de sécurité pour GLPI 11
 * -------------------------------------------------------------------------
 * @license   GPLv3 https://www.gnu.org/licenses/gpl-3.0.html
 * -------------------------------------------------------------------------
 */

namespace GlpiPlugin\Secincident;

use Plugin;
use Throwable;

/**
 * Traductions dans la langue de l'INSTANCE (Configuration > Générale > Langue
 * par défaut), et non dans celle de l'utilisateur connecté.
 *
 * Utilisé pour tout ce qui est enregistré en base et relu par d'autres
 * personnes : journal d'audit, événements automatiques de la chronologie,
 * procédures et catégories installées par défaut. Le journal d'audit reste
 * ainsi homogène (une seule langue) quelle que soit la langue de chacun.
 */
class I18n
{
    /** @var array<string, bool> */
    private static array $loaded = [];

    public static function getInstanceLanguage(): string
    {
        global $CFG_GLPI;
        $lang = (string) ($CFG_GLPI['language'] ?? '');
        return $lang !== '' ? $lang : 'en_GB';
    }

    /**
     * Marque un texte à traduire plus tard (extraction gettext) sans le traduire.
     */
    public static function noop(string $message): string
    {
        return $message;
    }

    /**
     * Traduit dans la langue de l'utilisateur, ou dans celle de l'instance si
     * le texte est destiné à être enregistré.
     */
    public static function tr(string $message, bool $instance = false): string
    {
        return $instance ? self::instance($message) : __($message, 'secincident');
    }

    /**
     * Traduit un message du plugin dans la langue de l'instance.
     */
    public static function instance(string $message): string
    {
        global $TRANSLATE, $CFG_GLPI;

        $lang = self::getInstanceLanguage();
        try {
            if (!isset(self::$loaded[$lang])) {
                self::$loaded[$lang] = true;
                $file = $CFG_GLPI['languages'][$lang][1] ?? '';
                $mo   = Plugin::getPhpDir('secincident') . '/locales/' . $file;
                if ($file !== '' && is_readable($mo) && $TRANSLATE !== null) {
                    $TRANSLATE->addTranslationFile('gettext', $mo, 'secincident', $lang);
                }
            }
            if ($TRANSLATE === null) {
                return $message;
            }
            $translated = $TRANSLATE->translate($message, 'secincident', $lang);
            return is_string($translated) && $translated !== '' ? $translated : $message;
        } catch (Throwable) {
            return $message;
        }
    }
}
