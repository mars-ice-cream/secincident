<?php

/**
 * -------------------------------------------------------------------------
 * SecIncident — Suivi des incidents de sécurité pour GLPI 11
 * -------------------------------------------------------------------------
 * @license   GPLv3 https://www.gnu.org/licenses/gpl-3.0.html
 * -------------------------------------------------------------------------
 */

namespace GlpiPlugin\Secincident;

use Config;
use Glpi\Application\View\TemplateRenderer;
use Group;
use Group_User;
use Profile;
use Profile_User;
use QueuedNotification;
use Session;
use Throwable;
use User;

/**
 * Contrôle d'accès renforcé au plugin.
 *
 *  - Restriction optionnelle à un groupe GLPI : même avec les droits dans son
 *    profil, un utilisateur hors du groupe n'a aucun accès au plugin.
 *  - Toute ouverture d'accès (droits d'un profil, attribution d'un profil
 *    donnant accès, ajout au groupe, changement de configuration,
 *    désactivation du plugin) est tracée et déclenche une alerte par mail.
 *
 * Limite assumée : un Super-Admin garde la main sur GLPI. Il peut se donner
 * l'accès, mais pas discrètement.
 */
class AccessGuard
{
    private const CONTEXT = 'plugin:secincident';

    /** Valeur réelle des droits du profil actif, avant restriction */
    private static ?int $profile_rights = null;

    /**
     * @return array{restrict_groups_id: int, alert_emails: array<int, string>}
     */
    public static function getConfig(): array
    {
        $config = Config::getConfigurationValues(self::CONTEXT, ['restrict_groups_id', 'alert_emails']);
        return [
            'restrict_groups_id' => (int) ($config['restrict_groups_id'] ?? 0),
            'alert_emails'       => self::parseEmails((string) ($config['alert_emails'] ?? '')),
        ];
    }

    /**
     * @return array<int, string>
     */
    public static function parseEmails(string $value): array
    {
        $emails = [];
        foreach (preg_split('/[\s,;]+/', $value) ?: [] as $email) {
            $email = trim($email);
            if ($email !== '' && filter_var($email, FILTER_VALIDATE_EMAIL)) {
                $emails[] = strtolower($email);
            }
        }
        return array_values(array_unique($emails));
    }

    public static function isMember(int $users_id, int $groups_id): bool
    {
        return $users_id > 0 && $groups_id > 0
            && countElementsInTable(Group_User::getTable(), ['users_id' => $users_id, 'groups_id' => $groups_id]) > 0;
    }

    // ---------------------------------------------------------------------
    // Restriction par groupe
    // ---------------------------------------------------------------------

    /**
     * Appelé à chaque requête (initialisation du plugin) : neutralise les droits
     * du plugin dans la session d'un utilisateur hors du groupe sécurité.
     * Recalculé à partir de la base à chaque fois : un ajout ou un retrait du
     * groupe s'applique immédiatement, sans reconnexion.
     */
    public static function applyGroupRestriction(): void
    {
        global $DB;

        try {
            $users_id    = (int) Session::getLoginUserID();
            $profiles_id = (int) ($_SESSION['glpiactiveprofile']['id'] ?? 0);
            if ($users_id <= 0 || $profiles_id <= 0 || !$DB->tableExists('glpi_configs')) {
                return;
            }
            $groups_id = self::getConfig()['restrict_groups_id'];
            if ($groups_id <= 0) {
                return;
            }
            self::$profile_rights = (int) ($DB->request([
                'SELECT' => ['rights'],
                'FROM'   => 'glpi_profilerights',
                'WHERE'  => ['profiles_id' => $profiles_id, 'name' => Incident::$rightname],
            ])->current()['rights'] ?? 0);
            $_SESSION['glpiactiveprofile'][Incident::$rightname] = self::isMember($users_id, $groups_id)
                ? self::$profile_rights
                : 0;
        } catch (Throwable $e) {
            trigger_error('SecIncident access guard: ' . $e->getMessage(), E_USER_WARNING);
        }
    }

    /**
     * Droits accordés par le profil mais neutralisés car hors du groupe sécurité.
     */
    public static function isBlockedByGroup(): bool
    {
        return self::$profile_rights !== null
            && self::$profile_rights > 0
            && (int) ($_SESSION['glpiactiveprofile'][Incident::$rightname] ?? 0) === 0;
    }

    // ---------------------------------------------------------------------
    // Alertes
    // ---------------------------------------------------------------------

    /**
     * Trace l'événement et envoie une alerte aux adresses configurées
     * (file d'attente des notifications GLPI : action automatique « queuednotification »).
     *
     * @param array<string, mixed> $details
     */
    public static function alert(string $action, string $subject, array $details, ?array $recipients = null): void
    {
        AuditLog::record($action, null, $details + ['alerte' => true]);
        self::sendMail($recipients ?? self::getConfig()['alert_emails'], $subject, $details);
    }

    /**
     * @param array<int, string>   $emails
     * @param array<string, mixed> $details
     */
    private static function sendMail(array $emails, string $subject, array $details): void
    {
        if ($emails === []) {
            return;
        }
        try {
            $actor = (int) Session::getLoginUserID();
            $lines = [
                $subject,
                '',
                sprintf(I18n::instance('By: %s'), $actor > 0 ? getUserName($actor) . ' (#' . $actor . ')' : (PHP_SAPI === 'cli' ? 'CLI' : '?')),
                sprintf(I18n::instance('Date: %s'), $_SESSION['glpi_currenttime'] ?? date('Y-m-d H:i:s')),
                sprintf(I18n::instance('IP address: %s'), (string) ($_SERVER['REMOTE_ADDR'] ?? '-')),
                '',
            ];
            foreach ($details as $key => $value) {
                $lines[] = $key . ' : ' . (is_scalar($value) ? (string) $value : (string) json_encode($value, JSON_UNESCAPED_UNICODE));
            }
            $lines[] = '';
            $lines[] = I18n::instance('This event is recorded in the SecIncident audit log.');
            $text   = implode("\n", $lines);
            $sender = Config::getAdminEmailSender();
            foreach (array_unique($emails) as $email) {
                (new QueuedNotification())->add([
                    'itemtype'                 => '',
                    'items_id'                 => 0,
                    'notificationtemplates_id' => 0,
                    'entities_id'              => 0,
                    'name'                     => '[SecIncident] ' . $subject,
                    'sender'                   => $sender['email'] ?? '',
                    'sendername'               => $sender['name'] ?? 'GLPI',
                    'recipient'                => $email,
                    'recipientname'            => $email,
                    'body_text'                => $text,
                    'body_html'                => '<pre style="font-family:sans-serif;white-space:pre-wrap">' . htmlescape($text) . '</pre>',
                    'messageid'                => '<secincident.' . bin2hex(random_bytes(8)) . '@' . (gethostname() ?: 'glpi') . '>',
                    'mode'                     => 'mailing',
                ]);
            }
        } catch (Throwable $e) {
            trigger_error('SecIncident alert: ' . $e->getMessage(), E_USER_WARNING);
        }
    }

    /** Les notifications par mail de GLPI sont-elles actives ? */
    public static function isMailingEnabled(): bool
    {
        global $CFG_GLPI;
        return !empty($CFG_GLPI['use_notifications']) && !empty($CFG_GLPI['notifications_mailing']);
    }

    // ---------------------------------------------------------------------
    // Hooks GLPI
    // ---------------------------------------------------------------------

    private static function profileGrantsAccess(int $profiles_id): int
    {
        global $DB;
        return (int) ($DB->request([
            'SELECT' => ['rights'],
            'FROM'   => 'glpi_profilerights',
            'WHERE'  => ['profiles_id' => $profiles_id, 'name' => Incident::$rightname],
        ])->current()['rights'] ?? 0);
    }

    private static function name(string $itemtype, int $id): string
    {
        $item = getItemForItemtype($itemtype);
        return $item && $item->getFromDB($id) ? (string) $item->getName() : '#' . $id;
    }

    /** Un profil donnant accès au plugin est attribué à un utilisateur */
    public static function onProfileUserAdd(Profile_User $link): void
    {
        $profiles_id = (int) ($link->fields['profiles_id'] ?? 0);
        $rights      = self::profileGrantsAccess($profiles_id);
        if ($rights === 0) {
            return;
        }
        $users_id = (int) $link->fields['users_id'];
        self::alert('access_grant', sprintf(
            I18n::instance('Profile with access to security incidents assigned to %s'),
            self::name(User::class, $users_id)
        ), [
            'utilisateur' => self::name(User::class, $users_id) . ' (#' . $users_id . ')',
            'profil'      => self::name(Profile::class, $profiles_id),
            'droits'      => AuditLog::rightsToLabels($rights),
        ]);
    }

    public static function onProfileUserPurge(Profile_User $link): void
    {
        $profiles_id = (int) ($link->fields['profiles_id'] ?? 0);
        if (self::profileGrantsAccess($profiles_id) === 0) {
            return;
        }
        $users_id = (int) $link->fields['users_id'];
        AuditLog::record('access_revoke', null, [
            'utilisateur' => self::name(User::class, $users_id) . ' (#' . $users_id . ')',
            'profil'      => self::name(Profile::class, $profiles_id),
        ]);
    }

    /** Ajout d'un utilisateur au groupe sécurité */
    public static function onGroupUserAdd(Group_User $link): void
    {
        $groups_id = self::getConfig()['restrict_groups_id'];
        if ($groups_id <= 0 || (int) ($link->fields['groups_id'] ?? 0) !== $groups_id) {
            return;
        }
        $users_id = (int) $link->fields['users_id'];
        self::alert('access_grant', sprintf(
            I18n::instance('%s added to the security group'),
            self::name(User::class, $users_id)
        ), [
            'utilisateur' => self::name(User::class, $users_id) . ' (#' . $users_id . ')',
            'groupe'      => self::name(Group::class, $groups_id),
        ]);
    }

    public static function onGroupUserPurge(Group_User $link): void
    {
        $groups_id = self::getConfig()['restrict_groups_id'];
        if ($groups_id <= 0 || (int) ($link->fields['groups_id'] ?? 0) !== $groups_id) {
            return;
        }
        $users_id = (int) $link->fields['users_id'];
        AuditLog::record('access_revoke', null, [
            'utilisateur' => self::name(User::class, $users_id) . ' (#' . $users_id . ')',
            'groupe'      => self::name(Group::class, $groups_id),
        ]);
    }

    /** Changement des droits du plugin sur un profil (appelé après l'audit existant) */
    public static function onProfileRightsChange(string $profile_name, int $old, int $new): void
    {
        if (($new & ~$old) === 0) {
            return; // retrait de droits uniquement : tracé, pas d'alerte
        }
        self::alert('access_grant', sprintf(
            I18n::instance('Security incident rights extended on profile %s'),
            $profile_name
        ), [
            'profil' => $profile_name,
            'avant'  => AuditLog::rightsToLabels($old),
            'apres'  => AuditLog::rightsToLabels($new),
        ]);
    }

    // ---------------------------------------------------------------------
    // Configuration
    // ---------------------------------------------------------------------

    public static function canConfigure(): bool
    {
        return Session::haveRight(Incident::$rightname, Incident::AUDIT);
    }

    /**
     * @param array<string, mixed> $input
     */
    public static function saveConfig(array $input): void
    {
        $before    = self::getConfig();
        $groups_id = max(0, (int) ($input['restrict_groups_id'] ?? 0));
        $emails    = self::parseEmails((string) ($input['alert_emails'] ?? ''));

        // Garde-fou : on ne peut pas activer une restriction qui exclut la personne qui l'active
        if ($groups_id > 0 && !self::isMember((int) Session::getLoginUserID(), $groups_id)) {
            Session::addMessageAfterRedirect(
                __s('You must be a member of the security group yourself before enabling the restriction.', 'secincident'),
                false,
                ERROR
            );
            return;
        }

        Config::setConfigurationValues(self::CONTEXT, [
            'restrict_groups_id' => $groups_id,
            'alert_emails'       => implode(', ', $emails),
        ]);

        $changes = [];
        if ($before['restrict_groups_id'] !== $groups_id) {
            $changes['groupe'] = [
                'avant' => $before['restrict_groups_id'] > 0 ? self::name(Group::class, $before['restrict_groups_id']) : I18n::instance('none'),
                'apres' => $groups_id > 0 ? self::name(Group::class, $groups_id) : I18n::instance('none'),
            ];
        }
        if ($before['alert_emails'] !== $emails) {
            $changes['alertes'] = ['avant' => $before['alert_emails'], 'apres' => $emails];
        }
        if ($changes === []) {
            return;
        }
        // Alerte envoyée aux anciennes ET aux nouvelles adresses : retirer un
        // destinataire ou la restriction ne passe pas inaperçu.
        self::alert(
            'config_change',
            I18n::instance('SecIncident access settings changed'),
            $changes,
            array_values(array_unique(array_merge($before['alert_emails'], $emails)))
        );
        Session::addMessageAfterRedirect(__s('Settings saved', 'secincident'));
    }

    public static function showConfigForm(): void
    {
        $config = self::getConfig();
        TemplateRenderer::getInstance()->display('@secincident/config.html.twig', [
            'groups_id'       => $config['restrict_groups_id'],
            'alert_emails'    => implode(', ', $config['alert_emails']),
            'mailing_enabled' => self::isMailingEnabled(),
            'action'          => $GLOBALS['CFG_GLPI']['root_doc'] . '/plugins/secincident/front/config.form.php',
            'profiles_url'    => Profile::getSearchURL(),
        ]);
    }
}
