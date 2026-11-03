# Contribuer

## Branches

| Branche | GLPI | Versions |
|---|---|---|
| `main` | 12.0.x | 2.x |
| `glpi-11` | 11.0.x | 1.x |

Les deux branches gardent les mêmes fonctionnalités. Le code est identique, sauf :

- `setup.php` : numéro de version, bornes GLPI (`PLUGIN_SECINCIDENT_MIN_GLPI` / `MAX_GLPI`), PHP minimal ;
- `src/*.php` : types des propriétés héritées de GLPI (`public static string $rightname`, `public bool $dohistory`… sur `main`, sans type sur `glpi-11`) — GLPI 12 les exige, GLPI 11 les refuse ;
- `templates/parts/csrf.html.twig` : vide sur `main`, champ `_glpi_csrf_token` sur `glpi-11` ;

Tout ce qui dépend d'une version de GLPI passe par un test d'existence (`class_exists`, `method_exists`) plutôt que par une divergence de code, comme `AccessGuard::requireReauthentication()`.

## Faire une évolution

1. Développer et tester sur `main` (GLPI 12), dans des commits qui ne touchent pas aux fichiers ci-dessus.
2. Reporter sur `glpi-11` : `git checkout glpi-11 && git cherry-pick <commits>`.
3. Lancer les tests sur GLPI 12 et sur GLPI 11.
4. Publier ensemble : `1.N.x` depuis `glpi-11`, `2.N.x` depuis `main`. `CHANGELOG.md`, `secincident.xml` et la documentation sont identiques sur les deux branches et listent les deux versions.

Nouvelle propriété qui redéfinit une propriété de GLPI : typée sur `main`, sans type sur `glpi-11`.

## Tests

Tests d'intégration contre une instance GLPI réelle : voir [tests/README.md](tests/README.md). Ils tournent en intégration continue sur chaque branche (GLPI 12 sur `main`, GLPI 11.0.4 et 11.0.11 sur `glpi-11`), avec en plus, sur `main`, une migration GLPI 11 → 12 avec données.

## Traductions

Chaînes source en anglais, domaine `secincident`. Après toute modification de texte : `python3 tools/i18n.py` (vérification : `--check`).

## Sécurité

Pour une faille, ne pas ouvrir d'issue publique : voir [SECURITY.md](SECURITY.md).
