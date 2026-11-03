# Tests d'intégration SecIncident

Les tests pilotent une instance GLPI réelle (HTTP) et lisent ou altèrent sa base (client `mysql`) pour simuler ce que ferait quelqu'un qui a accès à la base. **N'utilisez jamais une instance de production** : les tests suppriment et réécrivent des entrées du journal d'audit (puis les restaurent), créent des utilisateurs, une entité et un groupe.

Prérequis : Python 3.10+ (bibliothèque standard), client `mysql`, PHP en ligne de commande. Instance GLPI 12 (branche `main`) ou 11 (branche `glpi-11`) avec SecIncident installé, comptes par défaut (`glpi`, `tech`, `normal`).

```
export SI_BASE=http://127.0.0.1:8080        # URL de GLPI
export SI_DB=glpi                           # base GLPI
export SI_MYSQL="mysql -h 127.0.0.1 -uroot -proot"
export SI_GLPI_DIR=/var/www/glpi            # facultatif : commande console, fichier d'échecs, mise à jour du plugin
python3 tests/run.py                        # ou : python3 tests/run.py test_audit
```

Le serveur web intégré de PHP suffit, avec plusieurs workers pour les tests de concurrence :
`PHP_CLI_SERVER_WORKERS=6 php -S 127.0.0.1:8080 -t /var/www/glpi/public tests/router.php`.

| Fichier | Couvre |
|---|---|
| `test_audit.py` | verrou maintenu jusqu'à expiration (aucune entrée écrite, échec visible), écritures concurrentes (pas de fourche), insertion refusée, altération d'une entrée, troncature sans point de contrôle (non détectée, limite documentée) et avec (détectée), entrée référencée disparue, réécriture complète de la chaîne, autre instance, commande console |
| `test_integrity.py` | intact, altéré, manquant, non scellé (sans empreinte, jamais ancré après un échec de journalisation), preuve absente du journal, aucun rescellement par la vérification ni par une mise à jour du plugin |
| `test_isolation.py` | cloisonnement entre techniciens et entre entités dans la liste, la recherche, les accès directs (fiche, onglets, sous-objets, éditions), les exports CSV ; révocation du groupe sécurité sur une session ouverte |
| `migration_seed.py`, `migration_check.py` | migration GLPI 11 → 12 avec données : droits, paramètres, journal, empreintes, verdicts et point de contrôle conservés (job `migration` de la CI) |
