# Changelog

Deux branches maintenues en parallèle, avec les mêmes fonctionnalités : 2.x pour GLPI 12 (`main`), 1.x pour GLPI 11 (`glpi-11`).

## 2.1.0 (GLPI 12) et 1.11.0 (GLPI 11) — 2026-11-03
Mêmes corrections sur les deux branches.

- **Journal d'audit — écritures concurrentes** : si le verrou de chaînage n'est pas obtenu dans le délai, plus aucune entrée n'est écrite (auparavant l'écriture continuait sans verrou et pouvait rompre la chaîne). Le résultat de l'insertion est vérifié. Tout échec est visible : message à l'utilisateur, bandeau sur la page du journal jusqu'à acquittement (journalisé), entrée complète consignée dans `files/_log/secincident-audit-failures.log`. Délai réglable (`audit_lock_timeout`).
- **Intégrité — faux positifs** : un élément sans ancre dans le journal (inséré hors application, empreinte effacée, ou dont la journalisation a échoué) est « non scellé » et empêche de conclure à l'intégrité. Trois verdicts : intact, anomalies, intégrité non établie. Les preuves absentes du journal sont signalées de la même façon.
- **Intégrité — pas de rescellement automatique** : les mises à jour du plugin ne scellent plus les lignes sans empreinte (seules les données antérieures à 1.2.0 reçoivent le scellement initial) ; la migration 1.5.0 ne rescelle plus que les lignes vérifiées intactes. Après mise à jour, des éléments « non scellés » auparavant comptés à tort comme intacts peuvent apparaître.
- **Point de contrôle externe du journal** : export (page du journal ou `php bin/console plugins:secincident:audit-checkpoint`) et vérification d'un point de contrôle (instance, dernière entrée, empreinte, nombre d'entrées) conservé hors de la base. Détecte la suppression des dernières entrées et la réécriture de la chaîne ; affiche la dernière entrée couverte et distingue les entrées plus récentes, vérifiées par chaînage seul.
- **Groupe sécurité** : retirer quelqu'un du groupe retire aussi l'entrée de menu de sa session ouverte ; lever la restriction rend l'accès du profil aux sessions ouvertes sans reconnexion.
- **Documentation** : « journal d'audit chaîné avec détection d'altérations » ; ce que détecte le chaînage, ce que couvre le point de contrôle, comment repérer un échec de journalisation.
- **Tests** : tests d'intégration (`tests/`) et intégration continue GitHub Actions : verrou expiré, concurrence, échec d'écriture, altération, troncature avec et sans point de contrôle, éléments non scellés, cloisonnement (techniciens, entités, recherche, accès directs, exports), révocation du groupe sécurité en cours de session, migration GLPI 11 → 12 avec données.

## 2.0.0 — 2026-11-02 (GLPI 12, branche `main`)
- Compatibilité GLPI 12.0.x (PHP 8.3+). Mêmes fonctionnalités que la 1.10.x pour GLPI 11.
- Propriétés héritées de GLPI typées (exigence de GLPI 12).
- Plus de jeton CSRF dans les formulaires : GLPI 12 vérifie l'origine des requêtes.
- Paramètres d'accès : ré-authentification exigée (mot de passe redemandé) avant de les afficher ou de les modifier.
- Mise à jour depuis la 1.10.x sous GLPI 11 : données, droits, paramètres et journal d'audit conservés.
- Documentation : passation et récupération de l'accès.

## 1.10.1 — 2026-11-02 (GLPI 11, branche `glpi-11`)
- Branche de maintenance GLPI 11 ; mêmes fonctionnalités que la 2.0.0.
- Code commun aux deux branches : jeton CSRF des formulaires centralisé, ré-authentification sur les Paramètres d'accès quand GLPI la propose.
- Documentation : versions et branches, passation et récupération de l'accès, guide de contribution.

## 1.10.0 — 2026-10-30
- Installation neuve : aucun profil n'a accès au plugin, pas même Super-Admin ; les profils créés ensuite non plus (les mises à jour ne donnent plus de droits automatiquement).
- Paramètres d'accès : restriction optionnelle à un groupe GLPI « sécurité » (appliquée immédiatement, sans reconnexion).
- Alertes par mail au RSSI et traces d'audit pour toute ouverture d'accès : droits étendus sur un profil, attribution d'un profil donnant accès, ajout au groupe sécurité, changement des paramètres, désactivation / désinstallation du plugin.

## 1.9.1 — 2026-10-21
- Journal d'audit : verrou de chaînage via l'API GLPI (`getLock` / `releaseLock`) au lieu de SQL brut (exigence Marketplace).
- Logo du plugin et fiche catalogue complétée.

## 1.9.0 — 2026-10-20
- Multilingue : chaînes source en anglais, traduction française complète (fr_FR, fr_CA, fr_BE), catalogue `locales/secincident.pot` pour ajouter d'autres langues, outil `tools/i18n.py`.
- Contenu enregistré (journal d'audit, événements automatiques, procédures et catégories par défaut) écrit dans la langue par défaut de l'instance, pour un journal homogène.
- Tactiques MITRE ATT&CK : libellé traduit dans la langue de l'utilisateur à côté du nom officiel.

## 1.8.0 — 2026-10-20
- Plugin neutre vis-à-vis de l'éditeur : « EDR / XDR » remplace toute mention d'un éditeur (import CSV, source, outil, procédures par défaut, exemple). Reconnaissance d'en-têtes CSV élargie aux EDR courants.
- Robustesse : une valeur vide envoyée pour un champ numérique (formulaire, API) n'entraîne plus d'erreur SQL.
- Journal imprimable : séparateur en trop dans la ligne « Résultats » corrigé ; captures d'écran refaites avec un jeu de démonstration neutre.
- Migration : clés internes renommées ; vérification d'intégrité des incidents concernés avant, rescellement des seules lignes intactes (une ligne déjà altérée reste signalée), le tout tracé.

## 1.7.0 — 2026-10-20
- MITRE ATT&CK : liste déroulante des 15 tactiques et liste avec recherche des 706 techniques / sous-techniques (référentiel Enterprise v20 embarqué), filtrage par tactique, déduction de la tactique, normalisation des saisies et des imports EDR.
- Tableau de bord : répartition par tactique et techniques les plus fréquentes.
- Catégories : deux catégories ne peuvent plus porter le même nom.

## 1.6.1 — 2026-10-20
- Plan de remédiation : ajout, suppression et modification de la définition des tâches réservés au droit « Gérer les procédures » ; les intervenants renseignent statut, assignation et compte rendu (toute tentative hors droits est refusée et tracée).
- Journal téléchargeable : inclut les tâches de remédiation réalisées / non applicables, mêlées aux actions par ordre chronologique ; accessible aussi depuis l'onglet Remédiation.
- Sécurité : le marqueur interne `_no_audit` est désormais un jeton propre à la requête ; il ne peut plus être envoyé par un formulaire ou l'API pour échapper au journal d'audit.

## 1.6.0 — 2026-10-20
- Catégories d'incident paramétrables (menu Catégories) avec nouveau droit « Gérer les catégories » ; code interne stable, suppression bloquée si la catégorie est utilisée, toutes les opérations auditées.
- Droits de gestion des procédures et catégories vérifiés de bout en bout (refus tracés pour un profil sans ces droits).

## 1.5.2 — 2026-10-20
- Bouton « Ajouter » sur la liste des procédures de remédiation (visible avec le droit « Gérer les procédures »).

## 1.5.1 — 2026-10-20
- Compatibilité avec toute la branche GLPI 11.0.x (testé sur 11.0.4 et 11.0.11) : jeton CSRF et formulaires de liaison ne dépendent plus de macros/gabarits absents des premières versions 11.0.

## 1.5.0 — 2026-10-20
- Actions d'investigation / intervention structurées dans la chronologie (cible, outil, commande exacte, résultat, détection EDR et tâche liées).
- Journal des actions imprimable / PDF avec empreinte SHA-256.
- Nouveau format d'empreinte (colonnes vides ignorées) ; migration avec vérification préalable tracée.

## 1.4.0
- Équipe d'intervention par incident (intervenants, observateurs).
- Répartition des tâches de remédiation entre les membres, « Mes tâches » au tableau de bord.

## 1.3.0
- Procédures de remédiation (bibliothèque + 5 procédures par défaut), plan par incident, clôture bloquée si étapes obligatoires en attente, impression.

## 1.2.0
- SHA-256 sur toutes les preuves (documents) et tous les enregistrements, ancrés dans le journal d'audit ; onglet « Intégrité & preuves ».
- Le CSV importé est conservé comme preuve.

## 1.1.0
- Cloisonnement : un technicien ne voit que ses incidents (droit « tous les incidents » pour le RSSI).
- Journal d'audit chaîné (qui, privilège, quoi, sur quoi, IP), page de consultation, export, vérification.

## 1.0.0
- Incidents de sécurité, chronologie, IOC, éléments liés, RGPD / NIS2, tableau de bord, import CSV d'EDR.
