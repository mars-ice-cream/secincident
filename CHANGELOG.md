# Changelog

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
