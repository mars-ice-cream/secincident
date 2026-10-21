# Sécurité

Ce plugin manipule des données sensibles (incidents, preuves, journal d'audit).

**Signaler une vulnérabilité** : merci de ne pas ouvrir d'issue publique.

1. De préférence, utilisez le **signalement privé de GitHub** : onglet *Security* du dépôt > *Report a vulnerability*.
2. À défaut, écrivez à **securite@dokore.fr**.

Joignez une description et, si possible, les étapes pour reproduire. Une réponse est donnée sous 7 jours.

Versions maintenues : la dernière version mineure (1.5.x) pour GLPI 11.0.x.

Recommandations de déploiement :
- garder GLPI et ses plugins à jour (suivre les avis CERT-FR) ;
- ne pas exposer GLPI directement sur Internet ;
- sauvegarder la base et le dossier `files/` (preuves) ;
- exporter régulièrement le journal d'audit vers un stockage externe en écriture seule.
