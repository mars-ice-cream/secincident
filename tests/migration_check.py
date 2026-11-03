"""
Migration GLPI 11 → 12, étape 2 (sur GLPI 12, plugin 2.x, même base) : vérifie
que droits, journal d'audit, empreintes et verdicts sont conservés, et que le
point de contrôle exporté sous GLPI 11 couvre toujours le journal.
Usage : python3 migration_check.py instantane.json
"""
import json
import sys

import lib
from lib import P, Results, Session, sql_one
from migration_seed import snapshot


def main(path):
    before = json.load(open(path))
    version = sql_one("SELECT value FROM glpi_configs WHERE context='core' AND name='version'")
    r = Results(f"Migration GLPI {before['glpi_version']} → {version}")
    r.check("plugin mis à jour en 2.x", sql_one("SELECT version FROM glpi_plugins WHERE directory='secincident'").startswith("2."))
    admin = Session(*lib.ADMIN)
    after = snapshot(admin)

    r.check("droits des profils conservés à l'identique", after["rights"] == before["rights"], (before["rights"], after["rights"]))
    r.check("paramètres conservés (identifiant d'instance, restriction, alertes)", after["config"] == before["config"], (before["config"], after["config"]))
    prefix = after["audit"][:len(before["audit"])]
    r.check("journal : toutes les entrées antérieures présentes, empreintes inchangées", prefix == before["audit"],
            f"{len(before['audit'])} avant, {len(after['audit'])} après")
    r.check("journal : chaîne intacte après migration", after["chain"]["ok"], after["chain"])
    r.check("journal : la mise à jour du plugin est journalisée",
            sql_one(f"SELECT COUNT(*) FROM glpi_plugin_secincident_auditlogs WHERE action='update' AND id > {before['audit'][-1][0]}") != "0")
    for table, rows in before["seals"].items():
        r.check(f"empreintes conservées : {table}", after["seals"][table] == rows)
    r.check("verdicts d'intégrité identiques par incident (dont le non scellé)", after["verdicts"] == before["verdicts"],
            {k: (before["verdicts"].get(k), after["verdicts"].get(k)) for k in set(before["verdicts"]) | set(after["verdicts"]) if before["verdicts"].get(k) != after["verdicts"].get(k)})

    st, body, _ = admin.post(P + "/audit.php", [("checkpoint_verify", "1"), ("checkpoint_json", json.dumps(before["checkpoint"])), ("format", "json")])
    res = json.loads(body)
    r.check("point de contrôle exporté sous GLPI 11 : cohérent sous GLPI 12", res["ok"], res["anomalies"])
    r.check("point de contrôle : entrées couvertes = celles d'avant la migration, les suivantes par chaînage seul",
            res["covered"]["until_id"] == before["checkpoint"]["last_id"] and res["newer"]["count"] >= 1, (res["covered"], res["newer"]))

    tech = Session("tech", "tech")
    st, html, _ = tech.get(P + "/incident.php")
    r.check("technicien : accès conservé, cloisonnement actif", st == 200 and "MIG incident 0" in lib.text(html) and "MIG unsealed" not in lib.text(html), st)
    return 1 if r.done() else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
