"""
Migration GLPI 11 → 12, étape 1 (sur GLPI 11, plugin 1.x) : crée des données,
fige l'état attendu (droits, journal, empreintes, verdicts) et exporte un point
de contrôle. Usage : python3 migration_seed.py instantane.json
"""
import json
import sys

import lib
import setup_instance
from lib import NS, P, Session, sql, sql_one, sql_rows

FK = "plugin_secincident_incidents_id"


def snapshot(admin):
    data = json.loads(admin.get(P + "/audit.php?verify_all=1&format=json")[1])
    verdicts = {str(i): "intact" for i in [r[0] for r in sql_rows("SELECT id FROM glpi_plugin_secincident_incidents")]}
    for a in data["data"]["anomalies"]:
        verdicts[str(a["incident"])] = a["verdict"]
    return {
        "chain": data["chain"],
        "rights": dict(sql_rows(f"SELECT profiles_id, rights FROM glpi_profilerights WHERE name='{lib.RIGHTNAME}' ORDER BY profiles_id")),
        "audit": sql_rows("SELECT id, hash FROM glpi_plugin_secincident_auditlogs ORDER BY id"),
        "seals": {t: sql_rows(f"SELECT id, COALESCE(integrity_hash, '') FROM glpi_plugin_secincident_{t} ORDER BY id")
                  for t in ("incidents", "timelineevents", "iocs", "incidents_items", "remediationtasks", "teammembers")},
        "verdicts": verdicts,
        "config": dict(sql_rows("SELECT name, value FROM glpi_configs WHERE context='plugin:secincident' AND name IN ('instance_id', 'restrict_groups_id', 'alert_emails')")),
    }


def main(out):
    setup_instance.run()
    # Droits personnalisés à conserver
    lib.set_rights(lib.profile_id("Supervisor"), lib.READ | lib.READALL | lib.AUDIT)
    admin = Session(*lib.ADMIN)
    tech = lib.user_id("tech")
    for n in range(3):
        iid = lib.create_incident(admin, f"MIG incident {n}", users_id_tech=tech)
        admin.post(P + "/ioc.form.php", [(FK, iid), ("ioc_type", "auto"), ("verdict", "0"), ("values", f"198.51.100.{100 + n}\nevil{n}.example"), ("add", "1")])
        admin.post(P + "/timelineevent.form.php", [(FK, iid), ("name", f"Containment {n}"), ("event_type", "action"), ("date", "2026-10-21 09:00:00"),
                                                  ("target", f"PC-{n}"), ("tool", "edr_console"), ("command", "isolate"), ("result", "success"), ("add", "1")])
        admin.post(P + "/remediationtask.form.php", [(FK, iid), ("plugin_secincident_playbooks_id", "1"), ("apply_playbook", "1")])
    # Un incident volontairement non scellé : l'état doit être conservé, pas « réparé »
    unsealed = lib.create_incident(admin, "MIG unsealed")
    sql(f"INSERT INTO glpi_plugin_secincident_timelineevents ({FK}, date, event_type, name) VALUES ({unsealed}, NOW(), 'note', 'outside the application')")
    Session("tech", "tech").get(P + "/incident.php")

    cp = json.loads(admin.get(P + "/audit.php?checkpoint=export")[1])
    snap = snapshot(admin)
    snap["checkpoint"] = cp
    snap["glpi_version"] = sql_one("SELECT value FROM glpi_configs WHERE context='core' AND name='version'")
    snap["plugin_version"] = sql_one("SELECT version FROM glpi_plugins WHERE directory='secincident'")
    ok = snap["chain"]["ok"] and snap["verdicts"][str(unsealed)] == "unverifiable" \
        and sum(v == "intact" for v in snap["verdicts"].values()) >= 3
    json.dump(snap, open(out, "w"), indent=1)
    print(f"instantané : GLPI {snap['glpi_version']}, plugin {snap['plugin_version']}, {len(snap['audit'])} entrées, "
          f"{len(snap['verdicts'])} incidents, point de contrôle jusqu'à #{cp['last_id']}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
