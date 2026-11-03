"""
Intégrité des données : intact / altéré / manquant / non scellé, absence de
rescellement automatique (vérification, mise à jour du plugin).
"""
import os
import re
import subprocess
import time

import lib
from lib import NS, P, Results, Session, sql, sql_one

FK = "plugin_secincident_incidents_id"
GLPI_DIR = os.environ.get("SI_GLPI_DIR", "")


def integrity(session, iid):
    """Verdict et lignes en anomalie de l'onglet Intégrité & preuves."""
    st, html, _ = session.tab(NS + "Incident", NS + "Incident$2", iid, P + "/incident.form.php")
    m = re.search(r'data-secincident-verdict="(\w+)"', html)
    return (m.group(1) if m else None), html


def add_ioc(session, iid, value):
    session.post(P + "/ioc.form.php", [(FK, iid), ("ioc_type", "auto"), ("verdict", "0"), ("values", value), ("add", "1")])
    return int(sql_one(f"SELECT id FROM glpi_plugin_secincident_iocs WHERE {FK}={iid} AND value='{value}'") or 0)


def run_console(args):
    cmd = ["php", os.path.join(GLPI_DIR, "bin", "console"), "--no-interaction"]
    if os.geteuid() == 0:
        cmd.append("--allow-superuser")
    return subprocess.run(cmd + args, capture_output=True, text=True, cwd=GLPI_DIR, stdin=subprocess.DEVNULL)


def run():
    r = Results("Intégrité des données")
    admin = Session(*lib.ADMIN)

    # Référence : tout passe par l'application
    i1 = lib.create_incident(admin, "Integrity reference")
    add_ioc(admin, i1, "198.51.100.10")
    verdict, _ = integrity(admin, i1)
    r.check("données écrites par l'application : intactes", verdict == "intact", verdict)

    # Ligne insérée hors application : ni empreinte ni ancre
    i2 = lib.create_incident(admin, "Integrity unsealed")
    sql(f"INSERT INTO glpi_plugin_secincident_timelineevents ({FK}, date, event_type, name, content) VALUES ({i2}, NOW(), 'note', 'Inserted directly', 'outside the application')")
    ev = int(sql_one(f"SELECT MAX(id) FROM glpi_plugin_secincident_timelineevents WHERE {FK}={i2}"))
    verdict, html = integrity(admin, i2)
    r.check("ligne non scellée : la vérification ne conclut pas à l'intégrité", verdict == "unverifiable", verdict)
    r.check("ligne non scellée : motif « ni empreinte ni ancre » affiché", "no fingerprint and no anchor" in html)
    st, html, url = admin.post(P + "/incident.form.php", [("id", i2), ("verify_integrity", "1")])
    last = sql_one("SELECT CONCAT(result, '|', details) FROM glpi_plugin_secincident_auditlogs WHERE action='verify_integrity' ORDER BY id DESC LIMIT 1")
    r.check("vérification manuelle : résultat « non établi » tracé en erreur", last.startswith("error|") and "unsealed" in last, last[:200])
    r.check("vérification manuelle : aucun rescellement", sql_one(f"SELECT COALESCE(integrity_hash, 'NULL') FROM glpi_plugin_secincident_timelineevents WHERE id={ev}") == "NULL")
    verdict, _ = integrity(admin, i2)
    r.check("après vérification : toujours non scellé", verdict == "unverifiable", verdict)

    # Preuve inscrite hors application (absente du journal)
    sql(f"INSERT INTO glpi_plugin_secincident_evidences ({FK}, documents_id, filename, sha256, status, date_added) VALUES ({i1}, 0, 'forged.txt', '{'0' * 64}', 'active', NOW())")
    evid = sql_one(f"SELECT MAX(id) FROM glpi_plugin_secincident_evidences WHERE {FK}={i1}")
    admin.post(P + "/incident.form.php", [("id", i1), ("verify_integrity", "1")])
    verdict, html = integrity(admin, i1)
    r.check("preuve absente du journal : « non scellée », intégrité non établie", verdict == "unverifiable" and "absent from the audit log" in html, verdict)
    sql(f"DELETE FROM glpi_plugin_secincident_evidences WHERE id={evid}")

    # Écriture légitime dont la journalisation a échoué : scellée mais jamais ancrée
    i3 = lib.create_incident(admin, "Integrity not anchored")
    sql("INSERT INTO glpi_configs (context, name, value) VALUES ('plugin:secincident', 'audit_lock_timeout', '1') ON DUPLICATE KEY UPDATE value='1'")
    holder = lib.hold_lock(6)
    time.sleep(1)
    ioc = add_ioc(Session(*lib.ADMIN), i3, "198.51.100.20")
    holder.wait()
    sql("DELETE FROM glpi_configs WHERE context='plugin:secincident' AND name='audit_lock_timeout'")
    verdict, html = integrity(admin, i3)
    stored = sql_one(f"SELECT COALESCE(integrity_hash, '') FROM glpi_plugin_secincident_iocs WHERE id={ioc}")
    r.check("journalisation échouée : la ligne existe et porte une empreinte", ioc > 0 and len(stored) == 64, (ioc, stored))
    r.check("journalisation échouée : signalée « non scellée (jamais ancrée) »", verdict == "unverifiable" and "never anchored" in html, verdict)

    # Altération et suppression directes en base
    i4 = lib.create_incident(admin, "Integrity altered")
    a = add_ioc(admin, i4, "198.51.100.30")
    b = add_ioc(admin, i4, "198.51.100.31")
    sql(f"UPDATE glpi_plugin_secincident_iocs SET value='203.0.113.99' WHERE id={a}")
    verdict, _ = integrity(admin, i4)
    r.check("modification directe : « altéré »", verdict == "altered", verdict)
    sql(f"DELETE FROM glpi_plugin_secincident_iocs WHERE id={b}")
    verdict, html = integrity(admin, i4)
    r.check("suppression directe : « manquant » signalé en plus", verdict == "altered" and "Deleted outside the application" in html, verdict)

    # Effacer l'empreinte d'une ligne altérée, puis mettre à jour le plugin :
    # rien ne doit être rescellé ni légitimé
    sql(f"UPDATE glpi_plugin_secincident_iocs SET integrity_hash=NULL WHERE id={a}")
    if GLPI_DIR:
        p = run_console(["plugin:install", "--force", "--username=glpi", "secincident"])
        run_console(["plugin:activate", "secincident"])
        r.check("mise à jour du plugin exécutée", p.returncode == 0, p.stdout[-300:] + p.stderr[-300:])
        lib.set_rights(lib.profile_id("Super-Admin"), lib.ALL_RIGHTS)
        admin = Session(*lib.ADMIN)
    r.check("après mise à jour : ligne altérée non rescellée", sql_one(f"SELECT COALESCE(integrity_hash, 'NULL') FROM glpi_plugin_secincident_iocs WHERE id={a}") == "NULL")
    verdict, _ = integrity(admin, i4)
    r.check("après mise à jour : altération toujours signalée", verdict == "altered", verdict)
    r.check("après mise à jour : ligne insérée hors application non légitimée",
            sql_one(f"SELECT COALESCE(integrity_hash, 'NULL') FROM glpi_plugin_secincident_timelineevents WHERE id={ev}") == "NULL"
            and integrity(admin, i2)[0] == "unverifiable")
    r.check("après mise à jour : données saines toujours intactes", integrity(admin, i1)[0] == "intact")

    # Vérification globale : les trois verdicts sont distingués
    st, body, _ = admin.get(P + "/audit.php?verify_all=1&format=json")
    import json
    data = json.loads(body)["data"]
    verdicts = {a["incident"]: a["verdict"] for a in data["anomalies"]}
    r.check("vérification globale : non scellé et altéré distingués",
            verdicts.get(i2) == "unverifiable" and verdicts.get(i3) == "unverifiable" and verdicts.get(i4) == "altered" and i1 not in verdicts, verdicts)
    return r.done()


if __name__ == "__main__":
    raise SystemExit(1 if run() else 0)
