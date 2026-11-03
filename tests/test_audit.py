"""
Journal d'audit : verrou de chaînage, concurrence, échec d'écriture, altération,
troncature avec et sans point de contrôle externe, commande console.
"""
import json
import os
import subprocess
import threading
import time

import lib
from lib import NS, P, Results, Session, sql, sql_one, sql_rows

AUDIT = "glpi_plugin_secincident_auditlogs"
GLPI_DIR = os.environ.get("SI_GLPI_DIR", "")


def max_id():
    return int(sql_one(f"SELECT COALESCE(MAX(id), 0) FROM {AUDIT}") or 0)


def chain(admin):
    return lib.verify_chain_page(admin)["chain"]


def failures(admin):
    return lib.verify_chain_page(admin)["failures"]


def view_incident(session, iid):
    """Consultation de l'onglet principal : produit une entrée « view »."""
    return session.tab(NS + "Incident", NS + "Incident$main", iid, P + "/incident.form.php")


def export_checkpoint(admin):
    st, body, _ = admin.get(P + "/audit.php?checkpoint=export")
    return json.loads(body)


def verify_checkpoint(admin, checkpoint):
    raw = checkpoint if isinstance(checkpoint, str) else json.dumps(checkpoint)
    st, body, _ = admin.post(P + "/audit.php", [("checkpoint_verify", "1"), ("checkpoint_json", raw), ("format", "json")])
    return json.loads(body)


def codes(result):
    return sorted({a["code"] for a in result["anomalies"]})


def save_rows(where):
    """Copie brute de lignes du journal (pour les restaurer après un test destructif)."""
    cols = [c[0] for c in sql_rows(f"SHOW COLUMNS FROM {AUDIT}")]
    rows = sql_rows(f"SELECT {', '.join('HEX(CAST(`%s` AS CHAR))' % c for c in cols)} FROM {AUDIT} WHERE {where} ORDER BY id")
    return cols, rows


def restore_rows(saved):
    cols, rows = saved
    for row in rows:
        values = ", ".join("NULL" if v == "NULL" else f"UNHEX('{v}')" for v in row)
        sql(f"INSERT INTO {AUDIT} ({', '.join('`%s`' % c for c in cols)}) VALUES ({values})")


def run():
    r = Results("Journal d'audit")
    admin = Session(*lib.ADMIN)
    iid = lib.create_incident(admin, "Audit test")
    r.check("chaîne intacte au départ", chain(admin)["ok"], chain(admin))

    # ------------------------------------------------------------------
    # 1. Verrou maintenu au-delà du délai d'attente
    # ------------------------------------------------------------------
    sql("DELETE FROM glpi_configs WHERE context='plugin:secincident' AND name='audit_lock_timeout'")
    sql("INSERT INTO glpi_configs (context, name, value) VALUES ('plugin:secincident', 'audit_lock_timeout', '2')")
    f0 = failures(admin)["total"]
    before = max_id()
    holder = lib.hold_lock(8)
    time.sleep(1)
    sessions = [Session(*lib.ADMIN), Session(*lib.ADMIN)]
    t0 = time.time()
    threads = [threading.Thread(target=view_incident, args=(s, iid)) for s in sessions]
    [t.start() for t in threads]
    [t.join() for t in threads]
    elapsed = time.time() - t0
    written_during_lock = max_id() - before
    holder.wait()
    r.check("verrou indisponible : aucune entrée chaînée écrite", written_during_lock == 0, f"{written_during_lock} entrée(s)")
    r.check("verrou indisponible : l'attente est bornée par audit_lock_timeout", elapsed < 7, f"{elapsed:.1f} s")
    st = failures(admin)
    r.check("échecs comptés et visibles (bandeau du journal)", st["total"] - f0 >= 2 and st["count"] >= 2 and st["last"]["reason"] == "lock_timeout", st)
    st_html = admin.get(P + "/audit.php")[1]
    r.check("bandeau d'échecs affiché sur la page du journal", "data-secincident-audit-failures" in st_html)
    if GLPI_DIR:
        log = os.path.join(GLPI_DIR, "files", "_log", "secincident-audit-failures.log")
        lines = open(log, encoding="utf-8").read().splitlines() if os.path.exists(log) else []
        last = json.loads(lines[-1]) if lines else {}
        r.check("entrée non écrite consignée dans files/_log/secincident-audit-failures.log",
                last.get("reason") == "lock_timeout" and last.get("entry", {}).get("action") == "view", last)
    r.check("chaîne toujours intacte après les échecs", chain(admin)["ok"], chain(admin))

    # ------------------------------------------------------------------
    # 2. Écritures concurrentes (verrou libre)
    # ------------------------------------------------------------------
    f1 = failures(admin)["total"]
    before = max_id()
    pool = [Session(*lib.ADMIN) for _ in range(4)]

    def burst(s):
        for _ in range(5):
            view_incident(s, iid)
            s.get(P + "/incident.php")

    threads = [threading.Thread(target=burst, args=(s,)) for s in pool]
    [t.start() for t in threads]
    [t.join() for t in threads]
    new = max_id() - before
    forks = sql(f"SELECT prev_hash FROM {AUDIT} WHERE id > {before} GROUP BY prev_hash HAVING COUNT(*) > 1")
    r.check("concurrence : toutes les écritures ont abouti", new >= 20 and failures(admin)["total"] == f1, f"{new} entrées, échecs {failures(admin)['total'] - f1}")
    r.check("concurrence : aucune fourche (prev_hash unique)", forks == "", forks)
    r.check("concurrence : chaîne intacte", chain(admin)["ok"], chain(admin))

    # ------------------------------------------------------------------
    # 3. Insertion refusée par la base
    # ------------------------------------------------------------------
    f2 = failures(admin)["total"]
    before = max_id()
    sql(f"CREATE TRIGGER secincident_test_block BEFORE INSERT ON {AUDIT} FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'blocked by test'")
    try:
        st_code, html, _ = view_incident(Session(*lib.ADMIN), iid)
    finally:
        sql("DROP TRIGGER IF EXISTS secincident_test_block")
    written = max_id() - before
    st = failures(admin)
    r.check("insertion refusée : rien d'écrit, échec « insert_failed » signalé",
            written == 0 and st["total"] > f2 and st["last"]["reason"] == "insert_failed", (written, st))
    r.check("insertion refusée : l'action elle-même n'est pas bloquée", st_code == 200, st_code)

    # Acquittement (tracé)
    admin.post(P + "/audit.php", [("ack_failures", "1")])
    st = failures(admin)
    acks = sql_one(f"SELECT COUNT(*) FROM {AUDIT} WHERE action='audit_failure_ack'")
    r.check("acquittement : bandeau remis à zéro et acquittement journalisé", st["count"] == 0 and int(acks) >= 1, st)
    sql("DELETE FROM glpi_configs WHERE context='plugin:secincident' AND name='audit_lock_timeout'")

    # ------------------------------------------------------------------
    # 4. Altération d'une entrée
    # ------------------------------------------------------------------
    target = int(sql_one(f"SELECT id FROM {AUDIT} WHERE action='view' ORDER BY id DESC LIMIT 1 OFFSET 3"))
    original = sql_one(f"SELECT HEX(details) FROM {AUDIT} WHERE id={target}")
    sql(f"UPDATE {AUDIT} SET details='{{\"altere\":true}}' WHERE id={target}")
    res = chain(admin)
    r.check("altération : chaîne rompue à l'entrée modifiée", not res["ok"] and res["broken_id"] == target, res)
    sql(f"UPDATE {AUDIT} SET details=UNHEX('{original}') WHERE id={target}")
    r.check("altération annulée : chaîne de nouveau intacte", chain(admin)["ok"])

    # ------------------------------------------------------------------
    # 5. Troncature sans point de contrôle : non détectée par le chaînage seul
    # ------------------------------------------------------------------
    for _ in range(3):
        view_incident(Session(*lib.ADMIN), iid)
    cut = max_id() - 2
    saved = save_rows(f"id >= {cut}")
    sql(f"DELETE FROM {AUDIT} WHERE id >= {cut}")
    res = chain(admin)
    r.check("troncature sans point de contrôle : le chaînage seul ne la voit pas (limite documentée)", res["ok"], res)
    # Restauration des lignes supprimées (et de celles écrites par la vérification)
    sql(f"DELETE FROM {AUDIT} WHERE id >= {cut}")
    restore_rows(saved)
    r.check("lignes restaurées : chaîne intacte", chain(admin)["ok"])

    # ------------------------------------------------------------------
    # 6. Point de contrôle externe
    # ------------------------------------------------------------------
    cp = export_checkpoint(admin)
    r.check("export : format, instance, dernière entrée et empreinte",
            cp.get("format") == "secincident-audit-checkpoint/1" and len(cp.get("instance_id", "")) == 36
            and cp["last_id"] > 0 and len(cp["last_hash"]) == 64 and cp["chain_ok"], cp)
    r.check("export tracé dans le journal", sql_one(f"SELECT COUNT(*) FROM {AUDIT} WHERE action='checkpoint_export' AND id > {cp['last_id']}") == "1")

    res = verify_checkpoint(admin, cp)
    r.check("vérification : cohérent", res["ok"], codes(res))
    r.check("vérification : dernière entrée couverte affichée", res["covered"]["until_id"] == cp["last_id"] and res["covered"]["count"] == cp["count"], res["covered"])
    r.check("vérification : entrées plus récentes (chaînage seul) distinguées", res["newer"]["count"] >= 1 and res["newer"]["from_id"] == cp["last_id"] + 1, res["newer"])
    st, html, _ = admin.post(P + "/audit.php", [("checkpoint_verify", "1"), ("checkpoint_json", json.dumps(cp))])
    r.check("interface : badges couvert / chaînage seul sur les lignes", 'data-secincident-checkpoint="ok"' in html and "ti-lock" in html and "ti-link" in html)

    # Fichier JSON Lines (ajout seul) : la dernière ligne est utilisée
    res = verify_checkpoint(admin, "\n".join([json.dumps(dict(cp, last_id=1, count=1)), json.dumps(cp), ""]))
    r.check("JSON Lines : dernière ligne utilisée", res["ok"], codes(res))

    # Troncature : suppression des dernières entrées, dont celle du point de contrôle
    saved = save_rows(f"id >= {cp['last_id'] - 1}")
    sql(f"DELETE FROM {AUDIT} WHERE id >= {cp['last_id'] - 1}")
    res = verify_checkpoint(admin, cp)
    r.check("troncature avec point de contrôle : anomalie « log_truncated »", not res["ok"] and "log_truncated" in codes(res), codes(res))
    sql(f"DELETE FROM {AUDIT} WHERE id >= {cp['last_id'] - 1}")
    restore_rows(saved)

    # Entrée référencée disparue alors que des entrées plus récentes existent
    saved = save_rows(f"id = {cp['last_id']}")
    sql(f"DELETE FROM {AUDIT} WHERE id = {cp['last_id']}")
    res = verify_checkpoint(admin, cp)
    r.check("entrée référencée disparue : « entry_missing »", "entry_missing" in codes(res), codes(res))
    restore_rows(saved)

    # Chaîne entièrement recalculée après modification d'une entrée couverte : le chaînage
    # seul ne voit rien, le point de contrôle si (empreinte de la dernière entrée changée)
    if GLPI_DIR or os.environ.get("SI_PHP"):
        saved = save_rows("1=1")
        victim = int(sql_one(f"SELECT id FROM {AUDIT} WHERE id < {cp['last_id']} ORDER BY id DESC LIMIT 1 OFFSET 2"))
        sql(f"UPDATE {AUDIT} SET user_name='quelqu-un-d-autre' WHERE id={victim}")
        rehash()
        res_chain = chain(admin)
        res = verify_checkpoint(admin, cp)
        r.check("réécriture complète : chaîne « intacte » mais point de contrôle en anomalie « hash_changed »",
                res_chain["ok"] and "hash_changed" in codes(res), (res_chain, codes(res)))
        sql(f"DELETE FROM {AUDIT}")
        restore_rows(saved)
        r.check("journal d'origine restauré", chain(admin)["ok"])

    # Point de contrôle d'une autre instance / illisible
    res = verify_checkpoint(admin, dict(cp, instance_id="00000000-0000-4000-8000-000000000000"))
    r.check("autre instance : « instance_mismatch »", "instance_mismatch" in codes(res), codes(res))
    res = verify_checkpoint(admin, "pas du json")
    r.check("point de contrôle illisible : « format_invalid »", codes(res) == ["format_invalid"], codes(res))
    r.check("vérifications tracées dans le journal", int(sql_one(f"SELECT COUNT(*) FROM {AUDIT} WHERE action='checkpoint_verify'")) >= 5)

    # ------------------------------------------------------------------
    # 7. Commande console (export vers un fichier en ajout seul, vérification)
    # ------------------------------------------------------------------
    if GLPI_DIR:
        console = ["php", os.path.join(GLPI_DIR, "bin", "console"), "--no-interaction", "plugins:secincident:audit-checkpoint"]
        if os.geteuid() == 0:
            console.insert(3, "--allow-superuser")
        store = os.path.join(os.environ.get("SI_TMP", "/tmp"), f"secincident-cp-{os.getpid()}.jsonl")
        p1 = subprocess.run(console + [f"--output={store}"], capture_output=True, text=True, cwd=GLPI_DIR)
        p2 = subprocess.run(console + [f"--output={store}"], capture_output=True, text=True, cwd=GLPI_DIR)
        lines = open(store).read().splitlines() if os.path.exists(store) else []
        r.check("console : export ajouté au fichier (une ligne JSON par export)", p1.returncode == 0 and p2.returncode == 0 and len(lines) == 2, (p1.stderr[-300:], lines))
        p3 = subprocess.run(console + [f"--verify={store}", "--json"], capture_output=True, text=True, cwd=GLPI_DIR)
        r.check("console : vérification cohérente (code 0)", p3.returncode == 0, p3.stdout[-400:])
        last = json.loads(lines[-1])
        saved = save_rows(f"id >= {last['last_id']}")
        sql(f"DELETE FROM {AUDIT} WHERE id >= {last['last_id']}")
        p4 = subprocess.run(console + ["--verify=-"], input=lines[-1], capture_output=True, text=True, cwd=GLPI_DIR)
        r.check("console : troncature détectée (code 1)", p4.returncode == 1 and "log_truncated" in p4.stdout, p4.stdout[-400:])
        sql(f"DELETE FROM {AUDIT} WHERE id >= {last['last_id']}")
        restore_rows(saved)
        p5 = subprocess.run(console + ["--verify=-"], input="{}", capture_output=True, text=True, cwd=GLPI_DIR)
        r.check("console : point de contrôle illisible (code 2)", p5.returncode == 2, p5.stdout[-200:])
        os.path.exists(store) and os.remove(store)

    r.check("chaîne intacte en fin de test", chain(admin)["ok"], chain(admin))
    return r.done()


def rehash():
    """Recalcule toute la chaîne comme le ferait quelqu'un qui a accès à la base."""
    php = os.environ.get("SI_PHP", "php")
    script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rehash_chain.php")
    fields = ["date_utc", "users_id", "user_name", "users_id_impersonator", "profiles_id", "profile_name", "rights",
              "privilege", "ip", "action", "result", "itemtype", "items_id", "incidents_id", "details"]
    hexed = ", ".join("HEX(COALESCE(`%s`, ''))" % f for f in fields)
    rows = sql_rows(f"SELECT id, {hexed} FROM {AUDIT} ORDER BY id")
    out = subprocess.run([php, script], input="\n".join("\t".join(r) for r in rows), capture_output=True, text=True, check=True).stdout
    for line in out.splitlines():
        rid, prev, h = line.split("\t")
        sql(f"UPDATE {AUDIT} SET prev_hash='{prev}', hash='{h}' WHERE id={int(rid)}")


if __name__ == "__main__":
    raise SystemExit(1 if run() else 0)
