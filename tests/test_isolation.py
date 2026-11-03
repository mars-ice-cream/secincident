"""
Cloisonnement : techniciens entre eux et entités, dans la liste, la recherche,
les accès directs (fiches, onglets, sous-objets, éditions) et les exports ;
révocation du groupe sécurité sur une session déjà ouverte.
"""
import os
import re
import subprocess
import urllib.parse

import lib
from lib import NS, P, Results, Session, sql, sql_one

FK = "plugin_secincident_incidents_id"
IT = NS + "Incident"


def php_hash(password):
    php = os.environ.get("SI_PHP", "php")
    return subprocess.run([php, "-r", "echo password_hash($argv[1], PASSWORD_DEFAULT);", password],
                          capture_output=True, text=True, check=True).stdout.strip()


def ensure_user(login, profile, entity=0, recursive=0):
    uid = lib.user_id(login)
    if not uid:
        sql(f"INSERT INTO glpi_users (name, password, authtype, is_active, language, entities_id, profiles_id) "
            f"VALUES ('{login}', '{php_hash(login)}', 1, 1, 'en_GB', {entity}, {lib.profile_id(profile)})")
        uid = lib.user_id(login)
    sql(f"DELETE FROM glpi_profiles_users WHERE users_id={uid}")
    sql(f"INSERT INTO glpi_profiles_users (users_id, profiles_id, entities_id, is_recursive, is_dynamic, is_default_profile) "
        f"VALUES ({uid}, {lib.profile_id(profile)}, {entity}, {recursive}, 0, 1)")
    sql(f"UPDATE glpi_users SET profiles_id={lib.profile_id(profile)}, entities_id={entity} WHERE id={uid}")
    return uid


def ensure_entity(admin, name):
    eid = sql_one(f"SELECT id FROM glpi_entities WHERE name='{name}'")
    if not eid:
        admin.post("/front/entity.form.php", [("name", name), ("entities_id", "0"), ("add", "1")])
        eid = sql_one(f"SELECT id FROM glpi_entities WHERE name='{name}'")
    if not eid:
        raise RuntimeError("Création de l'entité de test impossible")
    return int(eid)


def search_names(session, needle):
    q = urllib.parse.urlencode({"criteria[0][field]": "1", "criteria[0][searchtype]": "contains", "criteria[0][value]": needle})
    st, html, _ = session.get(P + "/incident.php?" + q)
    return st, lib.text(html)


def csv_export(session, needle):
    q = urllib.parse.urlencode({"item_type": IT, "display_type": "3", "export_all": "1",
                                "criteria[0][field]": "1", "criteria[0][searchtype]": "contains", "criteria[0][value]": needle})
    return session.get("/front/report.dynamic.php?" + q)


def run():
    r = Results("Cloisonnement")
    admin = Session(*lib.ADMIN)
    tech_id = lib.user_id("tech")
    sub = ensure_entity(admin, "SI isolation sub-entity")

    # Autre technicien (mêmes droits « voir ses incidents ») et un RSSI limité à l'entité racine
    other_id = ensure_user("si-tech-b", "Technician", 0, 1)
    rssi_id = ensure_user("si-rssi", "Supervisor", 0, 0)
    lib.set_rights(lib.profile_id("Supervisor"), lib.READ | lib.READALL)

    a = lib.create_incident(admin, "ISO-A tech", users_id_tech=tech_id)
    b = lib.create_incident(admin, "ISO-B other", users_id_tech=other_id)
    c = lib.create_incident(admin, "ISO-C subentity", users_id_tech=other_id, entities_id=sub)
    r.check("incidents de test créés (dont un dans la sous-entité)",
            sql_one(f"SELECT entities_id FROM glpi_plugin_secincident_incidents WHERE id={c}") == str(sub), (a, b, c))
    event_b = int(sql_one(f"SELECT id FROM glpi_plugin_secincident_timelineevents WHERE {FK}={b} ORDER BY id LIMIT 1") or 0)
    admin.post(P + "/ioc.form.php", [(FK, b), ("ioc_type", "auto"), ("verdict", "0"), ("values", "198.51.100.66"), ("add", "1")])
    ioc_b = int(sql_one(f"SELECT id FROM glpi_plugin_secincident_iocs WHERE {FK}={b} LIMIT 1") or 0)

    tech = Session("tech", "tech")
    st, t = search_names(tech, "ISO-")
    r.check("liste : le technicien voit son incident", st == 200 and "ISO-A tech" in t, st)
    r.check("liste / recherche : pas l'incident d'un autre technicien", "ISO-B other" not in t and "ISO-C" not in t)
    st, body, _ = csv_export(tech, "ISO-")
    r.check("export CSV : son incident seulement", st == 200 and "ISO-A tech" in body and "ISO-B" not in body and "ISO-C" not in body, body[:200])

    denied_before = int(sql_one(f"SELECT COUNT(*) FROM glpi_plugin_secincident_auditlogs WHERE users_id={tech_id} AND result='denied'"))
    for label, path in [
        ("fiche", f"/incident.form.php?id={b}"),
        ("journal des actions imprimable", f"/actions.print.php?id={b}"),
        ("plan de remédiation imprimable", f"/remediation.print.php?id={b}"),
        ("événement de chronologie", f"/timelineevent.form.php?id={event_b}"),
        ("IOC", f"/ioc.form.php?id={ioc_b}"),
    ]:
        st, html, _ = tech.get(P + path)
        r.check(f"accès direct refusé : {label}", st in (403, 404) or ("ISO-B other" not in html and "198.51.100.66" not in html), st)
    st, html, _ = tech.tab(IT, IT + "$main", b, P + "/incident.form.php")
    r.check("accès direct refusé : onglet principal", "ISO-B other" not in html)
    st, html, _ = tech.tab(IT, NS + "Ioc$1", b, P + "/incident.form.php")
    r.check("accès direct refusé : onglet IOC", "198.51.100.66" not in html)
    st, html, _ = tech.post(P + "/incident.form.php", [("id", b), ("name", "ISO-B hijacked"), ("update", "1")])
    r.check("modification forgée refusée", sql_one(f"SELECT name FROM glpi_plugin_secincident_incidents WHERE id={b}") == "ISO-B other")
    denied_after = int(sql_one(f"SELECT COUNT(*) FROM glpi_plugin_secincident_auditlogs WHERE users_id={tech_id} AND result='denied'"))
    r.check("refus tracés dans le journal d'audit", denied_after - denied_before >= 5, denied_after - denied_before)
    st, html, _ = tech.get(P + "/audit.php?export=csv")
    r.check("export du journal d'audit refusé au technicien", st in (403, 404) or "date_utc" not in html, st)

    # Entités : « tous les incidents » ne franchit pas le périmètre d'entités du profil
    rssi = Session("si-rssi", "si-rssi")
    st, t = search_names(rssi, "ISO-")
    r.check("entités : READALL voit les incidents de son entité", "ISO-A tech" in t and "ISO-B other" in t, st)
    r.check("entités : pas ceux d'une sous-entité hors périmètre", "ISO-C" not in t)
    st, body, _ = csv_export(rssi, "ISO-")
    r.check("entités : export CSV limité à l'entité", "ISO-B other" in body and "ISO-C" not in body, body[:200])
    st, html, _ = rssi.get(P + f"/incident.form.php?id={c}")
    r.check("entités : accès direct à l'incident de la sous-entité refusé", st in (403, 404) or "ISO-C subentity" not in html, st)
    st, html, _ = rssi.get(P + f"/actions.print.php?id={c}")
    r.check("entités : édition imprimable de la sous-entité refusée", st in (403, 404) or "ISO-C subentity" not in html, st)

    # Révocation du groupe sécurité : effet immédiat sur une session ouverte
    gid = sql_one("SELECT id FROM glpi_groups WHERE name='SI isolation security group'")
    if not gid:
        admin.post("/front/group.form.php", [("name", "SI isolation security group"), ("entities_id", "0"), ("is_recursive", "1"), ("add", "1")])
        gid = sql_one("SELECT id FROM glpi_groups WHERE name='SI isolation security group'")
    if not gid:
        sql("INSERT INTO glpi_groups (name, entities_id, is_recursive, completename, level) VALUES ('SI isolation security group', 0, 1, 'SI isolation security group', 1)")
        gid = sql_one("SELECT id FROM glpi_groups WHERE name='SI isolation security group'")
    gid = int(gid)
    sql(f"DELETE FROM glpi_groups_users WHERE groups_id={gid}")
    sql(f"INSERT INTO glpi_groups_users (users_id, groups_id) VALUES ({tech_id}, {gid})")
    sql("DELETE FROM glpi_configs WHERE context='plugin:secincident' AND name='restrict_groups_id'")
    sql(f"INSERT INTO glpi_configs (context, name, value) VALUES ('plugin:secincident', 'restrict_groups_id', '{gid}')")
    try:
        member = Session("tech", "tech")
        st, html, _ = member.get(P + "/incident.php")
        r.check("groupe sécurité : membre, accès accordé", st == 200 and "ISO-A" in lib.text(html), st)
        sql(f"DELETE FROM glpi_groups_users WHERE groups_id={gid} AND users_id={tech_id}")
        st, html, _ = member.get(P + "/incident.php")
        r.check("groupe sécurité : retiré du groupe, la session ouverte perd l'accès (liste)", st == 403, st)
        st, html, _ = member.get(P + f"/incident.form.php?id={a}")
        r.check("groupe sécurité : session ouverte, fiche refusée", st in (403, 404) or "ISO-A tech" not in html, st)
        st, html, _ = csv_export(member, "ISO-")
        r.check("groupe sécurité : session ouverte, export vide", "ISO-A" not in html, st)
        st, html, _ = member.get("/front/central.php")
        r.check("groupe sécurité : menu retiré", "secincident/front/incident.php" not in html)
        sql(f"INSERT INTO glpi_groups_users (users_id, groups_id) VALUES ({tech_id}, {gid})")
        st, html, _ = member.get(P + "/incident.php")
        r.check("groupe sécurité : remis dans le groupe, accès rendu sans reconnexion", st == 200, st)
        sql(f"DELETE FROM glpi_groups_users WHERE groups_id={gid} AND users_id={tech_id}")
        member.get(P + "/incident.php")
    finally:
        sql("DELETE FROM glpi_configs WHERE context='plugin:secincident' AND name='restrict_groups_id'")
    st, html, _ = member.get(P + "/incident.php")
    r.check("restriction levée : la session ouverte retrouve l'accès de son profil", st == 200, st)
    return r.done()


if __name__ == "__main__":
    raise SystemExit(1 if run() else 0)
