"""
Prépare une instance GLPI de test (idempotent) :
  - Super-Admin : tous les droits du plugin ;
  - Technician  : voir ses incidents, créer, modifier ;
  - langue des comptes de test en anglais (textes stables) ;
  - aucune restriction par groupe, délai de verrou par défaut.
"""
import lib
from lib import sql


def run():
    sa = lib.profile_id("Super-Admin")
    tech = lib.profile_id("Technician")
    if not sa or not tech:
        raise SystemExit("Profils Super-Admin / Technician introuvables")
    if lib.sql_one(f"SELECT COUNT(*) FROM glpi_profilerights WHERE name='{lib.RIGHTNAME}'") == "0":
        raise SystemExit("Plugin non installé (aucune ligne de droits)")
    lib.set_rights(sa, lib.ALL_RIGHTS)
    lib.set_rights(tech, lib.READ | lib.CREATE | lib.UPDATE)
    sql("UPDATE glpi_users SET language='en_GB' WHERE name IN ('glpi', 'tech', 'normal', 'post-only')")
    sql("DELETE FROM glpi_configs WHERE context='plugin:secincident' AND name IN ('restrict_groups_id', 'audit_lock_timeout')")
    print("instance prête : Super-Admin=%d, Technician=%d" % (sa, tech))


if __name__ == "__main__":
    run()
