"""
Lance les tests d'intégration SecIncident contre une instance GLPI.

    SI_BASE=http://127.0.0.1:8080 SI_DB=glpi SI_GLPI_DIR=/var/www/glpi python3 tests/run.py [module ...]

Code de sortie non nul au premier module en échec (tous les modules sont exécutés).
"""
import importlib
import sys
import traceback

import setup_instance

MODULES = ["test_audit", "test_integrity", "test_isolation"]


def main(argv):
    setup_instance.run()
    failed = {}
    for name in (argv or MODULES):
        try:
            fails = importlib.import_module(name).run()
        except Exception:  # noqa: BLE001 — un module qui plante est un échec
            traceback.print_exc()
            fails = ["exception"]
        if fails:
            failed[name] = fails
    print("\n=== Bilan ===")
    for name in (argv or MODULES):
        print(f"{name:16} {'ÉCHEC: ' + ', '.join(failed[name]) if name in failed else 'OK'}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
