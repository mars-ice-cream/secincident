"""
check_php_errors.py <php-errors.log> : échoue si le journal PHP de GLPI contient une
erreur ou un avertissement provenant de SecIncident, hors avertissements attendus des
tests (échecs de journalisation provoqués volontairement).
"""
import re
import sys

EXPECTED = ("SecIncident audit failure", 'Plugin "secincident" version changed')

text = open(sys.argv[1], encoding="utf-8", errors="replace").read() if len(sys.argv) > 1 else ""
entries = re.split(r"(?m)^(?=\[\d{4}-\d\d-\d\d [\d:]+\] )", text)
bad = [e for e in entries
       if re.search(r"glpi\.(WARNING|ERROR|CRITICAL|ALERT|EMERGENCY)", e)
       and re.search(r"plugins/secincident|SecIncident|GlpiPlugin\\\\Secincident", e)
       and not any(x in e.split("\n", 1)[0] for x in EXPECTED)]
for e in bad[:20]:
    print(e.strip()[:1500], "\n---")
print(f"{len(bad)} erreur(s) PHP liée(s) à SecIncident")
sys.exit(1 if bad else 0)
