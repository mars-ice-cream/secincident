#!/usr/bin/env python3
"""
SecIncident — maintenance des traductions / translation maintenance.

    python3 tools/i18n.py          # extrait les chaînes, met à jour .pot et .po, compile les .mo
    python3 tools/i18n.py --check  # échoue si le .pot n'est pas à jour (CI)

Prérequis : gettext (msgmerge, msgfmt) et le module Python polib (pip install polib).

Chaînes reconnues (langue source : anglais, domaine « secincident ») :
  __('...', 'secincident'), __s(...), _x('ctx', '...', 'secincident'), _sx(...),
  _n('sing', 'plural', $n, 'secincident'), _sn(...),
  I18n::instance('...'), I18n::tr('...', ...), I18n::noop('...')   (PHP)
  et les mêmes appels dans les gabarits Twig.
"""
import os
import re
import subprocess
import sys

try:
    import polib
except ImportError:  # pragma: no cover
    sys.exit("Module Python « polib » requis : pip install polib")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOCALES = os.path.join(ROOT, "locales")
POT = os.path.join(LOCALES, "secincident.pot")
STR = r"'((?:[^'\\]|\\.)*)'"
NUM = r"[^,()]+(?:\([^()]*\))?[^,()]*"
PATTERNS = [
    ("s", re.compile(r"\bI18n::(?:instance|tr|noop)\(\s*" + STR + r"\s*[,)]")),
    ("s", re.compile(r"\b__s?\(\s*" + STR + r"\s*,\s*'secincident'\s*\)")),
    ("x", re.compile(r"\b_s?x\(\s*" + STR + r"\s*,\s*" + STR + r"\s*,\s*'secincident'\s*\)")),
    ("n", re.compile(r"\b_s?n\(\s*" + STR + r"\s*,\s*" + STR + r"\s*,\s*" + NUM + r"\s*,\s*'secincident'\s*\)")),
]
PLURAL_FORMS = {"fr": "nplurals=2; plural=(n > 1);"}


def unescape(s):
    return re.sub(r"\\(.)", r"\1", s)


def sources():
    for folder in ("src", "front", "templates"):
        for dirpath, _, files in os.walk(os.path.join(ROOT, folder)):
            for name in sorted(files):
                if name.endswith((".php", ".twig")):
                    yield os.path.join(dirpath, name)
    for name in ("hook.php", "setup.php"):
        yield os.path.join(ROOT, name)


def extract():
    pot = polib.POFile(wrapwidth=0)
    pot.metadata = {
        "Project-Id-Version": "secincident",
        "MIME-Version": "1.0",
        "Content-Type": "text/plain; charset=UTF-8",
        "Content-Transfer-Encoding": "8bit",
        "Plural-Forms": "nplurals=2; plural=(n != 1);",
    }
    entries = {}
    for path in sources():
        text = open(path, encoding="utf-8").read()
        rel = os.path.relpath(path, ROOT)
        for kind, rx in PATTERNS:
            for m in rx.finditer(text):
                line = str(text.count("\n", 0, m.start()) + 1)
                if kind == "s":
                    key = (None, unescape(m.group(1)), None)
                elif kind == "x":
                    key = (unescape(m.group(1)), unescape(m.group(2)), None)
                else:
                    key = (None, unescape(m.group(1)), unescape(m.group(2)))
                entries.setdefault(key, []).append((rel, line))
    # Un msgid singulier déjà présent au pluriel : une seule entrée gettext
    plural_ids = {(k[0], k[1]) for k in entries if k[2] is not None}
    for (ctx, msgid, plural), refs in sorted(entries.items(), key=lambda kv: kv[1][0]):
        if plural is None and (ctx, msgid) in plural_ids:
            continue
        entry = polib.POEntry(msgctxt=ctx, msgid=msgid, occurrences=refs)
        if plural is not None:
            entry.msgid_plural = plural
            entry.msgstr_plural = {0: "", 1: ""}
        if re.search(r"%(\d+\$)?[sd]", msgid):
            entry.flags.append("php-format")
        pot.append(entry)
    return pot


def main():
    pot = extract()
    if "--check" in sys.argv:
        current = polib.pofile(POT) if os.path.exists(POT) else polib.POFile()
        if {(e.msgctxt, e.msgid) for e in current} != {(e.msgctxt, e.msgid) for e in pot}:
            sys.exit("locales/secincident.pot n'est pas à jour : lancez python3 tools/i18n.py")
        print("secincident.pot à jour (%d chaînes)" % len(pot))
        return
    pot.save(POT)
    for name in sorted(os.listdir(LOCALES)):
        if not name.endswith(".po"):
            continue
        po_path = os.path.join(LOCALES, name)
        subprocess.run(["msgmerge", "--quiet", "--update", "--backup=none", "--no-fuzzy-matching", po_path, POT], check=True)
        po = polib.pofile(po_path, wrapwidth=0)
        lang = name[:-3]
        po.metadata["Plural-Forms"] = PLURAL_FORMS.get(lang.split("_")[0], "nplurals=2; plural=(n != 1);")
        po.metadata["Language"] = lang
        po.save(po_path)
        subprocess.run(["msgfmt", "--check", "-o", po_path[:-3] + ".mo", po_path], check=True)
        print("%-10s %3d%% traduit" % (lang, po.percent_translated()))
    print("%d chaînes dans secincident.pot" % len(pot))


if __name__ == "__main__":
    main()
