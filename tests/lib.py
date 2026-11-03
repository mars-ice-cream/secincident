"""
Outils communs aux tests d'intégration SecIncident (bibliothèque standard uniquement).

Les tests pilotent une instance GLPI réelle par HTTP et lisent / altèrent la base
avec le client `mysql`. Variables d'environnement :

  SI_BASE   URL de l'instance GLPI           (défaut http://127.0.0.1:8080)
  SI_DB     nom de la base GLPI              (défaut glpi)
  SI_MYSQL  commande du client mysql         (défaut "mysql")
  SI_ADMIN  identifiant:mot de passe Super-Admin (défaut glpi:glpi)
"""
import http.cookiejar
import json
import os
import re
import shlex
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

BASE = os.environ.get("SI_BASE", "http://127.0.0.1:8080").rstrip("/")
DB = os.environ.get("SI_DB", "glpi")
MYSQL = shlex.split(os.environ.get("SI_MYSQL", "mysql"))
ADMIN = tuple(os.environ.get("SI_ADMIN", "glpi:glpi").split(":", 1))
P = "/plugins/secincident/front"
NS = "GlpiPlugin\\Secincident\\"
RIGHTNAME = "plugin_secincident_incident"
LOCK = DB + ".plugin_secincident_audit"
# Droits du plugin (src/Incident.php)
READ, CREATE, UPDATE, DELETE, PURGE, READALL, AUDIT, PLAYBOOK, CATEGORY = 1, 2, 4, 8, 16, 1024, 4096, 8192, 16384
ALL_RIGHTS = READ | CREATE | UPDATE | DELETE | PURGE | READALL | AUDIT | PLAYBOOK | CATEGORY

for var in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
    os.environ.pop(var, None)


def sql(query, check=True):
    """Exécute une requête et renvoie la sortie brute (colonnes séparées par des tabulations)."""
    r = subprocess.run(MYSQL + ["--default-character-set=utf8mb4", "-N", "-B", DB, "-e", query],
                       capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"SQL échouée : {query}\n{r.stderr}")
    return r.stdout.strip()


def sql_rows(query):
    out = sql(query)
    return [line.split("\t") for line in out.splitlines()] if out else []


def sql_one(query):
    out = sql(query)
    return out.splitlines()[0].split("\t")[0] if out else ""


def hold_lock(seconds):
    """Prend le verrou d'audit depuis une autre connexion et le garde `seconds` secondes."""
    return subprocess.Popen(MYSQL + ["-N", DB, "-e", f"SELECT GET_LOCK('{LOCK}', 5); SELECT SLEEP({seconds});"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


class Session:
    """Session HTTP indépendante (son propre cookie GLPI)."""

    def __init__(self, user=None, password=None):
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(self.jar))
        if user is not None:
            self.login(user, password if password is not None else user)

    def _open(self, req, timeout=180):
        try:
            r = self.opener.open(req, timeout=timeout)
            return r.status, r.read().decode("utf-8", "replace"), r.geturl()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace"), req if isinstance(req, str) else req.full_url

    def get(self, path, timeout=180):
        return self._open(BASE + path, timeout)

    def post(self, path, data, files=None, timeout=180):
        headers = {"Origin": BASE, "Sec-Fetch-Site": "same-origin", "Referer": BASE + path}
        data = list(data)
        token = self.csrf()
        if token:
            data.append(("_glpi_csrf_token", token))
        if files:
            boundary = "----secincident" + os.urandom(8).hex()
            body = b""
            for k, v in data:
                body += f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n".encode()
            for k, (fname, content, ctype) in files.items():
                body += (f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"; filename=\"{fname}\"\r\n"
                         f"Content-Type: {ctype}\r\n\r\n").encode() + content + b"\r\n"
            body += f"--{boundary}--\r\n".encode()
            headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
        else:
            body = urllib.parse.urlencode(data).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        return self._open(urllib.request.Request(BASE + path, data=body, headers=headers, method="POST"), timeout)

    def csrf(self):
        """Jeton CSRF (GLPI 11). Sous GLPI 12 la page n'en contient pas : renvoie None."""
        st, html, _ = self.get("/front/central.php")
        m = re.search(r'name="_glpi_csrf_token" value="([^"]+)"', html) or re.search(r'meta property="glpi:csrf_token" content="([^"]+)"', html)
        return m.group(1) if m and m.group(1) else None

    def login(self, user, password):
        st, html, _ = self.get("/index.php")
        token = re.search(r'name="_glpi_csrf_token" value="([^"]+)"', html)
        lf = re.search(r'name="([^"]+)"[^>]*id="login_name"', html) or re.search(r'id="login_name"[^>]*name="([^"]+)"', html)
        pf = re.search(r'name="([^"]+)"[^>]*id="login_password"', html) or re.search(r'id="login_password"[^>]*name="([^"]+)"', html)
        data = [(lf.group(1), user), (pf.group(1), password), ("auth", "local"), ("submit", "")]
        if token and token.group(1):
            data.append(("_glpi_csrf_token", token.group(1)))
        headers = {"Origin": BASE, "Sec-Fetch-Site": "same-origin", "Referer": BASE + "/index.php",
                   "Content-Type": "application/x-www-form-urlencoded"}
        st, html, url = self._open(urllib.request.Request(BASE + "/front/login.php", data=urllib.parse.urlencode(data).encode(), headers=headers, method="POST"))
        if "login_name" in html and "/front/login.php" in url:
            raise RuntimeError(f"Connexion impossible pour {user}")
        return st

    def tab(self, itemtype, tabname, items_id, target):
        q = urllib.parse.urlencode({"_glpi_tab": tabname, "_target": target, "_itemtype": itemtype, "id": items_id})
        return self.get("/ajax/common.tabs.php?" + q)


def text(html):
    html = re.sub(r"<script.*?</script>", " ", html, flags=re.S)
    import html as h
    return re.sub(r"\s+", " ", h.unescape(re.sub(r"<[^>]+>", " ", html)))


def php_errors(html):
    out = []
    for pat in (r"Fatal error[^<]*", r"Warning:[^<]*", r"Uncaught[^<]*", r"An error has occurred[^<]*"):
        out += re.findall(pat, html)
    return out


# ---------------------------------------------------------------------------
# Données de test
# ---------------------------------------------------------------------------

def user_id(login):
    return int(sql_one(f"SELECT id FROM glpi_users WHERE name='{login}'") or 0)


def profile_id(name):
    return int(sql_one(f"SELECT id FROM glpi_profiles WHERE name='{name}'") or 0)


def set_rights(profiles_id, rights):
    sql(f"UPDATE glpi_profilerights SET rights={int(rights)} WHERE name='{RIGHTNAME}' AND profiles_id={int(profiles_id)}")


def create_incident(session, name, **fields):
    data = {"name": name, "category": "phishing", "status": "1", "severity": "3", "source": "manual",
            "date_detection": "2026-10-20 08:00:00", "entities_id": "0", "content": "test", "add": "1"}
    data.update({k: str(v) for k, v in fields.items()})
    st, html, url = session.post(P + "/incident.form.php", list(data.items()))
    m = re.search(r"incident\.form\.php\?id=(\d+)", url)
    if not m:
        iid = sql_one(f"SELECT MAX(id) FROM glpi_plugin_secincident_incidents WHERE name='{name}'")
        if not iid:
            raise RuntimeError(f"Création d'incident impossible ({st}) : {text(html)[:300]}")
        return int(iid)
    return int(m.group(1))


def verify_chain_page(session):
    """Résultat de la vérification de chaîne, tel que renvoyé par la page d'audit (JSON intégré)."""
    st, html, _ = session.get(P + "/audit.php?verify=1&format=json")
    try:
        return json.loads(html)
    except ValueError:
        raise RuntimeError(f"Réponse inattendue de audit.php ({st}) : {text(html)[:300]}")


class Results:
    def __init__(self, name):
        self.name = name
        self.fails = []
        self.count = 0
        print(f"\n## {name}")

    def check(self, label, cond, extra=""):
        self.count += 1
        print(("  OK   " if cond else "  FAIL ") + label + (f"  [{extra}]" if extra and not cond else ""))
        if not cond:
            self.fails.append(label)
        return cond

    def done(self):
        print(f"-> {self.count - len(self.fails)}/{self.count} vérifications OK")
        return self.fails
