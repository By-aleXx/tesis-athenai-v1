"""
generate_traffic_db.py
======================
Genera tráfico HTTP sintético realista directamente en traffic_logs.db
sin necesitar Flask ni LocalStack levantados.

Produce:
  - N registros legítimos variados (IPs, UA, rutas, horarios, métodos)
  - M registros de ataque etiquetados (is_test_attack=True)
    con payloads SQLi, XSS, brute-force, credential stuffing,
    impossible travel y session hijacking.

Uso:
  python generate_traffic_db.py                  # valores por defecto
  python generate_traffic_db.py --normal 3000 --attack 500
  python generate_traffic_db.py --db /ruta/custom/traffic_logs.db
  python generate_traffic_db.py --preview        # solo muestra stats, no escribe
"""

import sqlite3
import random
import json
import argparse
import sys
from datetime import datetime, timedelta
from pathlib import Path


# ---------------------------------------------------------------------------
# Configuración por defecto
# ---------------------------------------------------------------------------
DEFAULT_DB_PATH = "traffic_logs.db"
DEFAULT_NORMAL  = 3000   # registros legítimos a generar
DEFAULT_ATTACK  = 600    # registros de ataque a generar


# ---------------------------------------------------------------------------
# Datos de apoyo — tráfico legítimo
# ---------------------------------------------------------------------------
NORMAL_IPS = [
    "10.0.0.{}".format(i) for i in range(2, 100)
] + [
    "192.168.1.{}".format(i) for i in range(10, 80)
] + [
    "172.16.0.{}".format(i) for i in range(5, 50)
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/120.0.0.0 Mobile Safari/537.36",
    "PostmanRuntime/7.36.0",
    "python-requests/2.31.0",
    "axios/1.6.2",
]

NORMAL_ROUTES = {
    "GET": [
        ("/api/stats",           "application/json", None),
        ("/api/blocked-ips",     "application/json", None),
        ("/api/whitelist",       "application/json", None),
        ("/api/alerts",          "application/json", None),
        ("/api/attacks",         "application/json", None),
        ("/api/health",          "application/json", None),
        ("/api/users",           "application/json", None),
        ("/api/logs",            "application/json", None),
        ("/api/dashboard",       "application/json", None),
        ("/",                    "text/html",        None),
        ("/login",               "text/html",        None),
        ("/dashboard",           "text/html",        None),
        ("/products",            "application/json", None),
        ("/api/products?page=1", "application/json", None),
        ("/api/products?page=2", "application/json", None),
        ("/api/reports",         "application/json", None),
        ("/api/config",          "application/json", None),
        ("/static/main.js",      "text/javascript",  None),
        ("/static/style.css",    "text/css",         None),
        ("/favicon.ico",         "image/x-icon",     None),
    ],
    "POST": [
        ("/api/login",      "application/json",
            lambda: json.dumps({"username": random.choice(["alice", "bob", "carlos", "diana", "admin"]),
                                "password": "correctpass{}".format(random.randint(1, 99))})),
        ("/api/logout",     "application/json",
            lambda: json.dumps({"session_id": _rand_token()})),
        ("/api/alerts/ack", "application/json",
            lambda: json.dumps({"alert_id": random.randint(1000, 9999)})),
        ("/api/whitelist",  "application/json",
            lambda: json.dumps({"ip": "10.0.0.{}".format(random.randint(2, 50))})),
        ("/api/users",      "application/json",
            lambda: json.dumps({"name": random.choice(["Ana", "Luis", "Pedro", "Maria"]),
                                "role": random.choice(["viewer", "analyst"])})),
        ("/api/products",   "application/json",
            lambda: json.dumps({"name": random.choice(["Widget", "Gadget", "Tool"]),
                                "price": round(random.uniform(9.99, 999.99), 2)})),
        ("/api/feedback",   "application/json",
            lambda: json.dumps({"message": random.choice(["Great product", "Works well", "No issues"]),
                                "rating": random.randint(1, 5)})),
    ],
    "PUT": [
        ("/api/users/1",  "application/json",
            lambda: json.dumps({"role": "analyst"})),
        ("/api/users/2",  "application/json",
            lambda: json.dumps({"role": "viewer"})),
        ("/api/config",   "application/json",
            lambda: json.dumps({"max_requests": random.randint(100, 1000)})),
    ],
    "DELETE": [
        ("/api/blocked-ips/1",  "application/json", None),
        ("/api/blocked-ips/2",  "application/json", None),
        ("/api/whitelist/3",    "application/json", None),
    ],
}

NORMAL_HEADERS_BASE = {
    "Accept":           "application/json, text/html, */*",
    "Accept-Language":  "es-MX,es;q=0.9,en;q=0.8",
    "Accept-Encoding":  "gzip, deflate, br",
    "Connection":       "keep-alive",
}


# ---------------------------------------------------------------------------
# Datos de apoyo — tráfico de ataque
# ---------------------------------------------------------------------------
ATTACK_IPS = [
    "45.33.32.{}".format(i) for i in range(1, 30)
] + [
    "185.220.101.{}".format(i) for i in range(1, 20)
] + [
    "198.51.100.{}".format(i) for i in range(1, 15)
] + [
    "203.0.113.{}".format(i) for i in range(1, 15)
]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR 1=1 --",
    "admin'--",
    "' UNION SELECT NULL,NULL,NULL --",
    "' UNION SELECT username,password,NULL FROM users --",
    "1; DROP TABLE users --",
    "1' AND SLEEP(5) --",
    "' OR pg_sleep(5) --",
    "' AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects)) --",
    "'; INSERT INTO users VALUES ('hacker','hacked') --",
    "' OR EXISTS(SELECT * FROM users WHERE username='admin') --",
    "' AND EXTRACTVALUE(4,CONCAT(0x7e,(SELECT version()))) --",
    "' UNION SELECT NULL,table_name,NULL FROM information_schema.tables --",
    "1 OR 1=1",
    "1' OR '1'='1' /*",
    "' OR 'unusual'='unusual",
    "'; EXEC xp_cmdshell('dir') --",
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a) --",
    "' OR 4801=4801 -- -",
    "' UNION ALL SELECT NULL,NULL,NULL,NULL --",
    "1; WAITFOR DELAY '0:0:5' --",
    "admin' OR '1'='1' #",
    "' OR true='a' --+",
]

XSS_PAYLOADS = [
    "<script>alert('xss')</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(document.cookie)",
    "<svg onload=alert(1)>",
    "'\"><script>alert(String.fromCharCode(88,83,83))</script>",
    "<body onload=alert('XSS')>",
    "<iframe src=javascript:alert('xss')>",
    "';alert(String.fromCharCode(88,83,83))//",
    "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
    "%3Cscript%3Ealert('xss')%3C/script%3E",
]

BRUTE_FORCE_PASSWORDS = [
    "password", "123456", "admin", "root", "letmein",
    "qwerty", "abc123", "pass", "test", "guest",
    "12345678", "password1", "1q2w3e", "dragon", "master",
]

ATTACK_USER_AGENTS = [
    "sqlmap/1.7.8#stable (https://sqlmap.org)",
    "Nikto/2.1.6",
    "masscan/1.3",
    "curl/7.88.1",
    "python-requests/2.28.0",
    "Go-http-client/1.1",
    "Havij",
    "acunetix-product",
    "nmap scripting engine",
    "DirBuster-1.0-RC1",
    "Burp Suite Professional",
    "OWASP ZAP/2.14.0",
]

ATTACK_SCENARIOS = [
    "sqli", "xss", "brute_force", "credential_stuffing",
    "impossible_travel", "session_hijacking", "path_traversal",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _rand_token(length=32):
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(random.choices(chars, k=length))


def _rand_timestamp(start: datetime, end: datetime) -> str:
    delta = end - start
    random_seconds = random.randint(0, int(delta.total_seconds()))
    return (start + timedelta(seconds=random_seconds)).strftime("%Y-%m-%d %H:%M:%S")


def _normal_timestamp() -> str:
    """Timestamps distribuidos Feb-Mar 2026, con más peso en horario laboral."""
    start = datetime(2026, 2, 20, 8, 0, 0)
    end   = datetime(2026, 3, 18, 22, 0, 0)
    return _rand_timestamp(start, end)


def _attack_timestamp() -> str:
    """Ataques distribuidos uniformemente, incluyendo madrugada."""
    start = datetime(2026, 2, 20, 0, 0, 0)
    end   = datetime(2026, 3, 18, 23, 59, 59)
    return _rand_timestamp(start, end)


def _build_headers(ip: str, ua: str, content_type: str, extra: dict = None) -> str:
    h = {
        **NORMAL_HEADERS_BASE,
        "User-Agent":      ua,
        "Content-Type":    content_type,
        "X-Forwarded-For": ip,
    }
    if extra:
        h.update(extra)
    return json.dumps(h)


# ---------------------------------------------------------------------------
# Generadores de registros
# ---------------------------------------------------------------------------
def generate_normal_record() -> dict:
    method = random.choices(
        ["GET", "POST", "PUT", "DELETE"],
        weights=[80, 15, 3, 2],
    )[0]

    # PUT y DELETE tienen pocas rutas — fallback a GET si no hay entradas
    if method not in NORMAL_ROUTES or not NORMAL_ROUTES[method]:
        method = "GET"

    route_entry  = random.choice(NORMAL_ROUTES[method])
    path, content_type, body_fn = route_entry

    ip   = random.choice(NORMAL_IPS)
    ua   = random.choice(USER_AGENTS)
    body = body_fn() if callable(body_fn) else ""

    # query_params opcionales en GETs
    query_params = {}
    if method == "GET" and random.random() < 0.3:
        query_params = {
            "page":  random.randint(1, 10),
            "limit": random.choice([10, 25, 50]),
        }

    return {
        "source_ip":      ip,
        "method":         method,
        "path":           path,
        "headers":        _build_headers(ip, ua, content_type),
        "body":           body,
        "query_params":   json.dumps(query_params),
        "user_agent":     ua,
        "is_test_attack": 0,
        "content_type":   content_type,
        "timestamp":      _normal_timestamp(),
    }


def generate_attack_record() -> dict:
    scenario = random.choice(ATTACK_SCENARIOS)
    ip       = random.choice(ATTACK_IPS)
    ua       = random.choice(ATTACK_USER_AGENTS)

    # defaults
    method        = "GET"
    path          = "/api/login"
    content_type  = "application/x-www-form-urlencoded"
    body          = ""
    query_params  = {}
    extra_headers = {}

    if scenario == "sqli":
        payload = random.choice(SQLI_PAYLOADS)
        method  = random.choice(["GET", "POST"])
        path    = random.choice(["/api/login", "/api/users", "/api/products",
                                  "/search", "/api/reports"])
        if method == "POST":
            body         = json.dumps({"query": payload, "id": payload})
            content_type = "application/json"
        else:
            query_params = {"id": payload, "search": payload}
        extra_headers = {"X-Attack-Type": "sqli"}

    elif scenario == "xss":
        payload = random.choice(XSS_PAYLOADS)
        method  = random.choice(["GET", "POST"])
        path    = random.choice(["/search", "/comments", "/feedback", "/api/feedback"])
        if method == "POST":
            body         = json.dumps({"message": payload, "name": payload})
            content_type = "application/json"
        else:
            query_params = {"q": payload, "input": payload}
        extra_headers = {"X-Attack-Type": "xss"}

    elif scenario == "brute_force":
        username     = random.choice(["admin", "root", "administrator", "user"])
        password     = random.choice(BRUTE_FORCE_PASSWORDS)
        method       = "POST"
        path         = "/api/login"
        body         = json.dumps({"username": username, "password": password})
        content_type = "application/json"
        extra_headers = {
            "X-Attack-Type":    "brute_force",
            "X-Attempt-Count":  str(random.randint(10, 500)),
        }

    elif scenario == "credential_stuffing":
        method       = "POST"
        path         = "/api/login"
        body         = json.dumps({
            "username": "{}@example.com".format(_rand_token(8)),
            "password": _rand_token(12),
        })
        content_type = "application/json"
        # Botnet: IP aleatoria por intento
        ip = "{}.{}.{}.{}".format(
            random.randint(1, 254), random.randint(1, 254),
            random.randint(1, 254), random.randint(1, 254),
        )
        extra_headers = {"X-Attack-Type": "credential_stuffing"}

    elif scenario == "impossible_travel":
        method = "GET"
        path   = "/api/dashboard"
        extra_headers = {
            "X-Attack-Type": "impossible_travel",
            "Authorization": "Bearer {}".format(_rand_token(40)),
            "X-Country":     random.choice(["MX", "RU", "CN", "BR", "NG"]),
        }

    elif scenario == "session_hijacking":
        method = "GET"
        path   = random.choice(["/api/users", "/api/config", "/api/reports"])
        extra_headers = {
            "X-Attack-Type": "session_hijacking",
            "Cookie":        "session={}; token={}".format(
                             _rand_token(20), _rand_token(20)),
            "Authorization": "Bearer {}".format(_rand_token(40)),
        }

    elif scenario == "path_traversal":
        traversal = random.choice([
            "../../etc/passwd",
            "../../../etc/shadow",
            "..%2F..%2Fetc%2Fpasswd",
            "....//....//etc/passwd",
        ])
        method       = "GET"
        path         = "/static/{}".format(traversal)
        query_params = {"file": traversal}
        extra_headers = {"X-Attack-Type": "path_traversal"}

    return {
        "source_ip":      ip,
        "method":         method,
        "path":           path,
        "headers":        _build_headers(ip, ua, content_type, extra_headers),
        "body":           body,
        "query_params":   json.dumps(query_params),
        "user_agent":     ua,
        "is_test_attack": 1,
        "content_type":   content_type,
        "timestamp":      _attack_timestamp(),
    }


# ---------------------------------------------------------------------------
# Base de datos
# ---------------------------------------------------------------------------
def ensure_table(conn: sqlite3.Connection):
    """Crea la tabla si no existe (compatible con el schema de Flask)."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS traffic_logs (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            source_ip      TEXT,
            method         TEXT,
            path           TEXT,
            headers        TEXT,
            body           TEXT,
            query_params   TEXT,
            user_agent     TEXT,
            is_test_attack INTEGER DEFAULT 0,
            content_type   TEXT,
            timestamp      TEXT
        )
    """)
    conn.commit()


def insert_records(conn: sqlite3.Connection, records: list):
    sql = """
        INSERT INTO traffic_logs
            (source_ip, method, path, headers, body, query_params,
             user_agent, is_test_attack, content_type, timestamp)
        VALUES
            (:source_ip, :method, :path, :headers, :body, :query_params,
             :user_agent, :is_test_attack, :content_type, :timestamp)
    """
    conn.executemany(sql, records)
    conn.commit()


def print_stats(conn: sqlite3.Connection):
    total   = conn.execute("SELECT COUNT(*) FROM traffic_logs").fetchone()[0]
    if total == 0:
        print("\n  (La tabla está vacía)")
        return

    legit   = conn.execute("SELECT COUNT(*) FROM traffic_logs WHERE is_test_attack=0").fetchone()[0]
    attacks = conn.execute("SELECT COUNT(*) FROM traffic_logs WHERE is_test_attack=1").fetchone()[0]
    methods = conn.execute(
        "SELECT method, COUNT(*) FROM traffic_logs GROUP BY method ORDER BY 2 DESC"
    ).fetchall()
    routes  = conn.execute(
        "SELECT path, COUNT(*) FROM traffic_logs GROUP BY path ORDER BY 2 DESC LIMIT 10"
    ).fetchall()
    dates   = conn.execute(
        "SELECT MIN(timestamp), MAX(timestamp) FROM traffic_logs"
    ).fetchone()

    print("\n=== Estado de traffic_logs.db ===")
    print(f"  Total registros : {total:,}")
    print(f"  Legítimos       : {legit:,}  ({legit/total*100:.1f}%)")
    print(f"  Ataques         : {attacks:,}  ({attacks/total*100:.1f}%)")
    print(f"  Primer registro : {dates[0]}")
    print(f"  Último registro : {dates[1]}")
    print("\n  Métodos HTTP:")
    for m, c in methods:
        print(f"    {m:<8} {c:,}")
    print("\n  Top 10 rutas:")
    for p, c in routes:
        print(f"    {c:>6}  {p}")
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Genera tráfico HTTP sintético en traffic_logs.db"
    )
    parser.add_argument(
        "--db", default=DEFAULT_DB_PATH,
        help="Ruta a traffic_logs.db (default: traffic_logs.db en el directorio actual)"
    )
    parser.add_argument(
        "--normal", type=int, default=DEFAULT_NORMAL,
        help="Registros legítimos a generar (default: {})".format(DEFAULT_NORMAL)
    )
    parser.add_argument(
        "--attack", type=int, default=DEFAULT_ATTACK,
        help="Registros de ataque a generar (default: {})".format(DEFAULT_ATTACK)
    )
    parser.add_argument(
        "--preview", action="store_true",
        help="Solo muestra stats actuales, no genera nada"
    )
    args = parser.parse_args()

    db_path = Path(args.db)
    conn    = sqlite3.connect(db_path)
    ensure_table(conn)

    if args.preview:
        print_stats(conn)
        conn.close()
        return

    prev_total = conn.execute("SELECT COUNT(*) FROM traffic_logs").fetchone()[0]
    print(f"\nBase de datos   : {db_path.resolve()}")
    print(f"Registros prev. : {prev_total:,}")
    print(f"Generando       : {args.normal:,} legítimos + {args.attack:,} ataques\n")

    # — Generar tráfico legítimo —
    print("[1/2] Generando tráfico legítimo...", end=" ", flush=True)
    normal_records = [generate_normal_record() for _ in range(args.normal)]
    insert_records(conn, normal_records)
    print("listo.")

    # — Generar tráfico de ataque —
    print("[2/2] Generando tráfico de ataque...", end=" ", flush=True)
    attack_records = [generate_attack_record() for _ in range(args.attack)]
    insert_records(conn, attack_records)
    print("listo.")

    print_stats(conn)
    conn.close()

    print("Siguiente paso sugerido:")
    print("  py retrain_isolation_forest_db.py --db {}".format(db_path))
    print()


if __name__ == "__main__":
    main()
