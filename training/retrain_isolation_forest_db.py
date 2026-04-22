"""
retrain_isolation_forest_db.py
================================
Reentrena el Isolation Forest de AthenAI usando los registros reales
(y sintéticos) almacenados en traffic_logs.db.

Lee directamente de SQLite — no requiere Flask ni LocalStack.

Features extraídas de cada request HTTP:
  1.  hour_of_day          Hora del request (0-23)
  2.  day_of_week          Día de la semana (0=lun … 6=dom)
  3.  is_night             1 si hora < 6 o hora >= 22
  4.  is_weekend           1 si sábado o domingo
  5.  method_encoded       GET=0, POST=1, PUT=2, DELETE=3, otro=4
  6.  path_depth           Número de segmentos en la URL
  7.  query_param_count    Número de parámetros en query string
  8.  body_length          Longitud del body (0 si vacío)
  9.  ua_is_bot            1 si User-Agent es de herramienta automatizada
  10. has_sqli_pattern     1 si hay indicios de SQL injection en path/body/params
  11. has_xss_pattern      1 si hay indicios de XSS en path/body/params
  12. has_traversal        1 si hay path traversal (../)
  13. ip_is_internal       1 si la IP es de rango privado
  14. content_length       Longitud del Content-Type (proxy de tipo de request)

Uso:
  py retrain_isolation_forest_db.py
  py retrain_isolation_forest_db.py --db /ruta/traffic_logs.db
  py retrain_isolation_forest_db.py --contamination 0.08
  py retrain_isolation_forest_db.py --no-save        # solo evaluación, no sobreescribe .pkl
  py retrain_isolation_forest_db.py --preview        # solo muestra distribución del dataset
"""

import argparse
import json
import re
import sqlite3
import sys
import warnings
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.preprocessing import StandardScaler

warnings.filterwarnings("ignore")

# ---------------------------------------------------------------------------
# Rutas por defecto
# ---------------------------------------------------------------------------
DEFAULT_DB          = Path(__file__).parent.parent / "athenai-dashboard" / "traffic_logs.db"
DEFAULT_MODEL_OUT   = Path(__file__).parent / "models" / "isolation_forest.pkl"
DEFAULT_SCALER_OUT  = Path(__file__).parent / "models" / "auth_scaler.pkl"
DEFAULT_METRICS_OUT = Path(__file__).parent / "results" / "isolation_forest_metrics.json"
DEFAULT_CONTAMINATION = 0.05

# ---------------------------------------------------------------------------
# Patrones de detección (regex)
# ---------------------------------------------------------------------------
_SQLI_RE = re.compile(
    r"union\s+select|or\s+1\s*=\s*1|'\s*or\s+'|drop\s+table|insert\s+into|"
    r"delete\s+from|xp_cmdshell|exec\s*\(|waitfor\s+delay|benchmark\s*\(|"
    r"sleep\s*\(|pg_sleep|extractvalue|information_schema",
    re.IGNORECASE,
)
_XSS_RE = re.compile(
    r"<script|onerror\s*=|javascript:|<svg|<iframe|<body\s+onload|"
    r"alert\s*\(|document\.cookie",
    re.IGNORECASE,
)
_TRAVERSAL_RE = re.compile(r"\.\./|\.\.%2F|%2e%2e/", re.IGNORECASE)

_BOT_UA_RE = re.compile(
    r"sqlmap|nikto|masscan|havij|acunetix|nmap|dirbuster|burp\s*suite|"
    r"owasp\s*zap|go-http-client|python-requests|curl/|wget/",
    re.IGNORECASE,
)

_METHOD_MAP = {"GET": 0, "POST": 1, "PUT": 2, "DELETE": 3}
_INTERNAL_PREFIXES = ("10.", "192.168.", "172.16.", "172.17.", "172.18.",
                      "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
                      "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
                      "172.29.", "172.30.", "172.31.", "127.", "::1")


# ---------------------------------------------------------------------------
# Extracción de features
# ---------------------------------------------------------------------------
def _flag(text: str, pattern: re.Pattern) -> int:
    return 1 if text and pattern.search(text) else 0


def extract_features(row: dict) -> np.ndarray:
    """Convierte una fila de traffic_logs en un vector de features."""
    ts_raw = row.get("timestamp") or ""
    try:
        ts = datetime.strptime(ts_raw[:19], "%Y-%m-%d %H:%M:%S")
    except ValueError:
        ts = datetime.utcnow()

    hour       = ts.hour
    dow        = ts.weekday()
    is_night   = 1 if hour < 6 or hour >= 22 else 0
    is_weekend = 1 if dow >= 5 else 0

    method  = (row.get("method") or "GET").upper()
    method_enc = _METHOD_MAP.get(method, 4)

    path    = row.get("path") or "/"
    depth   = max(len([p for p in path.split("/") if p]), 1)

    qp_raw  = row.get("query_params") or "{}"
    try:
        qp = json.loads(qp_raw)
        qp_count = len(qp) if isinstance(qp, dict) else 0
    except (json.JSONDecodeError, TypeError):
        qp_count = 0

    body        = row.get("body") or ""
    body_len    = len(body)

    ua          = row.get("user_agent") or ""
    ua_is_bot   = _flag(ua, _BOT_UA_RE)

    combined    = " ".join([path, body, str(qp_raw)])
    has_sqli    = _flag(combined, _SQLI_RE)
    has_xss     = _flag(combined, _XSS_RE)
    has_trav    = _flag(combined, _TRAVERSAL_RE)

    source_ip   = row.get("source_ip") or ""
    ip_internal = 1 if any(source_ip.startswith(p) for p in _INTERNAL_PREFIXES) else 0

    ct          = row.get("content_type") or ""
    ct_len      = len(ct)

    return np.array([
        hour, dow, is_night, is_weekend,
        method_enc, depth, qp_count, body_len,
        ua_is_bot, has_sqli, has_xss, has_trav,
        ip_internal, ct_len,
    ], dtype=np.float32)


FEATURE_NAMES = [
    "hour_of_day", "day_of_week", "is_night", "is_weekend",
    "method_encoded", "path_depth", "query_param_count", "body_length",
    "ua_is_bot", "has_sqli_pattern", "has_xss_pattern", "has_traversal",
    "ip_is_internal", "content_type_length",
]


# ---------------------------------------------------------------------------
# Carga de datos desde SQLite
# ---------------------------------------------------------------------------
def load_from_db(db_path: Path) -> tuple:
    """
    Lee traffic_logs y devuelve (X, y):
      X — matriz de features  (n_samples, n_features)
      y — etiquetas binarias  0=legítimo, 1=ataque
    """
    print(f"📂 Leyendo datos de: {db_path}")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    rows = conn.execute(
        "SELECT source_ip, method, path, headers, body, query_params, "
        "user_agent, is_test_attack, content_type, timestamp "
        "FROM traffic_logs"
    ).fetchall()
    conn.close()

    if not rows:
        print("❌ La tabla traffic_logs está vacía.")
        sys.exit(1)

    X, y = [], []
    for row in rows:
        X.append(extract_features(dict(row)))
        y.append(int(row["is_test_attack"]))

    X = np.array(X, dtype=np.float32)
    y = np.array(y, dtype=int)

    n_legit   = int((y == 0).sum())
    n_attack  = int((y == 1).sum())
    print(f"  ✓ Registros cargados : {len(y):,}")
    print(f"  ✓ Legítimos          : {n_legit:,}  ({n_legit/len(y)*100:.1f}%)")
    print(f"  ✓ Ataques            : {n_attack:,}  ({n_attack/len(y)*100:.1f}%)")
    return X, y


# ---------------------------------------------------------------------------
# Entrenamiento y evaluación
# ---------------------------------------------------------------------------
def train(X_train: np.ndarray, contamination: float) -> tuple:
    print(f"\n🌲 Entrenando Isolation Forest  (contamination={contamination}) ...")
    scaler  = StandardScaler()
    X_sc    = scaler.fit_transform(X_train)

    model = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        max_samples="auto",
        random_state=42,
        n_jobs=-1,
        verbose=0,
    )
    model.fit(X_sc)
    print("  ✓ Modelo entrenado")
    return model, scaler


def evaluate(model: IsolationForest, scaler: StandardScaler,
             X_test: np.ndarray, y_test: np.ndarray) -> dict:
    print("\n📊 Evaluando sobre conjunto de test ...")

    X_sc      = scaler.transform(X_test)
    raw_pred  = model.predict(X_sc)          # 1=normal, -1=anomalía
    scores    = model.score_samples(X_sc)    # más negativo = más anómalo
    y_pred    = (raw_pred == -1).astype(int) # 1=anomalía detectada

    prec = precision_score(y_test, y_pred, zero_division=0)
    rec  = recall_score(y_test, y_pred, zero_division=0)
    f1   = f1_score(y_test, y_pred, zero_division=0)
    cm   = confusion_matrix(y_test, y_pred)

    tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)

    print(f"  Precision : {prec:.4f}")
    print(f"  Recall    : {rec:.4f}")
    print(f"  F1-Score  : {f1:.4f}")
    print(f"\n  Matriz de Confusión:")
    print(f"    TN: {tn:6,}  |  FP: {fp:6,}")
    print(f"    FN: {fn:6,}  |  TP: {tp:6,}")
    print()
    print(classification_report(y_test, y_pred,
                                 target_names=["Legítimo", "Ataque"],
                                 zero_division=0))

    # Precision@K
    k_vals = [10, 50, 100]
    top_k  = {}
    for k in k_vals:
        if k <= len(scores):
            idx = np.argsort(scores)[:k]
            top_k[f"precision_at_{k}"] = float(y_test[idx].sum() / k)

    metrics = {
        "precision":        float(prec),
        "recall":           float(rec),
        "f1_score":         float(f1),
        "confusion_matrix": cm.tolist(),
        "timestamp":        datetime.utcnow().isoformat(),
        **top_k,
    }
    return metrics


# ---------------------------------------------------------------------------
# Persistencia
# ---------------------------------------------------------------------------
def save_model(model, scaler, model_path: Path, scaler_path: Path):
    model_path.parent.mkdir(parents=True, exist_ok=True)
    scaler_path.parent.mkdir(parents=True, exist_ok=True)

    joblib.dump({"model": model, "scaler": scaler}, model_path)
    joblib.dump(scaler, scaler_path)
    print(f"  💾 Modelo  guardado en : {model_path}")
    print(f"  💾 Scaler  guardado en : {scaler_path}")


def save_metrics(metrics: dict, path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    print(f"  💾 Métricas guardadas en: {path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Reentrena el Isolation Forest de AthenAI desde traffic_logs.db"
    )
    parser.add_argument("--db", type=Path, default=DEFAULT_DB,
                        help="Ruta a traffic_logs.db")
    parser.add_argument("--model-out", type=Path, default=DEFAULT_MODEL_OUT,
                        help="Ruta de salida del modelo (.pkl)")
    parser.add_argument("--scaler-out", type=Path, default=DEFAULT_SCALER_OUT,
                        help="Ruta de salida del scaler (.pkl)")
    parser.add_argument("--metrics-out", type=Path, default=DEFAULT_METRICS_OUT,
                        help="Ruta de salida de métricas (.json)")
    parser.add_argument("--contamination", type=float, default=DEFAULT_CONTAMINATION,
                        help="Fracción esperada de anomalías (default: 0.05)")
    parser.add_argument("--test-size", type=float, default=0.2,
                        help="Fracción del dataset para test (default: 0.2)")
    parser.add_argument("--no-save", action="store_true",
                        help="No sobreescribir .pkl — solo evalúa")
    parser.add_argument("--preview", action="store_true",
                        help="Solo muestra distribución, no entrena")
    args = parser.parse_args()

    print("\n" + "=" * 70)
    print("  ATHENAI — Reentrenamiento Isolation Forest desde SQLite")
    print("=" * 70 + "\n")

    # Verificar DB
    if not args.db.exists():
        print(f"❌ No se encontró: {args.db}")
        print("   Genera tráfico primero con:")
        print("   py athenai-dashboard/generate_traffic_db.py")
        sys.exit(1)

    # Cargar datos
    X, y = load_from_db(args.db)

    if args.preview:
        sys.exit(0)

    # Split train/test estratificado
    from sklearn.model_selection import train_test_split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=args.test_size,
        random_state=42,
        stratify=y,
    )
    print(f"\n📊 Split  →  Train: {len(X_train):,}  |  Test: {len(X_test):,}")

    # IF solo ve tráfico legítimo en entrenamiento (aprendizaje no supervisado)
    X_train_legit = X_train[y_train == 0]
    print(f"   (IF entrenado solo sobre {len(X_train_legit):,} registros legítimos)")

    # Entrenar
    model, scaler = train(X_train_legit, args.contamination)

    # Evaluar sobre TODO el test (legítimo + ataques) para medir detección
    print(f"\n   Evaluando sobre test completo "
          f"({(y_test == 0).sum():,} legítimos + {(y_test == 1).sum():,} ataques) ...")
    metrics = evaluate(model, scaler, X_test, y_test)

    # Guardar
    if not args.no_save:
        print("\n💾 Guardando artefactos ...")
        save_model(model, scaler, args.model_out, args.scaler_out)
        save_metrics(metrics, args.metrics_out)
    else:
        print("\n⚠️  --no-save activo: artefactos NO sobreescritos.")

    print("\n" + "=" * 70)
    print("  ✅  Reentrenamiento completado")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
