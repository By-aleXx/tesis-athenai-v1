"""
AthenAI - Experimento Cross-Dataset XGBoost
============================================

Evalúa la generalización REAL del modelo entrenando en 2 datasets
y testeando en el tercero completo (no visto durante entrenamiento).

3 experimentos:
  Exp 1: Train(CSIC + SQLiV3)  → Test(sqli.csv completo)
  Exp 2: Train(CSIC + sqli)    → Test(SQLiV3 completo)
  Exp 3: Train(SQLiV3 + sqli)  → Test(CSIC completo)

Uso:
    py cross_dataset_eval.py --csic /ruta/csic.csv --sqliv3 /ruta/SQLiV3.csv --sqli /ruta/sqli.csv

Autor: AthenAI Team
Fecha: 2026-03-18
"""

import argparse
import os
import sys
import json
import warnings
warnings.filterwarnings('ignore')

import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import MaxAbsScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, confusion_matrix
)
from scipy.sparse import hstack
import xgboost as xgb


# ─────────────────────────────────────────────
# CONFIGURACIÓN POR DEFECTO (rutas editables)
# ─────────────────────────────────────────────
DEFAULT_PATHS = {
    "csic":    r"c:\Users\jcond\OneDrive\Escritorio\prubas AthenAI\training\raw\csic_database.csv",
    "sqliv3":  r"c:\Users\jcond\OneDrive\Escritorio\prubas AthenAI\training\raw\SQLiV3.csv",
    "sqli":    r"c:\Users\jcond\OneDrive\Escritorio\prubas AthenAI\training\raw\sqli.csv",
}

OUTPUT_DIR = r"c:\Users\jcond\OneDrive\Escritorio\prubas AthenAI\training\results"


# ─────────────────────────────────────────────
# CARGA Y NORMALIZACIÓN DE DATASETS
# ─────────────────────────────────────────────

def load_csic(path: str) -> pd.DataFrame:
    """CSIC: columnas Query + Label (0=normal, 1=ataque)"""
    df = pd.read_csv(path, encoding='utf-8', on_bad_lines='skip')
    df.columns = df.columns.str.strip()
    # Soporte para dos variantes de cabecera
    text_col  = 'Query' if 'Query' in df.columns else 'URL'
    label_col = 'Label' if 'Label' in df.columns else 'classification'
    if label_col == 'classification':
        labels = df[label_col].apply(
            lambda x: 0 if str(x).strip().lower() == 'normal' else 1
        )
    else:
        labels = pd.to_numeric(df[label_col], errors='coerce').fillna(0).astype(int)
    data = pd.DataFrame({'text': df[text_col].astype(str), 'label': labels})
    return _clean(data, 'CSIC')


def load_sqliv3(path: str) -> pd.DataFrame:
    """SQLiV3: sin cabecera, col[0]=Sentence, col[1]=Label"""
    df = pd.read_csv(path, encoding='utf-8', on_bad_lines='skip', header=None)
    # Si la primera fila tiene cabeceras de texto, usarlas; si no, usar posición
    if str(df.iloc[0, 1]).strip().lower() in ('label', 'etiqueta'):
        df.columns = df.iloc[0]
        df = df[1:].reset_index(drop=True)
        df.columns = df.columns.str.strip()
        text_col, label_col = 'Sentence', 'Label'
        df = df.dropna(subset=[text_col, label_col])
        data = pd.DataFrame({
            'text':  df[text_col].astype(str),
            'label': pd.to_numeric(df[label_col], errors='coerce').fillna(0).astype(int)
        })
    else:
        df = df[[0, 1]].copy()
        df.columns = ['text', 'label']
        df = df[pd.to_numeric(df['label'], errors='coerce').notna()]
        df['label'] = pd.to_numeric(df['label'], errors='coerce').fillna(0).astype(int)
        data = df.reset_index(drop=True)
    return _clean(data, 'SQLiV3')


def load_sqli(path: str) -> pd.DataFrame:
    """sqli.csv: columnas Sentence + Label, encoding UTF-16"""
    try:
        df = pd.read_csv(path, encoding='utf-16', on_bad_lines='skip')
    except Exception:
        df = pd.read_csv(path, encoding='utf-8', on_bad_lines='skip')
    df.columns = df.columns.str.strip()
    df = df.dropna(subset=['Sentence', 'Label'])
    data = pd.DataFrame({
        'text':  df['Sentence'].astype(str),
        'label': df['Label'].astype(int)
    })
    return _clean(data, 'sqli.csv')


def _clean(df: pd.DataFrame, name: str) -> pd.DataFrame:
    """Limpieza básica: eliminar vacíos, muy cortos y duplicados."""
    initial = len(df)
    df = df[df['text'].notna()]
    df = df[df['text'].str.strip() != '']
    df = df[df['text'].str.len() >= 3]
    df = df.drop_duplicates(subset=['text'], keep='first')
    df = df.reset_index(drop=True)
    n_mal = int(df['label'].sum())
    n_ben = int((df['label'] == 0).sum())
    print(f"  [{name}] {len(df):,} muestras  "
          f"({n_mal:,} maliciosas / {n_ben:,} normales)  "
          f"[eliminados {initial - len(df):,}]")
    return df


# ─────────────────────────────────────────────
# FEATURE ENGINEERING (TF-IDF + handcrafted)
# ─────────────────────────────────────────────

ATTACK_PATTERNS = [
    r"union\s+select", r"or\s+1\s*=\s*1", r"'\s*or\s+'",
    r"drop\s+table", r"insert\s+into", r"delete\s+from",
    r"<script", r"onerror\s*=", r"javascript:",
    r"--", r"/\*", r"xp_cmdshell", r"exec\s*\(",
    r"waitfor\s+delay", r"benchmark\s*\(", r"sleep\s*\("
]


def handcrafted_features(texts):
    import re
    rows = []
    for t in texts:
        tl = t.lower()
        n_special = sum(1 for c in t if c in "'\"<>()[];")
        n_attack   = sum(1 for p in ATTACK_PATTERNS if re.search(p, tl))
        n_digits   = sum(1 for c in t if c.isdigit())
        rows.append([len(t), n_special, n_attack, n_digits,
                     n_special / max(len(t), 1)])
    return np.array(rows, dtype=np.float32)


class CrossDatasetPipeline:
    def __init__(self, max_features: int = 3000):
        self.tfidf   = TfidfVectorizer(
            max_features=max_features,
            analyzer='char_wb',
            ngram_range=(3, 5),
            sublinear_tf=True
        )
        self.scaler  = MaxAbsScaler()
        self.model   = None

    def fit_transform(self, texts, labels):
        X_tfidf = self.tfidf.fit_transform(texts)
        X_hand  = self.scaler.fit_transform(handcrafted_features(texts))
        from scipy.sparse import csr_matrix
        X = hstack([X_tfidf, csr_matrix(X_hand)])
        self.model = xgb.XGBClassifier(
            n_estimators=200,
            max_depth=10,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            random_state=42,
            n_jobs=-1,
            eval_metric='logloss',
            verbosity=0
        )
        self.model.fit(X, labels)
        return X

    def transform(self, texts):
        X_tfidf = self.tfidf.transform(texts)
        X_hand  = self.scaler.transform(handcrafted_features(texts))
        from scipy.sparse import csr_matrix
        return hstack([X_tfidf, csr_matrix(X_hand)])


# ─────────────────────────────────────────────
# EVALUACIÓN
# ─────────────────────────────────────────────

def evaluate(pipeline: CrossDatasetPipeline,
             test_df: pd.DataFrame,
             test_name: str,
             train_names: str) -> dict:
    """Evalúa el modelo sobre el dataset de test y retorna métricas."""
    X_test = pipeline.transform(test_df['text'].tolist())
    y_test = test_df['label'].values

    y_pred  = pipeline.model.predict(X_test)
    y_proba = pipeline.model.predict_proba(X_test)[:, 1]

    acc  = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec  = recall_score(y_test, y_pred, zero_division=0)
    f1   = f1_score(y_test, y_pred, zero_division=0)
    auc  = roc_auc_score(y_test, y_proba)
    cm   = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()

    print(f"\n  ┌─ RESULTADOS sobre {test_name} ─────────────────────")
    print(f"  │  Accuracy : {acc:.4f}  ({acc*100:.2f}%)")
    print(f"  │  Precision: {prec:.4f}")
    print(f"  │  Recall   : {rec:.4f}")
    print(f"  │  F1-Score : {f1:.4f}")
    print(f"  │  AUC-ROC  : {auc:.4f}")
    print(f"  │  Confusion Matrix:")
    print(f"  │    TN={tn:6,}  FP={fp:6,}")
    print(f"  │    FN={fn:6,}  TP={tp:6,}")
    print(f"  └─────────────────────────────────────────────────────")

    return {
        "train_on": train_names,
        "test_on":  test_name,
        "n_test":   len(test_df),
        "accuracy":  round(acc,  4),
        "precision": round(prec, 4),
        "recall":    round(rec,  4),
        "f1_score":  round(f1,   4),
        "auc_roc":   round(auc,  4),
        "confusion_matrix": {"TN": int(tn), "FP": int(fp),
                             "FN": int(fn), "TP": int(tp)}
    }


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def run_experiments(csic_path, sqliv3_path, sqli_path):
    sep = "=" * 70

    print(f"\n{sep}")
    print("   AthenAI — Experimento Cross-Dataset XGBoost")
    print(f"{sep}\n")

    # ── Cargar datasets ──────────────────────────────────────
    print("📂 Cargando datasets originales...")
    csic   = load_csic(csic_path)
    sqliv3 = load_sqliv3(sqliv3_path)
    sqli   = load_sqli(sqli_path)

    results = []

    # ══ Experimento 1 ══════════════════════════════════════
    print(f"\n{sep}")
    print("  Experimento 1: Train(CSIC + SQLiV3) → Test(sqli.csv)")
    print(f"{sep}")
    train1 = pd.concat([csic, sqliv3], ignore_index=True).sample(
        frac=1, random_state=42).reset_index(drop=True)
    print(f"  Train: {len(train1):,} muestras | "
          f"Test : {len(sqli):,} muestras")
    p1 = CrossDatasetPipeline()
    p1.fit_transform(train1['text'].tolist(), train1['label'].values)
    r1 = evaluate(p1, sqli, "sqli.csv", "CSIC + SQLiV3")
    results.append(r1)

    # ══ Experimento 2 ══════════════════════════════════════
    print(f"\n{sep}")
    print("  Experimento 2: Train(CSIC + sqli.csv) → Test(SQLiV3)")
    print(f"{sep}")
    train2 = pd.concat([csic, sqli], ignore_index=True).sample(
        frac=1, random_state=42).reset_index(drop=True)
    print(f"  Train: {len(train2):,} muestras | "
          f"Test : {len(sqliv3):,} muestras")
    p2 = CrossDatasetPipeline()
    p2.fit_transform(train2['text'].tolist(), train2['label'].values)
    r2 = evaluate(p2, sqliv3, "SQLiV3", "CSIC + sqli.csv")
    results.append(r2)

    # ══ Experimento 3 ══════════════════════════════════════
    print(f"\n{sep}")
    print("  Experimento 3: Train(SQLiV3 + sqli.csv) → Test(CSIC)")
    print(f"{sep}")
    train3 = pd.concat([sqliv3, sqli], ignore_index=True).sample(
        frac=1, random_state=42).reset_index(drop=True)
    print(f"  Train: {len(train3):,} muestras | "
          f"Test : {len(csic):,} muestras")
    p3 = CrossDatasetPipeline()
    p3.fit_transform(train3['text'].tolist(), train3['label'].values)
    r3 = evaluate(p3, csic, "CSIC", "SQLiV3 + sqli.csv")
    results.append(r3)

    # ── Resumen final ─────────────────────────────────────
    print(f"\n{sep}")
    print("   RESUMEN — Generalización Cross-Dataset")
    print(f"{sep}")
    print(f"  {'Experimento':<35} {'Accuracy':>9} {'F1':>8} {'AUC':>8} {'Recall':>8}")
    print("  " + "-"*70)
    for r in results:
        exp_name = f"Test: {r['test_on']}"
        print(f"  {exp_name:<35} {r['accuracy']:>9.4f} "
              f"{r['f1_score']:>8.4f} {r['auc_roc']:>8.4f} "
              f"{r['recall']:>8.4f}")

    avg_f1  = sum(r['f1_score'] for r in results) / 3
    avg_acc = sum(r['accuracy'] for r in results) / 3
    avg_auc = sum(r['auc_roc'] for r in results) / 3
    print("  " + "-"*70)
    print(f"  {'PROMEDIO':<35} {avg_acc:>9.4f} "
          f"{avg_f1:>8.4f} {avg_auc:>8.4f}")

    # ── Guardar resultados ────────────────────────────────
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    out_path = os.path.join(OUTPUT_DIR, "cross_dataset_results.json")
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump({
            "experiments": results,
            "summary": {
                "avg_accuracy":  round(avg_acc, 4),
                "avg_f1_score":  round(avg_f1,  4),
                "avg_auc_roc":   round(avg_auc, 4),
            }
        }, f, indent=2, ensure_ascii=False)
    print(f"\n  ✅ Resultados guardados en: {out_path}")
    print(f"{sep}\n")

    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Experimento cross-dataset XGBoost para AthenAI"
    )
    parser.add_argument("--csic",   default=DEFAULT_PATHS["csic"],
                        help="Ruta al CSV de CSIC")
    parser.add_argument("--sqliv3", default=DEFAULT_PATHS["sqliv3"],
                        help="Ruta al CSV de SQLiV3")
    parser.add_argument("--sqli",   default=DEFAULT_PATHS["sqli"],
                        help="Ruta al CSV de sqli")
    args = parser.parse_args()

    # Verificar que existen los archivos
    missing = []
    for name, path in [("CSIC", args.csic),
                        ("SQLiV3", args.sqliv3),
                        ("sqli.csv", args.sqli)]:
        if not os.path.isfile(path):
            missing.append(f"  ✗ {name}: {path}")

    if missing:
        print("\n❌ No se encontraron los siguientes archivos:")
        print("\n".join(missing))
        print("\nUso: py cross_dataset_eval.py --csic <ruta> --sqliv3 <ruta> --sqli <ruta>")
        print("O edita DEFAULT_PATHS en la línea 47 del script.")
        sys.exit(1)

    run_experiments(args.csic, args.sqliv3, args.sqli)
