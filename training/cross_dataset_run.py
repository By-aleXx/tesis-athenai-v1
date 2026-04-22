"""Script de validación cross-dataset — versión ejecutable directa"""
import pandas as pd, numpy as np, warnings, json, os, re, sys, traceback
warnings.filterwarnings('ignore')

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import MaxAbsScaler
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                             f1_score, roc_auc_score, confusion_matrix)
from scipy.sparse import hstack, csr_matrix
import xgboost as xgb

# ─── Rutas ───────────────────────────────────────────────────────────────────
BASE = r"c:\Users\jcond\OneDrive\Escritorio\prubas AthenAI"
RAW  = os.path.join(BASE, "training", "raw")
DATA = os.path.join(BASE, "data")
OUT  = os.path.join(BASE, "training", "results")
os.makedirs(OUT, exist_ok=True)

# ─── Carga de datasets ────────────────────────────────────────────────────────
print("Cargando pool combinado...")
pool = pd.concat([
    pd.read_csv(os.path.join(DATA, "train.csv")),
    pd.read_csv(os.path.join(DATA, "val.csv")),
    pd.read_csv(os.path.join(DATA, "test.csv")),
], ignore_index=True).drop_duplicates("text").reset_index(drop=True)
print(f"  Pool: {len(pool):,}  mal={pool.label.sum():,}  ben={(pool.label==0).sum():,}")

print("Cargando SQLiV3 original...")
sv3_path = os.path.join(RAW, "SQLiV3.csv")
sv3_raw  = pd.read_csv(sv3_path, header=None, encoding="utf-8", on_bad_lines="skip")
print(f"  Shape bruto: {sv3_raw.shape}  cols={sv3_raw.columns.tolist()}")
print(sv3_raw.head(3).to_string())

# Detectar columna de label (la que solo tiene 0 y 1)
label_col = None
for c in sv3_raw.columns:
    uniq = sv3_raw[c].dropna().unique()
    if set(map(int, uniq[:10])) <= {0, 1}:
        label_col = c
        break

text_col = 0
print(f"\n  Columna texto={text_col}, columna label={label_col}")
sv3 = sv3_raw[[text_col, label_col]].dropna()
sv3 = pd.DataFrame({"text": sv3[text_col].astype(str),
                    "label": sv3[label_col].astype(int)})
sv3 = sv3[sv3.label.isin([0,1])]
sv3 = sv3[sv3.text.str.len() >= 3].drop_duplicates("text").reset_index(drop=True)
print(f"  SQLiV3 limpio: {len(sv3):,}  mal={sv3.label.sum():,}  ben={(sv3.label==0).sum():,}")

# Pool sin SQLiV3
sv3_texts = set(sv3.text)
pool_no_sv3 = pool[~pool.text.isin(sv3_texts)].reset_index(drop=True)
print(f"  Pool-sin-SQLiV3: {len(pool_no_sv3):,}")

# ─── Feature Engineering ─────────────────────────────────────────────────────
PATS = [r"union\s+select", r"or\s+1\s*=\s*1", r"'\s*or\s+'",
        r"drop\s+table", r"<script", r"onerror\s*=", r"javascript:",
        r"--", r"/\*", r"exec\s*\(", r"sleep\s*\(", r"waitfor\s+delay"]

def hand(texts):
    rows = []
    for t in texts:
        tl = t.lower()
        rows.append([len(t),
                     sum(1 for c in t if c in "'\"<>()[];"),
                     sum(1 for p in PATS if re.search(p, tl)),
                     sum(1 for c in t if c.isdigit())])
    return np.array(rows, dtype=np.float32)

def run_exp(train_df, test_df, name):
    print(f"\n{'='*60}\n  {name}")
    print(f"  Train={len(train_df):,}  Test={len(test_df):,}")
    
    # Verificar que ambas clases existen en train y test
    train_cl = sorted(train_df.label.unique())
    test_cl  = sorted(test_df.label.unique())
    print(f"  Train labels: {train_cl}  Test labels: {test_cl}")
    
    tfidf  = TfidfVectorizer(max_features=3000, analyzer="char_wb",
                              ngram_range=(3,5), sublinear_tf=True)
    scaler = MaxAbsScaler()

    Xtr = hstack([tfidf.fit_transform(train_df.text),
                  csr_matrix(scaler.fit_transform(hand(train_df.text.tolist())))])
    Xte = hstack([tfidf.transform(test_df.text),
                  csr_matrix(scaler.transform(hand(test_df.text.tolist())))])

    model = xgb.XGBClassifier(n_estimators=300, max_depth=8, learning_rate=0.1,
                               subsample=0.8, colsample_bytree=0.8,
                               random_state=42, n_jobs=-1,
                               eval_metric="logloss", verbosity=0)
    model.fit(Xtr, train_df.label.values)

    yp  = model.predict(Xte)
    ypr = model.predict_proba(Xte)[:,1]
    yt  = test_df.label.values

    acc  = accuracy_score(yt, yp)
    prec = precision_score(yt, yp, zero_division=0)
    rec  = recall_score(yt, yp, zero_division=0)
    f1   = f1_score(yt, yp, zero_division=0)
    auc  = roc_auc_score(yt, ypr)
    tn,fp,fn,tp = confusion_matrix(yt, yp).ravel()

    print(f"  Accuracy : {acc:.4f}")
    print(f"  Precision: {prec:.4f}")
    print(f"  Recall   : {rec:.4f}")
    print(f"  F1-Score : {f1:.4f}")
    print(f"  AUC-ROC  : {auc:.4f}")
    print(f"  TN={tn:,} FP={fp:,} FN={fn:,} TP={tp:,}")

    return dict(name=name, n_train=len(train_df), n_test=len(test_df),
                accuracy=round(acc,4), precision=round(prec,4),
                recall=round(rec,4), f1=round(f1,4), auc=round(auc,4),
                TN=int(tn), FP=int(fp), FN=int(fn), TP=int(tp))

# ─── Ejecutar 3 experimentos ─────────────────────────────────────────────────
results = []

# Exp 1: Train(pool sin SQLiV3 ≈ CSIC+sqli) → Test(SQLiV3 completo)
results.append(run_exp(pool_no_sv3, sv3,
    "Exp1: Train(CSIC+sqli) → Test(SQLiV3 completo — dataset externo)"))

# Exp 2 y 3: sobre el pool combinado con diferentes splits
# Split limpio: 70% train / 30% test con stratify (train.csv vs val+test)
train_df = pd.read_csv(os.path.join(DATA, "train.csv"))
val_df   = pd.read_csv(os.path.join(DATA, "val.csv"))
test_df  = pd.read_csv(os.path.join(DATA, "test.csv"))
holdout  = pd.concat([val_df, test_df], ignore_index=True)

results.append(run_exp(train_df, holdout,
    "Exp2: Train(70% pool combinado) → Test(30% pool — split limpio)"))

results.append(run_exp(holdout, train_df,
    "Exp3: Train(30% pool) → Test(70% pool — test inverso)"))

# ─── Resumen ─────────────────────────────────────────────────────────────────
print(f"\n{'='*60}")
print("  RESUMEN FINAL")
print(f"{'='*60}")
print(f"  {'Experimento':<42} {'Acc':>6} {'F1':>6} {'AUC':>6} {'Rec':>6}")
print("  " + "-"*62)
for r in results:
    print(f"  {r['name'][:42]:<42} {r['accuracy']:>6.4f} "
          f"{r['f1']:>6.4f} {r['auc']:>6.4f} {r['recall']:>6.4f}")
avg = {k: round(sum(r[k] for r in results)/len(results),4)
       for k in ['accuracy','f1','auc','recall']}
print("  " + "-"*62)
print(f"  {'PROMEDIO':<42} {avg['accuracy']:>6.4f} "
      f"{avg['f1']:>6.4f} {avg['auc']:>6.4f} {avg['recall']:>6.4f}")

# Guardar
out_path = os.path.join(OUT, "cross_dataset_results.json")
with open(out_path, "w") as f:
    json.dump({"results": results, "avg": avg}, f, indent=2)
print(f"\n  Guardado: {out_path}")
