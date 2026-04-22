"""
AthenAI - Calibración del Umbral Óptimo
=========================================

Calcula el umbral de decisión óptimo para el modelo XGBoost principal
usando tres criterios estadísticos:

  1. Youden's J (maximiza Sensibilidad + Especificidad)
  2. Máximo F1-Score
  3. Punto más cercano a (0,1) en la curva ROC

El umbral calibrado se guarda en 'models/threshold.json' para ser
consumido por model_inference.py y el pipeline de producción.

Uso:
    python -m training.calibrate_threshold

    # O directamente desde el directorio raíz:
    python training/calibrate_threshold.py

Salida:
    training/results/threshold_calibration.json
    models/threshold.json  (para producción)

Autor: AthenAI Team
Fecha: 2026-03-30
"""

from __future__ import annotations

import json
import os
import sys
import warnings
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV, calibration_curve
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)

warnings.filterwarnings("ignore")

# ---------------------------------------------------------------------------
# Rutas del proyecto (relativas al directorio raíz)
# ---------------------------------------------------------------------------
ROOT = Path(__file__).resolve().parent.parent
DATA_DIR       = ROOT / "data"
MODELS_DIR     = ROOT / "training" / "models"
PROD_MODELS    = ROOT / "models"
RESULTS_DIR    = ROOT / "training" / "results"

VAL_CSV        = DATA_DIR / "val.csv"
TEST_CSV       = DATA_DIR / "test.csv"
XGBOOST_PKL    = MODELS_DIR / "xgboost.pkl"
FEAT_ENG_PKL   = MODELS_DIR / "feature_engineer.pkl"

OUT_RESULTS    = RESULTS_DIR / "threshold_calibration.json"
OUT_PROD       = PROD_MODELS / "threshold.json"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_artifacts() -> tuple:
    """Carga modelo XGBoost y feature engineer desde disco."""
    print(f"📦 Cargando modelo XGBoost desde {XGBOOST_PKL}...")
    model = joblib.load(XGBOOST_PKL)

    print(f"📦 Cargando FeatureEngineer desde {FEAT_ENG_PKL}...")
    fe = joblib.load(FEAT_ENG_PKL)

    print("✅ Artefactos cargados correctamente.\n")
    return model, fe


def load_split(csv_path: Path, fe) -> tuple[np.ndarray, np.ndarray]:
    """Carga un CSV y extrae features."""
    df = pd.read_csv(csv_path)
    print(f"  📂 {csv_path.name}: {len(df):,} muestras")
    X, _ = fe.extract_all_features(df)
    y = df["label"].values
    return X, y


def get_probabilities(model, X: np.ndarray) -> np.ndarray:
    """Devuelve probabilidades P(clase=1) para el array X."""
    if hasattr(model, "predict_proba"):
        return model.predict_proba(X)[:, 1]
    # Fallback para modelos sin predict_proba (no debería ocurrir con XGBoost)
    scores = model.decision_function(X)
    return (scores - scores.min()) / (scores.max() - scores.min() + 1e-10)


# ---------------------------------------------------------------------------
# Criterios de selección de umbral
# ---------------------------------------------------------------------------

def threshold_youden(fpr: np.ndarray, tpr: np.ndarray, thresholds: np.ndarray) -> tuple[float, dict]:
    """Umbral que maximiza el índice J de Youden (TPR - FPR)."""
    j_scores = tpr - fpr
    idx = int(np.argmax(j_scores))
    return float(thresholds[idx]), {"j_score": float(j_scores[idx])}


def threshold_max_f1(y_true: np.ndarray, y_proba: np.ndarray) -> tuple[float, dict]:
    """Umbral que maximiza el F1-Score en la curva Precision-Recall."""
    precisions, recalls, thresholds_pr = precision_recall_curve(y_true, y_proba)
    # precision_recall_curve devuelve N+1 puntos; thresholds tiene N
    f1_scores = 2 * precisions[:-1] * recalls[:-1] / (precisions[:-1] + recalls[:-1] + 1e-10)
    idx = int(np.argmax(f1_scores))
    return float(thresholds_pr[idx]), {
        "f1": float(f1_scores[idx]),
        "precision": float(precisions[idx]),
        "recall": float(recalls[idx]),
    }


def threshold_closest_roc(fpr: np.ndarray, tpr: np.ndarray, thresholds: np.ndarray) -> tuple[float, dict]:
    """Umbral del punto más cercano a la esquina (0,1) de la curva ROC."""
    distances = np.sqrt(fpr**2 + (1 - tpr)**2)
    idx = int(np.argmin(distances))
    return float(thresholds[idx]), {"distance_to_01": float(distances[idx])}


# ---------------------------------------------------------------------------
# Evaluación con un umbral dado
# ---------------------------------------------------------------------------

def evaluate_at_threshold(y_true: np.ndarray, y_proba: np.ndarray, threshold: float) -> dict:
    """Calcula métricas completas aplicando el umbral indicado."""
    y_pred = (y_proba >= threshold).astype(int)
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()

    return {
        "threshold": round(threshold, 6),
        "accuracy":  round(float(accuracy_score(y_true, y_pred)),  6),
        "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 6),
        "recall":    round(float(recall_score(y_true, y_pred,    zero_division=0)), 6),
        "f1_score":  round(float(f1_score(y_true, y_pred,        zero_division=0)), 6),
        "auc_roc":   round(float(roc_auc_score(y_true, y_proba)),  6),
        "avg_precision": round(float(average_precision_score(y_true, y_proba)), 6),
        "brier_score":   round(float(brier_score_loss(y_true, y_proba)), 6),
        "confusion_matrix": {"TN": int(tn), "FP": int(fp), "FN": int(fn), "TP": int(tp)},
        "false_positive_rate": round(float(fp / (fp + tn + 1e-10)), 6),
        "false_negative_rate": round(float(fn / (fn + tp + 1e-10)), 6),
        "specificity": round(float(tn / (tn + fp + 1e-10)), 6),
    }


# ---------------------------------------------------------------------------
# Calibración de probabilidades (Platt Scaling / Isotonic)
# ---------------------------------------------------------------------------

def calibrate_probabilities(model, X_val: np.ndarray, y_val: np.ndarray
                             ) -> tuple[object, np.ndarray]:
    """
    Aplica calibración de probabilidades usando Isotonic Regression.

    Estrategia compatible con scikit-learn ≥1.0:
      - Usamos las probabilidades crudas del modelo como input.
      - Ajustamos un IsotonicRegression directamente sobre el conjunto
        de validación (equivalente funcional a cv='prefit').

    Devuelve el calibrador ajustado y las probabilidades calibradas en val.
    """
    from sklearn.isotonic import IsotonicRegression

    print("🔧 Calibrando probabilidades del modelo (Isotonic Regression)...")
    raw_proba = get_probabilities(model, X_val)

    calibrator = IsotonicRegression(out_of_bounds="clip")
    calibrator.fit(raw_proba, y_val)

    y_cal = calibrator.predict(raw_proba).astype(float)
    print("  ✅ Calibración completada.\n")
    return calibrator, y_cal


# ---------------------------------------------------------------------------
# Función principal
# ---------------------------------------------------------------------------

def main():
    print("\n" + "="*80)
    print("ATHENAI — CALIBRACIÓN DEL UMBRAL ÓPTIMO")
    print("="*80 + "\n")
    start_time = datetime.now()

    # 1. Cargar artefactos
    model, fe = load_artifacts()

    # 2. Cargar splits
    print("📊 Cargando splits de datos...")
    X_val,  y_val  = load_split(VAL_CSV,  fe)
    X_test, y_test = load_split(TEST_CSV, fe)
    print()

    # 3. Probabilidades crudas en validación
    print("📈 Calculando probabilidades crudas en validación...")
    y_val_proba_raw = get_probabilities(model, X_val)

    # 4. Calibrar probabilidades
    calibrator, y_val_proba_cal = calibrate_probabilities(model, X_val, y_val)

    # Guardar calibrador
    cal_path = MODELS_DIR / "xgboost_isotonic_calibrator.pkl"
    joblib.dump(calibrator, cal_path)
    print(f"  💾 Calibrador guardado: {cal_path}\n")

    # 5. Calcular curva ROC en validación (con probabilidades calibradas)
    fpr, tpr, thresholds_roc = roc_curve(y_val, y_val_proba_cal)

    # 6. Encontrar umbral óptimo con los tres criterios
    print("🎯 Calculando umbrales óptimos...\n")
    th_youden, meta_youden     = threshold_youden(fpr, tpr, thresholds_roc)
    th_f1,     meta_f1        = threshold_max_f1(y_val, y_val_proba_cal)
    th_roc,    meta_roc       = threshold_closest_roc(fpr, tpr, thresholds_roc)

    candidates = {
        "youden_j":        th_youden,
        "max_f1":          th_f1,
        "closest_roc_01":  th_roc,
    }

    print(f"  Youden J         → {th_youden:.4f}  (J={meta_youden['j_score']:.4f})")
    print(f"  Máximo F1        → {th_f1:.4f}  (F1={meta_f1['f1']:.4f})")
    print(f"  Cercano ROC(0,1) → {th_roc:.4f}  (dist={meta_roc['distance_to_01']:.4f})\n")

    # 7. Métricas de validación para cada candidato
    print("📊 Evaluando candidatos en conjunto de VALIDACIÓN:")
    print("-"*80)
    val_evals: dict[str, dict] = {}
    for name, th in candidates.items():
        ev = evaluate_at_threshold(y_val, y_val_proba_cal, th)
        val_evals[name] = ev
        print(f"  [{name}]")
        print(f"    Umbral={ev['threshold']:.4f}  Acc={ev['accuracy']:.4f}  "
              f"Prec={ev['precision']:.4f}  Rec={ev['recall']:.4f}  F1={ev['f1_score']:.4f}")
        print(f"    AUC={ev['auc_roc']:.4f}  FPR={ev['false_positive_rate']:.4f}  "
              f"FNR={ev['false_negative_rate']:.4f}  Brier={ev['brier_score']:.4f}")
    print()

    # 8. Seleccionar el mejor umbral: priorizar F1 más alto en validación
    best_name = max(val_evals, key=lambda k: val_evals[k]["f1_score"])
    best_threshold = val_evals[best_name]["threshold"]

    print(f"🏆 UMBRAL SELECCIONADO: [{best_name}] → {best_threshold:.4f}\n")

    # 9. Evaluación final en TEST SET (datos nunca vistos)
    print("="*80)
    print("🧪 EVALUACIÓN FINAL EN TEST SET (datos no vistos)")
    print("="*80)

    y_test_proba_raw = get_probabilities(model, X_test)
    y_test_proba = calibrator.predict(y_test_proba_raw).astype(float)

    # Con umbral por defecto (0.5)
    test_default = evaluate_at_threshold(y_test, y_test_proba, 0.5)
    # Con umbral óptimo calibrado
    test_optimal = evaluate_at_threshold(y_test, y_test_proba, best_threshold)

    print(f"\n  Umbral 0.5 (por defecto):")
    print(f"    Acc={test_default['accuracy']:.4f}  Prec={test_default['precision']:.4f}  "
          f"Rec={test_default['recall']:.4f}  F1={test_default['f1_score']:.4f}")
    print(f"    FPR={test_default['false_positive_rate']:.4f}  FNR={test_default['false_negative_rate']:.4f}")

    print(f"\n  Umbral {best_threshold:.4f} (óptimo calibrado):")
    print(f"    Acc={test_optimal['accuracy']:.4f}  Prec={test_optimal['precision']:.4f}  "
          f"Rec={test_optimal['recall']:.4f}  F1={test_optimal['f1_score']:.4f}")
    print(f"    FPR={test_optimal['false_positive_rate']:.4f}  FNR={test_optimal['false_negative_rate']:.4f}")

    delta_f1 = test_optimal["f1_score"] - test_default["f1_score"]
    delta_fpr = test_default["false_positive_rate"] - test_optimal["false_positive_rate"]
    print(f"\n  ΔF1  = {delta_f1:+.4f}   (mejora positiva = mejor)")
    print(f"  ΔFPR = {delta_fpr:+.4f}   (reducción positiva = menos falsos positivos)\n")

    # 10. Matrices de confusión comparativas
    print("  Matriz de Confusión — Umbral 0.5:")
    cm0 = test_default["confusion_matrix"]
    print(f"    TN={cm0['TN']:>6}  FP={cm0['FP']:>6}")
    print(f"    FN={cm0['FN']:>6}  TP={cm0['TP']:>6}")

    print(f"\n  Matriz de Confusión — Umbral {best_threshold:.4f}:")
    cmo = test_optimal["confusion_matrix"]
    print(f"    TN={cmo['TN']:>6}  FP={cmo['FP']:>6}")
    print(f"    FN={cmo['FN']:>6}  TP={cmo['TP']:>6}")

    # 11. Construcción del resultado final
    result = {
        "generated_at": datetime.now().isoformat(),
        "model": "XGBoost (calibrado con Isotonic Regression)",
        "calibration_method": "IsotonicRegression(out_of_bounds='clip') aplicada sobre probabilidades crudas de XGBoost",
        "selected_criterion": best_name,
        "optimal_threshold": best_threshold,
        "default_threshold": 0.5,
        "threshold_candidates": {
            name: {
                "threshold": candidates[name],
                "validation_metrics": val_evals[name],
            }
            for name in candidates
        },
        "test_set_evaluation": {
            "default_threshold_0_5": test_default,
            "optimal_threshold":     test_optimal,
            "delta_f1_score":        round(delta_f1, 6),
            "delta_false_positive_rate": round(delta_fpr, 6),
        },
    }

    # 12. Guardar resultados
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    with open(OUT_RESULTS, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"\n💾 Resultados detallados → {OUT_RESULTS}")

    # 13. Guardar artefacto de producción (solo umbral + metadata mínima)
    PROD_MODELS.mkdir(parents=True, exist_ok=True)
    prod_payload = {
        "optimal_threshold": best_threshold,
        "criterion":         best_name,
        "auc_roc":           test_optimal["auc_roc"],
        "f1_score":          test_optimal["f1_score"],
        "generated_at":      datetime.now().isoformat(),
    }
    with open(OUT_PROD, "w", encoding="utf-8") as f:
        json.dump(prod_payload, f, indent=2)
    print(f"💾 Umbral de producción    → {OUT_PROD}\n")

    duration = (datetime.now() - start_time).total_seconds()
    print("="*80)
    print(f"✅ CALIBRACIÓN COMPLETADA  |  Tiempo: {duration:.1f}s")
    print("="*80 + "\n")


if __name__ == "__main__":
    # Asegurar que el directorio raíz está en el path de Python
    sys.path.insert(0, str(ROOT))
    main()
