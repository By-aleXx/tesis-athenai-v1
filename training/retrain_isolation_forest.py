"""
AthenAI - Re-entrenamiento de Isolation Forest (Sin Dependencias de Clases)
Versión simplificada que guarda solo el modelo y scaler sin clases personalizadas
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix
import joblib
import json
from datetime import datetime, timedelta
import random

def generate_synthetic_auth_data(n_normal=5000, n_anomalies=250):
    """Genera datos sintéticos de autenticación"""
    print("📊 Generando dataset sintético...")
    
    events = []
    
    # Eventos normales
    print(f"  Generando {n_normal} eventos normales...")
    for i in range(n_normal):
        event = {
            'time_since_last_login': random.randint(3600, 86400),  # 1-24 horas
            'failed_attempts_count': random.choice([0, 0, 0, 1, 2]),  # Mayormente 0
            'login_hour': random.randint(8, 18),  # Horas laborales
            'is_weekend': 0,
            'unusual_location': 0,
            'login_day_of_week': random.randint(0, 4),  # Lunes-Viernes
            'geo_distance_km': random.uniform(0, 50),  # Cerca
            'session_duration_avg': random.randint(1200, 3600),  # 20-60 min
            'label': 0  # Normal
        }
        events.append(event)
    
    # Eventos anómalos
    print(f"  Generando {n_anomalies} eventos anómalos...")
    
    # Brute force
    for i in range(n_anomalies // 3):
        event = {
            'time_since_last_login': random.randint(10, 300),  # Muy rápido
            'failed_attempts_count': random.randint(15, 50),  # Muchos fallos
            'login_hour': random.randint(0, 6),  # Madrugada
            'is_weekend': 1,
            'unusual_location': 1,
            'login_day_of_week': random.randint(5, 6),  # Fin de semana
            'geo_distance_km': random.uniform(1000, 10000),  # Lejos
            'session_duration_avg': random.randint(10, 100),  # Muy corto
            'label': 1  # Anómalo
        }
        events.append(event)
    
    # Credential stuffing
    for i in range(n_anomalies // 3):
        event = {
            'time_since_last_login': random.randint(5, 60),  # Muy rápido
            'failed_attempts_count': random.randint(5, 15),
            'login_hour': random.randint(0, 23),
            'is_weekend': random.choice([0, 1]),
            'unusual_location': 1,
            'login_day_of_week': random.randint(0, 6),
            'geo_distance_km': random.uniform(500, 5000),
            'session_duration_avg': random.randint(30, 200),
            'label': 1
        }
        events.append(event)
    
    # Impossible travel
    for i in range(n_anomalies - 2 * (n_anomalies // 3)):
        event = {
            'time_since_last_login': random.randint(300, 1800),  # 5-30 min
            'failed_attempts_count': random.choice([0, 1, 2]),
            'login_hour': random.randint(0, 23),
            'is_weekend': random.choice([0, 1]),
            'unusual_location': 1,
            'login_day_of_week': random.randint(0, 6),
            'geo_distance_km': random.uniform(5000, 15000),  # Muy lejos
            'session_duration_avg': random.randint(600, 2400),
            'label': 1
        }
        events.append(event)
    
    df = pd.DataFrame(events)
    
    print(f"\n✓ Total eventos: {len(df)}")
    print(f"  Normal:   {(df['label']==0).sum()} ({(df['label']==0).mean()*100:.1f}%)")
    print(f"  Anómalos: {(df['label']==1).sum()} ({(df['label']==1).mean()*100:.1f}%)")
    
    return df

def main():
    print("\n" + "="*80)
    print("ATHENAI - RE-ENTRENAMIENTO DE ISOLATION FOREST")
    print("Versión Simplificada (Sin Clases Personalizadas)")
    print("="*80 + "\n")
    
    # Generar datos
    df = generate_synthetic_auth_data(n_normal=5000, n_anomalies=250)
    
    # Separar features y labels
    feature_cols = [
        'time_since_last_login',
        'failed_attempts_count',
        'login_hour',
        'is_weekend',
        'unusual_location',
        'login_day_of_week',
        'geo_distance_km',
        'session_duration_avg'
    ]
    
    X = df[feature_cols].values
    y = df['label'].values
    
    print(f"\n🔧 Features extraídas: {X.shape}")
    
    # Split train/test
    from sklearn.model_selection import train_test_split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"  Train: {X_train.shape[0]} muestras")
    print(f"  Test:  {X_test.shape[0]} muestras")
    
    # Escalar features
    print("\n🔧 Escalando features...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Entrenar Isolation Forest
    print("\n🌲 Entrenando Isolation Forest...")
    contamination = 0.05  # 5% de anomalías esperadas
    
    model = IsolationForest(
        n_estimators=100,
        max_samples=256,
        contamination=contamination,
        random_state=42,
        n_jobs=-1
    )
    
    # Entrenar solo con datos normales (unsupervised)
    X_train_normal = X_train_scaled[y_train == 0]
    print(f"  Entrenando con {len(X_train_normal)} muestras normales...")
    model.fit(X_train_normal)
    
    print("  ✓ Modelo entrenado")
    
    # Evaluar
    print("\n" + "="*80)
    print("EVALUACIÓN")
    print("="*80 + "\n")
    
    # Predicciones (-1 = anomalía, 1 = normal)
    y_pred_raw = model.predict(X_test_scaled)
    y_pred = (y_pred_raw == -1).astype(int)  # Convertir a 0/1
    
    # Métricas
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    cm = confusion_matrix(y_test, y_pred)
    
    print("📊 Métricas:")
    print(f"  Precision: {precision:.4f}")
    print(f"  Recall:    {recall:.4f}")
    print(f"  F1-Score:  {f1:.4f}")
    
    print(f"\n📊 Matriz de Confusión:")
    print(f"  TN: {cm[0,0]:5d}  |  FP: {cm[0,1]:5d}")
    print(f"  FN: {cm[1,0]:5d}  |  TP: {cm[1,1]:5d}")
    
    # Precision@K
    scores = model.score_samples(X_test_scaled)
    top_k_indices = np.argsort(scores)  # Menor score = más anómalo
    
    precision_at_10 = y_test[top_k_indices[:10]].mean()
    precision_at_50 = y_test[top_k_indices[:50]].mean()
    precision_at_100 = y_test[top_k_indices[:100]].mean()
    
    print(f"\n📊 Precision@K:")
    print(f"  Precision@ 10: {precision_at_10:.4f}")
    print(f"  Precision@ 50: {precision_at_50:.4f}")
    print(f"  Precision@100: {precision_at_100:.4f}")
    
    # Guardar modelo y scaler
    print("\n💾 Guardando modelo y scaler...")
    
    joblib.dump(model, 'training/models/isolation_forest.pkl')
    joblib.dump(scaler, 'training/models/auth_scaler.pkl')
    
    print("  ✓ Modelo guardado: training/models/isolation_forest.pkl")
    print("  ✓ Scaler guardado: training/models/auth_scaler.pkl")
    
    # Guardar métricas
    metrics = {
        'precision': float(precision),
        'recall': float(recall),
        'f1_score': float(f1),
        'confusion_matrix': cm.tolist(),
        'precision_at_10': float(precision_at_10),
        'precision_at_50': float(precision_at_50),
        'precision_at_100': float(precision_at_100),
        'timestamp': datetime.utcnow().isoformat()
    }
    
    with open('training/results/isolation_forest_metrics.json', 'w') as f:
        json.dump(metrics, f, indent=2)
    
    print("  ✓ Métricas guardadas: training/results/isolation_forest_metrics.json")
    
    print("\n" + "="*80)
    print("✅ ENTRENAMIENTO COMPLETADO!")
    print("="*80 + "\n")

if __name__ == "__main__":
    main()
