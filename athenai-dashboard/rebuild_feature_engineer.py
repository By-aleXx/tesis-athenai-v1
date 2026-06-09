"""
Script para recrear el feature_engineer.pkl sin dependencias del módulo training
"""

import joblib
import pandas as pd
import sys
from pathlib import Path

_BASE_DIR = Path(__file__).parent
sys.path.append(str(_BASE_DIR))

from feature_engineering import FeatureEngineer

print("="*80)
print("RECREANDO FEATURE ENGINEER")
print("="*80 + "\n")

# Cargar datos de entrenamiento
print("📂 Cargando datos de entrenamiento...")
train_df = pd.read_csv(str(_BASE_DIR.parent / 'data' / 'train.csv'))
print(f"  ✓ Cargados {len(train_df):,} registros\n")

# Crear feature engineer
print("🔧 Creando Feature Engineer...")
fe = FeatureEngineer(max_features=3000)

# Entrenar TF-IDF
fe.fit_tfidf(train_df['text'].tolist())

# Guardar
output_path = str(_BASE_DIR / 'models' / 'feature_engineer.pkl')
print(f"\n💾 Guardando en {output_path}...")
joblib.dump(fe, output_path)
print("  ✓ Guardado exitosamente")

# Verificar
print("\n🔍 Verificando...")
fe_loaded = joblib.load(output_path)
print(f"  ✓ TF-IDF features: {len(fe_loaded.feature_names)}")
print(f"  ✓ Vectorizer: {type(fe_loaded.tfidf_vectorizer)}")

print("\n✅ Feature Engineer recreado exitosamente!")
