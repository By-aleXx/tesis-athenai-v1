"""
AthenAI - Training Traditional ML Models
Entrena y evalúa modelos tradicionales de Machine Learning para detectar SQL Injection
"""

import pandas as pd
import numpy as np
import joblib
import json
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_auc_score, roc_curve
)
from sklearn.model_selection import GridSearchCV
import xgboost as xgb
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

# Importar feature engineering
import sys
sys.path.append('.')
from training.feature_engineering import FeatureEngineer


class ModelTrainer:
    """Entrena y evalúa modelos de ML tradicionales"""
    
    def __init__(self):
        self.models = {}
        self.results = {}
        self.feature_engineer = None
        
    def load_data(self):
        """Carga los datasets preprocesados"""
        print("="*80)
        print("CARGANDO DATOS")
        print("="*80 + "\n")
        
        print("📂 Cargando splits...")
        train_df = pd.read_csv('data/train.csv')
        val_df = pd.read_csv('data/val.csv')
        test_df = pd.read_csv('data/test.csv')
        
        print(f"  ✓ Train: {len(train_df):,} muestras")
        print(f"  ✓ Val:   {len(val_df):,} muestras")
        print(f"  ✓ Test:  {len(test_df):,} muestras\n")
        
        return train_df, val_df, test_df
    
    def prepare_features(self, train_df, val_df, test_df):
        """Prepara features para entrenamiento"""
        print("="*80)
        print("PREPARANDO FEATURES")
        print("="*80 + "\n")
        
        # Crear feature engineer
        self.feature_engineer = FeatureEngineer(max_features=3000)
        
        # Entrenar TF-IDF en datos de entrenamiento
        self.feature_engineer.fit_tfidf(train_df['text'].tolist())
        
        # Extraer features para cada split
        print("\n📊 Extrayendo features de train...")
        X_train, feature_names = self.feature_engineer.extract_all_features(train_df)
        y_train = train_df['label'].values
        
        print("\n📊 Extrayendo features de validation...")
        X_val, _ = self.feature_engineer.extract_all_features(val_df)
        y_val = val_df['label'].values
        
        print("\n📊 Extrayendo features de test...")
        X_test, _ = self.feature_engineer.extract_all_features(test_df)
        y_test = test_df['label'].values
        
        print(f"\n✅ Features preparadas!")
        print(f"   X_train shape: {X_train.shape}")
        print(f"   X_val shape:   {X_val.shape}")
        print(f"   X_test shape:  {X_test.shape}\n")
        
        return X_train, y_train, X_val, y_val, X_test, y_test, feature_names
    
    def train_random_forest(self, X_train, y_train, X_val, y_val):
        """Entrena Random Forest con grid search"""
        print("="*80)
        print("ENTRENANDO RANDOM FOREST")
        print("="*80 + "\n")
        
        print("🌲 Configurando Random Forest...")
        
        # Modelo base
        rf = RandomForestClassifier(
            n_estimators=200,
            max_depth=20,
            min_samples_split=5,
            min_samples_leaf=2,
            max_features='sqrt',
            random_state=42,
            n_jobs=-1,
            verbose=0
        )
        
        print("🔧 Entrenando modelo...")
        rf.fit(X_train, y_train)
        
        # Evaluar
        train_pred = rf.predict(X_train)
        val_pred = rf.predict(X_val)
        
        train_acc = accuracy_score(y_train, train_pred)
        val_acc = accuracy_score(y_val, val_pred)
        
        print(f"\n📊 Resultados:")
        print(f"   Train Accuracy: {train_acc:.4f}")
        print(f"   Val Accuracy:   {val_acc:.4f}")
        
        self.models['random_forest'] = rf
        
        return rf
    
    def train_xgboost(self, X_train, y_train, X_val, y_val):
        """Entrena XGBoost"""
        print("\n" + "="*80)
        print("ENTRENANDO XGBOOST")
        print("="*80 + "\n")
        
        print("🚀 Configurando XGBoost...")
        
        xgb_model = xgb.XGBClassifier(
            n_estimators=200,
            max_depth=10,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            random_state=42,
            n_jobs=-1,
            eval_metric='logloss'
        )
        
        print("🔧 Entrenando modelo...")
        xgb_model.fit(
            X_train, y_train,
            eval_set=[(X_val, y_val)],
            verbose=False
        )
        
        # Evaluar
        train_pred = xgb_model.predict(X_train)
        val_pred = xgb_model.predict(X_val)
        
        train_acc = accuracy_score(y_train, train_pred)
        val_acc = accuracy_score(y_val, val_pred)
        
        print(f"\n📊 Resultados:")
        print(f"   Train Accuracy: {train_acc:.4f}")
        print(f"   Val Accuracy:   {val_acc:.4f}")
        
        self.models['xgboost'] = xgb_model
        
        return xgb_model
    
    def train_svm(self, X_train, y_train, X_val, y_val):
        """Entrena SVM (en subset por velocidad)"""
        print("\n" + "="*80)
        print("ENTRENANDO SVM")
        print("="*80 + "\n")
        
        print("⚡ Configurando SVM...")
        print("   Nota: Usando subset de 5000 muestras para velocidad\n")
        
        # Usar subset para SVM (es lento con muchos datos)
        subset_size = min(5000, len(X_train))
        indices = np.random.choice(len(X_train), subset_size, replace=False)
        X_train_subset = X_train[indices]
        y_train_subset = y_train[indices]
        
        svm_model = SVC(
            kernel='rbf',
            C=1.0,
            gamma='scale',
            random_state=42,
            probability=True
        )
        
        print("🔧 Entrenando modelo...")
        svm_model.fit(X_train_subset, y_train_subset)
        
        # Evaluar
        train_pred = svm_model.predict(X_train_subset)
        val_pred = svm_model.predict(X_val)
        
        train_acc = accuracy_score(y_train_subset, train_pred)
        val_acc = accuracy_score(y_val, val_pred)
        
        print(f"\n📊 Resultados:")
        print(f"   Train Accuracy: {train_acc:.4f} (en subset)")
        print(f"   Val Accuracy:   {val_acc:.4f}")
        
        self.models['svm'] = svm_model
        
        return svm_model
    
    def train_logistic_regression(self, X_train, y_train, X_val, y_val):
        """Entrena Logistic Regression (baseline)"""
        print("\n" + "="*80)
        print("ENTRENANDO LOGISTIC REGRESSION (Baseline)")
        print("="*80 + "\n")
        
        print("📈 Configurando Logistic Regression...")
        
        lr_model = LogisticRegression(
            C=1.0,
            max_iter=1000,
            random_state=42,
            n_jobs=-1
        )
        
        print("🔧 Entrenando modelo...")
        lr_model.fit(X_train, y_train)
        
        # Evaluar
        train_pred = lr_model.predict(X_train)
        val_pred = lr_model.predict(X_val)
        
        train_acc = accuracy_score(y_train, train_pred)
        val_acc = accuracy_score(y_val, val_pred)
        
        print(f"\n📊 Resultados:")
        print(f"   Train Accuracy: {train_acc:.4f}")
        print(f"   Val Accuracy:   {val_acc:.4f}")
        
        self.models['logistic_regression'] = lr_model
        
        return lr_model
    
    def evaluate_model(self, model, X_test, y_test, model_name):
        """Evalúa un modelo en el test set"""
        print(f"\n📊 Evaluando {model_name}...")
        
        # Predicciones
        y_pred = model.predict(X_test)
        
        # Probabilidades (si el modelo las soporta)
        if hasattr(model, 'predict_proba'):
            y_proba = model.predict_proba(X_test)[:, 1]
            auc = roc_auc_score(y_test, y_proba)
        else:
            auc = None
        
        # Métricas
        metrics = {
            'accuracy': accuracy_score(y_test, y_pred),
            'precision': precision_score(y_test, y_pred),
            'recall': recall_score(y_test, y_pred),
            'f1_score': f1_score(y_test, y_pred),
            'auc_roc': auc
        }
        
        # Confusion matrix
        cm = confusion_matrix(y_test, y_pred)
        
        # Guardar resultados
        self.results[model_name] = {
            'metrics': metrics,
            'confusion_matrix': cm.tolist(),
            'predictions': y_pred.tolist()
        }
        
        # Mostrar resultados
        print(f"   Accuracy:  {metrics['accuracy']:.4f}")
        print(f"   Precision: {metrics['precision']:.4f}")
        print(f"   Recall:    {metrics['recall']:.4f}")
        print(f"   F1-Score:  {metrics['f1_score']:.4f}")
        if auc:
            print(f"   AUC-ROC:   {auc:.4f}")
        
        print(f"\n   Confusion Matrix:")
        print(f"   TN: {cm[0,0]:5d}  |  FP: {cm[0,1]:5d}")
        print(f"   FN: {cm[1,0]:5d}  |  TP: {cm[1,1]:5d}")
        
        return metrics
    
    def save_models(self):
        """Guarda todos los modelos entrenados"""
        print("\n" + "="*80)
        print("GUARDANDO MODELOS")
        print("="*80 + "\n")
        
        for model_name, model in self.models.items():
            filename = f"training/models/{model_name}.pkl"
            joblib.dump(model, filename)
            print(f"  ✓ {model_name} guardado: {filename}")
        
        # Guardar feature engineer
        joblib.dump(self.feature_engineer, 'training/models/feature_engineer.pkl')
        print(f"  ✓ feature_engineer guardado: training/models/feature_engineer.pkl")
    
    def save_results(self):
        """Guarda resultados de evaluación"""
        print("\n💾 Guardando resultados...")
        
        # Convertir numpy arrays a listas para JSON
        results_json = {}
        for model_name, result in self.results.items():
            results_json[model_name] = {
                'metrics': result['metrics'],
                'confusion_matrix': result['confusion_matrix']
            }
        
        with open('training/results/metrics.json', 'w') as f:
            json.dump(results_json, f, indent=2)
        
        print(f"  ✓ Resultados guardados: training/results/metrics.json")
    
    def print_summary(self):
        """Imprime resumen de todos los modelos"""
        print("\n" + "="*80)
        print("RESUMEN DE MODELOS")
        print("="*80 + "\n")
        
        # Crear tabla comparativa
        print(f"{'Modelo':<25} {'Accuracy':<12} {'Precision':<12} {'Recall':<12} {'F1-Score':<12}")
        print("-"*80)
        
        for model_name, result in self.results.items():
            metrics = result['metrics']
            print(f"{model_name:<25} "
                  f"{metrics['accuracy']:<12.4f} "
                  f"{metrics['precision']:<12.4f} "
                  f"{metrics['recall']:<12.4f} "
                  f"{metrics['f1_score']:<12.4f}")
        
        # Encontrar mejor modelo
        best_model = max(self.results.items(), key=lambda x: x[1]['metrics']['f1_score'])
        print("\n" + "="*80)
        print(f"🏆 MEJOR MODELO: {best_model[0].upper()}")
        print(f"   F1-Score: {best_model[1]['metrics']['f1_score']:.4f}")
        print("="*80 + "\n")


def main():
    """Función principal"""
    print("\n" + "="*80)
    print("ATHENAI - ENTRENAMIENTO DE MODELOS ML")
    print("="*80 + "\n")
    
    start_time = datetime.now()
    
    # Crear trainer
    trainer = ModelTrainer()
    
    # Cargar datos
    train_df, val_df, test_df = trainer.load_data()
    
    # Preparar features
    X_train, y_train, X_val, y_val, X_test, y_test, feature_names = trainer.prepare_features(
        train_df, val_df, test_df
    )
    
    # Entrenar modelos
    trainer.train_logistic_regression(X_train, y_train, X_val, y_val)
    trainer.train_random_forest(X_train, y_train, X_val, y_val)
    trainer.train_xgboost(X_train, y_train, X_val, y_val)
    trainer.train_svm(X_train, y_train, X_val, y_val)
    
    # Evaluar en test set
    print("\n" + "="*80)
    print("EVALUACIÓN EN TEST SET")
    print("="*80)
    
    for model_name, model in trainer.models.items():
        trainer.evaluate_model(model, X_test, y_test, model_name)
    
    # Guardar modelos y resultados
    trainer.save_models()
    trainer.save_results()
    
    # Resumen final
    trainer.print_summary()
    
    # Tiempo total
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()
    print(f"⏱️  Tiempo total de entrenamiento: {duration:.1f} segundos ({duration/60:.1f} minutos)\n")
    
    print("✅ ENTRENAMIENTO COMPLETADO!\n")


if __name__ == "__main__":
    main()
