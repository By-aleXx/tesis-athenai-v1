"""
AthenAI - Entrenamiento de Modelo de Detección de Amenazas

Entrena un modelo Random Forest para detectar amenazas en tráfico web
usando Mock SageMaker.

Features:
- request_count: Número de requests
- error_rate: Tasa de errores
- avg_response_time: Tiempo promedio de respuesta
- unique_ips: Número de IPs únicas

Target:
- is_threat: 0 = Normal, 1 = Amenaza
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, 
    precision_score, 
    recall_score, 
    f1_score,
    confusion_matrix,
    classification_report
)
from mock_sagemaker import mock_sagemaker
import joblib
from datetime import datetime


def load_dataset(file_path='data/traffic_dataset.csv'):
    """Carga el dataset"""
    print(f"📂 Cargando dataset desde {file_path}...")
    df = pd.read_csv(file_path)
    print(f"  ✅ Dataset cargado: {len(df)} muestras")
    return df


def prepare_data(df):
    """Prepara los datos para entrenamiento"""
    print("\n🔧 Preparando datos...")
    
    # Features
    feature_columns = ['request_count', 'error_rate', 'avg_response_time', 'unique_ips']
    X = df[feature_columns].values
    
    # Target
    y = df['is_threat'].values
    
    # Split train/test
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"  ✅ Training set: {len(X_train)} muestras")
    print(f"  ✅ Test set: {len(X_test)} muestras")
    print(f"  ✅ Features: {feature_columns}")
    
    return X_train, X_test, y_train, y_test, feature_columns


def train_model(data, hyperparameters):
    """
    Función de entrenamiento para Mock SageMaker.
    
    Args:
        data: Tupla (X_train, y_train)
        hyperparameters: Diccionario de hiperparámetros
    
    Returns:
        Modelo entrenado
    """
    X_train, y_train = data
    
    print(f"\n🏋️  Entrenando modelo con hiperparámetros:")
    for key, value in hyperparameters.items():
        print(f"    {key}: {value}")
    
    # Crear y entrenar modelo
    model = RandomForestClassifier(**hyperparameters)
    model.fit(X_train, y_train)
    
    print(f"  ✅ Modelo entrenado exitosamente")
    
    return model


def evaluate_model(model, X_test, y_test):
    """Evalúa el modelo"""
    print("\n📊 Evaluando modelo...")
    
    # Predicciones
    y_pred = model.predict(X_test)
    
    # Métricas
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    
    print(f"\n✅ Resultados:")
    print(f"  Accuracy:  {accuracy:.4f} ({accuracy * 100:.2f}%)")
    print(f"  Precision: {precision:.4f} ({precision * 100:.2f}%)")
    print(f"  Recall:    {recall:.4f} ({recall * 100:.2f}%)")
    print(f"  F1-Score:  {f1:.4f}")
    
    # Matriz de confusión
    cm = confusion_matrix(y_test, y_pred)
    print(f"\n📈 Matriz de Confusión:")
    print(f"                Predicho")
    print(f"              Normal  Amenaza")
    print(f"  Real Normal    {cm[0][0]:4d}    {cm[0][1]:4d}")
    print(f"       Amenaza   {cm[1][0]:4d}    {cm[1][1]:4d}")
    
    # Reporte detallado
    print(f"\n📋 Reporte de Clasificación:")
    print(classification_report(y_test, y_pred, target_names=['Normal', 'Amenaza']))
    
    # Feature importance
    if hasattr(model, 'feature_importances_'):
        print(f"\n🎯 Importancia de Features:")
        feature_names = ['request_count', 'error_rate', 'avg_response_time', 'unique_ips']
        importances = model.feature_importances_
        for name, importance in sorted(zip(feature_names, importances), key=lambda x: x[1], reverse=True):
            print(f"  {name:20s}: {importance:.4f} ({importance * 100:.2f}%)")
    
    return {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1_score': f1,
        'confusion_matrix': cm.tolist()
    }


def main():
    """Flujo principal de entrenamiento"""
    
    print("=" * 80)
    print("ATHENAI - ENTRENAMIENTO DE MODELO DE DETECCIÓN DE AMENAZAS")
    print("=" * 80)
    
    # 1. Cargar dataset
    df = load_dataset()
    
    # 2. Preparar datos
    X_train, X_test, y_train, y_test, feature_columns = prepare_data(df)
    
    # 3. Configurar hiperparámetros
    hyperparameters = {
        'n_estimators': 200,
        'max_depth': 15,
        'min_samples_split': 5,
        'min_samples_leaf': 2,
        'random_state': 42,
        'n_jobs': -1  # Usar todos los cores
    }
    
    # 4. Crear training job en Mock SageMaker
    print("\n🤖 Creando Training Job en Mock SageMaker...")
    
    job_name = f'threat_detector_training_{datetime.now().strftime("%Y%m%d_%H%M%S")}'
    
    try:
        job_info = mock_sagemaker.create_training_job(
            job_name=job_name,
            training_function=train_model,
            training_data=(X_train, y_train),
            hyperparameters=hyperparameters
        )
        
        print(f"\n✅ Training Job Completado:")
        print(f"  Job Name: {job_info['TrainingJobName']}")
        print(f"  Status: {job_info['Status']}")
        print(f"  Model Name: {job_info['ModelName']}")
        print(f"  Training Time: {job_info['TrainingTime']:.2f}s")
        
    except Exception as e:
        print(f"\n❌ Error en training job: {e}")
        return
    
    # 5. Cargar modelo y evaluar
    print(f"\n📥 Cargando modelo entrenado...")
    model = mock_sagemaker.get_model(job_info['ModelName'])
    
    # 6. Evaluar modelo
    metrics = evaluate_model(model, X_test, y_test)
    
    # 7. Crear endpoint de producción
    print(f"\n🔌 Creando endpoint de producción...")
    
    try:
        endpoint_info = mock_sagemaker.create_endpoint(
            endpoint_name='threat-detector-prod',
            model_name=job_info['ModelName']
        )
        
        print(f"\n✅ Endpoint Creado:")
        print(f"  Endpoint Name: {endpoint_info['EndpointName']}")
        print(f"  Model: {endpoint_info['ModelName']}")
        print(f"  Status: {endpoint_info['Status']}")
        
    except Exception as e:
        print(f"\n⚠️  Endpoint ya existe o error: {e}")
        print(f"  Puedes eliminarlo con: mock_sagemaker.delete_endpoint('threat-detector-prod')")
    
    # 8. Probar endpoint
    print(f"\n🧪 Probando endpoint con datos de prueba...")
    
    # Caso 1: Tráfico normal
    normal_traffic = [25, 0.02, 150, 10]  # request_count, error_rate, avg_response_time, unique_ips
    prediction = mock_sagemaker.invoke_endpoint('threat-detector-prod', normal_traffic)
    print(f"\n  Caso 1 - Tráfico Normal:")
    print(f"    Features: {normal_traffic}")
    print(f"    Predicción: {'🟢 Normal' if prediction[0] == 0 else '🔴 Amenaza'}")
    
    # Caso 2: DDoS
    ddos_traffic = [500, 0.5, 3000, 100]
    prediction = mock_sagemaker.invoke_endpoint('threat-detector-prod', ddos_traffic)
    print(f"\n  Caso 2 - Posible DDoS:")
    print(f"    Features: {ddos_traffic}")
    print(f"    Predicción: {'🟢 Normal' if prediction[0] == 0 else '🔴 Amenaza'}")
    
    # Caso 3: Brute Force
    brute_force_traffic = [200, 0.8, 200, 2]
    prediction = mock_sagemaker.invoke_endpoint('threat-detector-prod', brute_force_traffic)
    print(f"\n  Caso 3 - Posible Brute Force:")
    print(f"    Features: {brute_force_traffic}")
    print(f"    Predicción: {'🟢 Normal' if prediction[0] == 0 else '🔴 Amenaza'}")
    
    print("\n" + "=" * 80)
    print("✅ ENTRENAMIENTO COMPLETADO EXITOSAMENTE!")
    print("=" * 80)
    print(f"\n🎯 Próximos pasos:")
    print(f"  1. Probar endpoint desde API: POST http://localhost:5000/api/ml/predict/threat")
    print(f"  2. Ver estadísticas ML: GET http://localhost:5000/api/ml/stats")
    print(f"  3. Integrar con Security Middleware para detección automática")
    print("\n" + "=" * 80)
    
    return {
        'job_info': job_info,
        'endpoint_info': endpoint_info,
        'metrics': metrics
    }


if __name__ == "__main__":
    main()
