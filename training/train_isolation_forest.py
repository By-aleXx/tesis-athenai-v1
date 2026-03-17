"""
AthenAI - Entrenamiento de Isolation Forest para Detección de Anomalías en Autenticación
Tesis de Maestría: Deep Learning para Ciberseguridad

Este módulo implementa Isolation Forest para detectar comportamientos
anómalos en eventos de autenticación (brute force, credential stuffing, etc.)
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)
import joblib
import json
from datetime import datetime, timedelta
import warnings
warnings.filterwarnings('ignore')


class AuthFeatureExtractor:
    """Extrae features de eventos de autenticación"""
    
    def __init__(self):
        self.scaler = StandardScaler()
        self.user_history = {}  # Historial por usuario
    
    def extract_features(self, event: dict) -> np.ndarray:
        """
        Extrae features de un evento de autenticación
        
        Features:
        1. time_since_last_login: Tiempo desde último login (segundos)
        2. failed_attempts_count: Intentos fallidos recientes
        3. ip_change_flag: Cambio de IP desde último login
        4. user_agent_change_flag: Cambio de User-Agent
        5. login_hour: Hora del día (0-23)
        6. login_day_of_week: Día de la semana (0-6)
        7. geo_distance_km: Distancia geográfica desde último login
        8. session_duration_avg: Duración promedio de sesiones
        """
        
        username = event.get('username', 'unknown')
        timestamp = datetime.fromisoformat(event.get('timestamp', datetime.utcnow().isoformat()))
        ip_address = event.get('ip_address', '0.0.0.0')
        user_agent = event.get('user_agent', 'unknown')
        success = event.get('success', True)
        geo_lat = event.get('geo_lat', 0.0)
        geo_lon = event.get('geo_lon', 0.0)
        
        # Inicializar historial si no existe
        if username not in self.user_history:
            self.user_history[username] = {
                'last_login': None,
                'last_ip': None,
                'last_user_agent': None,
                'last_geo': (0.0, 0.0),
                'failed_attempts': 0,
                'session_durations': []
            }
        
        history = self.user_history[username]
        
        # Feature 1: Tiempo desde último login
        if history['last_login']:
            time_diff = (timestamp - history['last_login']).total_seconds()
        else:
            time_diff = 86400  # 24 horas por defecto
        
        # Feature 2: Intentos fallidos
        failed_attempts = history['failed_attempts']
        
        # Feature 3: Cambio de IP
        ip_change = 1 if history['last_ip'] and history['last_ip'] != ip_address else 0
        
        # Feature 4: Cambio de User-Agent
        ua_change = 1 if history['last_user_agent'] and history['last_user_agent'] != user_agent else 0
        
        # Feature 5-6: Hora y día
        login_hour = timestamp.hour
        login_day = timestamp.weekday()
        
        # Feature 7: Distancia geográfica (Haversine)
        if history['last_geo'] != (0.0, 0.0):
            geo_distance = self._haversine_distance(
                history['last_geo'][0], history['last_geo'][1],
                geo_lat, geo_lon
            )
        else:
            geo_distance = 0.0
        
        # Feature 8: Duración promedio de sesión
        if history['session_durations']:
            avg_session = np.mean(history['session_durations'])
        else:
            avg_session = 1800  # 30 minutos por defecto
        
        # Actualizar historial
        if success:
            history['last_login'] = timestamp
            history['last_ip'] = ip_address
            history['last_user_agent'] = user_agent
            history['last_geo'] = (geo_lat, geo_lon)
            history['failed_attempts'] = 0
        else:
            history['failed_attempts'] += 1
        
        # Retornar features
        features = np.array([
            time_diff,
            failed_attempts,
            ip_change,
            ua_change,
            login_hour,
            login_day,
            geo_distance,
            avg_session
        ])
        
        return features
    
    def _haversine_distance(self, lat1, lon1, lat2, lon2):
        """Calcula distancia en km entre dos coordenadas"""
        R = 6371  # Radio de la Tierra en km
        
        lat1, lon1, lat2, lon2 = map(np.radians, [lat1, lon1, lat2, lon2])
        dlat = lat2 - lat1
        dlon = lon2 - lon1
        
        a = np.sin(dlat/2)**2 + np.cos(lat1) * np.cos(lat2) * np.sin(dlon/2)**2
        c = 2 * np.arcsin(np.sqrt(a))
        
        return R * c


class SyntheticAuthDataGenerator:
    """Genera dataset sintético de eventos de autenticación"""
    
    def __init__(self, n_normal=5000, n_anomalies=250):
        self.n_normal = n_normal
        self.n_anomalies = n_anomalies
        self.feature_extractor = AuthFeatureExtractor()
    
    def generate_normal_events(self):
        """Genera eventos normales de autenticación"""
        events = []
        
        for i in range(self.n_normal):
            # Usuario regular
            username = f"user_{np.random.randint(1, 100)}"
            
            # Timestamp en horario laboral (8am-6pm)
            base_time = datetime.now() - timedelta(days=np.random.randint(0, 30))
            hour = np.random.choice(range(8, 18))  # 8am-6pm
            timestamp = base_time.replace(hour=hour, minute=np.random.randint(0, 60))
            
            # IP consistente
            ip_base = f"192.168.{np.random.randint(1, 10)}"
            ip_address = f"{ip_base}.{np.random.randint(1, 255)}"
            
            # User-Agent consistente
            user_agent = np.random.choice([
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
                "Mozilla/5.0 (X11; Linux x86_64)"
            ])
            
            # Geolocalización consistente
            geo_lat = 40.7128 + np.random.normal(0, 0.1)  # NYC
            geo_lon = -74.0060 + np.random.normal(0, 0.1)
            
            event = {
                'username': username,
                'timestamp': timestamp.isoformat(),
                'ip_address': ip_address,
                'user_agent': user_agent,
                'success': True,
                'geo_lat': geo_lat,
                'geo_lon': geo_lon,
                'label': 0  # Normal
            }
            
            events.append(event)
        
        return events
    
    def generate_anomalous_events(self):
        """Genera eventos anómalos (ataques)"""
        events = []
        
        for i in range(self.n_anomalies):
            username = f"user_{np.random.randint(1, 100)}"
            
            attack_type = np.random.choice([
                'brute_force',
                'credential_stuffing',
                'impossible_travel',
                'session_hijacking'
            ])
            
            if attack_type == 'brute_force':
                # Múltiples intentos fallidos en corto tiempo
                base_time = datetime.now()
                for j in range(np.random.randint(5, 20)):
                    timestamp = base_time + timedelta(seconds=j*2)
                    event = {
                        'username': username,
                        'timestamp': timestamp.isoformat(),
                        'ip_address': f"203.0.113.{np.random.randint(1, 255)}",
                        'user_agent': "Python-requests/2.28.0",
                        'success': False,
                        'geo_lat': 51.5074,  # London
                        'geo_lon': -0.1278,
                        'label': 1  # Anomalía
                    }
                    events.append(event)
            
            elif attack_type == 'credential_stuffing':
                # Login desde IP/país diferente
                timestamp = datetime.now()
                event = {
                    'username': username,
                    'timestamp': timestamp.isoformat(),
                    'ip_address': f"185.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}",
                    'user_agent': "curl/7.68.0",
                    'success': True,
                    'geo_lat': 55.7558,  # Moscow
                    'geo_lon': 37.6173,
                    'label': 1
                }
                events.append(event)
            
            elif attack_type == 'impossible_travel':
                # Logins desde ubicaciones geográficamente imposibles
                base_time = datetime.now()
                # Login desde NYC
                event1 = {
                    'username': username,
                    'timestamp': base_time.isoformat(),
                    'ip_address': "192.168.1.100",
                    'user_agent': "Mozilla/5.0",
                    'success': True,
                    'geo_lat': 40.7128,
                    'geo_lon': -74.0060,
                    'label': 1
                }
                # Login desde Tokyo 10 minutos después
                event2 = {
                    'username': username,
                    'timestamp': (base_time + timedelta(minutes=10)).isoformat(),
                    'ip_address': "203.0.113.50",
                    'user_agent': "Mozilla/5.0",
                    'success': True,
                    'geo_lat': 35.6762,
                    'geo_lon': 139.6503,
                    'label': 1
                }
                events.extend([event1, event2])
            
            elif attack_type == 'session_hijacking':
                # Cambio abrupto de User-Agent
                timestamp = datetime.now()
                event = {
                    'username': username,
                    'timestamp': timestamp.isoformat(),
                    'ip_address': "192.168.1.100",
                    'user_agent': "Suspicious-Bot/1.0",
                    'success': True,
                    'geo_lat': 40.7128,
                    'geo_lon': -74.0060,
                    'label': 1
                }
                events.append(event)
        
        return events
    
    def generate_dataset(self):
        """Genera dataset completo"""
        print("="*80)
        print("GENERANDO DATASET SINTÉTICO DE AUTENTICACIÓN")
        print("="*80 + "\n")
        
        print(f"📊 Generando {self.n_normal} eventos normales...")
        normal_events = self.generate_normal_events()
        
        print(f"🚨 Generando {self.n_anomalies} eventos anómalos...")
        anomalous_events = self.generate_anomalous_events()
        
        # Combinar
        all_events = normal_events + anomalous_events
        
        # Mezclar
        np.random.shuffle(all_events)
        
        print(f"\n✓ Total de eventos: {len(all_events)}")
        print(f"  Normal:   {len(normal_events)} ({len(normal_events)/len(all_events)*100:.1f}%)")
        print(f"  Anómalos: {len(anomalous_events)} ({len(anomalous_events)/len(all_events)*100:.1f}%)")
        
        return all_events


class IsolationForestTrainer:
    """Entrenador de Isolation Forest"""
    
    def __init__(self, contamination=0.05):
        self.contamination = contamination
        self.model = None
        self.feature_extractor = AuthFeatureExtractor()
        self.scaler = StandardScaler()
    
    def prepare_data(self, events):
        """Prepara features y labels"""
        print("\n🔧 Extrayendo features...")
        
        X = []
        y = []
        
        for event in events:
            features = self.feature_extractor.extract_features(event)
            X.append(features)
            y.append(event['label'])
        
        X = np.array(X)
        y = np.array(y)
        
        print(f"  ✓ Features extraídas: {X.shape}")
        
        # Normalizar
        X_scaled = self.scaler.fit_transform(X)
        
        return X_scaled, y
    
    def train(self, X_train):
        """Entrena Isolation Forest"""
        print("\n" + "="*80)
        print("ENTRENANDO ISOLATION FOREST")
        print("="*80 + "\n")
        
        print(f"🌲 Configurando Isolation Forest (contamination={self.contamination})...")
        
        self.model = IsolationForest(
            n_estimators=100,
            contamination=self.contamination,
            max_samples='auto',
            random_state=42,
            n_jobs=-1,
            verbose=0
        )
        
        print("🔧 Entrenando modelo...")
        self.model.fit(X_train)
        
        print("  ✓ Modelo entrenado")
    
    def evaluate(self, X_test, y_test):
        """Evalúa el modelo"""
        print("\n" + "="*80)
        print("EVALUACIÓN DEL MODELO")
        print("="*80 + "\n")
        
        # Predicciones (-1 = anomalía, 1 = normal)
        predictions = self.model.predict(X_test)
        scores = self.model.score_samples(X_test)
        
        # Convertir a formato binario (0 = normal, 1 = anomalía)
        y_pred = (predictions == -1).astype(int)
        
        # Métricas
        precision = precision_score(y_test, y_pred)
        recall = recall_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred)
        cm = confusion_matrix(y_test, y_pred)
        
        print("📊 Métricas de Rendimiento:")
        print(f"  Precision: {precision:.4f}")
        print(f"  Recall:    {recall:.4f}")
        print(f"  F1-Score:  {f1:.4f}")
        
        print(f"\n📊 Matriz de Confusión:")
        print(f"  TN: {cm[0,0]:5d}  |  FP: {cm[0,1]:5d}")
        print(f"  FN: {cm[1,0]:5d}  |  TP: {cm[1,1]:5d}")
        
        # Precision@K
        k_values = [10, 50, 100]
        print(f"\n📊 Precision@K:")
        for k in k_values:
            top_k_indices = np.argsort(scores)[:k]
            precision_at_k = y_test[top_k_indices].sum() / k
            print(f"  Precision@{k:3d}: {precision_at_k:.4f}")
        
        # Guardar métricas
        metrics = {
            'precision': float(precision),
            'recall': float(recall),
            'f1_score': float(f1),
            'confusion_matrix': cm.tolist(),
            'precision_at_10': float(y_test[np.argsort(scores)[:10]].sum() / 10),
            'precision_at_50': float(y_test[np.argsort(scores)[:50]].sum() / 50),
            'precision_at_100': float(y_test[np.argsort(scores)[:100]].sum() / 100),
            'timestamp': datetime.utcnow().isoformat()
        }
        
        with open('training/results/isolation_forest_metrics.json', 'w') as f:
            json.dump(metrics, f, indent=2)
        
        print(f"\n💾 Métricas guardadas")
        
        return metrics
    
    def save_model(self, path='training/models/isolation_forest.pkl'):
        """Guarda el modelo"""
        print(f"\n💾 Guardando modelo en {path}...")
        
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'feature_extractor': self.feature_extractor
        }
        
        joblib.dump(model_data, path)
        print("  ✓ Modelo guardado")


def main():
    """Función principal"""
    print("\n" + "="*80)
    print("ATHENAI - ENTRENAMIENTO DE ISOLATION FOREST")
    print("Detección de Anomalías en Autenticación")
    print("="*80 + "\n")
    
    # Generar dataset
    generator = SyntheticAuthDataGenerator(n_normal=5000, n_anomalies=250)
    events = generator.generate_dataset()
    
    # Crear trainer
    trainer = IsolationForestTrainer(contamination=0.05)
    
    # Preparar datos
    X, y = trainer.prepare_data(events)
    
    # Split train/test (80/20)
    split_idx = int(0.8 * len(X))
    X_train, X_test = X[:split_idx], X[split_idx:]
    y_train, y_test = y[:split_idx], y[split_idx:]
    
    print(f"\n📊 Splits:")
    print(f"  Train: {len(X_train)} muestras")
    print(f"  Test:  {len(X_test)} muestras")
    
    # Entrenar
    trainer.train(X_train)
    
    # Evaluar
    metrics = trainer.evaluate(X_test, y_test)
    
    # Guardar
    trainer.save_model()
    
    print("\n" + "="*80)
    print("✅ ENTRENAMIENTO COMPLETADO!")
    print("="*80 + "\n")


if __name__ == "__main__":
    main()
