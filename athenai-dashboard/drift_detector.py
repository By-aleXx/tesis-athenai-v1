"""
AthenAI - Concept Drift Detector

Detecta cambios en la distribución de datos que indican que el modelo
se está volviendo obsoleto y necesita re-entrenamiento completo.

Autor: AthenAI Team
Fecha: 2026-02-13
"""

import numpy as np
import logging
from typing import Dict, List, Tuple
from collections import deque
from datetime import datetime, timedelta
from scipy import stats

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DriftDetector:
    """
    Detector de concept drift para modelos de ML.
    
    Detecta cambios en:
    - Distribución de features
    - Distribución de predicciones
    - Performance del modelo
    """
    
    def __init__(self, 
                 window_size: int = 1000,
                 warning_threshold: float = 0.05,
                 critical_threshold: float = 0.01):
        """
        Inicializa el detector de drift.
        
        Args:
            window_size: Tamaño de ventana para comparación
            warning_threshold: P-value para warning
            critical_threshold: P-value para critical drift
        """
        self.window_size = window_size
        self.warning_threshold = warning_threshold
        self.critical_threshold = critical_threshold
        
        # Ventanas de datos
        self.historical_window = deque(maxlen=window_size)
        self.recent_window = deque(maxlen=window_size // 2)
        
        # Historial de drift
        self.drift_history = []
        
        logger.info("✅ Drift Detector initialized")
    
    def add_sample(self, features: np.ndarray, prediction: int):
        """Agrega una muestra a las ventanas"""
        sample = {
            'features': features,
            'prediction': prediction,
            'timestamp': datetime.now()
        }
        
        # Primero llenar ventana histórica
        if len(self.historical_window) < self.window_size:
            self.historical_window.append(sample)
        else:
            # Luego llenar ventana reciente
            self.recent_window.append(sample)
    
    def detect_drift(self) -> Dict:
        """
        Detecta drift comparando ventanas.
        
        Returns:
            Dict con tipo de drift y detalles
        """
        if len(self.recent_window) < self.window_size // 4:
            return {
                'drift_detected': False,
                'drift_type': 'NO_DRIFT',
                'reason': 'Not enough recent data',
                'p_value': 1.0
            }
        
        # Extraer features de ambas ventanas
        historical_features = np.array([s['features'] for s in self.historical_window])
        recent_features = np.array([s['features'] for s in self.recent_window])
        
        # Test de Kolmogorov-Smirnov para cada feature
        p_values = []
        for i in range(historical_features.shape[1]):
            try:
                _, p_value = stats.ks_2samp(
                    historical_features[:, i],
                    recent_features[:, i]
                )
                p_values.append(p_value)
            except:
                p_values.append(1.0)
        
        # P-value mínimo (más significativo)
        min_p_value = min(p_values) if p_values else 1.0
        
        # Determinar tipo de drift
        if min_p_value < self.critical_threshold:
            drift_type = 'CRITICAL_DRIFT'
            drift_detected = True
            reason = f"Critical drift detected (p={min_p_value:.4f})"
            logger.error(f"🚨 {reason}")
        elif min_p_value < self.warning_threshold:
            drift_type = 'WARNING_DRIFT'
            drift_detected = True
            reason = f"Warning drift detected (p={min_p_value:.4f})"
            logger.warning(f"⚠️ {reason}")
        else:
            drift_type = 'NO_DRIFT'
            drift_detected = False
            reason = "No significant drift"
        
        # Registrar en historial
        drift_event = {
            'timestamp': datetime.now().isoformat(),
            'drift_type': drift_type,
            'p_value': min_p_value,
            'reason': reason
        }
        self.drift_history.append(drift_event)
        
        return {
            'drift_detected': drift_detected,
            'drift_type': drift_type,
            'reason': reason,
            'p_value': min_p_value,
            'historical_samples': len(self.historical_window),
            'recent_samples': len(self.recent_window)
        }
    
    def get_drift_history(self, limit: int = 10) -> List[Dict]:
        """Retorna historial de drift"""
        return self.drift_history[-limit:]
    
    def reset_windows(self):
        """Resetea las ventanas (después de re-entrenamiento completo)"""
        # Mover ventana reciente a histórica
        self.historical_window.extend(self.recent_window)
        self.recent_window.clear()
        logger.info("✅ Drift detector windows reset")


# Singleton instance
_drift_detector = None

def get_drift_detector() -> DriftDetector:
    """Obtiene la instancia singleton del drift detector"""
    global _drift_detector
    if _drift_detector is None:
        _drift_detector = DriftDetector()
    return _drift_detector


if __name__ == "__main__":
    # Test básico
    print("🧪 Testing Drift Detector...")
    
    detector = DriftDetector(window_size=100)
    
    # Simular datos sin drift
    print("\n1. Adding normal data...")
    for i in range(150):
        features = np.random.randn(10)
        prediction = np.random.randint(0, 2)
        detector.add_sample(features, prediction)
    
    result = detector.detect_drift()
    print(f"Drift check 1: {result}")
    
    # Simular drift (cambio en distribución)
    print("\n2. Adding drifted data...")
    for i in range(50):
        features = np.random.randn(10) + 2.0  # Shift en media
        prediction = np.random.randint(0, 2)
        detector.add_sample(features, prediction)
    
    result = detector.detect_drift()
    print(f"Drift check 2: {result}")
