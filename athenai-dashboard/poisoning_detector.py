"""
AthenAI - Data Poisoning Detector

Detecta y filtra datos maliciosos que podrían envenenar el modelo
durante el aprendizaje continuo.

Autor: AthenAI Team
Fecha: 2026-02-13
"""

import numpy as np
import logging
from typing import Dict, Tuple
from sklearn.ensemble import IsolationForest

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PoisoningDetector:
    """
    Detector de envenenamiento de datos para aprendizaje continuo.
    
    Protege contra:
    - Outliers extremos
    - Ejemplos adversariales
    - Datos inconsistentes
    """
    
    def __init__(self, 
                 contamination: float = 0.05,
                 outlier_threshold: float = 3.0):
        """
        Inicializa el detector de poisoning.
        
        Args:
            contamination: Porcentaje esperado de outliers
            outlier_threshold: Threshold de Z-score para outliers
        """
        self.contamination = contamination
        self.outlier_threshold = outlier_threshold
        
        # Isolation Forest para detección de anomalías
        self.isolation_forest = IsolationForest(
            contamination=contamination,
            random_state=42
        )
        
        # Estadísticas de features
        self.feature_means = None
        self.feature_stds = None
        
        # Estadísticas
        self.stats = {
            'total_checked': 0,
            'poisoned_detected': 0,
            'outliers_detected': 0,
            'adversarial_detected': 0
        }
        
        logger.info("✅ Poisoning Detector initialized")
    
    def fit(self, clean_data: np.ndarray):
        """
        Entrena el detector con datos limpios.
        
        Args:
            clean_data: Datos limpios de referencia
        """
        try:
            self.isolation_forest.fit(clean_data)
            
            # Calcular estadísticas
            self.feature_means = np.mean(clean_data, axis=0)
            self.feature_stds = np.std(clean_data, axis=0)
            
            logger.info(f"✅ Poisoning detector trained with {len(clean_data)} samples")
        except Exception as e:
            logger.error(f"❌ Error training poisoning detector: {e}")
    
    def is_poisoned(self, features: np.ndarray) -> Tuple[bool, str]:
        """
        Verifica si un ejemplo es envenenado.
        
        Args:
            features: Features a verificar
        
        Returns:
            (is_poisoned, reason)
        """
        self.stats['total_checked'] += 1
        
        # 1. Check outliers extremos
        if self._is_extreme_outlier(features):
            self.stats['outliers_detected'] += 1
            self.stats['poisoned_detected'] += 1
            return True, "Extreme outlier detected"
        
        # 2. Check anomalía con Isolation Forest
        if self.feature_means is not None:
            try:
                prediction = self.isolation_forest.predict(features.reshape(1, -1))[0]
                if prediction == -1:  # Anomalía
                    self.stats['poisoned_detected'] += 1
                    return True, "Anomaly detected by Isolation Forest"
            except:
                pass
        
        # 3. Check valores inválidos
        if np.any(np.isnan(features)) or np.any(np.isinf(features)):
            self.stats['poisoned_detected'] += 1
            return True, "Invalid values (NaN or Inf)"
        
        return False, "Clean data"
    
    def _is_extreme_outlier(self, features: np.ndarray) -> bool:
        """Detecta outliers extremos usando Z-score"""
        if self.feature_means is None or self.feature_stds is None:
            return False
        
        try:
            # Calcular Z-scores
            z_scores = np.abs((features - self.feature_means) / (self.feature_stds + 1e-10))
            
            # Si algún feature tiene Z-score muy alto
            if np.any(z_scores > self.outlier_threshold):
                return True
            
            return False
        except:
            return False
    
    def filter_poisoned_data(self, data_buffer: list) -> Tuple[list, int]:
        """
        Filtra datos envenenados de un buffer.
        
        Args:
            data_buffer: Lista de (features, label)
        
        Returns:
            (clean_buffer, num_filtered)
        """
        clean_buffer = []
        num_filtered = 0
        
        for features, label in data_buffer:
            is_poisoned, reason = self.is_poisoned(features)
            
            if not is_poisoned:
                clean_buffer.append((features, label))
            else:
                num_filtered += 1
                logger.warning(f"⚠️ Filtered poisoned data: {reason}")
        
        return clean_buffer, num_filtered
    
    def get_stats(self) -> Dict:
        """Retorna estadísticas del detector"""
        poisoning_rate = (self.stats['poisoned_detected'] / max(self.stats['total_checked'], 1)) * 100
        
        return {
            **self.stats,
            'poisoning_rate': poisoning_rate
        }


# Singleton instance
_poisoning_detector = None

def get_poisoning_detector() -> PoisoningDetector:
    """Obtiene la instancia singleton del poisoning detector"""
    global _poisoning_detector
    if _poisoning_detector is None:
        _poisoning_detector = PoisoningDetector()
    return _poisoning_detector


if __name__ == "__main__":
    # Test básico
    print("🧪 Testing Poisoning Detector...")
    
    detector = PoisoningDetector()
    
    # Entrenar con datos limpios
    clean_data = np.random.randn(1000, 10)
    detector.fit(clean_data)
    
    # Test 1: Datos normales
    normal_sample = np.random.randn(10)
    is_poisoned, reason = detector.is_poisoned(normal_sample)
    print(f"\nNormal sample: poisoned={is_poisoned}, reason={reason}")
    
    # Test 2: Outlier extremo
    outlier_sample = np.random.randn(10) * 10  # 10x más grande
    is_poisoned, reason = detector.is_poisoned(outlier_sample)
    print(f"Outlier sample: poisoned={is_poisoned}, reason={reason}")
    
    # Test 3: Valores inválidos
    invalid_sample = np.array([np.nan] * 10)
    is_poisoned, reason = detector.is_poisoned(invalid_sample)
    print(f"Invalid sample: poisoned={is_poisoned}, reason={reason}")
    
    # Ver estadísticas
    stats = detector.get_stats()
    print(f"\n📊 Stats: {stats}")
