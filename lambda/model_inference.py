"""
AthenAI - Model Inference Module
Módulo optimizado para inferencia de modelos ML en Lambda
"""

import joblib
import numpy as np
from typing import Tuple, List
import os


class SQLInjectionDetector:
    """Detector de SQL Injection usando modelo ML entrenado"""
    
    def __init__(self, model_path: str = None):
        """
        Args:
            model_path: Ruta al archivo .pkl del modelo
        """
        self.model = None
        self.feature_engineer = None
        self.model_loaded = False
        
        if model_path:
            self.load_model(model_path)
    
    def load_model(self, model_path: str):
        """
        Carga el modelo y feature engineer desde archivos
        
        Args:
            model_path: Ruta al modelo (ej: 'training/models/xgboost.pkl')
        """
        try:
            print(f"📦 Cargando modelo desde {model_path}...")
            
            # Cargar modelo
            self.model = joblib.load(model_path)
            
            # Cargar feature engineer
            fe_path = os.path.join(os.path.dirname(model_path), 'feature_engineer.pkl')
            self.feature_engineer = joblib.load(fe_path)
            
            self.model_loaded = True
            print(f"✓ Modelo cargado exitosamente")
            
        except Exception as e:
            print(f"✗ Error cargando modelo: {e}")
            self.model_loaded = False
            raise
    
    def predict(self, text: str) -> Tuple[bool, float, List[str]]:
        """
        Predice si un texto contiene SQL Injection
        
        Args:
            text: Texto a analizar (log de tráfico web)
            
        Returns:
            Tuple[bool, float, List[str]]: (es_malicioso, confianza, patrones_detectados)
        """
        if not self.model_loaded:
            raise ValueError("Modelo no cargado. Llama a load_model() primero.")
        
        try:
            # Crear DataFrame temporal
            import pandas as pd
            df = pd.DataFrame({'text': [text]})
            
            # Extraer features
            X, _ = self.feature_engineer.extract_all_features(df)
            
            # Predecir
            prediction = self.model.predict(X)[0]
            
            # Obtener probabilidad si el modelo lo soporta
            if hasattr(self.model, 'predict_proba'):
                proba = self.model.predict_proba(X)[0]
                confidence = float(proba[1] if prediction == 1 else proba[0])
            else:
                confidence = 1.0 if prediction == 1 else 0.0
            
            # Detectar patrones (usando features manuales)
            detected_patterns = self._get_detected_patterns(text)
            
            is_malicious = bool(prediction == 1)
            
            return is_malicious, confidence, detected_patterns
            
        except Exception as e:
            print(f"✗ Error en predicción: {e}")
            # Fallback a detección basada en reglas
            return self._fallback_detection(text)
    
    def predict_batch(self, texts: List[str]) -> List[Tuple[bool, float, List[str]]]:
        """
        Predice múltiples textos en batch (más eficiente)
        
        Args:
            texts: Lista de textos a analizar
            
        Returns:
            List[Tuple[bool, float, List[str]]]: Lista de predicciones
        """
        if not self.model_loaded:
            raise ValueError("Modelo no cargado. Llama a load_model() primero.")
        
        try:
            import pandas as pd
            df = pd.DataFrame({'text': texts})
            
            # Extraer features
            X, _ = self.feature_engineer.extract_all_features(df)
            
            # Predecir
            predictions = self.model.predict(X)
            
            # Obtener probabilidades
            if hasattr(self.model, 'predict_proba'):
                probas = self.model.predict_proba(X)
            else:
                probas = np.ones((len(texts), 2))
            
            # Construir resultados
            results = []
            for i, (pred, proba) in enumerate(zip(predictions, probas)):
                is_malicious = bool(pred == 1)
                confidence = float(proba[1] if pred == 1 else proba[0])
                patterns = self._get_detected_patterns(texts[i])
                results.append((is_malicious, confidence, patterns))
            
            return results
            
        except Exception as e:
            print(f"✗ Error en predicción batch: {e}")
            return [self._fallback_detection(text) for text in texts]
    
    def _get_detected_patterns(self, text: str) -> List[str]:
        """Identifica patrones de ataque detectados"""
        import re
        text_lower = text.lower()
        patterns = []
        
        # UNION-based
        if re.search(r'union\s+(all\s+)?select', text_lower):
            patterns.append('UNION-based Injection')
        
        # Boolean-based
        if re.search(r"('\s*or\s*'1'\s*=\s*'1|'\s*or\s*1\s*=\s*1|\bor\b\s+\d+\s*=\s*\d+)", text_lower):
            patterns.append('Boolean-based Blind Injection')
        
        # Time-based
        if re.search(r'(sleep|benchmark|waitfor|pg_sleep)\s*\(', text_lower):
            patterns.append('Time-based Blind Injection')
        
        # Stacked queries
        if re.search(r';\s*(drop|delete|update|insert|exec)', text_lower):
            patterns.append('Stacked Queries')
        
        # Comment-based
        if re.search(r'(--\s*$|#\s*$|/\*.*\*/)', text):
            patterns.append('Comment-based Injection')
        
        # Information schema
        if 'information_schema' in text_lower or 'sys.databases' in text_lower:
            patterns.append('Information Schema Exploitation')
        
        return patterns if patterns else ['ML Model Detection']
    
    def _fallback_detection(self, text: str) -> Tuple[bool, float, List[str]]:
        """
        Detección de fallback basada en reglas (si el modelo falla)
        """
        import re
        text_lower = text.lower()
        
        # Patrones básicos de SQL Injection
        sql_patterns = [
            r"union\s+select",
            r"'\s*or\s*'1'\s*=\s*'1",
            r"'\s*or\s*1\s*=\s*1",
            r";\s*drop\s+table",
            r";\s*delete\s+from",
            r"sleep\s*\(",
            r"benchmark\s*\(",
            r"information_schema"
        ]
        
        detected_patterns = []
        for pattern in sql_patterns:
            if re.search(pattern, text_lower):
                detected_patterns.append('Pattern-based Detection')
                break
        
        is_malicious = len(detected_patterns) > 0
        confidence = 0.8 if is_malicious else 0.2
        
        return is_malicious, confidence, detected_patterns


def main():
    """Función de prueba"""
    print("="*80)
    print("MODEL INFERENCE - PRUEBA")
    print("="*80 + "\n")
    
    # Crear detector
    detector = SQLInjectionDetector('training/models/xgboost.pkl')
    
    # Casos de prueba
    test_cases = [
        "GET /products?id=1 HTTP/1.1",  # Normal
        "GET /login?user=admin' OR '1'='1 HTTP/1.1",  # SQL Injection
        "POST /search?q=laptop HTTP/1.1",  # Normal
        "GET /api/users?id=1 UNION SELECT * FROM passwords-- HTTP/1.1",  # SQL Injection
    ]
    
    print("🧪 Probando detector...\n")
    
    for i, text in enumerate(test_cases, 1):
        is_malicious, confidence, patterns = detector.predict(text)
        
        status = "🔴 MALICIOSO" if is_malicious else "🟢 NORMAL"
        print(f"[{i}] {status} (confianza: {confidence:.2%})")
        print(f"    Texto: {text[:80]}...")
        if patterns:
            print(f"    Patrones: {', '.join(patterns)}")
        print()
    
    print("✅ Prueba completada!\n")


if __name__ == "__main__":
    main()
