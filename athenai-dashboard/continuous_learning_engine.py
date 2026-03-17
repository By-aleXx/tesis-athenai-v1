"""
AthenAI - Continuous Learning Engine

Sistema de aprendizaje continuo para detectar ataques de día cero.
Permite al modelo aprender de nuevos patrones en tiempo real.

Autor: AthenAI Team
Fecha: 2026-02-13
"""

import numpy as np
import pickle
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
from collections import deque
import json
import os

from sklearn.linear_model import SGDClassifier
from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ContinuousLearningEngine:
    """
    Motor de aprendizaje continuo para AthenAI.
    
    Características:
    - Re-entrenamiento incremental con partial_fit
    - Buffer de datos para aprendizaje
    - Validación automática antes de desplegar
    - Rollback si modelo empeora
    - Detección de concept drift
    """
    
    def __init__(self, 
                 buffer_size: int = 1000,
                 validation_split: float = 0.2,
                 min_improvement: float = 0.01,
                 model_path: str = 'models/online_model.pkl'):
        """
        Inicializa el motor de aprendizaje continuo.
        
        Args:
            buffer_size: Tamaño del buffer antes de re-entrenar
            validation_split: Porcentaje de datos para validación
            min_improvement: Mejora mínima requerida para desplegar
            model_path: Ruta para guardar el modelo
        """
        self.buffer_size = buffer_size
        self.validation_split = validation_split
        self.min_improvement = min_improvement
        self.model_path = model_path
        
        # Buffers
        self.training_buffer = deque(maxlen=buffer_size)
        self.validation_buffer = deque(maxlen=int(buffer_size * validation_split))
        
        # Modelo online (SGDClassifier soporta partial_fit)
        self.online_model = self._load_or_create_model()
        
        # Backup del modelo anterior
        self.previous_model = None
        
        # Historial de performance
        self.performance_history = {
            'timestamp': [],
            'precision': [],
            'recall': [],
            'f1_score': [],
            'accuracy': [],
            'training_samples': []
        }
        
        # Estadísticas
        self.stats = {
            'total_predictions': 0,
            'total_retrains': 0,
            'successful_deploys': 0,
            'rollbacks': 0,
            'buffer_size': 0
        }
        
        logger.info("✅ Continuous Learning Engine initialized")
    
    def _load_or_create_model(self) -> SGDClassifier:
        """Carga modelo existente o crea uno nuevo"""
        if os.path.exists(self.model_path):
            try:
                with open(self.model_path, 'rb') as f:
                    model = pickle.load(f)
                logger.info(f"✅ Loaded online model from {self.model_path}")
                return model
            except Exception as e:
                logger.warning(f"⚠️ Could not load model: {e}. Creating new one.")
        
        # Crear nuevo modelo SGD
        model = SGDClassifier(
            loss='log_loss',  # Para probabilidades
            penalty='l2',
            alpha=0.0001,
            max_iter=1000,
            tol=1e-3,
            random_state=42,
            warm_start=True  # Permite partial_fit
        )
        
        logger.info("✅ Created new SGDClassifier for online learning")
        return model
    
    def predict_and_learn(self, features: np.ndarray, actual_label: Optional[int] = None) -> Tuple[int, float]:
        """
        Hace predicción y aprende del resultado.
        
        Args:
            features: Features del request
            actual_label: Label real (si está disponible)
        
        Returns:
            (prediction, confidence)
        """
        self.stats['total_predictions'] += 1
        
        # Predicción
        try:
            if hasattr(self.online_model, 'classes_'):
                prediction = self.online_model.predict(features.reshape(1, -1))[0]
                
                # Obtener probabilidad
                if hasattr(self.online_model, 'predict_proba'):
                    proba = self.online_model.predict_proba(features.reshape(1, -1))[0]
                    confidence = float(max(proba))
                else:
                    # Usar decision_function como proxy
                    decision = self.online_model.decision_function(features.reshape(1, -1))[0]
                    confidence = float(1 / (1 + np.exp(-decision)))  # Sigmoid
            else:
                # Modelo no entrenado aún
                prediction = 0
                confidence = 0.5
        except Exception as e:
            logger.error(f"Error en predicción: {e}")
            prediction = 0
            confidence = 0.5
        
        # Agregar al buffer si tenemos label
        if actual_label is not None:
            self._add_to_buffer(features, actual_label)
            
            # Re-entrenar si buffer está lleno
            if self._should_retrain():
                self._retrain_incremental()
        
        return int(prediction), confidence
    
    def _add_to_buffer(self, features: np.ndarray, label: int):
        """Agrega ejemplo al buffer de entrenamiento"""
        # Dividir entre training y validation
        if np.random.random() < self.validation_split:
            self.validation_buffer.append((features, label))
        else:
            self.training_buffer.append((features, label))
        
        self.stats['buffer_size'] = len(self.training_buffer)
    
    def _should_retrain(self) -> bool:
        """Determina si es momento de re-entrenar"""
        return len(self.training_buffer) >= self.buffer_size
    
    def _retrain_incremental(self):
        """Re-entrena el modelo incrementalmente"""
        logger.info(f"🔄 Starting incremental retraining with {len(self.training_buffer)} samples")
        
        try:
            # Backup del modelo actual
            self.previous_model = pickle.loads(pickle.dumps(self.online_model))
            
            # Preparar datos
            X_train = np.array([x[0] for x in self.training_buffer])
            y_train = np.array([x[1] for x in self.training_buffer])
            
            # Re-entrenar incrementalmente
            if not hasattr(self.online_model, 'classes_'):
                # Primera vez: fit completo
                self.online_model.fit(X_train, y_train)
                logger.info("✅ Initial model training completed")
            else:
                # Incremental: partial_fit
                self.online_model.partial_fit(X_train, y_train, classes=[0, 1])
                logger.info("✅ Incremental training completed")
            
            # Validar nuevo modelo
            if self._validate_model():
                self._deploy_model()
                self.stats['successful_deploys'] += 1
            else:
                self._rollback_model()
                self.stats['rollbacks'] += 1
            
            self.stats['total_retrains'] += 1
            
            # Limpiar buffer
            self.training_buffer.clear()
            
        except Exception as e:
            logger.error(f"❌ Error during retraining: {e}")
            self._rollback_model()
    
    def _validate_model(self) -> bool:
        """
        Valida el nuevo modelo contra el anterior.
        
        Returns:
            True si el nuevo modelo es mejor
        """
        if len(self.validation_buffer) < 10:
            logger.warning("⚠️ Not enough validation data, accepting new model")
            return True
        
        # Preparar datos de validación
        X_val = np.array([x[0] for x in self.validation_buffer])
        y_val = np.array([x[1] for x in self.validation_buffer])
        
        try:
            # Métricas del nuevo modelo
            y_pred_new = self.online_model.predict(X_val)
            new_f1 = f1_score(y_val, y_pred_new, zero_division=0)
            new_precision = precision_score(y_val, y_pred_new, zero_division=0)
            new_recall = recall_score(y_val, y_pred_new, zero_division=0)
            new_accuracy = accuracy_score(y_val, y_pred_new)
            
            logger.info(f"📊 New Model - F1: {new_f1:.4f}, Precision: {new_precision:.4f}, Recall: {new_recall:.4f}")
            
            # Si no hay modelo anterior, aceptar
            if self.previous_model is None:
                self._record_performance(new_precision, new_recall, new_f1, new_accuracy)
                return True
            
            # Métricas del modelo anterior
            y_pred_old = self.previous_model.predict(X_val)
            old_f1 = f1_score(y_val, y_pred_old, zero_division=0)
            
            logger.info(f"📊 Old Model - F1: {old_f1:.4f}")
            
            # Comparar
            improvement = new_f1 - old_f1
            
            if improvement >= self.min_improvement:
                logger.info(f"✅ Model improved by {improvement:.4f}")
                self._record_performance(new_precision, new_recall, new_f1, new_accuracy)
                return True
            else:
                logger.warning(f"⚠️ Model did not improve enough (improvement: {improvement:.4f})")
                return False
                
        except Exception as e:
            logger.error(f"❌ Error during validation: {e}")
            return False
    
    def _deploy_model(self):
        """Despliega el nuevo modelo"""
        try:
            # Guardar modelo
            os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
            with open(self.model_path, 'wb') as f:
                pickle.dump(self.online_model, f)
            
            logger.info(f"✅ New model deployed to {self.model_path}")
            
        except Exception as e:
            logger.error(f"❌ Error deploying model: {e}")
    
    def _rollback_model(self):
        """Revierte al modelo anterior"""
        if self.previous_model is not None:
            self.online_model = self.previous_model
            logger.warning("⚠️ Rolled back to previous model")
        else:
            logger.warning("⚠️ No previous model to rollback to")
    
    def _record_performance(self, precision: float, recall: float, f1: float, accuracy: float):
        """Registra métricas de performance"""
        self.performance_history['timestamp'].append(datetime.now().isoformat())
        self.performance_history['precision'].append(precision)
        self.performance_history['recall'].append(recall)
        self.performance_history['f1_score'].append(f1)
        self.performance_history['accuracy'].append(accuracy)
        self.performance_history['training_samples'].append(len(self.training_buffer))
    
    def get_stats(self) -> Dict:
        """Retorna estadísticas del sistema"""
        return {
            **self.stats,
            'performance_history': self.performance_history,
            'last_performance': {
                'precision': self.performance_history['precision'][-1] if self.performance_history['precision'] else 0,
                'recall': self.performance_history['recall'][-1] if self.performance_history['recall'] else 0,
                'f1_score': self.performance_history['f1_score'][-1] if self.performance_history['f1_score'] else 0,
                'accuracy': self.performance_history['accuracy'][-1] if self.performance_history['accuracy'] else 0
            }
        }
    
    def force_retrain(self):
        """Fuerza un re-entrenamiento inmediato"""
        if len(self.training_buffer) > 0:
            logger.info("🔄 Forcing immediate retraining")
            self._retrain_incremental()
        else:
            logger.warning("⚠️ No data in buffer to retrain")


# Singleton instance
_continuous_learner = None

def get_continuous_learner() -> ContinuousLearningEngine:
    """Obtiene la instancia singleton del continuous learner"""
    global _continuous_learner
    if _continuous_learner is None:
        _continuous_learner = ContinuousLearningEngine()
    return _continuous_learner


if __name__ == "__main__":
    # Test básico
    print("🧪 Testing Continuous Learning Engine...")
    
    learner = ContinuousLearningEngine(buffer_size=10)
    
    # Simular datos
    for i in range(50):
        features = np.random.randn(10)
        label = np.random.randint(0, 2)
        
        prediction, confidence = learner.predict_and_learn(features, label)
        print(f"Sample {i+1}: Prediction={prediction}, Confidence={confidence:.2f}, Label={label}")
    
    # Ver estadísticas
    stats = learner.get_stats()
    print(f"\n📊 Stats: {json.dumps(stats, indent=2)}")
