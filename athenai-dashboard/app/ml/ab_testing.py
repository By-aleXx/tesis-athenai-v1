"""
A/B Testing Manager for Model Comparison
Enables traffic splitting and performance tracking between multiple models
"""

import random
from typing import Dict, Tuple
from datetime import datetime
import json

class ABTestManager:
    """
    Manages A/B testing for ML models
    
    Features:
    - Traffic splitting between models
    - Performance metrics tracking
    - Auto-promotion based on performance
    - Configurable traffic percentages
    """
    
    def __init__(self):
        self.models = {
            'model_a': {
                'version': 'v1.0.0',
                'name': 'Production Model',
                'traffic_percentage': 90,
                'metrics': {
                    'requests': 0,
                    'correct_predictions': 0,
                    'false_positives': 0,
                    'false_negatives': 0,
                    'avg_confidence': 0.0,
                    'total_confidence': 0.0,
                },
                'enabled': True,
            },
            'model_b': {
                'version': 'v1.1.0',
                'name': 'Candidate Model',
                'traffic_percentage': 10,
                'metrics': {
                    'requests': 0,
                    'correct_predictions': 0,
                    'false_positives': 0,
                    'false_negatives': 0,
                    'avg_confidence': 0.0,
                    'total_confidence': 0.0,
                },
                'enabled': True,
            }
        }
        
        self.auto_promote_threshold = 0.02  # 2% improvement required
        self.min_requests_for_promotion = 1000  # Minimum requests before auto-promotion
    
    def select_model(self) -> str:
        """
        Select model based on traffic split
        
        Returns:
            Model ID ('model_a' or 'model_b')
        """
        # Only consider enabled models
        enabled_models = {k: v for k, v in self.models.items() if v['enabled']}
        
        if not enabled_models:
            return 'model_a'  # Fallback
        
        if len(enabled_models) == 1:
            return list(enabled_models.keys())[0]
        
        # Traffic splitting
        rand = random.random() * 100
        
        cumulative = 0
        for model_id, model_data in enabled_models.items():
            cumulative += model_data['traffic_percentage']
            if rand < cumulative:
                return model_id
        
        return 'model_a'  # Fallback
    
    def record_prediction(self, model_id: str, prediction: str, confidence: float, actual: str = None):
        """
        Record prediction result for metrics
        
        Args:
            model_id: ID of the model that made the prediction
            prediction: Predicted label ('malicious' or 'benign')
            confidence: Confidence score (0.0-1.0)
            actual: Actual label (if known)
        """
        if model_id not in self.models:
            return
        
        metrics = self.models[model_id]['metrics']
        metrics['requests'] += 1
        metrics['total_confidence'] += confidence
        metrics['avg_confidence'] = metrics['total_confidence'] / metrics['requests']
        
        # Only update accuracy metrics if we have ground truth
        if actual:
            if prediction == actual:
                metrics['correct_predictions'] += 1
            elif prediction == 'malicious' and actual == 'benign':
                metrics['false_positives'] += 1
            elif prediction == 'benign' and actual == 'malicious':
                metrics['false_negatives'] += 1
    
    def get_stats(self) -> Dict:
        """
        Get A/B testing statistics
        
        Returns:
            Dictionary with stats for all models
        """
        stats = {}
        
        for model_id, model_data in self.models.items():
            metrics = model_data['metrics']
            total = metrics['requests']
            
            # Calculate derived metrics
            accuracy = (metrics['correct_predictions'] / total * 100) if total > 0 else 0
            fpr = (metrics['false_positives'] / total * 100) if total > 0 else 0
            fnr = (metrics['false_negatives'] / total * 100) if total > 0 else 0
            
            # F1 Score calculation
            tp = metrics['correct_predictions'] - metrics['false_positives']
            fp = metrics['false_positives']
            fn = metrics['false_negatives']
            
            precision = (tp / (tp + fp)) if (tp + fp) > 0 else 0
            recall = (tp / (tp + fn)) if (tp + fn) > 0 else 0
            f1_score = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0
            
            stats[model_id] = {
                'version': model_data['version'],
                'name': model_data['name'],
                'traffic_percentage': model_data['traffic_percentage'],
                'enabled': model_data['enabled'],
                'total_requests': total,
                'accuracy': round(accuracy, 2),
                'false_positive_rate': round(fpr, 2),
                'false_negative_rate': round(fnr, 2),
                'f1_score': round(f1_score * 100, 2),
                'avg_confidence': round(metrics['avg_confidence'] * 100, 2),
            }
        
        # Add comparison
        if self.models['model_a']['metrics']['requests'] > 0 and self.models['model_b']['metrics']['requests'] > 0:
            acc_diff = stats['model_b']['accuracy'] - stats['model_a']['accuracy']
            f1_diff = stats['model_b']['f1_score'] - stats['model_a']['f1_score']
            
            stats['comparison'] = {
                'accuracy_diff': round(acc_diff, 2),
                'f1_diff': round(f1_diff, 2),
                'winner': 'model_b' if f1_diff > 0 else 'model_a',
                'can_auto_promote': self._can_auto_promote(),
            }
        
        return stats
    
    def update_traffic_split(self, model_a_percentage: int):
        """
        Update traffic split percentages
        
        Args:
            model_a_percentage: Percentage of traffic for model A (0-100)
        """
        model_a_percentage = max(0, min(100, model_a_percentage))
        self.models['model_a']['traffic_percentage'] = model_a_percentage
        self.models['model_b']['traffic_percentage'] = 100 - model_a_percentage
    
    def enable_model(self, model_id: str, enabled: bool = True):
        """Enable or disable a model"""
        if model_id in self.models:
            self.models[model_id]['enabled'] = enabled
    
    def _can_auto_promote(self) -> bool:
        """
        Check if model B can be auto-promoted
        
        Returns:
            True if model B should be promoted to production
        """
        model_a_metrics = self.models['model_a']['metrics']
        model_b_metrics = self.models['model_b']['metrics']
        
        # Need minimum requests
        if model_b_metrics['requests'] < self.min_requests_for_promotion:
            return False
        
        # Calculate F1 scores
        def calc_f1(metrics):
            tp = metrics['correct_predictions'] - metrics['false_positives']
            fp = metrics['false_positives']
            fn = metrics['false_negatives']
            
            precision = (tp / (tp + fp)) if (tp + fp) > 0 else 0
            recall = (tp / (tp + fn)) if (tp + fn) > 0 else 0
            return (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0
        
        f1_a = calc_f1(model_a_metrics)
        f1_b = calc_f1(model_b_metrics)
        
        # Model B must be significantly better
        return (f1_b - f1_a) >= self.auto_promote_threshold
    
    def promote_model_b(self):
        """
        Promote model B to production (swap models)
        """
        # Swap model data
        temp = self.models['model_a'].copy()
        self.models['model_a'] = self.models['model_b'].copy()
        self.models['model_b'] = temp
        
        # Reset traffic split
        self.models['model_a']['traffic_percentage'] = 90
        self.models['model_b']['traffic_percentage'] = 10
        
        # Reset metrics for new candidate
        self.models['model_b']['metrics'] = {
            'requests': 0,
            'correct_predictions': 0,
            'false_positives': 0,
            'false_negatives': 0,
            'avg_confidence': 0.0,
            'total_confidence': 0.0,
        }
        
        print(f"✅ Model promoted: {self.models['model_a']['version']} is now in production")
    
    def reset_metrics(self, model_id: str = None):
        """Reset metrics for a model or all models"""
        if model_id:
            if model_id in self.models:
                self.models[model_id]['metrics'] = {
                    'requests': 0,
                    'correct_predictions': 0,
                    'false_positives': 0,
                    'false_negatives': 0,
                    'avg_confidence': 0.0,
                    'total_confidence': 0.0,
                }
        else:
            for model in self.models.values():
                model['metrics'] = {
                    'requests': 0,
                    'correct_predictions': 0,
                    'false_positives': 0,
                    'false_negatives': 0,
                    'avg_confidence': 0.0,
                    'total_confidence': 0.0,
                }

# Global instance
ab_test_manager = ABTestManager()

if __name__ == "__main__":
    # Test the A/B testing manager
    print("Testing A/B Testing Manager...")
    
    # Simulate some predictions
    for i in range(100):
        model_id = ab_test_manager.select_model()
        prediction = 'malicious' if random.random() > 0.5 else 'benign'
        confidence = random.uniform(0.7, 0.99)
        actual = prediction if random.random() > 0.05 else ('benign' if prediction == 'malicious' else 'malicious')
        
        ab_test_manager.record_prediction(model_id, prediction, confidence, actual)
    
    # Get stats
    stats = ab_test_manager.get_stats()
    print("\nA/B Testing Stats:")
    print(json.dumps(stats, indent=2))
