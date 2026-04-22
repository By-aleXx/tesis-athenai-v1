"""
AthenAI - Entrenamiento de DistilBERT para Detección de SQLi/XSS
Tesis de Maestría: Deep Learning para Ciberseguridad

Este módulo implementa el fine-tuning de DistilBERT para detectar
inyecciones SQL y XSS mediante análisis semántico contextual.
"""

import pandas as pd
import numpy as np

try:
    import torch
    from torch.utils.data import Dataset, DataLoader
    from transformers import (
        DistilBertTokenizer,
        DistilBertForSequenceClassification,
        Trainer,
        TrainingArguments,
        EarlyStoppingCallback
    )
except ImportError as _import_err:
    print(
        "ERROR: Dependencias de Deep Learning no encontradas.\n"
        "Ejecuta: pip install transformers torch\n"
        f"Detalle: {_import_err}"
    )
    exit(1)
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    roc_auc_score,
    confusion_matrix,
    classification_report
)
from sklearn.model_selection import train_test_split
import json
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')


class SQLiDataset(Dataset):
    """Dataset personalizado para DistilBERT"""
    
    def __init__(self, texts, labels, tokenizer, max_length=128):
        self.texts = texts
        self.labels = labels
        self.tokenizer = tokenizer
        self.max_length = max_length
    
    def __len__(self):
        return len(self.texts)
    
    def __getitem__(self, idx):
        text = str(self.texts[idx])
        label = self.labels[idx]
        
        # Tokenizar
        encoding = self.tokenizer(
            text,
            add_special_tokens=True,
            max_length=self.max_length,
            padding='max_length',
            truncation=True,
            return_attention_mask=True,
            return_tensors='pt'
        )
        
        return {
            'input_ids': encoding['input_ids'].flatten(),
            'attention_mask': encoding['attention_mask'].flatten(),
            'labels': torch.tensor(label, dtype=torch.long)
        }


class DistilBERTTrainer:
    """Entrenador de DistilBERT para detección de inyecciones"""
    
    def __init__(self, model_name='distilbert-base-uncased'):
        self.model_name = model_name
        self.tokenizer = None
        self.model = None
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        
        print(f"🔧 Dispositivo: {self.device}")
        if torch.cuda.is_available():
            print(f"   GPU: {torch.cuda.get_device_name(0)}")
    
    def load_data(self):
        """Carga los datasets preprocesados"""
        print("\n" + "="*80)
        print("CARGANDO DATOS")
        print("="*80 + "\n")
        
        print("📂 Cargando splits...")
        train_df = pd.read_csv('data/train.csv')
        val_df = pd.read_csv('data/val.csv')
        test_df = pd.read_csv('data/test.csv')
        
        print(f"  ✓ Train: {len(train_df):,} muestras")
        print(f"  ✓ Val:   {len(val_df):,} muestras")
        print(f"  ✓ Test:  {len(test_df):,} muestras")
        
        # Distribución de clases
        print(f"\n📊 Distribución de clases (Train):")
        print(f"  Normal:    {(train_df['label']==0).sum():,} ({(train_df['label']==0).mean()*100:.1f}%)")
        print(f"  Malicioso: {(train_df['label']==1).sum():,} ({(train_df['label']==1).mean()*100:.1f}%)")
        
        return train_df, val_df, test_df
    
    def initialize_model(self):
        """Inicializa tokenizer y modelo"""
        print("\n" + "="*80)
        print("INICIALIZANDO DISTILBERT")
        print("="*80 + "\n")
        
        print(f"📥 Descargando {self.model_name}...")
        self.tokenizer = DistilBertTokenizer.from_pretrained(self.model_name)
        
        self.model = DistilBertForSequenceClassification.from_pretrained(
            self.model_name,
            num_labels=2,  # Binario: Normal vs Malicioso
            output_attentions=False,
            output_hidden_states=False
        )
        
        self.model.to(self.device)
        
        print(f"  ✓ Tokenizer cargado")
        print(f"  ✓ Modelo cargado ({sum(p.numel() for p in self.model.parameters()):,} parámetros)")
    
    def create_datasets(self, train_df, val_df, test_df, max_length=128):
        """Crea datasets de PyTorch"""
        print("\n🔧 Creando datasets...")
        
        train_dataset = SQLiDataset(
            train_df['text'].values,
            train_df['label'].values,
            self.tokenizer,
            max_length
        )
        
        val_dataset = SQLiDataset(
            val_df['text'].values,
            val_df['label'].values,
            self.tokenizer,
            max_length
        )
        
        test_dataset = SQLiDataset(
            test_df['text'].values,
            test_df['label'].values,
            self.tokenizer,
            max_length
        )
        
        print(f"  ✓ Train dataset: {len(train_dataset)} muestras")
        print(f"  ✓ Val dataset:   {len(val_dataset)} muestras")
        print(f"  ✓ Test dataset:  {len(test_dataset)} muestras")
        
        return train_dataset, val_dataset, test_dataset
    
    def compute_metrics(self, pred):
        """Calcula métricas para evaluación"""
        labels = pred.label_ids
        preds = pred.predictions.argmax(-1)
        
        precision, recall, f1, _ = precision_recall_fscore_support(
            labels, preds, average='binary'
        )
        acc = accuracy_score(labels, preds)
        
        return {
            'accuracy': acc,
            'precision': precision,
            'recall': recall,
            'f1': f1
        }
    
    def train(self, train_dataset, val_dataset, output_dir='training/models/distilbert'):
        """Entrena el modelo con Hugging Face Trainer"""
        print("\n" + "="*80)
        print("ENTRENANDO DISTILBERT")
        print("="*80 + "\n")
        
        # Configuración de entrenamiento
        training_args = TrainingArguments(
            output_dir=output_dir,
            num_train_epochs=3,
            per_device_train_batch_size=16,
            per_device_eval_batch_size=32,
            warmup_steps=500,
            weight_decay=0.01,
            learning_rate=2e-5,
            logging_dir=f'{output_dir}/logs',
            logging_steps=100,
            eval_strategy='steps',
            eval_steps=500,
            save_strategy='steps',
            save_steps=500,
            load_best_model_at_end=True,
            metric_for_best_model='f1',
            greater_is_better=True,
            save_total_limit=2,
            fp16=torch.cuda.is_available(),  # Mixed precision si hay GPU
        )
        
        # Trainer
        trainer = Trainer(
            model=self.model,
            args=training_args,
            train_dataset=train_dataset,
            eval_dataset=val_dataset,
            compute_metrics=self.compute_metrics,
            callbacks=[EarlyStoppingCallback(early_stopping_patience=3)]
        )
        
        # Entrenar
        print("🚀 Iniciando entrenamiento...\n")
        train_result = trainer.train()
        
        # Guardar modelo
        print("\n💾 Guardando modelo...")
        trainer.save_model(output_dir)
        self.tokenizer.save_pretrained(output_dir)
        
        print(f"  ✓ Modelo guardado en: {output_dir}")
        
        return trainer, train_result
    
    def evaluate(self, trainer, test_dataset):
        """Evalúa el modelo en test set"""
        print("\n" + "="*80)
        print("EVALUACIÓN EN TEST SET")
        print("="*80 + "\n")
        
        # Predicciones
        predictions = trainer.predict(test_dataset)
        
        # Extraer labels y predicciones
        y_true = predictions.label_ids
        y_pred = predictions.predictions.argmax(-1)
        y_proba = torch.softmax(torch.tensor(predictions.predictions), dim=1)[:, 1].numpy()
        
        # Métricas
        accuracy = accuracy_score(y_true, y_pred)
        precision, recall, f1, _ = precision_recall_fscore_support(
            y_true, y_pred, average='binary'
        )
        auc_roc = roc_auc_score(y_true, y_proba)
        cm = confusion_matrix(y_true, y_pred)
        
        # Mostrar resultados
        print("📊 Métricas de Rendimiento:")
        print(f"  Accuracy:  {accuracy:.4f}")
        print(f"  Precision: {precision:.4f}")
        print(f"  Recall:    {recall:.4f}")
        print(f"  F1-Score:  {f1:.4f}")
        print(f"  AUC-ROC:   {auc_roc:.4f}")
        
        print(f"\n📊 Matriz de Confusión:")
        print(f"  TN: {cm[0,0]:5d}  |  FP: {cm[0,1]:5d}")
        print(f"  FN: {cm[1,0]:5d}  |  TP: {cm[1,1]:5d}")
        
        # Classification report
        print(f"\n📋 Reporte de Clasificación:")
        print(classification_report(y_true, y_pred, target_names=['Normal', 'Malicioso']))
        
        # Guardar métricas
        metrics = {
            'accuracy': float(accuracy),
            'precision': float(precision),
            'recall': float(recall),
            'f1_score': float(f1),
            'auc_roc': float(auc_roc),
            'confusion_matrix': cm.tolist(),
            'timestamp': datetime.utcnow().isoformat()
        }
        
        with open('training/results/distilbert_metrics.json', 'w') as f:
            json.dump(metrics, f, indent=2)
        
        print(f"\n💾 Métricas guardadas en: training/results/distilbert_metrics.json")
        
        return metrics
    
    def test_inference(self, text_samples):
        """Prueba inferencia con ejemplos"""
        print("\n" + "="*80)
        print("PRUEBA DE INFERENCIA")
        print("="*80 + "\n")
        
        self.model.eval()
        
        for i, text in enumerate(text_samples, 1):
            # Tokenizar
            inputs = self.tokenizer(
                text,
                add_special_tokens=True,
                max_length=128,
                padding='max_length',
                truncation=True,
                return_tensors='pt'
            )
            
            inputs = {k: v.to(self.device) for k, v in inputs.items()}
            
            # Predecir
            with torch.no_grad():
                outputs = self.model(**inputs)
                logits = outputs.logits
                proba = torch.softmax(logits, dim=1)
                prediction = torch.argmax(proba, dim=1).item()
                confidence = proba[0, prediction].item()
            
            # Mostrar resultado
            label = "🚨 MALICIOSO" if prediction == 1 else "✅ NORMAL"
            print(f"[{i}] {label} (Confianza: {confidence:.2%})")
            print(f"    Texto: {text[:100]}...")
            print()


def main():
    """Función principal"""
    print("\n" + "="*80)
    print("ATHENAI - ENTRENAMIENTO DE DISTILBERT")
    print("Detección de SQLi/XSS mediante Deep Learning")
    print("="*80)
    
    start_time = datetime.now()
    
    # Crear trainer
    trainer_obj = DistilBERTTrainer()
    
    # Cargar datos
    train_df, val_df, test_df = trainer_obj.load_data()
    
    # Inicializar modelo
    trainer_obj.initialize_model()
    
    # Crear datasets
    train_dataset, val_dataset, test_dataset = trainer_obj.create_datasets(
        train_df, val_df, test_df
    )
    
    # Entrenar
    trainer, train_result = trainer_obj.train(train_dataset, val_dataset)
    
    # Evaluar
    metrics = trainer_obj.evaluate(trainer, test_dataset)
    
    # Pruebas de inferencia
    test_samples = [
        "GET /products?id=1 HTTP/1.1",  # Normal
        "GET /login?user=admin' OR '1'='1 HTTP/1.1",  # SQLi
        "POST /search?q=laptop HTTP/1.1",  # Normal
        "GET /api/users?id=1 UNION SELECT * FROM passwords-- HTTP/1.1",  # SQLi
        "<script>alert('XSS')</script>",  # XSS
    ]
    
    trainer_obj.test_inference(test_samples)
    
    # Tiempo total
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()
    
    print("="*80)
    print(f"⏱️  Tiempo total: {duration:.1f}s ({duration/60:.1f} min)")
    print("✅ ENTRENAMIENTO COMPLETADO!")
    print("="*80 + "\n")


if __name__ == "__main__":
    main()
