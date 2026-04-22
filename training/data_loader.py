"""
AthenAI - Data Loader
Módulo para cargar y combinar datasets de SQL Injection

Datasets soportados:
1. CSIC Database - Tráfico HTTP normal y malicioso
2. SQLiV3 - SQL injection queries etiquetados
3. sqli.csv - SQL injection samples adicionales
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from typing import Tuple, Dict
import re
import warnings
from pathlib import Path
warnings.filterwarnings('ignore')

_TRAINING_DIR = Path(__file__).parent
_RAW_DIR = _TRAINING_DIR / 'raw'


class DataLoader:
    """Carga y preprocesa datasets de SQL Injection"""

    def __init__(self):
        self.datasets = {
            'csic': str(_RAW_DIR / 'csic_database.csv'),
            'sqliv3': str(_RAW_DIR / 'SQLiV3.csv'),
            'sqli': str(_RAW_DIR / 'sqli.csv')
        }
        
    def load_csic_database(self) -> pd.DataFrame:
        """
        Carga CSIC database.
        Formato: Unnamed: 0,Method,User-Agent,...,classification,URL
        """
        print("📂 Cargando CSIC Database...")
        
        try:
            df = pd.read_csv(self.datasets['csic'], encoding='utf-8', on_bad_lines='skip')
            
            # CSIC usa 'classification' y 'URL' como columnas principales
            # classification puede ser 'Normal' o 'Anomalous'
            
            # Crear DataFrame limpio
            data = pd.DataFrame({
                'text': df['URL'].astype(str),
                'label': df['classification'].apply(lambda x: 0 if str(x).strip().lower() == 'normal' else 1)
            })
            
            print(f"  ✓ Cargados {len(data):,} registros")
            print(f"  ✓ Maliciosos: {data['label'].sum():,} ({data['label'].mean()*100:.1f}%)")
            
            return data
            
        except Exception as e:
            print(f"  ✗ Error cargando CSIC: {e}")
            return pd.DataFrame(columns=['text', 'label'])
    
    def load_sqliv3(self) -> pd.DataFrame:
        """
        Carga SQLiV3 dataset.
        Formato: Sentence,Label,,
        """
        print("📂 Cargando SQLiV3 Dataset...")
        
        try:
            df = pd.read_csv(self.datasets['sqliv3'], encoding='utf-8', on_bad_lines='skip')
            
            # Limpiar nombres de columnas
            df.columns = df.columns.str.strip()
            
            # Eliminar filas con NaN en columnas importantes
            df = df.dropna(subset=['Sentence', 'Label'])
            
            # Crear DataFrame limpio
            data = pd.DataFrame({
                'text': df['Sentence'].astype(str),
                'label': df['Label'].astype(int)
            })
            
            print(f"  ✓ Cargados {len(data):,} registros")
            print(f"  ✓ Maliciosos: {data['label'].sum():,} ({data['label'].mean()*100:.1f}%)")
            
            return data
            
        except Exception as e:
            print(f"  ✗ Error cargando SQLiV3: {e}")
            return pd.DataFrame(columns=['text', 'label'])
    
    def load_sqli(self) -> pd.DataFrame:
        """
        Carga sqli.csv dataset.
        Formato: Sentence,Label (UTF-16 encoding)
        """
        print("📂 Cargando sqli.csv Dataset...")
        
        try:
            # sqli.csv usa UTF-16 encoding
            df = pd.read_csv(self.datasets['sqli'], encoding='utf-16', on_bad_lines='skip')
            
            # Limpiar nombres de columnas
            df.columns = df.columns.str.strip()
            
            # Eliminar filas con NaN
            df = df.dropna(subset=['Sentence', 'Label'])
            
            # Crear DataFrame limpio
            data = pd.DataFrame({
                'text': df['Sentence'].astype(str),
                'label': df['Label'].astype(int)
            })
            
            print(f"  ✓ Cargados {len(data):,} registros")
            print(f"  ✓ Maliciosos: {data['label'].sum():,} ({data['label'].mean()*100:.1f}%)")
            
            return data
            
        except Exception as e:
            print(f"  ✗ Error cargando sqli.csv: {e}")
            return pd.DataFrame(columns=['text', 'label'])
    
    def clean_text(self, text: str) -> str:
        """Limpia y normaliza texto"""
        if pd.isna(text) or text == 'nan':
            return ''
        
        # Convertir a string
        text = str(text)
        
        # Eliminar caracteres de control
        text = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', text)
        
        # Normalizar espacios
        text = ' '.join(text.split())
        
        return text.strip()
    
    def load_and_combine(self) -> pd.DataFrame:
        """
        Carga todos los datasets y los combina en uno solo
        """
        print("\n" + "="*80)
        print("CARGANDO DATASETS DE SQL INJECTION")
        print("="*80 + "\n")
        
        # Cargar cada dataset
        csic_data = self.load_csic_database()
        sqliv3_data = self.load_sqliv3()
        sqli_data = self.load_sqli()
        
        # Combinar todos los datasets
        print("\n📊 Combinando datasets...")
        combined = pd.concat([csic_data, sqliv3_data, sqli_data], ignore_index=True)
        
        print(f"  ✓ Total combinado: {len(combined):,} registros")
        
        # Limpiar datos
        print("\n🧹 Limpiando datos...")
        
        # Eliminar filas con texto vacío
        initial_count = len(combined)
        combined = combined[combined['text'].notna()]
        combined = combined[combined['text'].astype(str).str.strip() != '']
        print(f"  ✓ Eliminados {initial_count - len(combined):,} registros vacíos")
        
        # Limpiar texto
        combined['text'] = combined['text'].apply(self.clean_text)
        
        # Eliminar duplicados
        initial_count = len(combined)
        combined = combined.drop_duplicates(subset=['text'], keep='first')
        print(f"  ✓ Eliminados {initial_count - len(combined):,} duplicados")
        
        # Eliminar textos muy cortos (< 3 caracteres)
        initial_count = len(combined)
        combined = combined[combined['text'].str.len() >= 3]
        print(f"  ✓ Eliminados {initial_count - len(combined):,} textos muy cortos")
        
        # Resetear índice
        combined = combined.reset_index(drop=True)
        
        return combined
    
    def balance_dataset(self, df: pd.DataFrame, method: str = 'undersample') -> pd.DataFrame:
        """
        Balancea el dataset si hay desbalance de clases
        
        Args:
            df: DataFrame con columnas 'text' y 'label'
            method: 'undersample' o 'oversample'
        """
        print("\n⚖️  Balanceando dataset...")
        
        # Contar clases
        class_counts = df['label'].value_counts()
        print(f"  Clase 0 (Normal): {class_counts.get(0, 0):,}")
        print(f"  Clase 1 (Malicioso): {class_counts.get(1, 0):,}")
        
        # Calcular ratio
        if len(class_counts) < 2:
            print("  ⚠️  Solo hay una clase en el dataset!")
            return df
        
        ratio = class_counts.max() / class_counts.min()
        print(f"  Ratio de desbalance: {ratio:.2f}:1")
        
        # Si el desbalance es menor a 2:1, no hacer nada
        if ratio < 2.0:
            print("  ✓ Dataset está balanceado, no se requiere ajuste")
            return df
        
        # Separar por clase
        df_majority = df[df['label'] == class_counts.idxmax()]
        df_minority = df[df['label'] == class_counts.idxmin()]
        
        if method == 'undersample':
            # Submuestrear la clase mayoritaria
            df_majority_downsampled = df_majority.sample(n=len(df_minority), random_state=42)
            balanced = pd.concat([df_majority_downsampled, df_minority])
            print(f"  ✓ Undersampling aplicado: {len(balanced):,} registros finales")
            
        elif method == 'oversample':
            # Sobremuestrear la clase minoritaria
            df_minority_upsampled = df_minority.sample(n=len(df_majority), replace=True, random_state=42)
            balanced = pd.concat([df_majority, df_minority_upsampled])
            print(f"  ✓ Oversampling aplicado: {len(balanced):,} registros finales")
        
        else:
            print(f"  ✗ Método desconocido: {method}")
            return df
        
        # Mezclar
        balanced = balanced.sample(frac=1, random_state=42).reset_index(drop=True)
        
        return balanced
    
    def create_splits(self, df: pd.DataFrame, 
                     train_size: float = 0.7,
                     val_size: float = 0.15,
                     test_size: float = 0.15) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
        """
        Divide el dataset en train/validation/test
        """
        print("\n📊 Creando splits train/val/test...")
        
        # Verificar que los tamaños sumen 1.0
        assert abs(train_size + val_size + test_size - 1.0) < 0.01, "Los tamaños deben sumar 1.0"
        
        # Primer split: train vs (val + test)
        train_df, temp_df = train_test_split(
            df, 
            test_size=(val_size + test_size),
            random_state=42,
            stratify=df['label']
        )
        
        # Segundo split: val vs test
        val_df, test_df = train_test_split(
            temp_df,
            test_size=test_size / (val_size + test_size),
            random_state=42,
            stratify=temp_df['label']
        )
        
        print(f"  ✓ Train: {len(train_df):,} ({len(train_df)/len(df)*100:.1f}%)")
        print(f"  ✓ Val:   {len(val_df):,} ({len(val_df)/len(df)*100:.1f}%)")
        print(f"  ✓ Test:  {len(test_df):,} ({len(test_df)/len(df)*100:.1f}%)")
        
        return train_df, val_df, test_df
    
    def save_splits(self, train_df: pd.DataFrame, val_df: pd.DataFrame, test_df: pd.DataFrame):
        """Guarda los splits en archivos CSV"""
        print("\n💾 Guardando splits...")
        
        _data_dir = _TRAINING_DIR.parent / 'data'
        _data_dir.mkdir(parents=True, exist_ok=True)
        train_df.to_csv(str(_data_dir / 'train.csv'), index=False)
        print(f"  ✓ Train guardado: {_data_dir / 'train.csv'}")

        val_df.to_csv(str(_data_dir / 'val.csv'), index=False)
        print(f"  ✓ Val guardado: {_data_dir / 'val.csv'}")

        test_df.to_csv(str(_data_dir / 'test.csv'), index=False)
        print(f"  ✓ Test guardado: {_data_dir / 'test.csv'}")
    
    def get_statistics(self, df: pd.DataFrame) -> Dict:
        """Obtiene estadísticas del dataset"""
        if len(df) == 0:
            return {
                'total_samples': 0,
                'malicious_samples': 0,
                'normal_samples': 0,
                'malicious_percentage': 0.0,
                'avg_text_length': 0.0,
                'max_text_length': 0,
                'min_text_length': 0
            }
        
        stats = {
            'total_samples': len(df),
            'malicious_samples': int(df['label'].sum()),
            'normal_samples': int((df['label'] == 0).sum()),
            'malicious_percentage': float(df['label'].mean() * 100),
            'avg_text_length': float(df['text'].str.len().mean()),
            'max_text_length': int(df['text'].str.len().max()),
            'min_text_length': int(df['text'].str.len().min())
        }
        return stats


def main():
    """Función principal para ejecutar el data loader"""
    
    # Crear loader
    loader = DataLoader()
    
    # Cargar y combinar datasets
    combined_df = loader.load_and_combine()
    
    # Mostrar estadísticas
    print("\n" + "="*80)
    print("ESTADÍSTICAS DEL DATASET COMBINADO")
    print("="*80)
    stats = loader.get_statistics(combined_df)
    print(f"Total de muestras:     {stats['total_samples']:,}")
    print(f"Muestras maliciosas:   {stats['malicious_samples']:,} ({stats['malicious_percentage']:.1f}%)")
    print(f"Muestras normales:     {stats['normal_samples']:,} ({100-stats['malicious_percentage']:.1f}%)")
    print(f"Longitud promedio:     {stats['avg_text_length']:.0f} caracteres")
    print(f"Longitud máxima:       {stats['max_text_length']:,} caracteres")
    print(f"Longitud mínima:       {stats['min_text_length']:,} caracteres")
    
    # Balancear dataset (opcional - comentar si no se desea)
    # combined_df = loader.balance_dataset(combined_df, method='undersample')
    
    # Crear splits
    train_df, val_df, test_df = loader.create_splits(combined_df)
    
    # Guardar splits
    loader.save_splits(train_df, val_df, test_df)
    
    # Estadísticas finales
    print("\n" + "="*80)
    print("SPLITS CREADOS EXITOSAMENTE")
    print("="*80)
    print(f"\nTrain set: {len(train_df):,} muestras")
    print(f"  - Maliciosas: {train_df['label'].sum():,} ({train_df['label'].mean()*100:.1f}%)")
    print(f"  - Normales:   {(train_df['label']==0).sum():,} ({(train_df['label']==0).mean()*100:.1f}%)")
    
    print(f"\nValidation set: {len(val_df):,} muestras")
    print(f"  - Maliciosas: {val_df['label'].sum():,} ({val_df['label'].mean()*100:.1f}%)")
    print(f"  - Normales:   {(val_df['label']==0).sum():,} ({(val_df['label']==0).mean()*100:.1f}%)")
    
    print(f"\nTest set: {len(test_df):,} muestras")
    print(f"  - Maliciosas: {test_df['label'].sum():,} ({test_df['label'].mean()*100:.1f}%)")
    print(f"  - Normales:   {(test_df['label']==0).sum():,} ({(test_df['label']==0).mean()*100:.1f}%)")
    
    print("\n✅ Data loading completado!\n")


if __name__ == "__main__":
    main()
