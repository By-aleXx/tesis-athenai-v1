"""
AthenAI - Feature Engineering
Módulo para extraer features de texto para modelos de ML tradicionales
"""

import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer, CountVectorizer
from typing import Tuple
import re


class FeatureEngineer:
    """Extrae features de texto para modelos tradicionales de ML"""
    
    def __init__(self, max_features: int = 5000):
        """
        Args:
            max_features: Número máximo de features TF-IDF a extraer
        """
        self.max_features = max_features
        self.tfidf_vectorizer = None
        self.feature_names = []
        
    def extract_manual_features(self, text: str) -> dict:
        """
        Extrae features manuales basadas en características de SQL Injection
        
        Args:
            text: Texto a analizar
            
        Returns:
            dict: Diccionario con features extraídas
        """
        text_lower = text.lower()
        
        features = {
            # Longitud
            'length': len(text),
            'word_count': len(text.split()),
            
            # Caracteres especiales
            'single_quote_count': text.count("'"),
            'double_quote_count': text.count('"'),
            'semicolon_count': text.count(';'),
            'dash_count': text.count('--'),
            'hash_count': text.count('#'),
            'percent_count': text.count('%'),
            'ampersand_count': text.count('&'),
            'pipe_count': text.count('|'),
            'equals_count': text.count('='),
            'parenthesis_count': text.count('(') + text.count(')'),
            
            # Palabras clave SQL
            'has_select': int('select' in text_lower),
            'has_union': int('union' in text_lower),
            'has_insert': int('insert' in text_lower),
            'has_update': int('update' in text_lower),
            'has_delete': int('delete' in text_lower),
            'has_drop': int('drop' in text_lower),
            'has_create': int('create' in text_lower),
            'has_alter': int('alter' in text_lower),
            'has_exec': int('exec' in text_lower or 'execute' in text_lower),
            'has_from': int('from' in text_lower),
            'has_where': int('where' in text_lower),
            'has_or': int(' or ' in text_lower),
            'has_and': int(' and ' in text_lower),
            
            # Funciones SQL
            'has_concat': int('concat' in text_lower),
            'has_sleep': int('sleep' in text_lower),
            'has_benchmark': int('benchmark' in text_lower),
            'has_waitfor': int('waitfor' in text_lower),
            'has_substring': int('substring' in text_lower),
            'has_ascii': int('ascii' in text_lower),
            'has_char': int('char' in text_lower),
            
            # Patrones de ataque
            'has_comment': int('--' in text or '#' in text or '/*' in text),
            'has_always_true': int(re.search(r"(1\s*=\s*1|'1'\s*=\s*'1'|'a'\s*=\s*'a')", text_lower) is not None),
            'has_stacked_query': int(re.search(r';\s*(select|insert|update|delete|drop)', text_lower) is not None),
            
            # Entropía (medida de aleatoriedad)
            'entropy': self._calculate_entropy(text),
            
            # Ratio de caracteres especiales
            'special_char_ratio': sum(not c.isalnum() and not c.isspace() for c in text) / max(len(text), 1),
        }
        
        return features
    
    def _calculate_entropy(self, text: str) -> float:
        """Calcula la entropía de Shannon del texto"""
        if not text:
            return 0.0
        
        # Contar frecuencia de cada carácter
        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calcular entropía
        entropy = 0.0
        text_len = len(text)
        for count in char_counts.values():
            probability = count / text_len
            if probability > 0:
                entropy -= probability * np.log2(probability)
        
        return entropy
    
    def fit_tfidf(self, texts: list):
        """
        Entrena el vectorizador TF-IDF
        
        Args:
            texts: Lista de textos para entrenar
        """
        print("🔧 Entrenando TF-IDF vectorizer...")
        
        self.tfidf_vectorizer = TfidfVectorizer(
            max_features=self.max_features,
            ngram_range=(1, 3),  # Unigrams, bigrams, trigrams
            min_df=2,  # Ignorar términos que aparecen en menos de 2 documentos
            max_df=0.95,  # Ignorar términos que aparecen en más del 95% de documentos
            sublinear_tf=True,  # Usar escala logarítmica para TF
            strip_accents='unicode',
            lowercase=True,
            analyzer='char_wb',  # Analizar caracteres dentro de palabras
        )
        
        self.tfidf_vectorizer.fit(texts)
        self.feature_names = self.tfidf_vectorizer.get_feature_names_out().tolist()
        
        print(f"  ✓ TF-IDF entrenado con {len(self.feature_names)} features")
    
    def transform_tfidf(self, texts: list) -> np.ndarray:
        """
        Transforma textos usando TF-IDF
        
        Args:
            texts: Lista de textos a transformar
            
        Returns:
            np.ndarray: Matriz TF-IDF
        """
        if self.tfidf_vectorizer is None:
            raise ValueError("TF-IDF vectorizer no ha sido entrenado. Llama a fit_tfidf() primero.")
        
        return self.tfidf_vectorizer.transform(texts).toarray()
    
    def extract_all_features(self, df: pd.DataFrame) -> Tuple[np.ndarray, list]:
        """
        Extrae todas las features (TF-IDF + manuales) de un DataFrame
        
        Args:
            df: DataFrame con columna 'text'
            
        Returns:
            Tuple[np.ndarray, list]: (matriz de features, nombres de features)
        """
        print("🔧 Extrayendo features...")
        
        # Extraer features TF-IDF
        tfidf_features = self.transform_tfidf(df['text'].tolist())
        print(f"  ✓ Features TF-IDF: {tfidf_features.shape[1]}")
        
        # Extraer features manuales
        manual_features_list = []
        for text in df['text']:
            manual_features_list.append(self.extract_manual_features(text))
        
        manual_features_df = pd.DataFrame(manual_features_list)
        manual_features = manual_features_df.values
        print(f"  ✓ Features manuales: {manual_features.shape[1]}")
        
        # Combinar todas las features
        all_features = np.hstack([tfidf_features, manual_features])
        all_feature_names = self.feature_names + manual_features_df.columns.tolist()
        
        print(f"  ✓ Total features: {all_features.shape[1]}")
        
        return all_features, all_feature_names


def main():
    """Función de prueba"""
    print("="*80)
    print("FEATURE ENGINEERING - PRUEBA")
    print("="*80 + "\n")
    
    # Cargar datos
    print("📂 Cargando datos de entrenamiento...")
    train_df = pd.read_csv('data/train.csv')
    print(f"  ✓ Cargados {len(train_df):,} registros\n")
    
    # Crear feature engineer
    fe = FeatureEngineer(max_features=3000)
    
    # Entrenar TF-IDF
    fe.fit_tfidf(train_df['text'].tolist())
    
    # Extraer features
    X_train, feature_names = fe.extract_all_features(train_df)
    
    print(f"\n✅ Features extraídas exitosamente!")
    print(f"   Shape: {X_train.shape}")
    print(f"   Total features: {len(feature_names)}")
    
    # Mostrar algunas features manuales
    print(f"\n📊 Ejemplo de features manuales:")
    sample_text = train_df.iloc[0]['text']
    manual_feats = fe.extract_manual_features(sample_text)
    print(f"   Texto: {sample_text[:100]}...")
    print(f"   Features: {list(manual_feats.items())[:10]}")


if __name__ == "__main__":
    main()
