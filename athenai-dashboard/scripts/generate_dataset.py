"""
AthenAI - Generador de Dataset de Tráfico

Genera un dataset sintético de tráfico web con patrones normales y maliciosos
para entrenar el modelo de detección de amenazas.

Features:
- request_count: Número de requests en ventana de tiempo
- error_rate: Tasa de errores (0.0 - 1.0)
- avg_response_time: Tiempo promedio de respuesta (ms)
- unique_ips: Número de IPs únicas

Target:
- is_threat: 0 = Normal, 1 = Amenaza
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random

# Seed para reproducibilidad
np.random.seed(42)
random.seed(42)


def generate_normal_traffic(n_samples=500):
    """Genera tráfico normal"""
    data = []
    
    for _ in range(n_samples):
        # Tráfico normal: bajo volumen, baja tasa de error, respuesta rápida
        request_count = np.random.randint(1, 50)
        error_rate = np.random.uniform(0.0, 0.05)  # 0-5% errores
        avg_response_time = np.random.uniform(50, 300)  # 50-300ms
        unique_ips = np.random.randint(1, min(request_count + 1, 20))
        
        data.append({
            'request_count': request_count,
            'error_rate': error_rate,
            'avg_response_time': avg_response_time,
            'unique_ips': unique_ips,
            'is_threat': 0,
            'threat_type': 'normal'
        })
    
    return data


def generate_ddos_traffic(n_samples=100):
    """Genera tráfico de ataque DDoS"""
    data = []
    
    for _ in range(n_samples):
        # DDoS: alto volumen, muchas IPs, alta tasa de error
        request_count = np.random.randint(200, 1000)
        error_rate = np.random.uniform(0.3, 0.7)  # 30-70% errores
        avg_response_time = np.random.uniform(2000, 5000)  # 2-5 segundos
        unique_ips = np.random.randint(50, 200)
        
        data.append({
            'request_count': request_count,
            'error_rate': error_rate,
            'avg_response_time': avg_response_time,
            'unique_ips': unique_ips,
            'is_threat': 1,
            'threat_type': 'ddos'
        })
    
    return data


def generate_brute_force_traffic(n_samples=100):
    """Genera tráfico de ataque de fuerza bruta"""
    data = []
    
    for _ in range(n_samples):
        # Brute Force: volumen medio, pocas IPs, alta tasa de error
        request_count = np.random.randint(100, 300)
        error_rate = np.random.uniform(0.6, 0.95)  # 60-95% errores (intentos fallidos)
        avg_response_time = np.random.uniform(100, 500)
        unique_ips = np.random.randint(1, 5)  # Pocas IPs
        
        data.append({
            'request_count': request_count,
            'error_rate': error_rate,
            'avg_response_time': avg_response_time,
            'unique_ips': unique_ips,
            'is_threat': 1,
            'threat_type': 'brute_force'
        })
    
    return data


def generate_sql_injection_traffic(n_samples=80):
    """Genera tráfico de ataque SQL Injection"""
    data = []
    
    for _ in range(n_samples):
        # SQL Injection: volumen bajo-medio, alta tasa de error, respuesta lenta
        request_count = np.random.randint(20, 100)
        error_rate = np.random.uniform(0.4, 0.8)  # 40-80% errores
        avg_response_time = np.random.uniform(500, 2000)
        unique_ips = np.random.randint(1, 10)
        
        data.append({
            'request_count': request_count,
            'error_rate': error_rate,
            'avg_response_time': avg_response_time,
            'unique_ips': unique_ips,
            'is_threat': 1,
            'threat_type': 'sql_injection'
        })
    
    return data


def generate_xss_traffic(n_samples=70):
    """Genera tráfico de ataque XSS"""
    data = []
    
    for _ in range(n_samples):
        # XSS: volumen bajo, tasa de error media, respuesta normal
        request_count = np.random.randint(10, 80)
        error_rate = np.random.uniform(0.2, 0.5)  # 20-50% errores
        avg_response_time = np.random.uniform(100, 800)
        unique_ips = np.random.randint(1, 15)
        
        data.append({
            'request_count': request_count,
            'error_rate': error_rate,
            'avg_response_time': avg_response_time,
            'unique_ips': unique_ips,
            'is_threat': 1,
            'threat_type': 'xss'
        })
    
    return data


def generate_port_scan_traffic(n_samples=50):
    """Genera tráfico de escaneo de puertos"""
    data = []
    
    for _ in range(n_samples):
        # Port Scan: alto volumen, pocas IPs, alta tasa de error
        request_count = np.random.randint(150, 400)
        error_rate = np.random.uniform(0.5, 0.9)  # 50-90% errores
        avg_response_time = np.random.uniform(50, 200)  # Rápido
        unique_ips = np.random.randint(1, 3)  # Muy pocas IPs
        
        data.append({
            'request_count': request_count,
            'error_rate': error_rate,
            'avg_response_time': avg_response_time,
            'unique_ips': unique_ips,
            'is_threat': 1,
            'threat_type': 'port_scan'
        })
    
    return data


def main():
    """Genera el dataset completo"""
    
    print("=" * 80)
    print("ATHENAI - GENERADOR DE DATASET DE TRÁFICO")
    print("=" * 80)
    
    # Generar datos
    print("\n📊 Generando datos...")
    
    all_data = []
    
    # Tráfico normal (50% del dataset)
    print("  ✅ Tráfico normal: 500 muestras")
    all_data.extend(generate_normal_traffic(500))
    
    # Ataques (50% del dataset)
    print("  ⚠️  DDoS: 100 muestras")
    all_data.extend(generate_ddos_traffic(100))
    
    print("  ⚠️  Brute Force: 100 muestras")
    all_data.extend(generate_brute_force_traffic(100))
    
    print("  ⚠️  SQL Injection: 80 muestras")
    all_data.extend(generate_sql_injection_traffic(80))
    
    print("  ⚠️  XSS: 70 muestras")
    all_data.extend(generate_xss_traffic(70))
    
    print("  ⚠️  Port Scan: 50 muestras")
    all_data.extend(generate_port_scan_traffic(50))
    
    # Crear DataFrame
    df = pd.DataFrame(all_data)
    
    # Mezclar datos
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    # Guardar
    output_file = 'data/traffic_dataset.csv'
    df.to_csv(output_file, index=False)
    
    print(f"\n✅ Dataset guardado en: {output_file}")
    print(f"\n📈 Estadísticas del Dataset:")
    print(f"  Total de muestras: {len(df)}")
    print(f"  Tráfico normal: {len(df[df['is_threat'] == 0])} ({len(df[df['is_threat'] == 0]) / len(df) * 100:.1f}%)")
    print(f"  Amenazas: {len(df[df['is_threat'] == 1])} ({len(df[df['is_threat'] == 1]) / len(df) * 100:.1f}%)")
    
    print(f"\n🎯 Distribución de amenazas:")
    threat_counts = df[df['is_threat'] == 1]['threat_type'].value_counts()
    for threat_type, count in threat_counts.items():
        print(f"  {threat_type}: {count}")
    
    print(f"\n📊 Estadísticas de features:")
    print(df[['request_count', 'error_rate', 'avg_response_time', 'unique_ips']].describe())
    
    print("\n" + "=" * 80)
    print("✅ Dataset generado exitosamente!")
    print("=" * 80)
    
    return df


if __name__ == "__main__":
    # Crear directorio data si no existe
    import os
    os.makedirs('data', exist_ok=True)
    
    main()
