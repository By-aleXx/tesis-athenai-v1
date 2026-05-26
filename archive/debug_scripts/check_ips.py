#!/usr/bin/env python3
"""
Script temporal para verificar IPs que están haciendo requests a AthenAI
"""

import sqlite3
from collections import Counter
import os

print("")
print("=" * 60)
print("  🌐 ANÁLISIS DE IPs - AthenAI Traffic")
print("=" * 60)
print("")

# Verificar si existe la base de datos
db_path = 'traffic_logs.db'

if not os.path.exists(db_path):
    print(f"⚠️  Base de datos no encontrada: {db_path}")
    print("   El sistema aún no ha registrado tráfico")
    print("")
    exit(0)

# Conectar a SQLite
try:
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Obtener IPs y conteo
    cursor.execute('''
        SELECT source_ip, COUNT(*) as count, 
               MAX(timestamp) as last_seen,
               method
        FROM traffic_logs 
        GROUP BY source_ip 
        ORDER BY count DESC
    ''')
    
    rows = cursor.fetchall()
    
    if rows:
        print("📊 IPs ACTIVAS:")
        print("")
        print(f"  {'IP Address':<20} {'Requests':<12} {'Última Vista':<25} {'Método Común':<10}")
        print("  " + "-" * 75)
        
        for ip, count, last_seen, method in rows:
            print(f"  {ip:<20} {count:<12} {last_seen:<25} {method:<10}")
        
        print("")
        print("=" * 60)
        print(f"  📊 Total IPs únicas:  {len(rows)}")
        print(f"  📊 Total requests:    {sum([r[1] for r in rows])}")
        print("=" * 60)
        
        # Obtener métodos más usados
        cursor.execute('''
            SELECT method, COUNT(*) as count 
            FROM traffic_logs 
            GROUP BY method 
            ORDER BY count DESC
        ''')
        
        methods = cursor.fetchall()
        
        if methods:
            print("")
            print("📋 MÉTODOS HTTP:")
            for method, count in methods:
                print(f"  {method:<10} → {count:4d} requests")
        
        # Obtener endpoints más visitados
        cursor.execute('''
            SELECT path, COUNT(*) as count 
            FROM traffic_logs 
            GROUP BY path 
            ORDER BY count DESC
            LIMIT 10
        ''')
        
        endpoints = cursor.fetchall()
        
        if endpoints:
            print("")
            print("🎯 TOP 10 ENDPOINTS:")
            for url, count in endpoints:
                url_display = url[:45] + "..." if len(url) > 48 else url
                print(f"  {url_display:<48} → {count:4d} requests")
        
        # Obtener requests recientes
        cursor.execute('''
            SELECT source_ip, method, path, response_status, timestamp
            FROM traffic_logs 
            ORDER BY timestamp DESC
            LIMIT 5
        ''')
        
        recent = cursor.fetchall()
        
        if recent:
            print("")
            print("🕐 ÚLTIMOS 5 REQUESTS:")
            for ip, method, url, status, ts in recent:
                url_display = url[:30] + "..." if len(url) > 33 else url
                print(f"  [{ts}] {ip:<15} {method:<6} {url_display:<33} → {status}")
        
    else:
        print("  ℹ️  No hay tráfico registrado todavía")
        print("  Espera a que se realicen algunas peticiones al sistema")
    
    print("")
    
    conn.close()
    
except Exception as e:
    print(f"❌ Error al consultar base de datos: {e}")
    print("")

print("")
