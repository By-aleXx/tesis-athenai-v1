# AthenAI - Testing Suite

## Scripts de Pruebas

### test_pipeline.py
Script principal de pruebas end-to-end con 5 casos:
1. ✅ Tráfico normal
2. 🚨 SQL Injection (UNION SELECT)
3. ✅ Login normal
4. 🚨 Brute Force
5. 🚨 XSS Attack

### Uso
```bash
# Ejecutar pruebas
python test_pipeline.py

# Limpiar entorno
./clean_test_env.sh
```

### Verificación
- Envía logs a Kinesis
- Espera 5 segundos
- Verifica alertas en S3
- Output con colores (verde=pasó, rojo=falló)

## Archivos Creados
- `test_pipeline.py` - Script de pruebas
- `clean_test_env.sh` - Limpieza de entorno
- Documentación completa en artifacts
