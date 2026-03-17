# AthenAI - Guía Rápida de Uso del Sistema de Logging

## 🚀 Inicio Rápido

### 1. Instalar Dependencias

```bash
cd /home/vbox/prubas\ AthenAI/athenai-dashboard
pip install -r requirements.txt
```

### 2. Iniciar el Servidor

```bash
python3 api_backend.py
```

El servidor iniciará en `http://0.0.0.0:5000` y automáticamente:
- ✅ Creará la base de datos `traffic_logs.db`
- ✅ Activará el middleware de logging
- ✅ Comenzará a registrar todo el tráfico

---

## 📡 Endpoints Nuevos

### Obtener Logs de Tráfico

```bash
# Todos los logs (últimos 100)
curl http://localhost:5000/api/traffic-logs

# Solo test attacks de la IP autorizada
curl http://localhost:5000/api/traffic-logs?is_test_attack=true

# Filtrar por IP específica
curl http://localhost:5000/api/traffic-logs?source_ip=100.108.127.116

# Paginación
curl http://localhost:5000/api/traffic-logs?limit=50&offset=100
```

### Obtener Estadísticas

```bash
curl http://localhost:5000/api/traffic-stats
```

---

## 🔴 Cómo Funciona el Marcado de Test Attacks

**Automático**: Cualquier request que provenga de la IP `100.108.127.116` se marca automáticamente como `is_test_attack: true` en la base de datos.

**En la consola del servidor verás**:
```
🔴 TEST ATTACK LOGGED: GET /api/stats from 100.108.127.116
```

**En tráfico normal verás**:
```
(sin mensaje especial)
```

---

## 🧪 Probar el Sistema

```bash
# Ejecutar script de prueba completo
python3 test_traffic_logging.py
```

---

## 🗄️ Consultar la Base de Datos Directamente

```bash
# Abrir SQLite
sqlite3 traffic_logs.db

# Ver últimos 10 logs
SELECT id, timestamp, source_ip, method, path, is_test_attack 
FROM traffic_logs 
ORDER BY timestamp DESC 
LIMIT 10;

# Ver solo test attacks
SELECT * FROM traffic_logs WHERE is_test_attack = 1;

# Salir
.quit
```

---

## 🎯 Configuración

**Cambiar IP autorizada**: Edita `middleware.py` línea 11:

```python
AUTHORIZED_TEST_IP = '100.108.127.116'  # Cambiar aquí
```

**Agregar múltiples IPs**: Modifica la función `is_test_attack()` en `middleware.py`:

```python
def is_test_attack(ip):
    AUTHORIZED_IPS = ['100.108.127.116', '192.168.1.50', '10.0.0.100']
    return ip in AUTHORIZED_IPS
```

---

## 📊 Estructura de un Log

```json
{
  "id": 1,
  "timestamp": "2026-01-26T22:30:00.123456",
  "source_ip": "100.108.127.116",
  "method": "GET",
  "path": "/api/stats",
  "query_params": "id=1' OR '1'='1",
  "headers": {
    "User-Agent": "Mozilla/5.0...",
    "Content-Type": "application/json"
  },
  "body": "{\"username\":\"admin' OR '1'='1\"}",
  "response_status": 200,
  "is_test_attack": true,
  "user_agent": "Mozilla/5.0...",
  "content_type": "application/json",
  "content_length": 45
}
```

---

## ⚠️ Notas Importantes

- Headers sensibles (`Cookie`, `Authorization`) **NO** se guardan
- Body limitado a **10KB** por seguridad
- Archivos estáticos (`/static/*`) **NO** se registran
- El logging es **no bloqueante** - no afecta el rendimiento
