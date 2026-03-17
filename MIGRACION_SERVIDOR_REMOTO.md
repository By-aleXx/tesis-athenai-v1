# 🌐 Migración a Servidor Remoto - Completada

**Fecha:** Febrero 18, 2026  
**Servidor Principal:** `100.108.127.116`

---

## ✅ Cambios Realizados

### **ANTES** (Configuración localhost)
```
LocalStack: http://localhost:4566
Redis:      localhost:6379
Origen:     Servidor local (misma máquina)
```

### **DESPUÉS** (Configuración servidor remoto)
```
LocalStack: http://100.108.127.116:4566
Redis:      100.108.127.116:6379
Origen:     Servidor remoto (infraestructura centralizada)
```

---

## 📝 Archivos Modificados

### 1. **config.py** - Configuración Principal
```python
REMOTE_SERVER_IP = "100.108.127.116"
AWS_ENDPOINT_URL = f"http://{REMOTE_SERVER_IP}:4566"
REDIS_HOST = REMOTE_SERVER_IP
REDIS_PORT = 6379
```

**Cambios:**
- ✅ Variable `REMOTE_SERVER_IP` apunta a servidor remoto
- ✅ `AWS_ENDPOINT_URL` usa servidor remoto para LocalStack
- ✅ `REDIS_HOST` usa servidor remoto

---

### 2. **dynamodb_client.py** - Cliente DynamoDB
```python
# Línea 62 (fallback)
endpoint_url='http://100.108.127.116:4566'  # Antes: localhost:4566
```

**Cambios:**
- ✅ Fallback actualizado de `localhost` a `100.108.127.116`
- ✅ Usa `config.py` como fuente principal

---

### 3. **evidence_store.py** - Almacenamiento S3
```python
# Línea 86 (fallback)
endpoint_url='http://100.108.127.116:4566'  # Antes: localhost:4566
```

**Cambios:**
- ✅ Cliente S3 apunta a servidor remoto
- ✅ Evidencias se almacenan en S3 remoto

---

### 4. **secrets_manager.py** - Gestión de Secretos
```python
# Línea 61 (fallback)
endpoint_url='http://100.108.127.116:4566'  # Antes: localhost:4566
```

**Cambios:**
- ✅ Secrets Manager usa servidor remoto
- ✅ Secretos almacenados centralizadamente

---

### 5. **sns_setup.py** - Sistema de Notificaciones
```python
# Línea 17
endpoint_url = os.getenv('AWS_ENDPOINT_URL', 'http://100.108.127.116:4566')
```

**Cambios:**
- ✅ SNS usa servidor remoto para notificaciones
- ✅ Alertas enviadas desde infraestructura remota

---

## 🔍 Verificación de Conexión

### **Script creado:** `verify_remote_connection.py`

Ejecutar con:
```bash
.\venv_win\Scripts\python.exe verify_remote_connection.py
```

### **Resultados de verificación:**

```
✅ S3 Conectado       → 4 buckets encontrados
✅ DynamoDB Conectado → 7 tablas encontradas  
✅ SNS Conectado      → Sistema de alertas listo
✅ Redis Conectado    → v8.6.0 funcionando
```

---

## 📊 Servicios AWS Remotos Disponibles

### **S3 (4 buckets):**
1. `athenai-evidence` - Almacenamiento de evidencias
2. `athenai-alertas` - Bucket de alertas
3. `athenai-sagemaker-models` - Modelos ML
4. `test-athenai-bucket` - Bucket de pruebas

### **DynamoDB (7 tablas):**
1. `athenai_traffic_logs` - Logs de tráfico
2. `athenai_security_alerts` - Alertas de seguridad
3. `athenai_blocked_ips` - IPs bloqueadas
4. `athenai_users` - Usuarios del sistema
5. `athenai_sagemaker_endpoints` - Endpoints ML
6. `athenai_sagemaker_models` - Modelos ML
7. `athenai_sagemaker_training_jobs` - Jobs de entrenamiento

### **Redis:**
- Versión: 8.6.0
- Uso: Rate limiting, caché, sesiones
- Puerto: 6379

---

## 🚀 Aplicar Cambios

### **Paso 1: Detener servidor actual**
Si el servidor está ejecutándose:
```bash
# Presionar Ctrl+C en el terminal donde corre api_backend.py
```

### **Paso 2: Reiniciar con nueva configuración**
Opción A - Script de inicio:
```bash
cd athenai-dashboard
.\start_windows.ps1
```

Opción B - Ejecución directa:
```bash
cd athenai-dashboard
.\venv_win\Scripts\python.exe api_backend.py
```

### **Paso 3: Verificar**
```bash
# Verificar configuración
.\venv_win\Scripts\python.exe config.py

# Verificar conexión remota
.\venv_win\Scripts\python.exe verify_remote_connection.py
```

---

## 📈 Beneficios de la Configuración Remota

### **1. Centralización**
- ✅ Todos los datos en un servidor central
- ✅ Múltiples instancias pueden compartir infraestructura
- ✅ Backup centralizado

### **2. Escalabilidad**
- ✅ Fácil agregar más nodos AthenAI
- ✅ Redis compartido para rate limiting global
- ✅ DynamoDB con capacidad escalable

### **3. Disponibilidad**
- ✅ Servidor remoto siempre disponible
- ✅ No depende de localhost
- ✅ Acceso desde múltiples ubicaciones

### **4. Producción**
- ✅ Configuración más cercana a producción real
- ✅ Separación de servicios
- ✅ Mayor resiliencia

---

## 🔒 Seguridad

### **Configuración actual:**
```python
IP_BLOCKER_WHITELIST = [
    "127.0.0.1",           # Localhost
    "::1",                 # IPv6 localhost
    "100.108.127.116"      # Servidor remoto
]
```

El servidor remoto está en la whitelist para evitar bloqueos accidentales.

---

## 🛠️ Scripts de Utilidad

| Script | Descripción | Comando |
|--------|-------------|---------|
| `config.py` | Muestra configuración actual | `python config.py` |
| `verify_remote_connection.py` | Verifica conexión a servidor remoto | `python verify_remote_connection.py` |
| `check_ips.py` | Analiza tráfico de IPs | `python check_ips.py` |
| `start_windows.ps1` | Inicia servidor backend | `.\start_windows.ps1` |

---

## ⚠️ Troubleshooting

### **Problema: No conecta a LocalStack**
```bash
# Verificar conectividad
Test-NetConnection -ComputerName "100.108.127.116" -Port 4566

# Si falla, verificar:
# 1. ¿Servidor remoto encendido?
# 2. ¿Firewall permite puerto 4566?
# 3. ¿LocalStack ejecutándose en servidor?
```

### **Problema: No conecta a Redis**
```bash
# Verificar conectividad
Test-NetConnection -ComputerName "100.108.127.116" -Port 6379

# Si falla, verificar:
# 1. ¿Redis ejecutándose?
# 2. ¿Puerto 6379 abierto?
# 3. ¿Redis acepta conexiones remotas?
```

### **Problema: Timeout en requests**
```python
# Ajustar timeouts en config.py
REDIS_TIMEOUT = 5  # Aumentar si conexión lenta
```

---

## 📞 Información Técnica

### **Servidor Remoto:**
- IP: `100.108.127.116`
- Nombre: "Dinosaurio Server"
- Servicios:
  - LocalStack (puerto 4566)
  - Redis (puerto 6379)

### **Endpoints AWS:**
- S3: `http://100.108.127.116:4566`
- DynamoDB: `http://100.108.127.116:4566`
- SNS: `http://100.108.127.116:4566`
- Secrets Manager: `http://100.108.127.116:4566`

### **Región AWS:**
- `us-east-1`

### **Credenciales (LocalStack):**
- Access Key: `test`
- Secret Key: `test`

---

## ✅ Estado Final

```
🌐 INFRAESTRUCTURA: 100% Remota
☁️  AWS SERVICES:     ✅ Conectados (4 buckets S3, 7 tablas DynamoDB)
🔴 REDIS:             ✅ Conectado (v8.6.0)
🔒 SEGURIDAD:         ✅ Configurada (whitelist actualizada)
📊 VERIFICACIÓN:      ✅ Todas las pruebas exitosas
```

**AthenAI está configurado 100% en servidor remoto y listo para producción.**

---

**Documentado por:** GitHub Copilot  
**Fecha:** Febrero 18, 2026
