# 📚 Ejemplos de Integración - AthenAI

Esta carpeta contiene ejemplos prácticos de cómo integrar AthenAI en diferentes tecnologías y arquitecturas web.

## 📁 Contenido

### 1. **ejemplo_iframe.html** - Integración en Sitio Web Existente
**Escenario:** Tienes un sitio web y quieres mostrar el dashboard de AthenAI

**Tecnologías:** HTML + JavaScript (vanilla)

**Características:**
- ✅ Incrusta el dashboard de AthenAI en un iframe
- ✅ Obtiene estadísticas desde la API
- ✅ Actualiza datos en tiempo real (cada 10s)
- ✅ Diseño responsive con Flexbox/Grid

**Cómo usar:**
```bash
# 1. Asegúrate de que AthenAI esté ejecutándose
cd athenai-dashboard
.\venv_win\Scripts\python.exe api_backend.py

# 2. Abre el archivo en tu navegador
start ejemplos_integracion\ejemplo_iframe.html

# 3. Login primero en AthenAI para obtener token
# Abre: http://localhost:5000/login.html
# Usuario: admin | Password: admin123
```

**Ideal para:**
- Portales corporativos
- Paneles de administración
- Dashboards empresariales

---

### 2. **ejemplo_middleware_nodejs.js** - Middleware para Node.js/Express
**Escenario:** Tienes un backend Node.js y quieres protegerlo con AthenAI

**Tecnologías:** Node.js + Express + Axios

**Características:**
- ✅ Verifica IP bloqueada antes de procesar requests
- ✅ Aplica rate limiting automático
- ✅ Logging de tráfico a AthenAI
- ✅ Verificación ML completa (opcional)
- ✅ Fail-open/fail-closed configurable

**Cómo usar:**
```bash
# 1. Instalar dependencias
npm install express axios

# 2. Obtener token JWT
# POST http://localhost:5000/api/auth/login
# Body: {"username": "admin", "password": "admin123"}

# 3. Copiar token en la constante ATHENAI_TOKEN

# 4. Ejecutar servidor
node ejemplo_middleware_nodejs.js

# 5. Probar
curl http://localhost:8080/api/users
curl http://localhost:8080/health
```

**Ideal para:**
- APIs REST
- Backends de aplicaciones móviles
- Microservicios

---

### 3. **ejemplo_middleware_python.py** - Middleware para Flask/Django
**Escenario:** Tienes un backend Python y quieres protegerlo con AthenAI

**Tecnologías:** Flask/Django + Requests

**Características:**
- ✅ Clase `AthenAIClient` reutilizable
- ✅ Decoradores `@require_athenai_check()`
- ✅ Middleware para Flask y Django
- ✅ Logging asíncrono (threading)
- ✅ Stats endpoint integrado

**Cómo usar:**
```bash
# 1. Instalar dependencias
pip install flask requests

# 2. Obtener token JWT (igual que Node.js)

# 3. Ejecutar servidor
python ejemplo_middleware_python.py

# 4. Probar
curl http://localhost:8080/api/public/status
curl http://localhost:8080/api/athenai/stats
```

**Ideal para:**
- Aplicaciones Django
- APIs Flask
- Backends Python en general

---

## 🎯 Comparación de Enfoques

| Enfoque | Complejidad | Control | Performance | Uso Ideal |
|---------|------------|---------|-------------|-----------|
| **iframe** | 🟢 Baja | 🟡 Medio | 🟢 Alta | Mostrar dashboard |
| **API Calls** | 🟡 Media | 🟢 Alto | 🟢 Alta | Integración custom |
| **Middleware** | 🟡 Media | 🟢 Alto | 🟡 Media | Proteger backends |
| **Reverse Proxy** | 🔴 Alta | 🟢 Alto | 🟢 Alta | Producción |

---

## 🔌 Endpoints de AthenAI Disponibles

### Autenticación
```http
POST /api/auth/login
Content-Type: application/json

{
  "username": "admin",
  "password": "admin123"
}

Response:
{
  "token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "user": {...}
}
```

### Estadísticas
```http
GET /api/stats
Authorization: Bearer <token>

Response:
{
  "total_requests": 1523,
  "threats_blocked": 42,
  "blocked_ips": 7,
  "uptime": "2h 15m"
}
```

### IPs Bloqueadas
```http
GET /api/blocked-ips
Authorization: Bearer <token>

Response:
{
  "blocked_ips": ["192.168.1.100", "10.0.0.5"]
}
```

### Tráfico
```http
GET /api/traffic
Authorization: Bearer <token>

Response:
{
  "traffic": [
    {
      "timestamp": "2026-02-18T10:30:00",
      "ip": "192.168.1.50",
      "method": "GET",
      "path": "/api/users",
      "status": 200
    },
    ...
  ]
}
```

### Alertas
```http
GET /api/alerts
Authorization: Bearer <token>

Response:
{
  "alerts": [
    {
      "id": "alert-123",
      "type": "SQL_INJECTION",
      "severity": "HIGH",
      "ip": "192.168.1.100",
      "timestamp": "2026-02-18T10:25:00"
    },
    ...
  ]
}
```

---

## 🛠️ Personalización

### Ajustar Timeouts
```javascript
// Node.js
const response = await axios.get(url, {
  timeout: 2000  // 2 segundos
});

# Python
response = requests.get(url, timeout=2)
```

### Fail-Open vs Fail-Closed
```javascript
// Fail-Open (permite si AthenAI falla)
catch (error) {
  console.error('AthenAI error:', error);
  next(); // ← Permite continuar
}

// Fail-Closed (bloquea si AthenAI falla)
catch (error) {
  console.error('AthenAI error:', error);
  res.status(503).json({error: 'Security unavailable'});
}
```

### Logging Selectivo
```python
# Solo loguear endpoints críticos
if request.path.startswith('/api/admin/'):
    athenai.log_request(log_data)
```

---

## 🚀 Despliegue en Producción

### 1. Variables de Entorno
```bash
# .env
ATHENAI_API_URL=https://athenai.miempresa.com
ATHENAI_TOKEN=<token_produccion>
```

### 2. HTTPS
```nginx
# nginx.conf
server {
    listen 443 ssl;
    server_name miapp.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    location /api/ {
        proxy_pass http://localhost:8080;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### 3. Docker
```dockerfile
# Dockerfile
FROM node:18
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
ENV ATHENAI_API_URL=http://athenai:5000
CMD ["node", "app.js"]
```

```yaml
# docker-compose.yml
version: '3.8'
services:
  athenai:
    image: athenai:latest
    ports:
      - "5000:5000"
  
  mi-app:
    build: .
    ports:
      - "8080:8080"
    depends_on:
      - athenai
    environment:
      - ATHENAI_API_URL=http://athenai:5000
```

---

## 📖 Recursos Adicionales

- **Documentación completa**: `../ARQUITECTURA_Y_FLUJO.md`
- **Revisión ejecutiva**: `../REVISION_EJECUTIVA.md`
- **Correcciones aplicadas**: `../athenai-dashboard/CORRECCIONES_APLICADAS.md`

---

## 💡 Tips y Mejores Prácticas

### 1. **Caché de IPs Bloqueadas**
```javascript
// En lugar de consultar cada vez, cachea la lista
let cachedBlockedIPs = [];
let cacheExpiry = 0;

async function getBlockedIPs() {
  if (Date.now() > cacheExpiry) {
    const response = await fetch(`${ATHENAI_API}/api/blocked-ips`);
    cachedBlockedIPs = await response.json();
    cacheExpiry = Date.now() + 60000; // 1 minuto
  }
  return cachedBlockedIPs;
}
```

### 2. **Verificación Asíncrona**
```javascript
// No bloquees el request, verifica en background
app.use(async (req, res, next) => {
  next(); // Continuar inmediatamente
  
  // Verificar en background
  verifyWithAthenAI(req).then(result => {
    if (!result.safe) {
      // Bloquear IP para futuros requests
      blockIP(req.ip);
    }
  });
});
```

### 3. **Circuit Breaker**
```javascript
// Si AthenAI falla 5 veces, dejar de llamar por 1 minuto
let failures = 0;
let circuitOpen = false;

async function callAthenAI() {
  if (circuitOpen) {
    return { safe: true }; // Fail-open
  }
  
  try {
    const result = await fetch(ATHENAI_API);
    failures = 0;
    return result;
  } catch (error) {
    failures++;
    if (failures >= 5) {
      circuitOpen = true;
      setTimeout(() => {
        circuitOpen = false;
        failures = 0;
      }, 60000);
    }
    return { safe: true };
  }
}
```

---

## 🆘 Troubleshooting

### Problema: "CORS error"
**Solución:** AthenAI ya tiene CORS habilitado, pero verifica:
```python
# api_backend.py
CORS(app)  # Debe estar presente
```

### Problema: "Connection refused"
**Solución:** Verifica que AthenAI esté ejecutándose:
```bash
netstat -ano | findstr :5000
```

### Problema: "401 Unauthorized"
**Solución:** El token JWT expiró, obtén uno nuevo:
```bash
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'
```

### Problema: "Rate limit en login"
**Solución:** Espera 60 segundos o limpia Redis:
```bash
.\venv_win\Scripts\python.exe -c "import redis; r = redis.Redis(host='100.108.127.116', port=6379, db=1); r.flushdb(); print('OK')"
```

---

## 📞 Soporte

Para más ayuda, revisa:
1. Logs de AthenAI: `athenai-dashboard/logs/`
2. Documentación: `ARQUITECTURA_Y_FLUJO.md`
3. Código fuente: `athenai-dashboard/`

---

**Creado por**: GitHub Copilot  
**Fecha**: Febrero 2026  
**Versión**: 1.0
