# 🏗️ Arquitectura y Flujo de AthenAI

## 📊 ¿Qué es AthenAI?

AthenAI es un **Sistema de Detección de Intrusos (IDS) Híbrido** con capacidades de Machine Learning que protege aplicaciones web mediante:

- 🛡️ **Detección de amenazas en tiempo real**
- 🤖 **Machine Learning** (XGBoost + Isolation Forest)
- 🚫 **Bloqueo automático de IPs maliciosas**
- 📊 **Dashboard visual** para monitoreo
- ⚡ **Rate Limiting** inteligente
- 📝 **Logging y evidencias** forenses

---

## 🔄 Flujo de Funcionamiento Actual

### 1️⃣ **Usuario accede al sistema**
```
http://localhost:5000/login.html
Usuario: admin | Password: admin123
```

### 2️⃣ **Cada petición HTTP pasa por 3 filtros de seguridad**

```
REQUEST → Security Middleware → Endpoint
           ↓
    1. IP Blocker (¿IP bloqueada?)
    2. Rate Limiter (¿Demasiados requests?)
    3. ML Detection (actualmente OFF)
```

### 3️⃣ **Si pasa los filtros:**
- ✅ Request llega al endpoint Flask
- 📊 Se registra en DynamoDB + SQLite
- 📈 Se actualiza Redis (caché)
- 🔄 Response se envía al frontend

### 4️⃣ **Si detecta amenaza:**
- 🚨 Alert System envía notificación (SNS)
- 🔒 Response Actions bloquea la IP automáticamente
- 📦 Evidence Store guarda evidencia en S3
- ❌ Request se rechaza (403/429)

---

## 🗂️ Componentes del Sistema

### **FRONTEND** (React SPA - Single Page Application)
| Archivo | Función |
|---------|---------|
| `login.html` | Página de autenticación |
| `index.html` | Dashboard principal (React 18) |
| `auth.js` | Servicio de autenticación JWT |

### **BACKEND** (Flask REST API)
| Componente | Archivo | Función |
|-----------|---------|---------|
| API Server | `api_backend.py` | 20+ endpoints REST |
| Security Layer | `security_middleware.py` | Filtros de seguridad |
| Traffic Logger | `middleware.py` | Registro de tráfico |
| AI Engine | `ai_engine.py` | XGBoost + Isolation Forest |
| Mock SageMaker | `mock_sagemaker.py` | Simulador de AWS SageMaker |
| IP Blocker | `ip_blocker.py` | Bloqueo de IPs |
| Rate Limiter | `rate_limiter.py` | Control de tasa |
| Alert System | `alert_system.py` | Notificaciones SNS |

### **BASES DE DATOS**
| Tipo | Tecnología | Propósito |
|------|-----------|-----------|
| SQLite | `traffic_logs.db` | Logs locales (backup) |
| DynamoDB | LocalStack (7 tablas) | Logs, alertas, IPs bloqueadas |
| S3 | LocalStack (4 buckets) | Evidencias, modelos ML |
| Redis | 100.108.127.116:6379 | Rate limits, caché |

### **INFRAESTRUCTURA**
| Servicio | Ubicación | Puerto |
|----------|-----------|--------|
| Flask API | localhost | 5000 |
| LocalStack | 100.108.127.116 | 4566 |
| Redis | 100.108.127.116 | 6379 |

---

## 🌐 ¿Cómo Integrar en una Página Web?

### **OPCIÓN 1: Standalone (Actual)** ⭐ Más Simple
**Situación:** AthenAI es tu aplicación web completa

✅ **Ventajas:**
- Ya está funcionando
- Cero configuración adicional
- Dashboard incluido

❌ **Desventajas:**
- No protege otras aplicaciones

📍 **Acceso:**
```
http://localhost:5000/login.html
http://localhost:5000/index.html
```

---

### **OPCIÓN 2: Integración en Sitio Existente** 🔗 Recomendado para Dashboards

**Situación:** Tienes tu sitio web (ej: `www.tusitio.com`) y quieres el dashboard de AthenAI

#### 2.1 **Como iframe** (Más fácil)
```html
<!-- En tu página de admin: www.tusitio.com/admin/security -->
<iframe 
  src="http://localhost:5000/index.html" 
  width="100%" 
  height="800px"
  frameborder="0">
</iframe>
```

#### 2.2 **Llamadas API directas** (Más flexible)
```javascript
// Desde tu frontend (React/Vue/Angular)
fetch('http://localhost:5000/api/stats', {
  headers: {
    'Authorization': 'Bearer ' + jwt_token
  }
})
.then(res => res.json())
.then(data => {
  // Mostrar estadísticas en tu propio diseño
  console.log(data);
});
```

#### 2.3 **Configuración CORS** (Ya está habilitada)
```python
# api_backend.py (línea ~85)
CORS(app)  # Ya configurado ✅
```

---

### **OPCIÓN 3: Middleware para Proteger tu Web** 🛡️ Máxima Seguridad

**Situación:** Tienes tu backend (Node.js/Django/PHP) y quieres que AthenAI lo proteja

#### Arquitectura:
```
Internet → AthenAI (Puerto 5000) → Tu Backend (Puerto 8080)
           ↓ verificación
      Si amenaza → BLOQUEA
      Si OK → Pasa request
```

#### Implementación:

**Opción 3A: Proxy en Python**
```python
# proxy_athenai.py
from flask import request
import requests

@app.route('/<path:path>', methods=['GET', 'POST'])
def proxy(path):
    # AthenAI verifica seguridad automáticamente (middleware)
    
    # Si pasa filtros, reenviar a tu backend real
    response = requests.request(
        method=request.method,
        url=f'http://localhost:8080/{path}',
        headers=request.headers,
        data=request.get_data()
    )
    return response.content
```

**Opción 3B: Usar API de verificación**
```javascript
// En tu backend Node.js/Express
app.use(async (req, res, next) => {
  // Preguntar a AthenAI si el request es seguro
  const check = await fetch('http://localhost:5000/api/security/check', {
    method: 'POST',
    body: JSON.stringify({
      ip: req.ip,
      endpoint: req.path,
      method: req.method
    })
  });
  
  if (check.ok) {
    next(); // Continuar
  } else {
    res.status(403).json({error: 'Blocked by AthenAI'});
  }
});
```

---

### **OPCIÓN 4: Reverse Proxy con Nginx** 🚀 Para Producción

**Situación:** Despliegue profesional con balanceo de carga

#### Configuración Nginx:
```nginx
# /etc/nginx/nginx.conf
upstream athenai_security {
    server localhost:5000;
}

upstream your_backend {
    server localhost:8080;
}

server {
    listen 80;
    server_name www.tusitio.com;
    
    # Todas las requests pasan por AthenAI primero
    location / {
        # AthenAI verifica y loguea
        proxy_pass http://athenai_security;
        
        # Si AthenAI aprueba, Nginx pasa a tu backend
        # (requiere modificar api_backend.py para reenviar)
    }
    
    # Dashboard de AthenAI
    location /security-dashboard/ {
        proxy_pass http://athenai_security/index.html;
    }
}
```

---

## 📋 Endpoints de API Disponibles

| Método | Endpoint | Descripción | Auth |
|--------|----------|-------------|------|
| POST | `/api/auth/login` | Login con JWT | No |
| POST | `/api/auth/logout` | Logout | Sí |
| GET | `/api/stats` | Estadísticas generales | Sí |
| GET | `/api/traffic` | Datos de tráfico | Sí |
| GET | `/api/alerts` | Alertas recientes | Sí |
| GET | `/api/health` | Estado del sistema | No |
| GET | `/api/blocked-ips` | IPs bloqueadas | Sí |
| POST | `/api/block-ip` | Bloquear IP manual | Sí |
| DELETE | `/api/unblock-ip` | Desbloquear IP | Sí |

---

## 🔐 Autenticación JWT

### Flujo de autenticación:

```javascript
// 1. Login
fetch('http://localhost:5000/api/auth/login', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({
    username: 'admin',
    password: 'admin123'
  })
})
.then(res => res.json())
.then(data => {
  // 2. Guardar token
  localStorage.setItem('token', data.token);
});

// 3. Usar token en requests protegidos
fetch('http://localhost:5000/api/stats', {
  headers: {
    'Authorization': 'Bearer ' + localStorage.getItem('token')
  }
})
.then(res => res.json())
.then(stats => console.log(stats));
```

---

## 🎯 Casos de Uso Reales

### **Caso 1: Dashboard de Seguridad para Empresa**
```
Tu tienes: Portal corporativo en React/Angular
Necesitas: Ver estadísticas de seguridad

Solución: OPCIÓN 2
- Integra el dashboard en tu portal de admin
- Haz fetch a /api/stats cada 5 segundos
- Muestra gráficos en tu diseño corporativo
```

### **Caso 2: Proteger API REST existente**
```
Tienes: API Node.js/FastAPI en puerto 8080
Necesitas: Proteger contra DDoS, SQL injection, etc.

Solución: OPCIÓN 3
- Configura tu API para recibir requests de AthenAI
- Todos los clientes llaman a AthenAI (puerto 5000)
- AthenAI filtra amenazas y reenvía a tu API (8080)
```

### **Caso 3: E-commerce con alta seguridad**
```
Tienes: Tienda online con Shopify/WooCommerce
Necesitas: Protección ML contra fraude

Solución: OPCIÓN 4
- Nginx recibe requests públicos
- AthenAI analiza cada request con ML
- Si es seguro → pasa a Shopify
- Si es amenaza → bloquea y guarda evidencia
```

---

## 🚀 Próximos Pasos para Producción

### 1. **Habilitar HTTPS**
```bash
# Generar certificado SSL
certbot --nginx -d www.tusitio.com
```

### 2. **Migrar a AWS Real**
```python
# Cambiar en config.py
LOCALSTACK_ENDPOINT = None  # Usar AWS real
AWS_REGION = 'us-east-1'
```

### 3. **Escalar con Docker**
```bash
# Crear múltiples instancias
docker-compose up --scale athenai=3
```

### 4. **Habilitar ML Asíncrono**
```bash
# Instalar Celery para procesamiento en background
pip install celery redis
```

### 5. **Monitoreo CloudWatch**
```python
# Ya incluido en cloudwatch_logger.py
# Solo necesitas credenciales AWS reales
```

---

## ❓ Preguntas Frecuentes

### **¿AthenAI reemplaza mi firewall?**
No, es complementario. AthenAI trabaja a nivel de **aplicación** (capa 7), mientras firewalls trabajan en capa 3-4.

### **¿Puedo usar AthenAI sin el dashboard?**
Sí, el dashboard es opcional. Puedes usar solo la API REST.

### **¿Funciona con cualquier framework web?**
Sí, porque trabaja con **HTTP estándar**. Compatible con Node.js, Django, PHP, .NET, etc.

### **¿Necesito LocalStack en producción?**
No, LocalStack es solo para desarrollo. En producción usa **AWS real** (DynamoDB, S3, SNS).

### **¿Cuánto tráfico soporta?**
Con la configuración actual:
- **SIN ML**: ~500-1000 requests/segundo
- **CON ML**: ~50-100 requests/segundo (necesita async)

---

## 📞 Soporte

Para más información:
- **Documentación completa**: `REVISION_EJECUTIVA.md`
- **Correcciones aplicadas**: `CORRECCIONES_APLICADAS.md`
- **Script de inicio**: `start_windows.ps1`

---

**Creado por**: GitHub Copilot  
**Fecha**: Febrero 2026  
**Versión**: 1.0  
