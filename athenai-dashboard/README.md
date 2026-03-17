# AthenAI Dashboard - Conectado con Backend

## 🎯 Dashboard Completo con Backend API

Dashboard profesional conectado a un backend Flask que sirve datos reales desde S3 y modelos ML.

## 🏗️ Arquitectura

```
┌─────────────────────────────────────────────────────────┐
│                   ATHENAI DASHBOARD                      │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  React Frontend  ←──HTTP──→  Flask API  ←──→  S3/ML    │
│  (index.html)              (api_backend.py)             │
│                                                          │
│  • Auto-refresh (10s)      • REST Endpoints             │
│  • Loading states          • CORS enabled               │
│  • Error handling          • LocalStack/AWS             │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

## 🚀 Inicio Rápido

### Opción 1: Script Automático (Recomendado)

```bash
cd athenai-dashboard
./start.sh
```

Esto:
1. Instala dependencias (Flask, Flask-CORS, boto3)
2. Inicia el backend API en puerto 5000
3. Muestra instrucciones para abrir el dashboard

### Opción 2: Manual

```bash
# Terminal 1 - Backend
cd athenai-dashboard
pip install -r requirements.txt --break-system-packages
python3 api_backend.py

# Terminal 2 - Frontend
firefox index.html
# o
google-chrome index.html
```

## 📡 API Endpoints

El backend expone los siguientes endpoints:

| Endpoint | Método | Descripción | Refresh |
|----------|--------|-------------|---------|
| `/api/stats` | GET | Estadísticas generales (KPIs) | 10s |
| `/api/traffic` | GET | Datos de tráfico (24h) | 10s |
| `/api/attacks` | GET | Tipos de ataques | 10s |
| `/api/alerts` | GET | Alertas recientes | 10s |
| `/api/health` | GET | Estado del sistema | 30s |
| `/api/model-info` | GET | Info de modelos ML | - |

### Ejemplo de Respuesta

```json
// GET /api/stats
{
  "threats_today": 524,
  "threats_change": 12.5,
  "model_precision": 99.96,
  "avg_latency": 195,
  "system_status": 100,
  "timestamp": "2026-01-22T14:30:00"
}
```

## 🔄 Auto-Refresh

El dashboard se actualiza automáticamente:
- **KPIs, Gráficos, Alertas**: Cada 10 segundos
- **Estado del Sistema**: Cada 30 segundos
- **Botón Manual**: Click en el icono de refresh en alertas

## 📊 Fuentes de Datos

### Datos Reales (desde S3)
- ✅ Alertas recientes (últimas 10)
- ✅ Tipos de ataques (conteo por tipo)
- ✅ Estadísticas de amenazas

### Datos Generados
- 🔄 Tráfico por hora (patrón realista)
- 🔄 Latencia (variación aleatoria 180-220ms)
- 🔄 Cambio porcentual vs ayer

## 🎨 Características del Frontend

### Animaciones
- ✅ Staggered entry (cascada suave)
- ✅ Hover effects (elevación + sombra)
- ✅ Layout transitions (fade + slide)
- ✅ Loading skeletons

### Estados
- **Loading**: Skeleton placeholders animados
- **Error**: Fallback a datos de ejemplo
- **Success**: Datos reales del backend

### Interactividad
- Click en pestañas (Dashboard, Alertas, Analíticas)
- Hover en tarjetas KPI
- Refresh manual de alertas
- Tooltips en gráficos

## ⚙️ Configuración

### Variables de Entorno

```bash
# Backend (api_backend.py)
export USE_LOCALSTACK=true  # true para LocalStack, false para AWS
export S3_BUCKET=athenai-alertas
```

### API Base URL

```javascript
// Frontend (index.html)
const API_BASE_URL = 'http://localhost:5000/api';
```

## 🔧 Desarrollo

### Modificar Endpoints

Edita `api_backend.py`:

```python
@app.route('/api/custom-endpoint', methods=['GET'])
def custom_endpoint():
    return jsonify({'data': 'value'})
```

### Agregar Nuevos Datos al Frontend

Edita `index.html`:

```javascript
const { data, loading } = useAPI('/custom-endpoint', REFRESH_INTERVAL);
```

## 🐛 Troubleshooting

### Backend no inicia

```bash
# Verificar puerto 5000 disponible
lsof -i :5000

# Matar proceso si está ocupado
kill -9 $(lsof -t -i:5000)
```

### CORS Error

Asegúrate de que Flask-CORS esté instalado:
```bash
pip install flask-cors --break-system-packages
```

### No se muestran alertas reales

Verifica que LocalStack esté corriendo y tenga alertas:
```bash
docker ps | grep localstack
awslocal s3 ls s3://athenai-alertas/alerts/ --recursive
```

## 📦 Dependencias

### Backend
- Flask 3.0.0
- Flask-CORS 4.0.0
- boto3 1.42.30

### Frontend (CDN)
- React 18
- Tailwind CSS 3
- Framer Motion 10
- Recharts 2.5
- Google Fonts (Inter)

## 🎓 Uso en Tesis

### Para Presentación
1. Inicia el dashboard con `./start.sh`
2. Abre en pantalla completa
3. Navega entre pestañas para mostrar funcionalidad
4. Los datos se actualizan automáticamente

### Para Screenshots
1. Espera a que los datos carguen
2. Captura pantalla completa
3. Incluye en documentación

### Para Video Demo
1. Graba navegación entre pestañas
2. Muestra actualización automática de datos
3. Demuestra hover effects

## 🚀 Deployment en Producción

### Backend

```bash
# Usar gunicorn para producción
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 api_backend:app
```

### Frontend

```bash
# Servir con nginx o Apache
# O usar un CDN para archivos estáticos
```

### AWS Real

```python
# En api_backend.py, cambiar:
USE_LOCALSTACK = False
# Y configurar credenciales AWS
```

## 📝 Notas

- El dashboard funciona con datos mock si el backend no está disponible
- Las alertas reales de S3 se mezclan con datos generados si hay pocas
- El sistema es completamente funcional para demostración

## 🎯 Próximos Pasos

- [ ] Agregar autenticación (JWT)
- [ ] Implementar WebSocket para updates en tiempo real
- [ ] Agregar más gráficos (pie chart, heatmap)
- [ ] Dashboard de configuración de modelos
- [ ] Exportar reportes PDF

---

**Desarrollado para AthenAI - Tesis de Maestría 2026**

*Dashboard profesional conectado con backend real*
