# AthenAI - Sistema Híbrido de Detección de Intrusos

![Dashboard Preview](athenai_dashboard_preview.png)

AthenAI es una solución avanzada de ciberseguridad que combina **Modelos de Machine Learning** (XGBoost + Isolation Forest) con una arquitectura moderna de **Detección en Tiempo Real** para identificar amenazas como SQL Injection, XSS y anomalías de comportamiento.

## 🚀 Características Principales

- **Detección Híbrida**: Combina detección de firmas con análisis de comportamiento anómalo.
- **Dashboard en Tiempo Real**: Interfaz visual basada en React y Recharts para monitoreo instantáneo.
- **Arquitectura Serverless**: Diseñado para escalar usando AWS Lambda y Kinesis (simulado localmente).
- **Modo Offline**: Funciona completamente en entornos aislados sin dependencias de CDN externos.

## 🛠️ Tecnologías

- **Backend**: Python, Flask, Boto3, PyTorch, Scikit-learn.
- **Frontend**: HTML5, React 18, Tailwind CSS, Recharts (Assets locales).
- **Infraestructura**: LocalStack (simulación AWS), Docker.

## 📦 Instalación y Uso

1. **Clonar el repositorio**:
   ```bash
   git clone https://github.com/tu-usuario/athenai.git
   cd athenai
   ```

2. **Iniciar el Sistema Completo**:
   Ejecuta el script maestro que levanta Backend y Dashboard:
   ```bash
   cd athenai-dashboard
   ./restart_clean.sh
   ```

3. **Acceder al Dashboard**:
   Abre tu navegador (preferiblemente incógnito para evitar caché) en:
   [http://localhost:8000/index.html](http://localhost:8000/index.html)

## 📂 Estructura del Proyecto

- `athenai-dashboard/`: Código fuente del frontend y backend API.
  - `assets/js/`: Librerías JS core (React, Recharts) para modo offline.
  - `api_backend.py`: Servidor Flask.
  - `index.html`: Punto de entrada del Dashboard.
- `training/`: Scripts de entrenamiento de modelos ML.
- `lambda_function.py`: Lógica de detección para AWS Lambda.

## 🧪 Pruebas

Para verificar la integridad del sistema:
```bash
cd athenai-dashboard
python3 test_dashboard_integration.py
```

## 📄 Licencia
Este proyecto es parte de una Tesis de Maestría/Doctorado 2026.
