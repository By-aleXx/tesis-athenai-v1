# Variantes de la función Lambda

Este directorio agrupa las distintas versiones de la función Lambda de detección de amenazas, sus paquetes de despliegue y los artefactos generados (`dist/`).

## Producción / viva

- **`lambda_function_hybrid.py`** — Sistema híbrido XGBoost + Isolation Forest. Es la que realmente se despliega vía `deploy/deploy_localstack.sh` (el pipeline de deploy más completo y actual).

## Obsoletas / experimentales

- **`lambda_function.py`** / **`lambda_function_simple.py`** — Byte-idénticas entre sí. Handler mock sin ML, usado por los scripts de deploy más antiguos (`deploy/deploy.sh`, `deploy/deploy_simple.sh`). Superadas por `_hybrid`.
- **`lambda_function_ml.py`** — Isolation Forest + detección de SQLi basada en patrones (experimento intermedio). Solo referenciada por `tests/legacy_scripts/test_lambda_ml.py`, ningún script de deploy la usa.
- **`lambda_function_full.py`** — DistilBERT + Isolation Forest (basada en torch). No referenciada por ningún script de deploy; parece un prototipo de tesis con la huella de dependencias más pesada.
- **`model_inference.py`** — Helper huérfano (clase `SQLInjectionDetector`), no importado por ninguna de las variantes anteriores.

## Paquetes / artefactos

- `lambda_package/`, `lambda_package_dl/`, `lambda_package_hybrid/`, `lambda_package_lite/` — directorios de build con las dependencias vendorizadas de cada variante (gitignored).
- `dist/` — zips de despliegue generados (`function.zip`, `lambda_deployment_dl.zip`, `lambda_deployment_hybrid.zip`, `lambda_deployment_lite.zip`), gitignored.

## Qué handler usa cada script de deploy

| Script | Handler usado |
|---|---|
| `deploy/deploy.sh`, `deploy/deploy_simple.sh` | `lambda_function.py` |
| `deploy/deploy_localstack.sh` | `lambda_function_hybrid.py` (**productivo**) |
| `deploy/deploy_deep_learning.sh` | `lambda_function.py` (nombre del script engañoso — pese a llamarse "deep learning" no despliega `_full` ni `_ml`, empaqueta la variante mock) |
