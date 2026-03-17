"""
AthenAI - Mock SageMaker

Simulación completa de AWS SageMaker usando S3 + DynamoDB.
Replica las funcionalidades principales sin necesitar LocalStack Pro.

Características:
- Model Registry (versionado de modelos)
- Training Jobs (simulación de entrenamiento)
- Endpoints (inferencia)
- Model Monitoring

Autor: AthenAI Team
Fecha: 2026-02-11
"""

import os
import boto3
import json
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
from decimal import Decimal
import hashlib
import joblib
import io
from enum import Enum
from dotenv import load_dotenv

load_dotenv()

# Importar configuración
try:
    from config import get_aws_config
    USE_CONFIG = True
except ImportError:
    USE_CONFIG = False

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def convert_floats_to_decimal(obj):
    """Convierte floats a Decimal para DynamoDB"""
    if isinstance(obj, float):
        return Decimal(str(obj))
    elif isinstance(obj, dict):
        return {k: convert_floats_to_decimal(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_floats_to_decimal(item) for item in obj]
    return obj


class ModelStatus(Enum):
    """Estados de un modelo"""
    CREATING = "Creating"
    IN_SERVICE = "InService"
    FAILED = "Failed"
    DELETING = "Deleting"


class TrainingJobStatus(Enum):
    """Estados de un training job"""
    IN_PROGRESS = "InProgress"
    COMPLETED = "Completed"
    FAILED = "Failed"
    STOPPED = "Stopped"


class EndpointStatus(Enum):
    """Estados de un endpoint"""
    CREATING = "Creating"
    IN_SERVICE = "InService"
    UPDATING = "Updating"
    FAILED = "Failed"
    DELETING = "Deleting"


class MockSageMaker:
    """
    Simulación de AWS SageMaker.
    
    Usa S3 para almacenar modelos y DynamoDB para metadata.
    """
    
    def __init__(self):
        """Inicializa Mock SageMaker"""
        
        # Configuración AWS
        if USE_CONFIG:
            aws_config = get_aws_config()
            self.s3_client = boto3.client('s3', **aws_config)
            self.dynamodb = boto3.resource('dynamodb', **aws_config)
        else:
            # Fallback: leer desde variables de entorno
            self.s3_client = boto3.client(
                's3',
                endpoint_url=os.environ['AWS_ENDPOINT_URL'],
                aws_access_key_id=os.environ['AWS_ACCESS_KEY_ID'],
                aws_secret_access_key=os.environ['AWS_SECRET_ACCESS_KEY'],
                region_name=os.getenv('AWS_REGION', 'us-east-1')
            )
            self.dynamodb = boto3.resource(
                'dynamodb',
                endpoint_url=os.environ['AWS_ENDPOINT_URL'],
                aws_access_key_id=os.environ['AWS_ACCESS_KEY_ID'],
                aws_secret_access_key=os.environ['AWS_SECRET_ACCESS_KEY'],
                region_name=os.getenv('AWS_REGION', 'us-east-1')
            )
        
        # Buckets y tablas
        self.models_bucket = 'athenai-sagemaker-models'
        self.models_table_name = 'athenai_sagemaker_models'
        self.training_jobs_table_name = 'athenai_sagemaker_training_jobs'
        self.endpoints_table_name = 'athenai_sagemaker_endpoints'
        
        # Inicializar infraestructura
        self._init_infrastructure()
        
        logger.info("✅ Mock SageMaker inicializado")
    
    def _init_infrastructure(self):
        """Crea buckets S3 y tablas DynamoDB necesarias"""
        
        # Crear bucket S3 para modelos
        try:
            self.s3_client.head_bucket(Bucket=self.models_bucket)
            logger.info(f"✅ Bucket '{self.models_bucket}' existe")
        except:
            try:
                self.s3_client.create_bucket(Bucket=self.models_bucket)
                logger.info(f"✅ Bucket '{self.models_bucket}' creado")
            except Exception as e:
                logger.error(f"❌ Error creando bucket: {e}")
        
        # Crear tabla de modelos
        try:
            self.dynamodb.create_table(
                TableName=self.models_table_name,
                KeySchema=[
                    {'AttributeName': 'ModelName', 'KeyType': 'HASH'},
                    {'AttributeName': 'Version', 'KeyType': 'RANGE'}
                ],
                AttributeDefinitions=[
                    {'AttributeName': 'ModelName', 'AttributeType': 'S'},
                    {'AttributeName': 'Version', 'AttributeType': 'N'}
                ],
                ProvisionedThroughput={
                    'ReadCapacityUnits': 5,
                    'WriteCapacityUnits': 5
                }
            )
            logger.info(f"✅ Tabla '{self.models_table_name}' creada")
        except self.dynamodb.meta.client.exceptions.ResourceInUseException:
            logger.info(f"ℹ️  Tabla '{self.models_table_name}' ya existe")
        except Exception as e:
            logger.error(f"❌ Error creando tabla de modelos: {e}")
        
        # Crear tabla de training jobs
        try:
            self.dynamodb.create_table(
                TableName=self.training_jobs_table_name,
                KeySchema=[
                    {'AttributeName': 'TrainingJobName', 'KeyType': 'HASH'}
                ],
                AttributeDefinitions=[
                    {'AttributeName': 'TrainingJobName', 'AttributeType': 'S'}
                ],
                ProvisionedThroughput={
                    'ReadCapacityUnits': 5,
                    'WriteCapacityUnits': 5
                }
            )
            logger.info(f"✅ Tabla '{self.training_jobs_table_name}' creada")
        except self.dynamodb.meta.client.exceptions.ResourceInUseException:
            logger.info(f"ℹ️  Tabla '{self.training_jobs_table_name}' ya existe")
        
        # Crear tabla de endpoints
        try:
            self.dynamodb.create_table(
                TableName=self.endpoints_table_name,
                KeySchema=[
                    {'AttributeName': 'EndpointName', 'KeyType': 'HASH'}
                ],
                AttributeDefinitions=[
                    {'AttributeName': 'EndpointName', 'AttributeType': 'S'}
                ],
                ProvisionedThroughput={
                    'ReadCapacityUnits': 5,
                    'WriteCapacityUnits': 5
                }
            )
            logger.info(f"✅ Tabla '{self.endpoints_table_name}' creada")
        except self.dynamodb.meta.client.exceptions.ResourceInUseException:
            logger.info(f"ℹ️  Tabla '{self.endpoints_table_name}' ya existe")
    
    # ==================== MODEL REGISTRY ====================
    
    def create_model(self, model_name: str, model_data: Any, 
                    description: str = "", tags: Dict = None) -> Dict:
        """
        Crea un nuevo modelo en el registry.
        
        Args:
            model_name: Nombre del modelo
            model_data: Objeto del modelo (scikit-learn, TensorFlow, etc.)
            description: Descripción del modelo
            tags: Tags adicionales
        
        Returns:
            Información del modelo creado
        """
        try:
            table = self.dynamodb.Table(self.models_table_name)
            
            # Obtener última versión
            response = table.query(
                KeyConditionExpression='ModelName = :name',
                ExpressionAttributeValues={':name': model_name},
                ScanIndexForward=False,
                Limit=1
            )
            
            if response['Items']:
                last_version = int(response['Items'][0]['Version'])
                new_version = last_version + 1
            else:
                new_version = 1
            
            # Serializar modelo
            model_buffer = io.BytesIO()
            joblib.dump(model_data, model_buffer)
            model_bytes = model_buffer.getvalue()
            model_hash = hashlib.sha256(model_bytes).hexdigest()
            
            # Guardar en S3
            s3_key = f"models/{model_name}/v{new_version}/model.pkl"
            self.s3_client.put_object(
                Bucket=self.models_bucket,
                Key=s3_key,
                Body=model_bytes,
                Metadata={
                    'model-name': model_name,
                    'version': str(new_version),
                    'hash': model_hash
                }
            )
            
            # Guardar metadata en DynamoDB
            model_info = {
                'ModelName': model_name,
                'Version': new_version,
                'S3Location': f"s3://{self.models_bucket}/{s3_key}",
                'ModelHash': model_hash,
                'Description': description,
                'Status': ModelStatus.IN_SERVICE.value,
                'CreationTime': datetime.now().isoformat(),
                'Tags': tags or {},
                'ModelSize': len(model_bytes)
            }
            
            # Convertir floats a Decimal para DynamoDB
            model_info = convert_floats_to_decimal(model_info)
            
            table.put_item(Item=model_info)
            
            logger.info(
                f"📦 Modelo creado: {model_name} v{new_version} | "
                f"Size: {len(model_bytes)} bytes | "
                f"Hash: {model_hash[:16]}..."
            )
            
            return model_info
            
        except Exception as e:
            logger.error(f"❌ Error creando modelo: {e}")
            raise
    
    def list_models(self, model_name: Optional[str] = None, 
                   max_results: int = 100) -> List[Dict]:
        """
        Lista modelos en el registry.
        
        Args:
            model_name: Filtrar por nombre (opcional)
            max_results: Número máximo de resultados
        
        Returns:
            Lista de modelos
        """
        try:
            table = self.dynamodb.Table(self.models_table_name)
            
            if model_name:
                # Buscar versiones de un modelo específico
                response = table.query(
                    KeyConditionExpression='ModelName = :name',
                    ExpressionAttributeValues={':name': model_name},
                    Limit=max_results,
                    ScanIndexForward=False  # Más recientes primero
                )
            else:
                # Listar todos los modelos
                response = table.scan(Limit=max_results)
            
            return response.get('Items', [])
            
        except Exception as e:
            logger.error(f"❌ Error listando modelos: {e}")
            return []
    
    def get_model(self, model_name: str, version: Optional[int] = None) -> Any:
        """
        Obtiene un modelo del registry.
        
        Args:
            model_name: Nombre del modelo
            version: Versión específica (None = última)
        
        Returns:
            Objeto del modelo deserializado
        """
        try:
            table = self.dynamodb.Table(self.models_table_name)
            
            if version is None:
                # Obtener última versión
                response = table.query(
                    KeyConditionExpression='ModelName = :name',
                    ExpressionAttributeValues={':name': model_name},
                    ScanIndexForward=False,
                    Limit=1
                )
                
                if not response['Items']:
                    raise ValueError(f"Modelo '{model_name}' no encontrado")
                
                model_info = response['Items'][0]
            else:
                # Obtener versión específica
                response = table.get_item(
                    Key={'ModelName': model_name, 'Version': version}
                )
                
                if 'Item' not in response:
                    raise ValueError(f"Modelo '{model_name}' v{version} no encontrado")
                
                model_info = response['Item']
            
            # Descargar de S3
            s3_key = model_info['S3Location'].replace(f"s3://{self.models_bucket}/", "")
            
            obj = self.s3_client.get_object(
                Bucket=self.models_bucket,
                Key=s3_key
            )
            
            model_bytes = obj['Body'].read()
            model_buffer = io.BytesIO(model_bytes)
            model = joblib.load(model_buffer)
            
            logger.info(
                f"📥 Modelo cargado: {model_name} v{model_info['Version']}"
            )
            
            return model
            
        except Exception as e:
            logger.error(f"❌ Error obteniendo modelo: {e}")
            raise
    
    def delete_model(self, model_name: str, version: int) -> bool:
        """
        Elimina un modelo del registry.
        
        Args:
            model_name: Nombre del modelo
            version: Versión a eliminar
        
        Returns:
            True si se eliminó exitosamente
        """
        try:
            table = self.dynamodb.Table(self.models_table_name)
            
            # Obtener info del modelo
            response = table.get_item(
                Key={'ModelName': model_name, 'Version': version}
            )
            
            if 'Item' not in response:
                logger.warning(f"⚠️  Modelo '{model_name}' v{version} no encontrado")
                return False
            
            model_info = response['Item']
            
            # Eliminar de S3
            s3_key = model_info['S3Location'].replace(f"s3://{self.models_bucket}/", "")
            self.s3_client.delete_object(
                Bucket=self.models_bucket,
                Key=s3_key
            )
            
            # Eliminar de DynamoDB
            table.delete_item(
                Key={'ModelName': model_name, 'Version': version}
            )
            
            logger.info(f"🗑️  Modelo eliminado: {model_name} v{version}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Error eliminando modelo: {e}")
            return False
    
    # ==================== TRAINING JOBS ====================
    
    def create_training_job(self, job_name: str, training_function: callable,
                           training_data: Any, hyperparameters: Dict = None) -> Dict:
        """
        Crea y ejecuta un training job.
        
        Args:
            job_name: Nombre del job
            training_function: Función que entrena el modelo
            training_data: Datos de entrenamiento
            hyperparameters: Hiperparámetros
        
        Returns:
            Información del training job
        """
        try:
            table = self.dynamodb.Table(self.training_jobs_table_name)
            
            # Crear registro del job
            job_info = {
                'TrainingJobName': job_name,
                'Status': TrainingJobStatus.IN_PROGRESS.value,
                'CreationTime': datetime.now().isoformat(),
                'Hyperparameters': hyperparameters or {},
                'StartTime': datetime.now().isoformat()
            }
            
            # Convertir floats a Decimal
            job_info = convert_floats_to_decimal(job_info)
            
            table.put_item(Item=job_info)
            
            logger.info(f"🏋️  Training job iniciado: {job_name}")
            
            # Ejecutar entrenamiento
            try:
                start_time = datetime.now()
                model = training_function(training_data, hyperparameters or {})
                end_time = datetime.now()
                
                training_time = (end_time - start_time).total_seconds()
                
                # Actualizar status
                table.update_item(
                    Key={'TrainingJobName': job_name},
                    UpdateExpression='SET #status = :status, EndTime = :end_time, TrainingTime = :training_time',
                    ExpressionAttributeNames={'#status': 'Status'},
                    ExpressionAttributeValues=convert_floats_to_decimal({
                        ':status': TrainingJobStatus.COMPLETED.value,
                        ':end_time': end_time.isoformat(),
                        ':training_time': training_time
                    })
                )
                
                logger.info(
                    f"✅ Training job completado: {job_name} | "
                    f"Tiempo: {training_time:.2f}s"
                )
                
                # Guardar modelo automáticamente
                model_name = f"{job_name}_model"
                self.create_model(
                    model_name=model_name,
                    model_data=model,
                    description=f"Modelo entrenado por job: {job_name}",
                    tags={'training_job': job_name}
                )
                
                job_info['Status'] = TrainingJobStatus.COMPLETED.value
                job_info['ModelName'] = model_name
                job_info['TrainingTime'] = training_time
                
                return job_info
                
            except Exception as e:
                # Marcar como fallido
                table.update_item(
                    Key={'TrainingJobName': job_name},
                    UpdateExpression='SET #status = :status, FailureReason = :reason',
                    ExpressionAttributeNames={'#status': 'Status'},
                    ExpressionAttributeValues={
                        ':status': TrainingJobStatus.FAILED.value,
                        ':reason': str(e)
                    }
                )
                
                logger.error(f"❌ Training job fallido: {job_name} - {e}")
                raise
                
        except Exception as e:
            logger.error(f"❌ Error creando training job: {e}")
            raise
    
    def list_training_jobs(self, max_results: int = 100) -> List[Dict]:
        """Lista training jobs"""
        try:
            table = self.dynamodb.Table(self.training_jobs_table_name)
            response = table.scan(Limit=max_results)
            return response.get('Items', [])
        except Exception as e:
            logger.error(f"❌ Error listando training jobs: {e}")
            return []
    
    # ==================== ENDPOINTS ====================
    
    def create_endpoint(self, endpoint_name: str, model_name: str,
                       version: Optional[int] = None) -> Dict:
        """
        Crea un endpoint de inferencia.
        
        Args:
            endpoint_name: Nombre del endpoint
            model_name: Nombre del modelo a desplegar
            version: Versión del modelo (None = última)
        
        Returns:
            Información del endpoint
        """
        try:
            table = self.dynamodb.Table(self.endpoints_table_name)
            
            # Cargar modelo
            model = self.get_model(model_name, version)
            
            # Crear endpoint
            endpoint_info = {
                'EndpointName': endpoint_name,
                'ModelName': model_name,
                'ModelVersion': version,
                'Status': EndpointStatus.IN_SERVICE.value,
                'CreationTime': datetime.now().isoformat(),
                'InvocationCount': 0
            }
            
            # Convertir floats a Decimal
            endpoint_info = convert_floats_to_decimal(endpoint_info)
            
            table.put_item(Item=endpoint_info)
            
            logger.info(f"🔌 Endpoint creado: {endpoint_name} → {model_name}")
            
            return endpoint_info
            
        except Exception as e:
            logger.error(f"❌ Error creando endpoint: {e}")
            raise
    
    def invoke_endpoint(self, endpoint_name: str, data: Any) -> Any:
        """
        Invoca un endpoint para inferencia.
        
        Args:
            endpoint_name: Nombre del endpoint
            data: Datos para predicción
        
        Returns:
            Predicción del modelo
        """
        try:
            table = self.dynamodb.Table(self.endpoints_table_name)
            
            # Obtener info del endpoint
            response = table.get_item(Key={'EndpointName': endpoint_name})
            
            if 'Item' not in response:
                raise ValueError(f"Endpoint '{endpoint_name}' no encontrado")
            
            endpoint_info = response['Item']
            
            # Cargar modelo
            model = self.get_model(
                endpoint_info['ModelName'],
                endpoint_info.get('ModelVersion')
            )
            
            # Hacer predicción
            prediction = model.predict([data])
            
            # Incrementar contador de invocaciones
            table.update_item(
                Key={'EndpointName': endpoint_name},
                UpdateExpression='SET InvocationCount = InvocationCount + :inc',
                ExpressionAttributeValues={':inc': 1}
            )
            
            logger.debug(f"🔮 Predicción: {endpoint_name}")
            
            return prediction
            
        except Exception as e:
            logger.error(f"❌ Error invocando endpoint: {e}")
            raise
    
    def list_endpoints(self, max_results: int = 100) -> List[Dict]:
        """Lista endpoints"""
        try:
            table = self.dynamodb.Table(self.endpoints_table_name)
            response = table.scan(Limit=max_results)
            return response.get('Items', [])
        except Exception as e:
            logger.error(f"❌ Error listando endpoints: {e}")
            return []
    
    def delete_endpoint(self, endpoint_name: str) -> bool:
        """Elimina un endpoint"""
        try:
            table = self.dynamodb.Table(self.endpoints_table_name)
            table.delete_item(Key={'EndpointName': endpoint_name})
            logger.info(f"🗑️  Endpoint eliminado: {endpoint_name}")
            return True
        except Exception as e:
            logger.error(f"❌ Error eliminando endpoint: {e}")
            return False


# Instancia global
mock_sagemaker = MockSageMaker()


if __name__ == "__main__":
    # Demo
    print("=" * 80)
    print("ATHENAI MOCK SAGEMAKER - DEMO")
    print("=" * 80)
    
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.datasets import make_classification
    
    # Crear datos de prueba
    X, y = make_classification(n_samples=1000, n_features=20, random_state=42)
    
    # Función de entrenamiento
    def train_model(data, hyperparameters):
        X, y = data
        model = RandomForestClassifier(**hyperparameters)
        model.fit(X, y)
        return model
    
    # Test 1: Training Job
    print("\n🏋️  Test 1: Crear Training Job")
    job_info = mock_sagemaker.create_training_job(
        job_name='threat_detector_training_v1',
        training_function=train_model,
        training_data=(X, y),
        hyperparameters={'n_estimators': 100, 'random_state': 42}
    )
    print(f"   Status: {job_info['Status']}")
    print(f"   Modelo: {job_info.get('ModelName')}")
    
    # Test 2: Listar Modelos
    print("\n📦 Test 2: Listar Modelos")
    models = mock_sagemaker.list_models()
    print(f"   Modelos encontrados: {len(models)}")
    for model in models:
        print(f"      - {model['ModelName']} v{model['Version']}")
    
    # Test 3: Crear Endpoint
    print("\n🔌 Test 3: Crear Endpoint")
    endpoint_info = mock_sagemaker.create_endpoint(
        endpoint_name='threat-detector-prod',
        model_name=job_info['ModelName']
    )
    print(f"   Endpoint: {endpoint_info['EndpointName']}")
    print(f"   Status: {endpoint_info['Status']}")
    
    # Test 4: Invocar Endpoint
    print("\n🔮 Test 4: Invocar Endpoint")
    test_data = X[0]
    prediction = mock_sagemaker.invoke_endpoint(
        endpoint_name='threat-detector-prod',
        data=test_data
    )
    print(f"   Predicción: {prediction[0]}")
    
    # Test 5: Estadísticas
    print("\n📊 Test 5: Estadísticas")
    endpoints = mock_sagemaker.list_endpoints()
    for ep in endpoints:
        print(f"   {ep['EndpointName']}: {ep['InvocationCount']} invocaciones")
    
    print("\n" + "=" * 80)
    print("✅ Mock SageMaker funcionando correctamente!")
    print("=" * 80)
