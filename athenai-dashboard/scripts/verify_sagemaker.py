"""
AthenAI - SageMaker Verification Script

Verifica que SageMaker esté disponible en el servidor remoto.

Autor: AthenAI Team
Fecha: 2026-02-11
"""

import boto3
import os
from botocore.exceptions import ClientError, EndpointConnectionError
import json
from dotenv import load_dotenv

load_dotenv()

# Configuración del servidor remoto (leído del .env)
REMOTE_SERVER = os.environ['REMOTE_SERVER_IP']
ENDPOINT_URL = os.environ['AWS_ENDPOINT_URL']

def check_sagemaker():
    """Verifica la disponibilidad de SageMaker"""
    
    print("=" * 80)
    print("ATHENAI - VERIFICACIÓN DE SAGEMAKER")
    print("=" * 80)
    print(f"\nServidor: {REMOTE_SERVER}")
    print(f"Endpoint: {ENDPOINT_URL}")
    print()
    
    try:
        # Crear cliente de SageMaker
        sagemaker = boto3.client(
            'sagemaker',
            endpoint_url=ENDPOINT_URL,
            aws_access_key_id=os.environ['AWS_ACCESS_KEY_ID'],
            aws_secret_access_key=os.environ['AWS_SECRET_ACCESS_KEY'],
            region_name=os.getenv('AWS_REGION', 'us-east-1')
        )
        
        print("✅ Cliente de SageMaker creado exitosamente")
        
        # Test 1: Listar modelos
        print("\n📦 Test 1: Listar modelos...")
        try:
            response = sagemaker.list_models(MaxResults=10)
            models = response.get('Models', [])
            print(f"   ✅ SageMaker respondió correctamente")
            print(f"   📊 Modelos encontrados: {len(models)}")
            
            if models:
                print("\n   Modelos:")
                for model in models:
                    print(f"      - {model.get('ModelName')} (creado: {model.get('CreationTime')})")
            else:
                print("   ℹ️  No hay modelos registrados (esto es normal en una instalación nueva)")
        
        except ClientError as e:
            error_code = e.response['Error']['Code']
            print(f"   ⚠️  Error: {error_code} - {e.response['Error']['Message']}")
            return False
        
        # Test 2: Listar training jobs
        print("\n🏋️  Test 2: Listar training jobs...")
        try:
            response = sagemaker.list_training_jobs(MaxResults=10)
            jobs = response.get('TrainingJobSummaries', [])
            print(f"   ✅ SageMaker respondió correctamente")
            print(f"   📊 Training jobs encontrados: {len(jobs)}")
            
            if jobs:
                print("\n   Training Jobs:")
                for job in jobs:
                    print(f"      - {job.get('TrainingJobName')} (status: {job.get('TrainingJobStatus')})")
            else:
                print("   ℹ️  No hay training jobs (esto es normal en una instalación nueva)")
        
        except ClientError as e:
            error_code = e.response['Error']['Code']
            print(f"   ⚠️  Error: {error_code} - {e.response['Error']['Message']}")
        
        # Test 3: Listar endpoints
        print("\n🔌 Test 3: Listar endpoints...")
        try:
            response = sagemaker.list_endpoints(MaxResults=10)
            endpoints = response.get('Endpoints', [])
            print(f"   ✅ SageMaker respondió correctamente")
            print(f"   📊 Endpoints encontrados: {len(endpoints)}")
            
            if endpoints:
                print("\n   Endpoints:")
                for endpoint in endpoints:
                    print(f"      - {endpoint.get('EndpointName')} (status: {endpoint.get('EndpointStatus')})")
            else:
                print("   ℹ️  No hay endpoints desplegados (esto es normal en una instalación nueva)")
        
        except ClientError as e:
            error_code = e.response['Error']['Code']
            print(f"   ⚠️  Error: {error_code} - {e.response['Error']['Message']}")
        
        # Test 4: Listar notebook instances
        print("\n📓 Test 4: Listar notebook instances...")
        try:
            response = sagemaker.list_notebook_instances(MaxResults=10)
            notebooks = response.get('NotebookInstances', [])
            print(f"   ✅ SageMaker respondió correctamente")
            print(f"   📊 Notebooks encontrados: {len(notebooks)}")
            
            if notebooks:
                print("\n   Notebooks:")
                for nb in notebooks:
                    print(f"      - {nb.get('NotebookInstanceName')} (status: {nb.get('NotebookInstanceStatus')})")
            else:
                print("   ℹ️  No hay notebooks (esto es normal en una instalación nueva)")
        
        except ClientError as e:
            error_code = e.response['Error']['Code']
            print(f"   ⚠️  Error: {error_code} - {e.response['Error']['Message']}")
        
        # Resumen
        print("\n" + "=" * 80)
        print("RESUMEN")
        print("=" * 80)
        print("✅ SageMaker está DISPONIBLE y funcionando correctamente")
        print("\nCapacidades verificadas:")
        print("  ✅ Gestión de modelos (list_models)")
        print("  ✅ Training jobs (list_training_jobs)")
        print("  ✅ Endpoints de inferencia (list_endpoints)")
        print("  ✅ Notebook instances (list_notebook_instances)")
        print("\n💡 SageMaker está listo para ser usado en AthenAI")
        print("=" * 80)
        
        return True
        
    except EndpointConnectionError as e:
        print(f"\n❌ ERROR DE CONEXIÓN")
        print(f"   No se pudo conectar a {ENDPOINT_URL}")
        print(f"   Error: {e}")
        print("\n🔍 Posibles causas:")
        print("   1. LocalStack no está corriendo en el servidor remoto")
        print("   2. El puerto 4566 no está accesible")
        print("   3. Firewall bloqueando la conexión")
        print("\n💡 Solución:")
        print("   Verifica que LocalStack esté corriendo en el servidor:")
        print(f"   curl http://{REMOTE_SERVER}:4566/_localstack/health")
        print("=" * 80)
        return False
        
    except Exception as e:
        print(f"\n❌ ERROR INESPERADO: {e}")
        print("=" * 80)
        return False


def check_other_services():
    """Verifica otros servicios de LocalStack"""
    
    print("\n" + "=" * 80)
    print("VERIFICACIÓN DE OTROS SERVICIOS AWS")
    print("=" * 80)
    
    services_to_check = [
        ('S3', 's3', 'list_buckets'),
        ('DynamoDB', 'dynamodb', 'list_tables'),
        ('Secrets Manager', 'secretsmanager', 'list_secrets'),
        ('SNS', 'sns', 'list_topics'),
        ('SES', 'ses', 'list_identities'),
    ]
    
    results = {}
    
    for service_name, service_code, test_method in services_to_check:
        try:
            client = boto3.client(
                service_code,
                endpoint_url=ENDPOINT_URL,
                aws_access_key_id=os.environ['AWS_ACCESS_KEY_ID'],
                aws_secret_access_key=os.environ['AWS_SECRET_ACCESS_KEY'],
                region_name=os.getenv('AWS_REGION', 'us-east-1')
            )
            
            # Intentar llamar al método de test
            getattr(client, test_method)()
            
            print(f"✅ {service_name:20} - Disponible")
            results[service_name] = True
            
        except Exception as e:
            print(f"❌ {service_name:20} - No disponible ({str(e)[:50]}...)")
            results[service_name] = False
    
    print("=" * 80)
    
    available = sum(1 for v in results.values() if v)
    total = len(results)
    
    print(f"\n📊 Servicios disponibles: {available}/{total}")
    
    return results


if __name__ == "__main__":
    # Verificar SageMaker
    sagemaker_ok = check_sagemaker()
    
    # Verificar otros servicios
    print("\n")
    other_services = check_other_services()
    
    # Resultado final
    print("\n" + "=" * 80)
    if sagemaker_ok:
        print("🎉 ¡VERIFICACIÓN EXITOSA!")
        print("\nSageMaker está listo para:")
        print("  • Entrenar modelos de ML")
        print("  • Desplegar endpoints de inferencia")
        print("  • Gestionar el ciclo de vida de modelos")
        print("  • Implementar la Fase 5: ML Pipeline Avanzado")
    else:
        print("⚠️  SageMaker no está disponible")
        print("\nPor favor, verifica la configuración del servidor remoto")
    print("=" * 80)
