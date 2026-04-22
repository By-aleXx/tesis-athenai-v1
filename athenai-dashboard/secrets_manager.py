"""
AthenAI - Secrets Manager Client

Cliente para AWS Secrets Manager (LocalStack) para gestión segura de credenciales.
Almacena API keys, tokens, y configuraciones sensibles.

Autor: AthenAI Team
Fecha: 2026-02-11
"""

import boto3
import json
import logging
import os
from typing import Dict, Optional, Any
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

# Importar configuración centralizada
try:
    from config import get_aws_config, SECRETS_PREFIX
    USE_CONFIG = True
except ImportError:
    USE_CONFIG = False
    print("⚠️  config.py no encontrado, usando variables de entorno directamente")

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SecretsManagerClient:
    """
    Cliente para AWS Secrets Manager con soporte para LocalStack.
    
    Gestiona:
    - API keys
    - Tokens de autenticación
    - Credenciales de bases de datos
    - Configuraciones sensibles
    """
    
    def __init__(self, use_localstack=True):
        """
        Inicializa el cliente de Secrets Manager.
        
        Args:
            use_localstack: Si True, usa LocalStack
        """
        self.use_localstack = use_localstack
        
        # Configuración de Secrets Manager usando config.py
        if USE_CONFIG:
            aws_config = get_aws_config()
            self.client = boto3.client('secretsmanager', **aws_config)
            self.secret_prefix = SECRETS_PREFIX
            logger.info(f"✅ Usando configuración remota: {aws_config.get('endpoint_url', 'AWS')}")
        else:
            # Fallback: leer desde variables de entorno
            if use_localstack:
                self.client = boto3.client(
                    'secretsmanager',
                    endpoint_url=os.getenv('AWS_ENDPOINT_URL', 'http://localhost:4566'),
                    aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID', 'test'),
                    aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY', 'test'),
                    region_name=os.getenv('AWS_REGION', 'us-east-1')
                )
            else:
                self.client = boto3.client('secretsmanager')
            
            self.secret_prefix = 'athenai/'
        
        # Inicializar secrets por defecto
        self._init_default_secrets()
        
        logger.info(f"✅ Secrets Manager Client inicializado ({'LocalStack' if use_localstack else 'AWS'})")
    
    def _init_default_secrets(self):
        """Crea secrets por defecto si no existen"""
        jwt_secret = os.getenv('JWT_SECRET_KEY')
        if not jwt_secret:
            raise ValueError("JWT_SECRET_KEY no está configurada en variables de entorno")
        db_password = os.getenv('DB_PASSWORD', '')
        hmac_key = os.getenv('HMAC_SECRET_KEY', '')
        default_secrets = {
            'database': {
                'host': 'localhost',
                'port': 4566,
                'username': 'athenai_user',
                'password': db_password
            },
            'api_keys': {
                'slack_webhook': os.getenv('SLACK_WEBHOOK_URL', ''),
                'email_api_key': os.getenv('EMAIL_API_KEY', ''),
                'sms_api_key': ''
            },
            'hmac_key': {
                'key': hmac_key,
                'algorithm': 'SHA-256'
            },
            'jwt_secret': {
                'secret': jwt_secret,
                'algorithm': 'HS256',
                'expiration_hours': 24
            }
        }
        
        for secret_name, secret_value in default_secrets.items():
            full_name = f"{self.secret_prefix}{secret_name}"
            
            try:
                # Intentar obtener el secret
                self.client.describe_secret(SecretId=full_name)
                logger.debug(f"ℹ️  Secret '{full_name}' ya existe")
            except self.client.exceptions.ResourceNotFoundException:
                # Crear el secret si no existe
                try:
                    self.create_secret(secret_name, secret_value)
                    logger.info(f"✅ Secret por defecto creado: {full_name}")
                except Exception as e:
                    logger.error(f"❌ Error creando secret por defecto '{full_name}': {e}")
            except Exception as e:
                logger.error(f"❌ Error verificando secret '{full_name}': {e}")
    
    def create_secret(self, secret_name: str, secret_value: Any, description: str = "") -> bool:
        """
        Crea un nuevo secret.
        
        Args:
            secret_name: Nombre del secret (sin prefijo)
            secret_value: Valor del secret (dict, string, etc.)
            description: Descripción del secret
        
        Returns:
            True si se creó exitosamente
        """
        try:
            full_name = f"{self.secret_prefix}{secret_name}"
            
            # Convertir a JSON si es dict
            if isinstance(secret_value, dict):
                secret_string = json.dumps(secret_value)
            else:
                secret_string = str(secret_value)
            
            self.client.create_secret(
                Name=full_name,
                Description=description or f"AthenAI secret: {secret_name}",
                SecretString=secret_string
            )
            
            logger.info(f"🔐 Secret creado: {full_name}")
            return True
            
        except self.client.exceptions.ResourceExistsException:
            logger.warning(f"⚠️  Secret ya existe: {full_name}")
            return False
        except Exception as e:
            logger.error(f"❌ Error creando secret: {e}")
            return False
    
    def get_secret(self, secret_name: str, parse_json: bool = True) -> Optional[Any]:
        """
        Obtiene el valor de un secret.
        
        Args:
            secret_name: Nombre del secret (sin prefijo)
            parse_json: Si True, intenta parsear como JSON
        
        Returns:
            Valor del secret o None si no existe
        """
        try:
            full_name = f"{self.secret_prefix}{secret_name}"
            
            response = self.client.get_secret_value(SecretId=full_name)
            secret_string = response.get('SecretString')
            
            if parse_json:
                try:
                    return json.loads(secret_string)
                except json.JSONDecodeError:
                    return secret_string
            
            return secret_string
            
        except self.client.exceptions.ResourceNotFoundException:
            logger.warning(f"⚠️  Secret no encontrado: {secret_name}")
            return None
        except Exception as e:
            logger.error(f"❌ Error obteniendo secret: {e}")
            return None
    
    def update_secret(self, secret_name: str, secret_value: Any) -> bool:
        """
        Actualiza el valor de un secret existente.
        
        Args:
            secret_name: Nombre del secret (sin prefijo)
            secret_value: Nuevo valor del secret
        
        Returns:
            True si se actualizó exitosamente
        """
        try:
            full_name = f"{self.secret_prefix}{secret_name}"
            
            # Convertir a JSON si es dict
            if isinstance(secret_value, dict):
                secret_string = json.dumps(secret_value)
            else:
                secret_string = str(secret_value)
            
            self.client.update_secret(
                SecretId=full_name,
                SecretString=secret_string
            )
            
            logger.info(f"🔄 Secret actualizado: {full_name}")
            return True
            
        except self.client.exceptions.ResourceNotFoundException:
            logger.warning(f"⚠️  Secret no encontrado para actualizar: {secret_name}")
            return False
        except Exception as e:
            logger.error(f"❌ Error actualizando secret: {e}")
            return False
    
    def delete_secret(self, secret_name: str, force_delete: bool = False) -> bool:
        """
        Elimina un secret.
        
        Args:
            secret_name: Nombre del secret (sin prefijo)
            force_delete: Si True, elimina inmediatamente sin período de recuperación
        
        Returns:
            True si se eliminó exitosamente
        """
        try:
            full_name = f"{self.secret_prefix}{secret_name}"
            
            if force_delete:
                self.client.delete_secret(
                    SecretId=full_name,
                    ForceDeleteWithoutRecovery=True
                )
            else:
                # Período de recuperación de 7 días por defecto
                self.client.delete_secret(
                    SecretId=full_name,
                    RecoveryWindowInDays=7
                )
            
            logger.info(f"🗑️  Secret eliminado: {full_name}")
            return True
            
        except self.client.exceptions.ResourceNotFoundException:
            logger.warning(f"⚠️  Secret no encontrado para eliminar: {secret_name}")
            return False
        except Exception as e:
            logger.error(f"❌ Error eliminando secret: {e}")
            return False
    
    def list_secrets(self) -> list:
        """
        Lista todos los secrets de AthenAI.
        
        Returns:
            Lista de nombres de secrets
        """
        try:
            response = self.client.list_secrets()
            
            # Filtrar solo secrets de AthenAI
            athenai_secrets = [
                secret['Name'].replace(self.secret_prefix, '')
                for secret in response.get('SecretList', [])
                if secret['Name'].startswith(self.secret_prefix)
            ]
            
            return athenai_secrets
            
        except Exception as e:
            logger.error(f"❌ Error listando secrets: {e}")
            return []
    
    def rotate_secret(self, secret_name: str, new_value: Any) -> bool:
        """
        Rota un secret (actualiza y registra la rotación).
        
        Args:
            secret_name: Nombre del secret
            new_value: Nuevo valor
        
        Returns:
            True si se rotó exitosamente
        """
        try:
            # Agregar metadata de rotación
            if isinstance(new_value, dict):
                new_value['_rotated_at'] = datetime.now().isoformat()
            
            success = self.update_secret(secret_name, new_value)
            
            if success:
                logger.info(f"🔄 Secret rotado: {secret_name}")
            
            return success
            
        except Exception as e:
            logger.error(f"❌ Error rotando secret: {e}")
            return False
    
    # ==================== HELPERS ESPECÍFICOS ====================
    
    def get_database_credentials(self) -> Optional[Dict]:
        """Obtiene credenciales de base de datos"""
        return self.get_secret('database')
    
    def get_api_keys(self) -> Optional[Dict]:
        """Obtiene API keys"""
        return self.get_secret('api_keys')
    
    def get_hmac_key(self) -> Optional[str]:
        """Obtiene la clave HMAC para Evidence Store"""
        hmac_data = self.get_secret('hmac_key')
        if hmac_data and isinstance(hmac_data, dict):
            return hmac_data.get('key')
        return None
    
    def get_jwt_secret(self) -> Optional[Dict]:
        """Obtiene configuración JWT"""
        return self.get_secret('jwt_secret')
    
    def set_slack_webhook(self, webhook_url: str) -> bool:
        """Configura Slack webhook"""
        api_keys = self.get_api_keys() or {}
        api_keys['slack_webhook'] = webhook_url
        return self.update_secret('api_keys', api_keys)
    
    def set_email_api_key(self, api_key: str) -> bool:
        """Configura Email API key"""
        api_keys = self.get_api_keys() or {}
        api_keys['email_api_key'] = api_key
        return self.update_secret('api_keys', api_keys)


# Instancia global
secrets_manager = SecretsManagerClient()


if __name__ == "__main__":
    # Demo
    print("=" * 80)
    print("ATHENAI SECRETS MANAGER - DEMO")
    print("=" * 80)
    
    # Listar secrets
    print("\n🔐 Secrets existentes:")
    secrets = secrets_manager.list_secrets()
    for secret in secrets:
        print(f"   - {secret}")
    
    # Crear nuevo secret
    print("\n➕ Creando nuevo secret:")
    test_secret = {
        'api_key': 'test_key_12345',
        'api_secret': 'test_secret_67890',
        'created_at': datetime.now().isoformat()
    }
    
    success = secrets_manager.create_secret('test_api', test_secret, "Test API credentials")
    print(f"   {'✅ Creado' if success else '❌ Error o ya existe'}")
    
    # Obtener secret
    print("\n🔍 Obteniendo secret:")
    retrieved = secrets_manager.get_secret('test_api')
    if retrieved:
        print(f"   ✅ Recuperado: {json.dumps(retrieved, indent=2)}")
    
    # Obtener credenciales de base de datos
    print("\n🗄️  Credenciales de base de datos:")
    db_creds = secrets_manager.get_database_credentials()
    if db_creds:
        print(f"   Host: {db_creds.get('host')}")
        print(f"   Port: {db_creds.get('port')}")
        print(f"   Username: {db_creds.get('username')}")
        print(f"   Password: {'*' * len(db_creds.get('password', ''))}")
    
    # Obtener HMAC key
    print("\n🔑 HMAC Key para Evidence Store:")
    hmac_key = secrets_manager.get_hmac_key()
    if hmac_key:
        print(f"   Key: {hmac_key[:20]}... (truncado)")
    
    # Actualizar secret
    print("\n🔄 Actualizando secret:")
    test_secret['updated_at'] = datetime.now().isoformat()
    success = secrets_manager.update_secret('test_api', test_secret)
    print(f"   {'✅ Actualizado' if success else '❌ Error'}")
    
    print("\n" + "=" * 80)
