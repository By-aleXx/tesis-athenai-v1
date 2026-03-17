"""
Sistema de Autenticación JWT para AthenAI

Proporciona:
- Registro y login de usuarios
- Generación de tokens JWT (access + refresh)
- Validación de tokens
- Hash de passwords con bcrypt
- Gestión de usuarios en DynamoDB
"""

import os
from dotenv import load_dotenv

# Cargar variables de entorno desde .env
load_dotenv()
import jwt
import bcrypt
import boto3
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify
import uuid
import logging

logger = logging.getLogger(__name__)

class AuthService:
    def __init__(self, dynamodb_client=None, jwt_secret=None, jwt_refresh_secret=None):
        """
        Inicializa el servicio de autenticación.
        
        Args:
            dynamodb_client: Cliente de DynamoDB (boto3)
            jwt_secret: Clave secreta para tokens JWT
            jwt_refresh_secret: Clave secreta para refresh tokens
        """
        self.dynamodb = dynamodb_client or boto3.client(
            'dynamodb',
            endpoint_url=os.environ['AWS_ENDPOINT_URL'],
            region_name=os.getenv('AWS_REGION', 'us-east-1'),
            aws_access_key_id=os.environ['AWS_ACCESS_KEY_ID'],
            aws_secret_access_key=os.environ['AWS_SECRET_ACCESS_KEY']
        )
        
        self.jwt_secret = jwt_secret or os.environ['JWT_SECRET_KEY']
        self.jwt_refresh_secret = jwt_refresh_secret or os.environ['JWT_REFRESH_SECRET_KEY']
        
        self.table_name = 'athenai_users'
        self.access_token_expiry = timedelta(hours=1)  # 1 hora
        self.refresh_token_expiry = timedelta(days=7)  # 7 días
        
        # Crear tabla si no existe
        self._create_table_if_not_exists()
        
        # Crear usuario admin por defecto
        self._create_default_admin()
    
    def _create_table_if_not_exists(self):
        """Crea la tabla de usuarios si no existe"""
        try:
            self.dynamodb.describe_table(TableName=self.table_name)
            logger.info(f"✅ Tabla {self.table_name} ya existe")
        except self.dynamodb.exceptions.ResourceNotFoundException:
            logger.info(f"📦 Creando tabla {self.table_name}...")
            
            self.dynamodb.create_table(
                TableName=self.table_name,
                KeySchema=[
                    {'AttributeName': 'user_id', 'KeyType': 'HASH'}
                ],
                AttributeDefinitions=[
                    {'AttributeName': 'user_id', 'AttributeType': 'S'},
                    {'AttributeName': 'username', 'AttributeType': 'S'}
                ],
                GlobalSecondaryIndexes=[
                    {
                        'IndexName': 'username-index',
                        'KeySchema': [
                            {'AttributeName': 'username', 'KeyType': 'HASH'}
                        ],
                        'Projection': {'ProjectionType': 'ALL'},
                        'ProvisionedThroughput': {
                            'ReadCapacityUnits': 5,
                            'WriteCapacityUnits': 5
                        }
                    }
                ],
                ProvisionedThroughput={
                    'ReadCapacityUnits': 5,
                    'WriteCapacityUnits': 5
                }
            )
            
            logger.info(f"✅ Tabla {self.table_name} creada exitosamente")
    
    def _create_default_admin(self):
        """Crea un usuario admin por defecto si no existe"""
        try:
            # Verificar si ya existe
            existing = self.get_user_by_username('admin')
            if existing:
                logger.info("✅ Usuario admin ya existe")
                return
            
            # Crear admin
            self.register_user(
                username='admin',
                password='admin123',
                email='admin@athenai.com',
                role='admin'
            )
            logger.info("✅ Usuario admin creado: username=admin, password=admin123")
        except Exception as e:
            logger.error(f"Error creando usuario admin: {e}")
    
    def hash_password(self, password: str) -> str:
        """Hash de password con bcrypt"""
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    def verify_password(self, password: str, hashed: str) -> bool:
        """Verifica password contra hash"""
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    
    def generate_access_token(self, user_id: str, username: str, role: str) -> str:
        """Genera un access token JWT"""
        payload = {
            'user_id': user_id,
            'username': username,
            'role': role,
            'type': 'access',
            'exp': datetime.utcnow() + self.access_token_expiry,
            'iat': datetime.utcnow()
        }
        return jwt.encode(payload, self.jwt_secret, algorithm='HS256')
    
    def generate_refresh_token(self, user_id: str) -> str:
        """Genera un refresh token JWT"""
        payload = {
            'user_id': user_id,
            'type': 'refresh',
            'exp': datetime.utcnow() + self.refresh_token_expiry,
            'iat': datetime.utcnow()
        }
        return jwt.encode(payload, self.jwt_refresh_secret, algorithm='HS256')
    
    def verify_access_token(self, token: str) -> dict:
        """
        Verifica un access token.
        
        Returns:
            dict con user_id, username, role si es válido
        Raises:
            jwt.ExpiredSignatureError si expiró
            jwt.InvalidTokenError si es inválido
        """
        payload = jwt.decode(token, self.jwt_secret, algorithms=['HS256'])
        
        if payload.get('type') != 'access':
            raise jwt.InvalidTokenError('Token type mismatch')
        
        return {
            'user_id': payload['user_id'],
            'username': payload['username'],
            'role': payload['role']
        }
    
    def verify_refresh_token(self, token: str) -> str:
        """
        Verifica un refresh token.
        
        Returns:
            user_id si es válido
        Raises:
            jwt.ExpiredSignatureError si expiró
            jwt.InvalidTokenError si es inválido
        """
        payload = jwt.decode(token, self.jwt_refresh_secret, algorithms=['HS256'])
        
        if payload.get('type') != 'refresh':
            raise jwt.InvalidTokenError('Token type mismatch')
        
        return payload['user_id']
    
    def register_user(self, username: str, password: str, email: str, role: str = 'viewer') -> dict:
        """
        Registra un nuevo usuario.
        
        Args:
            username: Nombre de usuario único
            password: Password en texto plano (será hasheado)
            email: Email del usuario
            role: Rol (admin, analyst, viewer)
        
        Returns:
            dict con user_id, username, email, role
        
        Raises:
            ValueError si el username ya existe
        """
        # Verificar si ya existe
        existing = self.get_user_by_username(username)
        if existing:
            raise ValueError(f'Username {username} already exists')
        
        # Validar role
        if role not in ['admin', 'analyst', 'viewer']:
            raise ValueError(f'Invalid role: {role}')
        
        user_id = str(uuid.uuid4())
        password_hash = self.hash_password(password)
        now = datetime.utcnow().isoformat()
        
        self.dynamodb.put_item(
            TableName=self.table_name,
            Item={
                'user_id': {'S': user_id},
                'username': {'S': username},
                'password_hash': {'S': password_hash},
                'email': {'S': email},
                'role': {'S': role},
                'created_at': {'S': now},
                'last_login': {'S': now},
                'is_active': {'BOOL': True}
            }
        )
        
        logger.info(f"✅ Usuario registrado: {username} ({role})")
        
        return {
            'user_id': user_id,
            'username': username,
            'email': email,
            'role': role
        }
    
    def get_user_by_username(self, username: str) -> dict:
        """Obtiene un usuario por username"""
        try:
            response = self.dynamodb.query(
                TableName=self.table_name,
                IndexName='username-index',
                KeyConditionExpression='username = :username',
                ExpressionAttributeValues={
                    ':username': {'S': username}
                }
            )
            
            if not response.get('Items'):
                return None
            
            item = response['Items'][0]
            return {
                'user_id': item['user_id']['S'],
                'username': item['username']['S'],
                'password_hash': item['password_hash']['S'],
                'email': item['email']['S'],
                'role': item['role']['S'],
                'created_at': item['created_at']['S'],
                'last_login': item.get('last_login', {}).get('S'),
                'is_active': item.get('is_active', {}).get('BOOL', True)
            }
        except Exception as e:
            logger.error(f"Error obteniendo usuario {username}: {e}")
            return None
    
    def get_user_by_id(self, user_id: str) -> dict:
        """Obtiene un usuario por user_id"""
        try:
            response = self.dynamodb.get_item(
                TableName=self.table_name,
                Key={'user_id': {'S': user_id}}
            )
            
            if 'Item' not in response:
                return None
            
            item = response['Item']
            return {
                'user_id': item['user_id']['S'],
                'username': item['username']['S'],
                'email': item['email']['S'],
                'role': item['role']['S'],
                'created_at': item['created_at']['S'],
                'last_login': item.get('last_login', {}).get('S'),
                'is_active': item.get('is_active', {}).get('BOOL', True)
            }
        except Exception as e:
            logger.error(f"Error obteniendo usuario {user_id}: {e}")
            return None
    
    def login(self, username: str, password: str) -> dict:
        """
        Login de usuario.
        
        Returns:
            dict con access_token, refresh_token, user
        
        Raises:
            ValueError si credenciales inválidas
        """
        user = self.get_user_by_username(username)
        
        if not user:
            raise ValueError('Invalid credentials')
        
        if not user.get('is_active'):
            raise ValueError('User is inactive')
        
        if not self.verify_password(password, user['password_hash']):
            raise ValueError('Invalid credentials')
        
        # Actualizar last_login
        try:
            self.dynamodb.update_item(
                TableName=self.table_name,
                Key={'user_id': {'S': user['user_id']}},
                UpdateExpression='SET last_login = :now',
                ExpressionAttributeValues={
                    ':now': {'S': datetime.utcnow().isoformat()}
                }
            )
        except Exception as e:
            logger.warning(f"Error actualizando last_login: {e}")
        
        # Generar tokens
        access_token = self.generate_access_token(
            user['user_id'],
            user['username'],
            user['role']
        )
        refresh_token = self.generate_refresh_token(user['user_id'])
        
        logger.info(f"✅ Login exitoso: {username}")
        
        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'user': {
                'user_id': user['user_id'],
                'username': user['username'],
                'email': user['email'],
                'role': user['role']
            }
        }
    
    def refresh(self, refresh_token: str) -> dict:
        """
        Refresh de access token.
        
        Returns:
            dict con nuevo access_token
        
        Raises:
            jwt.ExpiredSignatureError si refresh token expiró
            jwt.InvalidTokenError si refresh token es inválido
        """
        user_id = self.verify_refresh_token(refresh_token)
        user = self.get_user_by_id(user_id)
        
        if not user:
            raise ValueError('User not found')
        
        if not user.get('is_active'):
            raise ValueError('User is inactive')
        
        access_token = self.generate_access_token(
            user['user_id'],
            user['username'],
            user['role']
        )
        
        return {'access_token': access_token}


# Middleware Decorators

def require_auth(f):
    """Decorator para requerir autenticación"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        
        if not auth_header:
            return jsonify({'error': 'Missing authorization header'}), 401
        
        try:
            # Formato: "Bearer <token>"
            parts = auth_header.split()
            if len(parts) != 2 or parts[0].lower() != 'bearer':
                return jsonify({'error': 'Invalid authorization header format'}), 401
            
            token = parts[1]
            
            # Obtener auth_service del contexto de Flask
            from flask import current_app
            auth_service = current_app.config.get('AUTH_SERVICE')
            
            if not auth_service:
                return jsonify({'error': 'Auth service not configured'}), 500
            
            # Verificar token
            user_data = auth_service.verify_access_token(token)
            
            # Agregar user_data al request
            request.user = user_data
            
            return f(*args, **kwargs)
        
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        except Exception as e:
            logger.error(f"Error en autenticación: {e}")
            return jsonify({'error': 'Authentication failed'}), 401
    
    return decorated_function


def require_role(*roles):
    """Decorator para requerir un rol específico"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not hasattr(request, 'user'):
                return jsonify({'error': 'Authentication required'}), 401
            
            user_role = request.user.get('role')
            
            if user_role not in roles:
                return jsonify({'error': f'Insufficient permissions. Required: {roles}'}), 403
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator
