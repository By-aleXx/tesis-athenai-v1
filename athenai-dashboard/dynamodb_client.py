"""
AthenAI - DynamoDB Client

Cliente para interactuar con DynamoDB (LocalStack) como reemplazo de SQLite.
Proporciona almacenamiento escalable para logs de tráfico, alertas y eventos.

Autor: AthenAI Team
Fecha: 2026-02-11
"""

import os
import boto3
from boto3.dynamodb.conditions import Key, Attr
import logging
from typing import Dict, List, Optional
from datetime import datetime
from decimal import Decimal
import json
from dotenv import load_dotenv

load_dotenv()

# Importar configuración centralizada
try:
    from config import get_aws_config, get_dynamodb_tables
    USE_CONFIG = True
except ImportError:
    USE_CONFIG = False
    print("⚠️  config.py no encontrado, usando variables de entorno directamente")

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DynamoDBClient:
    """
    Cliente para DynamoDB con soporte para LocalStack.
    
    Tablas:
    - traffic_logs: Logs de tráfico HTTP
    - security_alerts: Alertas de seguridad
    - blocked_ips: IPs bloqueadas
    """
    
    def __init__(self, use_localstack=True):
        """
        Inicializa el cliente de DynamoDB.
        
        Args:
            use_localstack: Si True, usa LocalStack
        """
        self.use_localstack = use_localstack
        
        # Configuración de DynamoDB usando config.py
        if USE_CONFIG:
            aws_config = get_aws_config()
            self.dynamodb = boto3.resource('dynamodb', **aws_config)
            self.tables = get_dynamodb_tables()
            logger.info(f"✅ Usando configuración remota: {aws_config.get('endpoint_url', 'AWS')}")
        else:
            # Fallback: leer desde variables de entorno
            if use_localstack:
                self.dynamodb = boto3.resource(
                    'dynamodb',
                    endpoint_url=os.environ['AWS_ENDPOINT_URL'],
                    aws_access_key_id=os.environ['AWS_ACCESS_KEY_ID'],
                    aws_secret_access_key=os.environ['AWS_SECRET_ACCESS_KEY'],
                    region_name=os.getenv('AWS_REGION', 'us-east-1')
                )
            else:
                self.dynamodb = boto3.resource('dynamodb')
            
            self.tables = {
                'traffic_logs': 'athenai_traffic_logs',
                'security_alerts': 'athenai_security_alerts',
                'blocked_ips': 'athenai_blocked_ips'
            }
        
        # Crear tablas si no existen
        self._init_tables()
        
        logger.info(f"✅ DynamoDB Client inicializado ({'LocalStack' if use_localstack else 'AWS'})")
    
    def _init_tables(self):
        """Crea las tablas de DynamoDB si no existen"""
        
        # Tabla: traffic_logs
        try:
            self.dynamodb.create_table(
                TableName=self.tables['traffic_logs'],
                KeySchema=[
                    {'AttributeName': 'id', 'KeyType': 'HASH'},  # Partition key
                    {'AttributeName': 'timestamp', 'KeyType': 'RANGE'}  # Sort key
                ],
                AttributeDefinitions=[
                    {'AttributeName': 'id', 'AttributeType': 'S'},
                    {'AttributeName': 'timestamp', 'AttributeType': 'S'},
                    {'AttributeName': 'source_ip', 'AttributeType': 'S'}
                ],
                GlobalSecondaryIndexes=[
                    {
                        'IndexName': 'SourceIPIndex',
                        'KeySchema': [
                            {'AttributeName': 'source_ip', 'KeyType': 'HASH'}
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
            logger.info(f"✅ Tabla '{self.tables['traffic_logs']}' creada")
        except self.dynamodb.meta.client.exceptions.ResourceInUseException:
            logger.info(f"ℹ️  Tabla '{self.tables['traffic_logs']}' ya existe")
        except Exception as e:
            logger.error(f"❌ Error creando tabla traffic_logs: {e}")
        
        # Tabla: security_alerts
        try:
            self.dynamodb.create_table(
                TableName=self.tables['security_alerts'],
                KeySchema=[
                    {'AttributeName': 'alert_id', 'KeyType': 'HASH'},
                    {'AttributeName': 'timestamp', 'KeyType': 'RANGE'}
                ],
                AttributeDefinitions=[
                    {'AttributeName': 'alert_id', 'AttributeType': 'S'},
                    {'AttributeName': 'timestamp', 'AttributeType': 'S'},
                    {'AttributeName': 'severity', 'AttributeType': 'S'}
                ],
                GlobalSecondaryIndexes=[
                    {
                        'IndexName': 'SeverityIndex',
                        'KeySchema': [
                            {'AttributeName': 'severity', 'KeyType': 'HASH'},
                            {'AttributeName': 'timestamp', 'KeyType': 'RANGE'}
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
            logger.info(f"✅ Tabla '{self.tables['security_alerts']}' creada")
        except self.dynamodb.meta.client.exceptions.ResourceInUseException:
            logger.info(f"ℹ️  Tabla '{self.tables['security_alerts']}' ya existe")
        except Exception as e:
            logger.error(f"❌ Error creando tabla security_alerts: {e}")
        
        # Tabla: blocked_ips
        try:
            self.dynamodb.create_table(
                TableName=self.tables['blocked_ips'],
                KeySchema=[
                    {'AttributeName': 'ip_address', 'KeyType': 'HASH'}
                ],
                AttributeDefinitions=[
                    {'AttributeName': 'ip_address', 'AttributeType': 'S'}
                ],
                ProvisionedThroughput={
                    'ReadCapacityUnits': 5,
                    'WriteCapacityUnits': 5
                }
            )
            logger.info(f"✅ Tabla '{self.tables['blocked_ips']}' creada")
        except self.dynamodb.meta.client.exceptions.ResourceInUseException:
            logger.info(f"ℹ️  Tabla '{self.tables['blocked_ips']}' ya existe")
        except Exception as e:
            logger.error(f"❌ Error creando tabla blocked_ips: {e}")
    
    def _convert_floats_to_decimal(self, obj):
        """Convierte floats a Decimal para DynamoDB"""
        if isinstance(obj, float):
            return Decimal(str(obj))
        elif isinstance(obj, dict):
            return {k: self._convert_floats_to_decimal(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._convert_floats_to_decimal(item) for item in obj]
        return obj
    
    # ==================== TRAFFIC LOGS ====================
    
    def insert_traffic_log(self, log_data: Dict) -> bool:
        """
        Inserta un log de tráfico en DynamoDB.
        
        Args:
            log_data: Datos del log
        
        Returns:
            True si se insertó exitosamente
        """
        try:
            table = self.dynamodb.Table(self.tables['traffic_logs'])
            
            # Generar ID y timestamp si no existen
            if 'id' not in log_data:
                log_data['id'] = f"log_{datetime.now().timestamp()}"
            
            if 'timestamp' not in log_data:
                log_data['timestamp'] = datetime.now().isoformat()
            
            # Convertir floats a Decimal
            log_data = self._convert_floats_to_decimal(log_data)
            
            table.put_item(Item=log_data)
            
            logger.debug(f"📝 Log insertado: {log_data.get('id')}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Error insertando log: {e}")
            return False
    
    def get_traffic_logs(self, limit: int = 100, source_ip: Optional[str] = None) -> List[Dict]:
        """
        Obtiene logs de tráfico.
        
        Args:
            limit: Número máximo de logs
            source_ip: Filtrar por IP (opcional)
        
        Returns:
            Lista de logs
        """
        try:
            table = self.dynamodb.Table(self.tables['traffic_logs'])
            
            if source_ip:
                # Usar índice secundario
                response = table.query(
                    IndexName='SourceIPIndex',
                    KeyConditionExpression=Key('source_ip').eq(source_ip),
                    Limit=limit,
                    ScanIndexForward=False  # Orden descendente
                )
            else:
                # Scan completo (no recomendado en producción con muchos datos)
                response = table.scan(Limit=limit)
            
            items = response.get('Items', [])
            
            # Convertir Decimal a float para JSON
            items = json.loads(json.dumps(items, default=str))
            
            return items
            
        except Exception as e:
            logger.error(f"❌ Error obteniendo logs: {e}")
            return []
    
    def get_traffic_stats(self) -> Dict:
        """
        Obtiene estadísticas de tráfico.
        
        Returns:
            Diccionario con estadísticas
        """
        try:
            table = self.dynamodb.Table(self.tables['traffic_logs'])
            
            # Scan para contar (en producción, usar CloudWatch Metrics)
            response = table.scan(Select='COUNT')
            total_logs = response.get('Count', 0)
            
            return {
                'total_logs': total_logs,
                'table_name': self.tables['traffic_logs']
            }
            
        except Exception as e:
            logger.error(f"❌ Error obteniendo estadísticas: {e}")
            return {'total_logs': 0}
    
    # ==================== SECURITY ALERTS ====================
    
    def insert_alert(self, alert_data: Dict) -> bool:
        """
        Inserta una alerta de seguridad.
        
        Args:
            alert_data: Datos de la alerta
        
        Returns:
            True si se insertó exitosamente
        """
        try:
            table = self.dynamodb.Table(self.tables['security_alerts'])
            
            # Generar ID y timestamp si no existen
            if 'alert_id' not in alert_data:
                alert_data['alert_id'] = f"alert_{datetime.now().timestamp()}"
            
            if 'timestamp' not in alert_data:
                alert_data['timestamp'] = datetime.now().isoformat()
            
            # Convertir floats a Decimal
            alert_data = self._convert_floats_to_decimal(alert_data)
            
            table.put_item(Item=alert_data)
            
            logger.info(f"🚨 Alerta insertada: {alert_data.get('alert_id')}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Error insertando alerta: {e}")
            return False
    
    def get_alerts(self, severity: Optional[str] = None, limit: int = 100) -> List[Dict]:
        """
        Obtiene alertas de seguridad.
        
        Args:
            severity: Filtrar por severidad (opcional)
            limit: Número máximo de alertas
        
        Returns:
            Lista de alertas
        """
        try:
            table = self.dynamodb.Table(self.tables['security_alerts'])
            
            if severity:
                # Usar índice secundario
                response = table.query(
                    IndexName='SeverityIndex',
                    KeyConditionExpression=Key('severity').eq(severity),
                    Limit=limit,
                    ScanIndexForward=False
                )
            else:
                response = table.scan(Limit=limit)
            
            items = response.get('Items', [])
            items = json.loads(json.dumps(items, default=str))
            
            return items
            
        except Exception as e:
            logger.error(f"❌ Error obteniendo alertas: {e}")
            return []
    
    # ==================== BLOCKED IPS ====================
    
    def insert_blocked_ip(self, ip_data: Dict) -> bool:
        """
        Inserta una IP bloqueada.
        
        Args:
            ip_data: Datos del bloqueo (debe incluir 'ip_address')
        
        Returns:
            True si se insertó exitosamente
        """
        try:
            table = self.dynamodb.Table(self.tables['blocked_ips'])
            
            if 'blocked_at' not in ip_data:
                ip_data['blocked_at'] = datetime.now().isoformat()
            
            # Convertir floats a Decimal
            ip_data = self._convert_floats_to_decimal(ip_data)
            
            table.put_item(Item=ip_data)
            
            logger.info(f"🚫 IP bloqueada registrada: {ip_data.get('ip_address')}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Error insertando IP bloqueada: {e}")
            return False
    
    def get_blocked_ip(self, ip_address: str) -> Optional[Dict]:
        """
        Obtiene información de una IP bloqueada.
        
        Args:
            ip_address: Dirección IP
        
        Returns:
            Datos del bloqueo o None
        """
        try:
            table = self.dynamodb.Table(self.tables['blocked_ips'])
            
            response = table.get_item(Key={'ip_address': ip_address})
            item = response.get('Item')
            
            if item:
                return json.loads(json.dumps(item, default=str))
            return None
            
        except Exception as e:
            logger.error(f"❌ Error obteniendo IP bloqueada: {e}")
            return None
    
    def delete_blocked_ip(self, ip_address: str) -> bool:
        """
        Elimina una IP de la lista de bloqueadas.
        
        Args:
            ip_address: Dirección IP
        
        Returns:
            True si se eliminó exitosamente
        """
        try:
            table = self.dynamodb.Table(self.tables['blocked_ips'])
            
            table.delete_item(Key={'ip_address': ip_address})
            
            logger.info(f"✅ IP desbloqueada: {ip_address}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Error eliminando IP bloqueada: {e}")
            return False
    
    def get_all_blocked_ips(self) -> List[Dict]:
        """
        Obtiene todas las IPs bloqueadas.
        
        Returns:
            Lista de IPs bloqueadas
        """
        try:
            table = self.dynamodb.Table(self.tables['blocked_ips'])
            
            response = table.scan()
            items = response.get('Items', [])
            items = json.loads(json.dumps(items, default=str))
            
            return items
            
        except Exception as e:
            logger.error(f"❌ Error obteniendo IPs bloqueadas: {e}")
            return []
    
    # ==================== UTILIDADES ====================
    
    def batch_insert_traffic_logs(self, logs: List[Dict]) -> int:
        """
        Inserta múltiples logs en batch.
        
        Args:
            logs: Lista de logs
        
        Returns:
            Número de logs insertados exitosamente
        """
        success_count = 0
        
        try:
            table = self.dynamodb.Table(self.tables['traffic_logs'])
            
            with table.batch_writer() as batch:
                for log in logs:
                    if 'id' not in log:
                        log['id'] = f"log_{datetime.now().timestamp()}_{success_count}"
                    if 'timestamp' not in log:
                        log['timestamp'] = datetime.now().isoformat()
                    
                    log = self._convert_floats_to_decimal(log)
                    batch.put_item(Item=log)
                    success_count += 1
            
            logger.info(f"✅ Batch insert: {success_count} logs insertados")
            return success_count
            
        except Exception as e:
            logger.error(f"❌ Error en batch insert: {e}")
            return success_count


# Instancia global
dynamodb_client = DynamoDBClient()


if __name__ == "__main__":
    # Demo
    print("=" * 80)
    print("ATHENAI DYNAMODB CLIENT - DEMO")
    print("=" * 80)
    
    # Insertar log de tráfico
    print("\n📝 Insertando log de tráfico:")
    log_data = {
        'source_ip': '203.0.113.45',
        'method': 'POST',
        'path': '/api/login',
        'status_code': 403,
        'risk_score': 85.5,
        'attack_type': 'SQL Injection'
    }
    
    success = dynamodb_client.insert_traffic_log(log_data)
    print(f"   {'✅ Insertado' if success else '❌ Error'}")
    
    # Insertar alerta
    print("\n🚨 Insertando alerta de seguridad:")
    alert_data = {
        'type': 'threat_blocked',
        'severity': 'high',
        'source_ip': '203.0.113.45',
        'risk_score': 85.5,
        'attack_type': 'SQL Injection'
    }
    
    success = dynamodb_client.insert_alert(alert_data)
    print(f"   {'✅ Insertado' if success else '❌ Error'}")
    
    # Insertar IP bloqueada
    print("\n🚫 Registrando IP bloqueada:")
    ip_data = {
        'ip_address': '203.0.113.45',
        'reason': 'SQL Injection attempt',
        'duration': 3600,
        'permanent': False
    }
    
    success = dynamodb_client.insert_blocked_ip(ip_data)
    print(f"   {'✅ Insertado' if success else '❌ Error'}")
    
    # Obtener logs
    print("\n🔍 Obteniendo logs de tráfico:")
    logs = dynamodb_client.get_traffic_logs(limit=10)
    print(f"   Logs encontrados: {len(logs)}")
    
    # Obtener alertas
    print("\n🔍 Obteniendo alertas de severidad 'high':")
    alerts = dynamodb_client.get_alerts(severity='high', limit=10)
    print(f"   Alertas encontradas: {len(alerts)}")
    
    # Estadísticas
    print("\n📊 Estadísticas de tráfico:")
    stats = dynamodb_client.get_traffic_stats()
    print(f"   Total logs: {stats.get('total_logs', 0)}")
    
    print("\n" + "=" * 80)
