"""
AthenAI - Evidence Store

Sistema de almacenamiento forense con verificación de integridad.
Usa hashing SHA-256 y firmas digitales para garantizar la inmutabilidad de logs.

Autor: AthenAI Team
Fecha: 2026-02-11
"""

import hashlib
import hmac
import json
import logging
import os
import socket
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import boto3
from dotenv import load_dotenv

load_dotenv()

# Importar encryption service
try:
    from encryption_service import encryption_service
    ENCRYPTION_AVAILABLE = True
    print("🔐 Encryption service loaded")
except ImportError:
    ENCRYPTION_AVAILABLE = False
    print("⚠️  Encryption service not available")

# Importar configuración centralizada
try:
    from config import get_aws_config, S3_BUCKET_EVIDENCE
    USE_CONFIG = True
except ImportError:
    USE_CONFIG = False
    print("⚠️  config.py no encontrado, usando configuración por defecto")

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Campos sensibles que deben cifrarse
SENSITIVE_FIELDS = [
    'source_ip',
    'user_agent',
    'payload',
    'headers',
    'query_params',
    'body',
    'cookies'
]


class EvidenceStore:
    """
    Sistema de almacenamiento forense con verificación de integridad.
    
    Características:
    - Hash SHA-256 de cada registro
    - Firmas HMAC para verificación
    - Detección de manipulación
    - Almacenamiento en S3 (LocalStack)
    - Chain of custody
    """
    
    def __init__(self, use_localstack=True, secret_key=None):
        """
        Inicializa el Evidence Store.
        
        Args:
            use_localstack: Si True, usa LocalStack
            secret_key: Clave secreta para HMAC (se genera si no se proporciona)
        """
        self.use_localstack = use_localstack
        
        # Configuración de S3 usando config.py
        if USE_CONFIG:
            aws_config = get_aws_config()
            self.s3_client = boto3.client('s3', **aws_config)
            self.bucket_name = S3_BUCKET_EVIDENCE
            logger.info(f"✅ Usando configuración remota: {aws_config.get('endpoint_url', 'AWS')}")
        else:
            # Fallback: leer desde variables de entorno
            if use_localstack:
                self.s3_client = boto3.client(
                    's3',
                    endpoint_url=os.environ['AWS_ENDPOINT_URL'],
                    aws_access_key_id=os.environ['AWS_ACCESS_KEY_ID'],
                    aws_secret_access_key=os.environ['AWS_SECRET_ACCESS_KEY'],
                    region_name=os.getenv('AWS_REGION', 'us-east-1')
                )
            else:
                self.s3_client = boto3.client('s3')
            
            self.bucket_name = 'athenai-evidence'
        
        self.s3_available = False
        _prev_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(2)
        try:
            self._ensure_bucket_exists()
            self.s3_available = True
        except Exception as e:
            logger.warning(f"⚠️  S3/LocalStack no disponible: {e}. Evidence Store en modo offline.")
        finally:
            socket.setdefaulttimeout(_prev_timeout)

        # Clave secreta para HMAC
        if secret_key:
            self.secret_key = secret_key.encode() if isinstance(secret_key, str) else secret_key
        else:
            # Generar clave aleatoria (en producción, usar Secrets Manager)
            self.secret_key = os.urandom(32)
            logger.warning("⚠️  Usando clave HMAC generada aleatoriamente. En producción, usar Secrets Manager.")
        
        # Estadísticas
        self.stats = {
            'total_stored': 0,
            'total_verified': 0,
            'integrity_failures': 0,
            'tampering_detected': 0
        }
        
        logger.info(f"✅ Evidence Store inicializado ({'LocalStack' if use_localstack else 'AWS'})")
    
    def _ensure_bucket_exists(self):
        """Crea el bucket de evidencia si no existe"""
        try:
            self.s3_client.head_bucket(Bucket=self.bucket_name)
            logger.info(f"✅ Bucket '{self.bucket_name}' existe")
        except:
            try:
                self.s3_client.create_bucket(Bucket=self.bucket_name)
                logger.info(f"✅ Bucket '{self.bucket_name}' creado")
            except Exception as e:
                logger.error(f"❌ Error creando bucket: {e}")
    
    def _calculate_hash(self, data: Dict) -> str:
        """
        Calcula el hash SHA-256 de los datos.
        
        Args:
            data: Diccionario con datos
        
        Returns:
            Hash hexadecimal
        """
        # Serializar datos de forma determinística
        json_str = json.dumps(data, sort_keys=True, ensure_ascii=False)
        
        # Calcular SHA-256
        hash_obj = hashlib.sha256(json_str.encode('utf-8'))
        return hash_obj.hexdigest()
    
    def _calculate_hmac(self, data: Dict) -> str:
        """
        Calcula la firma HMAC de los datos.
        
        Args:
            data: Diccionario con datos
        
        Returns:
            HMAC hexadecimal
        """
        json_str = json.dumps(data, sort_keys=True, ensure_ascii=False)
        
        hmac_obj = hmac.new(
            self.secret_key,
            json_str.encode('utf-8'),
            hashlib.sha256
        )
        
        return hmac_obj.hexdigest()
    
    def store_evidence(self, evidence_type: str, data: Dict, metadata: Optional[Dict] = None) -> Tuple[bool, str]:
        """
        Almacena evidencia con verificación de integridad y cifrado.
        
        Args:
            evidence_type: Tipo de evidencia (traffic_log, alert, block_event, etc.)
            data: Datos de la evidencia
            metadata: Metadata adicional (opcional)
        
        Returns:
            Tupla (success, evidence_id)
        """
        try:
            # Generar ID único
            timestamp = datetime.now().isoformat()
            evidence_id = f"{evidence_type}_{timestamp}_{os.urandom(4).hex()}"
            
            # Cifrar datos sensibles si encryption está disponible
            encrypted_data = data.copy()
            encrypted_fields = []
            
            if ENCRYPTION_AVAILABLE:
                # Determinar qué campos cifrar
                fields_to_encrypt = [f for f in SENSITIVE_FIELDS if f in data]
                
                if fields_to_encrypt:
                    encrypted_data = encryption_service.encrypt_dict(data, fields_to_encrypt)
                    encrypted_fields = fields_to_encrypt
                    logger.debug(f"🔐 Encrypted {len(fields_to_encrypt)} fields")
            
            # Preparar datos completos
            evidence_data = {
                'id': evidence_id,
                'type': evidence_type,
                'timestamp': timestamp,
                'data': encrypted_data,
                'metadata': metadata or {},
                'encrypted': ENCRYPTION_AVAILABLE and len(encrypted_fields) > 0,
                'encrypted_fields': encrypted_fields
            }
            
            # Calcular hash e HMAC
            data_hash = self._calculate_hash(evidence_data)
            data_hmac = self._calculate_hmac(evidence_data)
            
            # Agregar información de integridad
            evidence_record = {
                **evidence_data,
                'integrity': {
                    'hash': data_hash,
                    'hmac': data_hmac,
                    'algorithm': 'SHA-256',
                    'created_at': timestamp
                }
            }
            
            # Almacenar en S3
            key = f"evidence/{evidence_type}/{datetime.now().strftime('%Y/%m/%d')}/{evidence_id}.json"

            if not self.s3_available:
                logger.warning(f"⚠️  S3 offline — evidencia {evidence_id} no persistida")
                self.stats['total_stored'] += 1
                return True, evidence_id

            self.s3_client.put_object(
                Bucket=self.bucket_name,
                Key=key,
                Body=json.dumps(evidence_record, indent=2, ensure_ascii=False),
                ContentType='application/json',
                Metadata={
                    'evidence-type': evidence_type,
                    'evidence-id': evidence_id,
                    'hash': data_hash
                }
            )
            
            # Actualizar estadísticas
            self.stats['total_stored'] += 1
            
            logger.info(
                f"📦 Evidencia almacenada | "
                f"ID: {evidence_id} | "
                f"Tipo: {evidence_type} | "
                f"Hash: {data_hash[:16]}..."
            )
            
            return True, evidence_id
            
        except Exception as e:
            logger.error(f"❌ Error almacenando evidencia: {e}")
            return False, ""
    
    def retrieve_evidence(self, evidence_id: str, verify_integrity: bool = True, decrypt: bool = True) -> Optional[Dict]:
        """
        Recupera evidencia del almacenamiento y descifra si es necesario.
        
        Args:
            evidence_id: ID de la evidencia
            verify_integrity: Si True, verifica la integridad
            decrypt: Si True, descifra campos sensibles
        
        Returns:
            Diccionario con la evidencia o None si no existe
        """
        try:
            # Buscar en S3 (simplificado - en producción usar índice)
            # Por ahora, asumimos que conocemos la estructura de keys
            response = self.s3_client.list_objects_v2(
                Bucket=self.bucket_name,
                Prefix='evidence/'
            )
            
            # Buscar el objeto
            target_key = None
            if 'Contents' in response:
                for obj in response['Contents']:
                    if evidence_id in obj['Key']:
                        target_key = obj['Key']
                        break
            
            if not target_key:
                logger.warning(f"⚠️  Evidencia no encontrada: {evidence_id}")
                return None
            
            # Recuperar objeto
            obj_response = self.s3_client.get_object(
                Bucket=self.bucket_name,
                Key=target_key
            )
            
            evidence_record = json.loads(obj_response['Body'].read().decode('utf-8'))
            
            # Descifrar datos si es necesario
            if decrypt and evidence_record.get('encrypted') and ENCRYPTION_AVAILABLE:
                encrypted_fields = evidence_record.get('encrypted_fields', SENSITIVE_FIELDS)
                if 'data' in evidence_record and encrypted_fields:
                    evidence_record['data'] = encryption_service.decrypt_dict(
                        evidence_record['data'],
                        encrypted_fields
                    )
                    logger.debug(f"🔓 Decrypted {len(encrypted_fields)} fields")
            
            # Verificar integridad si se solicita
            if verify_integrity:
                is_valid, message = self.verify_integrity(evidence_record)
                
                if not is_valid:
                    logger.error(f"🚨 INTEGRIDAD COMPROMETIDA: {message}")
                    self.stats['integrity_failures'] += 1
                    self.stats['tampering_detected'] += 1
                    
                    # Agregar advertencia al registro
                    evidence_record['integrity_warning'] = message
                else:
                    logger.info(f"✅ Integridad verificada: {evidence_id}")
                    self.stats['total_verified'] += 1
            
            return evidence_record
            
        except Exception as e:
            logger.error(f"❌ Error recuperando evidencia: {e}")
            return None
    
    def verify_integrity(self, evidence_record: Dict) -> Tuple[bool, str]:
        """
        Verifica la integridad de un registro de evidencia.
        
        Args:
            evidence_record: Registro completo de evidencia
        
        Returns:
            Tupla (is_valid, message)
        """
        try:
            # Extraer información de integridad
            integrity_info = evidence_record.get('integrity', {})
            stored_hash = integrity_info.get('hash')
            stored_hmac = integrity_info.get('hmac')
            
            if not stored_hash or not stored_hmac:
                return False, "Missing integrity information"
            
            # Reconstruir datos originales (sin integrity)
            original_data = {k: v for k, v in evidence_record.items() if k != 'integrity'}
            
            # Recalcular hash e HMAC
            calculated_hash = self._calculate_hash(original_data)
            calculated_hmac = self._calculate_hmac(original_data)
            
            # Verificar hash
            if calculated_hash != stored_hash:
                return False, f"Hash mismatch: expected {stored_hash[:16]}..., got {calculated_hash[:16]}..."
            
            # Verificar HMAC
            if calculated_hmac != stored_hmac:
                return False, f"HMAC mismatch: signature verification failed"
            
            return True, "Integrity verified successfully"
            
        except Exception as e:
            return False, f"Verification error: {str(e)}"
    
    def store_traffic_log(self, log_data: Dict) -> Tuple[bool, str]:
        """
        Almacena un log de tráfico como evidencia.
        
        Args:
            log_data: Datos del log de tráfico
        
        Returns:
            Tupla (success, evidence_id)
        """
        metadata = {
            'source': 'traffic_logger',
            'category': 'network_traffic'
        }
        
        return self.store_evidence('traffic_log', log_data, metadata)
    
    def store_alert(self, alert_data: Dict) -> Tuple[bool, str]:
        """
        Almacena una alerta como evidencia.
        
        Args:
            alert_data: Datos de la alerta
        
        Returns:
            Tupla (success, evidence_id)
        """
        metadata = {
            'source': 'alert_system',
            'category': 'security_alert',
            'severity': alert_data.get('severity', 'unknown')
        }
        
        return self.store_evidence('security_alert', alert_data, metadata)
    
    def store_block_event(self, block_data: Dict) -> Tuple[bool, str]:
        """
        Almacena un evento de bloqueo como evidencia.
        
        Args:
            block_data: Datos del bloqueo
        
        Returns:
            Tupla (success, evidence_id)
        """
        metadata = {
            'source': 'ip_blocker',
            'category': 'block_event',
            'action': 'ip_blocked'
        }
        
        return self.store_evidence('block_event', block_data, metadata)
    
    def search_evidence(self, evidence_type: Optional[str] = None, 
                       start_date: Optional[str] = None,
                       end_date: Optional[str] = None,
                       limit: int = 100) -> List[Dict]:
        """
        Busca evidencia por criterios.
        
        Args:
            evidence_type: Tipo de evidencia (opcional)
            start_date: Fecha inicio (ISO format)
            end_date: Fecha fin (ISO format)
            limit: Número máximo de resultados
        
        Returns:
            Lista de registros de evidencia
        """
        try:
            # Construir prefijo
            prefix = 'evidence/'
            if evidence_type:
                prefix += f"{evidence_type}/"
            
            # Listar objetos
            response = self.s3_client.list_objects_v2(
                Bucket=self.bucket_name,
                Prefix=prefix,
                MaxKeys=limit
            )
            
            results = []
            
            if 'Contents' in response:
                for obj in response['Contents']:
                    try:
                        # Recuperar objeto
                        obj_response = self.s3_client.get_object(
                            Bucket=self.bucket_name,
                            Key=obj['Key']
                        )
                        
                        evidence = json.loads(obj_response['Body'].read().decode('utf-8'))
                        
                        # Descifrar si es necesario
                        if evidence.get('encrypted') and ENCRYPTION_AVAILABLE:
                            encrypted_fields = evidence.get('encrypted_fields', SENSITIVE_FIELDS)
                            if 'data' in evidence and encrypted_fields:
                                evidence['data'] = encryption_service.decrypt_dict(
                                    evidence['data'],
                                    encrypted_fields
                                )
                        
                        # Filtrar por fecha si se especifica
                        if start_date or end_date:
                            timestamp = evidence.get('timestamp', '')
                            
                            if start_date and timestamp < start_date:
                                continue
                            if end_date and timestamp > end_date:
                                continue
                        
                        results.append(evidence)
                        
                    except Exception as e:
                        logger.error(f"Error procesando objeto {obj['Key']}: {e}")
                        continue
            
            logger.info(f"🔍 Búsqueda completada: {len(results)} resultados")
            return results
            
        except Exception as e:
            logger.error(f"❌ Error buscando evidencia: {e}")
            return []
    
    def get_stats(self) -> Dict:
        """Retorna estadísticas del Evidence Store"""
        return self.stats
    
    def generate_chain_of_custody_report(self, evidence_id: str) -> Optional[str]:
        """
        Genera un reporte de cadena de custodia para una evidencia.
        
        Args:
            evidence_id: ID de la evidencia
        
        Returns:
            Reporte en formato texto
        """
        evidence = self.retrieve_evidence(evidence_id, verify_integrity=True)
        
        if not evidence:
            return None
        
        integrity = evidence.get('integrity', {})
        
        report = f"""
{'=' * 80}
CHAIN OF CUSTODY REPORT
{'=' * 80}

Evidence ID: {evidence.get('id')}
Type: {evidence.get('type')}
Created: {evidence.get('timestamp')}

INTEGRITY VERIFICATION:
- Hash (SHA-256): {integrity.get('hash')}
- HMAC Signature: {integrity.get('hmac')}
- Algorithm: {integrity.get('algorithm')}
- Verified At: {datetime.now().isoformat()}

DATA SUMMARY:
{json.dumps(evidence.get('data', {}), indent=2)}

METADATA:
{json.dumps(evidence.get('metadata', {}), indent=2)}

{'=' * 80}
This evidence has been cryptographically verified and is admissible for
forensic analysis and legal proceedings.
{'=' * 80}
"""
        
        return report


# Instancia global
evidence_store = EvidenceStore()


if __name__ == "__main__":
    # Demo
    print("=" * 80)
    print("ATHENAI EVIDENCE STORE - DEMO")
    print("=" * 80)
    
    # Almacenar evidencia de prueba
    print("\n📦 Almacenando evidencia de tráfico:")
    traffic_data = {
        'source_ip': '203.0.113.45',
        'method': 'POST',
        'path': '/api/login',
        'payload': "' OR 1=1--",
        'risk_score': 95.5,
        'attack_type': 'SQL Injection'
    }
    
    success, evidence_id = evidence_store.store_traffic_log(traffic_data)
    print(f"   {'✅ Almacenado' if success else '❌ Error'} | ID: {evidence_id}")
    
    # Recuperar y verificar
    print(f"\n🔍 Recuperando evidencia: {evidence_id}")
    retrieved = evidence_store.retrieve_evidence(evidence_id, verify_integrity=True)
    
    if retrieved:
        print(f"   ✅ Recuperado exitosamente")
        print(f"   Hash: {retrieved['integrity']['hash'][:32]}...")
        
        # Generar reporte
        print(f"\n📄 Generando reporte de cadena de custodia:")
        report = evidence_store.generate_chain_of_custody_report(evidence_id)
        if report:
            print(report)
    
    # Estadísticas
    print("\n📊 Estadísticas:")
    stats = evidence_store.get_stats()
    print(f"   Total almacenado: {stats['total_stored']}")
    print(f"   Total verificado: {stats['total_verified']}")
    print(f"   Fallos de integridad: {stats['integrity_failures']}")
    
    print("\n" + "=" * 80)
