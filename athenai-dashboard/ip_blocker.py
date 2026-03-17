"""
AthenAI - IP Blocking Service

Sistema de bloqueo automático de IPs maliciosas usando Redis.
Soporta bloqueo temporal, permanente y whitelist.

Autor: AthenAI Team
Fecha: 2026-02-11
"""

import redis
import logging
from typing import Optional, List, Dict
from datetime import datetime, timedelta
import json

# Importar configuración centralizada
try:
    from config import get_redis_config
    USE_CONFIG = True
except ImportError:
    USE_CONFIG = False
    print("⚠️  config.py no encontrado, usando configuración por defecto")

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class IPBlocker:
    """
    Sistema de bloqueo de IPs con Redis.
    
    Características:
    - Bloqueo temporal con TTL
    - Bloqueo permanente
    - Whitelist de IPs confiables
    - Historial de bloqueos
    """
    
    def __init__(self, redis_host='localhost', redis_port=6379, redis_db=0):
        """
        Inicializa el IP Blocker.
        
        Args:
            redis_host: Host de Redis
            redis_port: Puerto de Redis
            redis_db: Base de datos de Redis
        """
        try:
            # Usar configuración centralizada si está disponible
            if USE_CONFIG:
                redis_config = get_redis_config()
                self.redis_client = redis.Redis(**redis_config)
                logger.info(f"✅ Usando configuración remota: {redis_config['host']}:{redis_config['port']}")
            else:
                # Fallback a parámetros
                self.redis_client = redis.Redis(
                    host=redis_host,
                    port=redis_port,
                    db=redis_db,
                    decode_responses=True
                )
            
            # Test de conexión
            self.redis_client.ping()
            logger.info(f"✅ Conectado a Redis exitosamente")
        except redis.ConnectionError as e:
            logger.error(f"❌ Error conectando a Redis: {e}")
            logger.warning("⚠️  IP Blocker funcionará en modo degradado (sin persistencia)")
            self.redis_client = None
        
        # Prefijos para keys de Redis
        self.BLOCKED_PREFIX = "athenai:blocked:"
        self.WHITELIST_PREFIX = "athenai:whitelist:"
        self.HISTORY_PREFIX = "athenai:block_history:"
        
        # Estadísticas
        self.stats = {
            'total_blocks': 0,
            'active_blocks': 0,
            'permanent_blocks': 0,
            'whitelisted_ips': 0
        }
        
        self._update_stats()
    
    def _update_stats(self):
        """Actualiza las estadísticas desde Redis"""
        if not self.redis_client:
            return
        
        try:
            # Contar IPs bloqueadas activas
            blocked_keys = self.redis_client.keys(f"{self.BLOCKED_PREFIX}*")
            self.stats['active_blocks'] = len(blocked_keys)
            
            # Contar bloqueos permanentes
            permanent = 0
            for key in blocked_keys:
                ttl = self.redis_client.ttl(key)
                if ttl == -1:  # Sin expiración = permanente
                    permanent += 1
            self.stats['permanent_blocks'] = permanent
            
            # Contar whitelist
            whitelist_keys = self.redis_client.keys(f"{self.WHITELIST_PREFIX}*")
            self.stats['whitelisted_ips'] = len(whitelist_keys)
            
        except Exception as e:
            logger.error(f"Error actualizando estadísticas: {e}")
    
    def is_blocked(self, ip: str) -> bool:
        """
        Verifica si una IP está bloqueada.
        
        Args:
            ip: Dirección IP a verificar
        
        Returns:
            True si está bloqueada, False en caso contrario
        """
        # Verificar whitelist primero
        if self.is_whitelisted(ip):
            return False
        
        if not self.redis_client:
            return False
        
        try:
            key = f"{self.BLOCKED_PREFIX}{ip}"
            return self.redis_client.exists(key) > 0
        except Exception as e:
            logger.error(f"Error verificando bloqueo de {ip}: {e}")
            return False
    
    def block_ip(self, ip: str, duration: int = 3600, reason: str = "Security threat") -> bool:
        """
        Bloquea una IP.
        
        Args:
            ip: Dirección IP a bloquear
            duration: Duración del bloqueo en segundos (-1 = permanente)
            reason: Razón del bloqueo
        
        Returns:
            True si se bloqueó exitosamente
        """
        # No bloquear IPs en whitelist
        if self.is_whitelisted(ip):
            logger.warning(f"⚠️  No se puede bloquear IP en whitelist: {ip}")
            return False
        
        if not self.redis_client:
            logger.warning(f"⚠️  Redis no disponible, no se puede bloquear {ip}")
            return False
        
        try:
            key = f"{self.BLOCKED_PREFIX}{ip}"
            
            # Datos del bloqueo
            block_data = {
                'ip': ip,
                'reason': reason,
                'blocked_at': datetime.now().isoformat(),
                'duration': duration,
                'permanent': duration == -1
            }
            
            # Guardar en Redis
            self.redis_client.set(key, json.dumps(block_data))
            
            # Establecer TTL si no es permanente
            if duration > 0:
                self.redis_client.expire(key, duration)
                unblock_time = datetime.now() + timedelta(seconds=duration)
                logger.warning(
                    f"🚫 IP bloqueada: {ip} | "
                    f"Razón: {reason} | "
                    f"Duración: {duration}s | "
                    f"Desbloqueo: {unblock_time.isoformat()}"
                )
            else:
                logger.error(
                    f"🚫 IP bloqueada PERMANENTEMENTE: {ip} | "
                    f"Razón: {reason}"
                )
            
            # Guardar en historial
            self._add_to_history(ip, block_data)
            
            # Actualizar estadísticas
            self.stats['total_blocks'] += 1
            self._update_stats()
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Error bloqueando IP {ip}: {e}")
            return False
    
    def unblock_ip(self, ip: str) -> bool:
        """
        Desbloquea una IP manualmente.
        
        Args:
            ip: Dirección IP a desbloquear
        
        Returns:
            True si se desbloqueó exitosamente
        """
        if not self.redis_client:
            return False
        
        try:
            key = f"{self.BLOCKED_PREFIX}{ip}"
            result = self.redis_client.delete(key)
            
            if result > 0:
                logger.info(f"✅ IP desbloqueada: {ip}")
                self._update_stats()
                return True
            else:
                logger.warning(f"⚠️  IP no estaba bloqueada: {ip}")
                return False
                
        except Exception as e:
            logger.error(f"❌ Error desbloqueando IP {ip}: {e}")
            return False
    
    def get_block_info(self, ip: str) -> Optional[Dict]:
        """
        Obtiene información sobre el bloqueo de una IP.
        
        Args:
            ip: Dirección IP
        
        Returns:
            Diccionario con información del bloqueo o None
        """
        if not self.redis_client:
            return None
        
        try:
            key = f"{self.BLOCKED_PREFIX}{ip}"
            data = self.redis_client.get(key)
            
            if data:
                block_info = json.loads(data)
                
                # Agregar TTL
                ttl = self.redis_client.ttl(key)
                if ttl > 0:
                    block_info['remaining_seconds'] = ttl
                    unblock_time = datetime.now() + timedelta(seconds=ttl)
                    block_info['unblock_at'] = unblock_time.isoformat()
                elif ttl == -1:
                    block_info['remaining_seconds'] = -1
                    block_info['unblock_at'] = 'Never (permanent)'
                
                return block_info
            
            return None
            
        except Exception as e:
            logger.error(f"Error obteniendo info de bloqueo para {ip}: {e}")
            return None
    
    def add_to_whitelist(self, ip: str, reason: str = "Trusted source") -> bool:
        """
        Agrega una IP a la whitelist.
        
        Args:
            ip: Dirección IP
            reason: Razón para agregar a whitelist
        
        Returns:
            True si se agregó exitosamente
        """
        if not self.redis_client:
            return False
        
        try:
            key = f"{self.WHITELIST_PREFIX}{ip}"
            
            whitelist_data = {
                'ip': ip,
                'reason': reason,
                'added_at': datetime.now().isoformat()
            }
            
            self.redis_client.set(key, json.dumps(whitelist_data))
            
            # Si estaba bloqueada, desbloquear
            if self.is_blocked(ip):
                self.unblock_ip(ip)
            
            logger.info(f"✅ IP agregada a whitelist: {ip} | Razón: {reason}")
            self._update_stats()
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Error agregando {ip} a whitelist: {e}")
            return False
    
    def remove_from_whitelist(self, ip: str) -> bool:
        """
        Remueve una IP de la whitelist.
        
        Args:
            ip: Dirección IP
        
        Returns:
            True si se removió exitosamente
        """
        if not self.redis_client:
            return False
        
        try:
            key = f"{self.WHITELIST_PREFIX}{ip}"
            result = self.redis_client.delete(key)
            
            if result > 0:
                logger.info(f"✅ IP removida de whitelist: {ip}")
                self._update_stats()
                return True
            else:
                logger.warning(f"⚠️  IP no estaba en whitelist: {ip}")
                return False
                
        except Exception as e:
            logger.error(f"❌ Error removiendo {ip} de whitelist: {e}")
            return False
    
    def is_whitelisted(self, ip: str) -> bool:
        """
        Verifica si una IP está en la whitelist.
        
        Args:
            ip: Dirección IP
        
        Returns:
            True si está en whitelist
        """
        if not self.redis_client:
            return False
        
        try:
            key = f"{self.WHITELIST_PREFIX}{ip}"
            return self.redis_client.exists(key) > 0
        except Exception as e:
            logger.error(f"Error verificando whitelist para {ip}: {e}")
            return False
    
    def _add_to_history(self, ip: str, block_data: Dict):
        """Agrega un bloqueo al historial"""
        if not self.redis_client:
            return
        
        try:
            key = f"{self.HISTORY_PREFIX}{ip}"
            
            # Agregar timestamp único
            history_entry = {
                **block_data,
                'id': datetime.now().timestamp()
            }
            
            # Usar lista de Redis para historial
            self.redis_client.lpush(key, json.dumps(history_entry))
            
            # Mantener solo últimos 100 registros
            self.redis_client.ltrim(key, 0, 99)
            
        except Exception as e:
            logger.error(f"Error agregando a historial: {e}")
    
    def get_history(self, ip: str, limit: int = 10) -> List[Dict]:
        """
        Obtiene el historial de bloqueos de una IP.
        
        Args:
            ip: Dirección IP
            limit: Número máximo de registros
        
        Returns:
            Lista de bloqueos históricos
        """
        if not self.redis_client:
            return []
        
        try:
            key = f"{self.HISTORY_PREFIX}{ip}"
            history = self.redis_client.lrange(key, 0, limit - 1)
            
            return [json.loads(entry) for entry in history]
            
        except Exception as e:
            logger.error(f"Error obteniendo historial de {ip}: {e}")
            return []
    
    def get_all_blocked_ips(self) -> List[Dict]:
        """
        Obtiene todas las IPs bloqueadas actualmente.
        
        Returns:
            Lista de IPs bloqueadas con su información
        """
        if not self.redis_client:
            return []
        
        try:
            blocked_ips = []
            keys = self.redis_client.keys(f"{self.BLOCKED_PREFIX}*")
            
            for key in keys:
                ip = key.replace(self.BLOCKED_PREFIX, '')
                info = self.get_block_info(ip)
                if info:
                    blocked_ips.append(info)
            
            return blocked_ips
            
        except Exception as e:
            logger.error(f"Error obteniendo IPs bloqueadas: {e}")
            return []
    
    def get_stats(self) -> Dict:
        """Retorna estadísticas del sistema"""
        self._update_stats()
        return self.stats
    
    def get_whitelist(self) -> List[Dict]:
        """
        Obtiene todas las IPs en la whitelist.
        
        Returns:
            Lista de IPs en whitelist con su información
        """
        if not self.redis_client:
            return []
        
        try:
            whitelist_ips = []
            keys = self.redis_client.keys(f"{self.WHITELIST_PREFIX}*")
            
            for key in keys:
                data = self.redis_client.get(key)
                if data:
                    ip_info = json.loads(data)
                    whitelist_ips.append(ip_info)
            
            return whitelist_ips
            
        except Exception as e:
            logger.error(f"Error obteniendo whitelist: {e}")
            return []
    
    def clear_all_blocks(self) -> int:
        """
        Limpia todos los bloqueos (usar con precaución).
        
        Returns:
            Número de IPs desbloqueadas
        """
        if not self.redis_client:
            return 0
        
        try:
            keys = self.redis_client.keys(f"{self.BLOCKED_PREFIX}*")
            if keys:
                count = self.redis_client.delete(*keys)
                logger.warning(f"⚠️  Se desbloquearon {count} IPs")
                self._update_stats()
                return count
            return 0
            
        except Exception as e:
            logger.error(f"Error limpiando bloqueos: {e}")
            return 0


# Instancia global
ip_blocker = IPBlocker()


if __name__ == "__main__":
    # Demo
    print("=" * 80)
    print("ATHENAI IP BLOCKER - DEMO")
    print("=" * 80)
    
    # Test IPs
    test_ips = [
        ("192.168.1.100", "Trusted internal IP"),
        ("10.0.0.50", "Suspicious activity"),
        ("203.0.113.45", "SQL Injection attempt"),
        ("198.51.100.10", "Brute force attack")
    ]
    
    # Agregar a whitelist
    print("\n✅ Agregando IP a whitelist:")
    ip_blocker.add_to_whitelist(test_ips[0][0], test_ips[0][1])
    
    # Bloquear IPs
    print("\n🚫 Bloqueando IPs:")
    ip_blocker.block_ip(test_ips[1][0], duration=60, reason=test_ips[1][1])
    ip_blocker.block_ip(test_ips[2][0], duration=3600, reason=test_ips[2][1])
    ip_blocker.block_ip(test_ips[3][0], duration=-1, reason=test_ips[3][1])
    
    # Verificar bloqueos
    print("\n🔍 Verificando bloqueos:")
    for ip, _ in test_ips:
        is_blocked = ip_blocker.is_blocked(ip)
        is_whitelisted = ip_blocker.is_whitelisted(ip)
        
        status = "🚫 BLOQUEADA" if is_blocked else "✅ PERMITIDA"
        if is_whitelisted:
            status += " (WHITELIST)"
        
        print(f"   {ip}: {status}")
        
        if is_blocked:
            info = ip_blocker.get_block_info(ip)
            if info:
                print(f"      Razón: {info['reason']}")
                print(f"      Desbloqueo: {info.get('unblock_at', 'N/A')}")
    
    # Estadísticas
    print("\n📊 Estadísticas:")
    stats = ip_blocker.get_stats()
    print(f"   Total bloqueos: {stats['total_blocks']}")
    print(f"   Bloqueos activos: {stats['active_blocks']}")
    print(f"   Bloqueos permanentes: {stats['permanent_blocks']}")
    print(f"   IPs en whitelist: {stats['whitelisted_ips']}")
    
    print("\n" + "=" * 80)
