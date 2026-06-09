"""
AthenAI - Rate Limiter

Sistema de limitación de tasa usando Redis con algoritmo Token Bucket.
Previene abuso y ataques DDoS mediante throttling configurable.

Autor: AthenAI Team
Fecha: 2026-02-11
"""

import redis
import logging
import time
from typing import Tuple, Optional, Dict
from datetime import datetime

# Importar configuración centralizada
try:
    from config import get_redis_config, get_rate_limits
    USE_CONFIG = True
except ImportError:
    USE_CONFIG = False
    print("⚠️  config.py no encontrado, usando configuración por defecto")

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class RateLimiter:
    """
    Rate Limiter usando algoritmo Token Bucket con Redis.
    
    Características:
    - Límites configurables por IP o por endpoint
    - Ventana deslizante (sliding window)
    - Estadísticas de uso
    - Múltiples niveles de límite
    """
    
    def __init__(self, redis_host='localhost', redis_port=6379, redis_db=1):
        """
        Inicializa el Rate Limiter.
        
        Args:
            redis_host: Host de Redis
            redis_port: Puerto de Redis
            redis_db: Base de datos de Redis (diferente a IP Blocker)
        """
        # Guardar config para reconexión lazy (cuando Tailscale no está disponible al inicio)
        self._redis_host = redis_host
        self._redis_port = redis_port
        self._redis_db = redis_db
        self._last_reconnect_attempt = 0  # Evitar reintentos demasiado frecuentes
        self._reconnect_interval = 30     # Reintentar cada 30 segundos
        
        self.redis_client = self._connect_redis()
        
        # Prefijo para keys
        self.RATE_LIMIT_PREFIX = "athenai:ratelimit:"
        
        # Configuración por defecto (requests por minuto)
        if USE_CONFIG:
            self.default_limits = get_rate_limits()
        else:
            self.default_limits = {
                'global': 100,      # 100 req/min global por IP
                'api': 60,          # 60 req/min para endpoints /api/*
                'security': 10,     # 10 req/min para /api/security/*
                'auth': 5           # 5 req/min para /api/auth/*
            }
        
        # Estadísticas
        self.stats = {
            'total_requests': 0,
            'rate_limited_requests': 0,
            'unique_ips': set()
        }
    
    def _connect_redis(self) -> object:
        """
        Intenta conectar a Redis. Retorna el cliente o None si no está disponible.
        Diseñado para ser llamado en startup y para reconexión lazy.
        """
        try:
            if USE_CONFIG:
                redis_config = get_redis_config()
                redis_config['db'] = 1  # db=1 para Rate Limiter (≠ IP Blocker db=0)
                client = redis.Redis(**redis_config)
                logger.info(f"✅ Usando configuración remota: {redis_config['host']}:{redis_config['port']}")
            else:
                client = redis.Redis(
                    host=self._redis_host,
                    port=self._redis_port,
                    db=self._redis_db,
                    decode_responses=True,
                    socket_timeout=2,
                    socket_connect_timeout=2,
                    socket_keepalive=True,
                    retry_on_timeout=True,
                    health_check_interval=30
                )
            
            client.ping()
            logger.info("✅ Rate Limiter conectado a Redis exitosamente")
            return client
        except (redis.ConnectionError, redis.TimeoutError) as e:
            logger.warning(f"⚠️  Redis no disponible (Tailscale inactivo?): {e}")
            logger.warning("⚠️  Rate Limiter en modo degradado — reintentará automáticamente")
            return None
        except Exception as e:
            logger.error(f"❌ Error inesperado conectando a Redis: {e}")
            logger.warning("⚠️  Rate Limiter en modo degradado — reintentará automáticamente")
            return None
    
    def _ensure_redis(self) -> bool:
        """
        Verifica si Redis está disponible. Si no lo está, intenta reconectar
        (máximo una vez cada 30s para no saturar la red Tailscale).
        
        Returns:
            True si Redis está disponible, False si no.
        """
        if self.redis_client is not None:
            return True
        
        # Reconexión lazy: solo reintentar cada 30 segundos
        now = time.time()
        if now - self._last_reconnect_attempt < self._reconnect_interval:
            return False
        
        self._last_reconnect_attempt = now
        logger.info("🔄 Intentando reconectar a Redis (Tailscale)...")
        self.redis_client = self._connect_redis()
        return self.redis_client is not None
    
    def _get_key(self, identifier: str, limit_type: str = 'global') -> str:
        """
        Genera la key de Redis para un identificador.
        
        Args:
            identifier: IP o identificador único
            limit_type: Tipo de límite (global, api, security, auth)
        
        Returns:
            Key de Redis
        """
        return f"{self.RATE_LIMIT_PREFIX}{limit_type}:{identifier}"
    
    def check_rate_limit(self, identifier: str, limit_type: str = 'global', 
                        custom_limit: Optional[int] = None) -> Tuple[bool, Dict]:
        """
        Verifica si un identificador ha excedido el rate limit.
        
        Args:
            identifier: IP o identificador único
            limit_type: Tipo de límite a aplicar
            custom_limit: Límite personalizado (sobrescribe default)
        
        Returns:
            Tupla (is_allowed, info_dict)
        """
        if not self._ensure_redis():
            # Sin Redis (Tailscale no disponible), permitir todo (fail-open)
            return True, {'allowed': True, 'reason': 'redis_unavailable'}
        
        # Determinar límite
        limit = custom_limit if custom_limit else self.default_limits.get(limit_type, 100)
        window = 60  # Ventana de 60 segundos
        
        try:
            key = self._get_key(identifier, limit_type)
            current_time = int(time.time())
            window_start = current_time - window
            
            # Usar sorted set para ventana deslizante
            pipe = self.redis_client.pipeline()
            
            # 1. Remover entradas antiguas fuera de la ventana
            pipe.zremrangebyscore(key, 0, window_start)
            
            # 2. Contar requests en la ventana actual
            pipe.zcard(key)
            
            # 3. Agregar request actual
            pipe.zadd(key, {current_time: current_time})
            
            # 4. Establecer expiración de la key
            pipe.expire(key, window + 10)
            
            # Ejecutar pipeline
            results = pipe.execute()
            request_count = results[1]  # Resultado del zcard
            
            # Verificar si excede el límite
            is_allowed = request_count < limit
            remaining = max(0, limit - request_count - 1)
            
            # Calcular tiempo de reset
            reset_time = current_time + window
            
            # Información de rate limit
            info = {
                'allowed': is_allowed,
                'limit': limit,
                'remaining': remaining,
                'reset_at': reset_time,
                'reset_in_seconds': window,
                'current_count': request_count + 1,
                'identifier': identifier,
                'limit_type': limit_type
            }
            
            # Actualizar estadísticas
            self.stats['total_requests'] += 1
            if len(self.stats['unique_ips']) < 10000:
                self.stats['unique_ips'].add(identifier)
            
            if not is_allowed:
                self.stats['rate_limited_requests'] += 1
                logger.warning(
                    f"⏱️  RATE LIMIT EXCEEDED | "
                    f"ID: {identifier} | "
                    f"Type: {limit_type} | "
                    f"Count: {request_count + 1}/{limit} | "
                    f"Reset in: {window}s"
                )
            else:
                logger.debug(
                    f"✅ Rate limit OK | "
                    f"ID: {identifier} | "
                    f"Count: {request_count + 1}/{limit} | "
                    f"Remaining: {remaining}"
                )
            
            return is_allowed, info
            
        except (redis.TimeoutError, redis.ConnectionError) as e:
            # Error de Redis - permitir request pero loguear solo una vez cada minuto
            if not hasattr(self, '_last_redis_error_log') or time.time() - self._last_redis_error_log > 60:
                logger.error(f"❌ Error verificando rate limit: {e}")
                self._last_redis_error_log = time.time()
            
            # Permitir request cuando Redis falla (fail-open)
            return True, {'allowed': True, 'reason': 'redis_timeout'}
        
        except Exception as e:
            logger.error(f"❌ Error verificando rate limit: {e}")
            # En caso de error, permitir (fail-open)
            return True, {'allowed': True, 'error': str(e)}
    
    def get_limit_info(self, identifier: str, limit_type: str = 'global') -> Dict:
        """
        Obtiene información del rate limit sin incrementar el contador.
        
        Args:
            identifier: IP o identificador único
            limit_type: Tipo de límite
        
        Returns:
            Diccionario con información del límite
        """
        if not self._ensure_redis():
            return {'error': 'redis_unavailable'}
        
        try:
            key = self._get_key(identifier, limit_type)
            current_time = int(time.time())
            window = 60
            window_start = current_time - window
            
            # Limpiar entradas antiguas
            self.redis_client.zremrangebyscore(key, 0, window_start)
            
            # Contar requests actuales
            request_count = self.redis_client.zcard(key)
            limit = self.default_limits.get(limit_type, 100)
            remaining = max(0, limit - request_count)
            
            return {
                'identifier': identifier,
                'limit_type': limit_type,
                'limit': limit,
                'current_count': request_count,
                'remaining': remaining,
                'window_seconds': window
            }
            
        except Exception as e:
            logger.error(f"Error obteniendo info de rate limit: {e}")
            return {'error': str(e)}
    
    def reset_limit(self, identifier: str, limit_type: str = 'global') -> bool:
        """
        Resetea el contador de rate limit para un identificador.
        
        Args:
            identifier: IP o identificador único
            limit_type: Tipo de límite
        
        Returns:
            True si se reseteó exitosamente
        """
        if not self._ensure_redis():
            return False
        
        try:
            key = self._get_key(identifier, limit_type)
            result = self.redis_client.delete(key)
            
            if result > 0:
                logger.info(f"✅ Rate limit reseteado: {identifier} ({limit_type})")
                return True
            return False
            
        except Exception as e:
            logger.error(f"Error reseteando rate limit: {e}")
            return False
    
    def set_custom_limit(self, limit_type: str, limit: int):
        """
        Establece un límite personalizado para un tipo.
        
        Args:
            limit_type: Tipo de límite
            limit: Nuevo límite (requests por minuto)
        """
        self.default_limits[limit_type] = limit
        logger.info(f"✅ Límite actualizado: {limit_type} = {limit} req/min")
    
    def get_stats(self) -> Dict:
        """
        Obtiene estadísticas del rate limiter.
        
        Returns:
            Diccionario con estadísticas
        """
        total = self.stats['total_requests']
        rate_limited = self.stats['rate_limited_requests']
        
        return {
            'total_requests': total,
            'rate_limited_requests': rate_limited,
            'allowed_requests': total - rate_limited,
            'unique_ips': len(self.stats['unique_ips']),
            'rate_limit_percentage': (rate_limited / total * 100) if total > 0 else 0,
            'configured_limits': self.default_limits
        }
    
    def clear_all_limits(self) -> int:
        """
        Limpia todos los contadores de rate limit.
        
        Returns:
            Número de keys eliminadas
        """
        if not self._ensure_redis():
            return 0
        
        try:
            keys = self.redis_client.keys(f"{self.RATE_LIMIT_PREFIX}*")
            if keys:
                count = self.redis_client.delete(*keys)
                logger.warning(f"⚠️  Se limpiaron {count} contadores de rate limit")
                return count
            return 0
            
        except Exception as e:
            logger.error(f"Error limpiando rate limits: {e}")
            return 0


# Instancia global
rate_limiter = RateLimiter()


if __name__ == "__main__":
    # Demo
    print("=" * 80)
    print("ATHENAI RATE LIMITER - DEMO")
    print("=" * 80)
    
    test_ip = "192.168.1.100"
    
    # Configurar límite bajo para demo
    rate_limiter.set_custom_limit('demo', 5)
    
    print(f"\n🧪 Simulando requests desde {test_ip}")
    print(f"   Límite: 5 requests/minuto\n")
    
    # Simular 10 requests
    for i in range(1, 11):
        is_allowed, info = rate_limiter.check_rate_limit(
            test_ip,
            limit_type='demo',
            custom_limit=5
        )
        
        status = "✅ PERMITIDO" if is_allowed else "🚫 BLOQUEADO"
        print(f"   Request {i}: {status} | Remaining: {info.get('remaining', 0)}")
        
        if not is_allowed:
            print(f"      ⏱️  Reset en: {info.get('reset_in_seconds', 0)}s")
        
        time.sleep(0.1)  # Pequeña pausa
    
    # Información del límite
    print(f"\n📊 Información del límite:")
    info = rate_limiter.get_limit_info(test_ip, 'demo')
    print(f"   Límite: {info.get('limit', 0)} req/min")
    print(f"   Usado: {info.get('current_count', 0)}")
    print(f"   Restante: {info.get('remaining', 0)}")
    
    # Estadísticas
    print(f"\n📈 Estadísticas globales:")
    stats = rate_limiter.get_stats()
    print(f"   Total requests: {stats['total_requests']}")
    print(f"   Rate limited: {stats['rate_limited_requests']}")
    print(f"   Permitidos: {stats['allowed_requests']}")
    print(f"   % Bloqueados: {stats['rate_limit_percentage']:.1f}%")
    
    print("\n" + "=" * 80)
