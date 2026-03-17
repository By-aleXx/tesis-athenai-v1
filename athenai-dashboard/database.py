"""
AthenAI - Database Configuration
Configuración de SQLAlchemy y funciones helper para la base de datos
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.pool import StaticPool
import os
from models import Base, TrafficLog

# Configuración de la base de datos
DB_PATH = os.path.join(os.path.dirname(__file__), 'traffic_logs.db')
DATABASE_URL = f'sqlite:///{DB_PATH}'

# Crear engine con configuración para SQLite
engine = create_engine(
    DATABASE_URL,
    connect_args={'check_same_thread': False},  # Necesario para SQLite con Flask
    poolclass=StaticPool,
    echo=False  # Cambiar a True para debug SQL
)

# Crear session factory
SessionLocal = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=engine))


def init_db():
    """
    Inicializa la base de datos creando todas las tablas
    """
    print(f"📦 Inicializando base de datos en: {DB_PATH}")
    Base.metadata.create_all(bind=engine)
    print("✅ Base de datos inicializada correctamente")


def get_db():
    """
    Obtiene una sesión de base de datos
    Usar con context manager:
    
    with get_db() as db:
        db.query(TrafficLog).all()
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def save_traffic_log(source_ip, method, path, headers=None, body=None, 
                     query_params=None, user_agent=None, is_test_attack=False,
                     content_type=None, content_length=None):
    """
    Guarda un log de tráfico en la base de datos
    
    Args:
        source_ip: IP de origen
        method: Método HTTP
        path: Ruta solicitada
        headers: Headers HTTP (dict)
        body: Body de la solicitud
        query_params: Parámetros de consulta
        user_agent: User-Agent
        is_test_attack: Si es una prueba de seguridad autorizada
        content_type: Content-Type de la solicitud
        content_length: Tamaño del contenido
    
    Returns:
        TrafficLog: El objeto guardado
    """
    db = SessionLocal()
    try:
        log = TrafficLog(
            source_ip=source_ip,
            method=method,
            path=path,
            headers=headers,
            body=body,
            query_params=query_params,
            user_agent=user_agent,
            is_test_attack=is_test_attack,
            content_type=content_type,
            content_length=content_length
        )
        db.add(log)
        db.commit()
        db.refresh(log)
        
        # Log especial para ataques de prueba
        if is_test_attack:
            print(f"🔴 TEST ATTACK LOGGED: {method} {path} from {source_ip}")
        
        return log
    except Exception as e:
        db.rollback()
        print(f"❌ Error guardando log de tráfico: {e}")
        raise
    finally:
        db.close()


def get_traffic_logs(limit=100, offset=0, is_test_attack=None, source_ip=None, exclude_source_ip=None):
    """
    Obtiene logs de tráfico con filtros opcionales
    
    Args:
        limit: Número máximo de resultados
        offset: Offset para paginación
        is_test_attack: Filtrar por test attacks (True/False/None)
        source_ip: Filtrar por IP específica
        exclude_source_ip: Excluir IP específica (ej: '127.0.0.1')
    
    Returns:
        List[TrafficLog]: Lista de logs
    """
    db = SessionLocal()
    try:
        query = db.query(TrafficLog)
        
        # Aplicar filtros
        if is_test_attack is not None:
            query = query.filter(TrafficLog.is_test_attack == is_test_attack)
        
        if source_ip:
            query = query.filter(TrafficLog.source_ip == source_ip)
        
        if exclude_source_ip:
            query = query.filter(TrafficLog.source_ip != exclude_source_ip)
        
        # Ordenar por timestamp descendente (más recientes primero)
        query = query.order_by(TrafficLog.timestamp.desc())
        
        # Aplicar paginación
        logs = query.limit(limit).offset(offset).all()
        
        return logs
    finally:
        db.close()


def get_traffic_stats():
    """
    Obtiene estadísticas de tráfico
    
    Returns:
        dict: Estadísticas
    """
    db = SessionLocal()
    try:
        total_requests = db.query(TrafficLog).count()
        test_attacks = db.query(TrafficLog).filter(TrafficLog.is_test_attack == True).count()
        normal_traffic = total_requests - test_attacks
        
        return {
            'total_requests': total_requests,
            'test_attacks': test_attacks,
            'normal_traffic': normal_traffic,
            'test_attack_percentage': (test_attacks / total_requests * 100) if total_requests > 0 else 0
        }
    finally:
        db.close()
