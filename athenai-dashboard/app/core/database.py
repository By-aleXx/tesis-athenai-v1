"""
AthenAI - Database Configuration
Configuración de SQLAlchemy y funciones helper para la base de datos
"""

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, scoped_session
import os
from app.core.models import Base, TrafficLog

# app/core -> app -> athenai-dashboard (donde vive traffic_logs.db)
_DASHBOARD_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DB_PATH = os.path.join(_DASHBOARD_ROOT, 'traffic_logs.db')
DATABASE_URL = f'sqlite:///{DB_PATH}'

def _set_pragmas(dbapi_conn, _):
    dbapi_conn.execute('PRAGMA journal_mode=WAL')
    dbapi_conn.execute('PRAGMA busy_timeout=5000')   # espera 5s antes de fallar por lock
    dbapi_conn.execute('PRAGMA synchronous=NORMAL')  # balance velocidad/seguridad

engine = create_engine(
    DATABASE_URL,
    connect_args={'check_same_thread': False},
    pool_size=10,
    max_overflow=20,
    pool_timeout=10,
    pool_pre_ping=True,
    echo=False
)
event.listen(engine, 'connect', _set_pragmas)

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
                     content_type=None, content_length=None,
                     risk_score=None, ai_prediction=None):
    Session = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = Session()
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
            content_length=content_length,
            risk_score=risk_score,
            ai_prediction=ai_prediction,
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
    Session = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = Session()
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
    Session = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = Session()
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
