"""
AthenAI - Database Models
Modelos SQLAlchemy para el sistema de logging de tráfico
"""

from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, JSON
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

Base = declarative_base()


class TrafficLog(Base):
    """
    Modelo para almacenar logs de tráfico HTTP
    Incluye marcado especial para pruebas de seguridad autorizadas
    """
    __tablename__ = 'traffic_logs'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    # Información de origen
    source_ip = Column(String(45), nullable=False, index=True)  # IPv4 o IPv6
    user_agent = Column(Text, nullable=True)
    
    # Detalles de la solicitud
    method = Column(String(10), nullable=False)  # GET, POST, PUT, DELETE, etc.
    path = Column(String(500), nullable=False, index=True)
    query_params = Column(Text, nullable=True)  # Parámetros de consulta como string
    
    # Headers y Body (JSON para facilitar análisis)
    headers = Column(JSON, nullable=True)
    body = Column(Text, nullable=True)  # Body de la solicitud
    
    # Información de respuesta
    response_status = Column(Integer, nullable=True)
    
    # Marcador especial para pruebas de seguridad
    is_test_attack = Column(Boolean, default=False, nullable=False, index=True)
    
    # Metadata adicional
    content_type = Column(String(100), nullable=True)
    content_length = Column(Integer, nullable=True)
    
    def __repr__(self):
        attack_marker = "🔴 TEST ATTACK" if self.is_test_attack else "🟢 Normal"
        return f"<TrafficLog {self.id} [{attack_marker}] {self.method} {self.path} from {self.source_ip}>"
    
    def to_dict(self):
        """Convierte el modelo a diccionario para JSON"""
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'source_ip': self.source_ip,
            'user_agent': self.user_agent,
            'method': self.method,
            'path': self.path,
            'query_params': self.query_params,
            'headers': self.headers,
            'body': self.body,
            'response_status': self.response_status,
            'is_test_attack': self.is_test_attack,
            'content_type': self.content_type,
            'content_length': self.content_length
        }
