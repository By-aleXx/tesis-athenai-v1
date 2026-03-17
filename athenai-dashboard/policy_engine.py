"""
AthenAI - Policy Engine

Motor de decisión de políticas de seguridad.

Recibe el threat_score del AI Engine y decide qué acción tomar:
  ALLOW      →  0   - 30   (tráfico normal)
  LOG        →  30  - 60   (monitorear)
  ALERT      →  60  - 80   (notificar al administrador)
  RATE_LIMIT →  80  - 95   (ralentizar la conexión)
  BLOCK      →  95  - 100  (bloquear inmediatamente)

Separación de responsabilidades:
  - AI Engine: evalúa el riesgo y genera un score (0-100)
  - Policy Engine: decide la acción basándose en el score y el contexto

Autor: AthenAI Team
"""

import os
import logging
from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict, Any

from dotenv import load_dotenv
load_dotenv()

logger = logging.getLogger(__name__)


# ============================================================
# Enumeración de acciones posibles
# ============================================================

class PolicyAction(Enum):
    """Acciones que el Policy Engine puede ordenar"""
    ALLOW      = "allow"       # Dejar pasar la petición
    LOG        = "log"         # Registrar para análisis
    ALERT      = "alert"       # Notificar al administrador
    RATE_LIMIT = "rate_limit"  # Reducir velocidad de la conexión
    BLOCK      = "block"       # Bloquear la IP inmediatamente


# ============================================================
# Resultado de una decisión de política
# ============================================================

@dataclass
class PolicyDecision:
    """
    Resultado de evaluar una petición con el Policy Engine.

    Attributes:
        action:       Acción a ejecutar (PolicyAction)
        threat_score: Score de amenaza del AI Engine (0-100)
        threat_type:  Tipo de amenaza detectada (ej. "sql_injection")
        reason:       Explicación en texto de la decisión
        timestamp:    Momento de la decisión
        metadata:     Contexto adicional usado en la decisión
    """
    action: PolicyAction
    threat_score: float
    threat_type: str
    reason: str
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serializa la decisión a un diccionario JSON-serializable"""
        return {
            "action": self.action.value,
            "threat_score": self.threat_score,
            "threat_type": self.threat_type,
            "reason": self.reason,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }

    def __repr__(self):
        return (
            f"PolicyDecision(action={self.action.value!r}, "
            f"score={self.threat_score:.1f}, "
            f"type={self.threat_type!r}, "
            f"reason={self.reason!r})"
        )


# ============================================================
# Policy Engine
# ============================================================

class PolicyEngine:
    """
    Motor de decisión de políticas de seguridad.

    Evalúa el threat_score del AI Engine junto con el contexto
    de la petición y devuelve una PolicyDecision con la acción
    a ejecutar.

    Thresholds configurables (desde config.py o .env):
        THRESHOLD_LOW    (default 30)  → score < LOW  → ALLOW
        THRESHOLD_MEDIUM (default 60)  → score < MED  → LOG
        THRESHOLD_HIGH   (default 80)  → score < HIGH → ALERT
        THRESHOLD_CRITICAL (default 95)→ score < CRIT → RATE_LIMIT
                                       → score >= CRIT → BLOCK
    """

    def __init__(self):
        # Cargar thresholds desde config.py (con fallback a valores predeterminados)
        try:
            from config import (
                POLICY_ENGINE_DEFAULT_THRESHOLD_LOW,
                POLICY_ENGINE_DEFAULT_THRESHOLD_MEDIUM,
                POLICY_ENGINE_DEFAULT_THRESHOLD_HIGH,
            )
            self.threshold_low      = POLICY_ENGINE_DEFAULT_THRESHOLD_LOW
            self.threshold_medium   = POLICY_ENGINE_DEFAULT_THRESHOLD_MEDIUM
            self.threshold_high     = POLICY_ENGINE_DEFAULT_THRESHOLD_HIGH
        except ImportError:
            self.threshold_low      = 30.0
            self.threshold_medium   = 60.0
            self.threshold_high     = 80.0

        self.threshold_critical = 95.0

        logger.info(
            f"⚖️  Policy Engine inicializado | "
            f"Thresholds: ALLOW<{self.threshold_low} | "
            f"LOG<{self.threshold_medium} | "
            f"ALERT<{self.threshold_high} | "
            f"RATE_LIMIT<{self.threshold_critical} | "
            f"BLOCK>={self.threshold_critical}"
        )

    # ----------------------------------------------------------
    # Método principal
    # ----------------------------------------------------------

    def evaluate(
        self,
        threat_score: float,
        threat_type: str = "unknown",
        context: Optional[Dict[str, Any]] = None,
    ) -> PolicyDecision:
        """
        Evalúa un threat_score y devuelve la PolicyDecision correspondiente.

        Args:
            threat_score: Score de amenaza del AI Engine (0.0 – 100.0)
            threat_type:  Tipo de amenaza (ej. "sql_injection", "brute_force")
            context:      Contexto adicional:
                            - ip (str): IP de origen
                            - is_authenticated (bool): usuario autenticado
                            - is_whitelisted (bool): IP en lista blanca
                            - endpoint (str): ruta solicitada

        Returns:
            PolicyDecision con la acción a ejecutar.
        """
        context = context or {}

        # Las IPs en whitelist siempre pasan, sin importar el score
        if context.get("is_whitelisted"):
            return PolicyDecision(
                action=PolicyAction.ALLOW,
                threat_score=threat_score,
                threat_type=threat_type,
                reason="IP en lista blanca — acceso permitido automáticamente",
                metadata=context,
            )

        # Determinar acción según threshold
        action, reason = self._apply_thresholds(threat_score, threat_type, context)

        decision = PolicyDecision(
            action=action,
            threat_score=threat_score,
            threat_type=threat_type,
            reason=reason,
            metadata=context,
        )

        self._log_decision(decision)
        return decision

    # ----------------------------------------------------------
    # Lógica de thresholds
    # ----------------------------------------------------------

    def _apply_thresholds(
        self,
        score: float,
        threat_type: str,
        context: Dict[str, Any],
    ):
        """
        Aplica la tabla de thresholds y retorna (PolicyAction, reason).
        """
        if score < self.threshold_low:
            return (
                PolicyAction.ALLOW,
                f"Score {score:.1f} por debajo del umbral bajo ({self.threshold_low}) — tráfico normal",
            )

        if score < self.threshold_medium:
            return (
                PolicyAction.LOG,
                f"Score {score:.1f} entre {self.threshold_low}-{self.threshold_medium} — registrando para análisis",
            )

        if score < self.threshold_high:
            return (
                PolicyAction.ALERT,
                f"Score {score:.1f} entre {self.threshold_medium}-{self.threshold_high} — amenaza [{threat_type}] detectada, notificando",
            )

        if score < self.threshold_critical:
            return (
                PolicyAction.RATE_LIMIT,
                f"Score {score:.1f} entre {self.threshold_high}-{self.threshold_critical} — amenaza alta [{threat_type}], aplicando rate limiting",
            )

        return (
            PolicyAction.BLOCK,
            f"Score {score:.1f} ≥ {self.threshold_critical} — amenaza crítica [{threat_type}], bloqueando IP",
        )

    # ----------------------------------------------------------
    # Logging
    # ----------------------------------------------------------

    def _log_decision(self, decision: PolicyDecision):
        """Registra la decisión en el logger del sistema"""
        icon_map = {
            PolicyAction.ALLOW:      "✅",
            PolicyAction.LOG:        "📝",
            PolicyAction.ALERT:      "🚨",
            PolicyAction.RATE_LIMIT: "⏱️",
            PolicyAction.BLOCK:      "🚫",
        }
        icon = icon_map.get(decision.action, "⚖️")
        logger.info(
            f"{icon} PolicyEngine → {decision.action.value.upper()} "
            f"| score={decision.threat_score:.1f} "
            f"| type={decision.threat_type} "
            f"| {decision.reason}"
        )

    # ----------------------------------------------------------
    # Utilidades
    # ----------------------------------------------------------

    def get_thresholds(self) -> Dict[str, float]:
        """Retorna los thresholds configurados actualmente"""
        return {
            "allow_below":       self.threshold_low,
            "log_below":         self.threshold_medium,
            "alert_below":       self.threshold_high,
            "rate_limit_below":  self.threshold_critical,
            "block_at_or_above": self.threshold_critical,
        }

    def update_thresholds(
        self,
        low: Optional[float] = None,
        medium: Optional[float] = None,
        high: Optional[float] = None,
        critical: Optional[float] = None,
    ):
        """
        Actualiza los thresholds en tiempo de ejecución sin reiniciar.

        Args:
            low:      Nuevo umbral para ALLOW (default 30)
            medium:   Nuevo umbral para LOG (default 60)
            high:     Nuevo umbral para ALERT (default 80)
            critical: Nuevo umbral para BLOCK (default 95)
        """
        if low is not None:
            self.threshold_low = low
        if medium is not None:
            self.threshold_medium = medium
        if high is not None:
            self.threshold_high = high
        if critical is not None:
            self.threshold_critical = critical

        logger.info(f"⚖️  Thresholds actualizados: {self.get_thresholds()}")


# ============================================================
# Instancia global (importada por api_backend.py)
# ============================================================

policy_engine = PolicyEngine()
