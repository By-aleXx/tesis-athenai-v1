"""
AthenAI - ML Async Predictor
=============================

Ejecuta predicciones del AI Engine en un ThreadPoolExecutor para que
las llamadas a `predict()` nunca bloqueen el hilo principal de Flask.

Estrategia fire-and-forget por IP:
  - Al llegar un request, se lanza `predict_async()` para esa IP/payload.
  - El Future se almacena en `_pending_futures[ip]`.
  - En el SIGUIENTE request de la misma IP, se comprueba si el Future
    completó marcando la IP como amenaza → se reporta al llamante.

Uso típico en SecurityMiddleware.check_security():

    threat_result = ml_predictor.check_and_fire(ai_engine, ip, payload)
    if threat_result:
        # El análisis del request ANTERIOR terminó con is_threat=True
        block_ip(ip)
        return 403

Autor: AthenAI Team
Fecha: 2026-03-17
"""

from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor, Future
from threading import Lock
from typing import Callable, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Executor global — 4 workers es suficiente para el volumen esperado
# ---------------------------------------------------------------------------
_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="ml_predict")


# ---------------------------------------------------------------------------
# Estado interno de predicciones pendientes por IP
# ---------------------------------------------------------------------------
class _PredictionResult:
    """Encapsula el resultado de una predicción ML asíncrona."""
    __slots__ = ("label", "confidence", "payload", "timestamp")

    def __init__(self, label: str, confidence: float, payload: str):
        self.label = label
        self.confidence = confidence
        self.payload = payload
        self.timestamp = time.time()


class MLAsyncPredictor:
    """
    Motor de predicción ML no bloqueante para el pipeline de seguridad.

    Registra si una IP ya tiene una predicción pendiente o completada y
    expone `check_and_fire()` como interfaz única para SecurityMiddleware.
    """

    def __init__(self, max_tracked_ips: int = 5000, result_ttl_seconds: int = 60):
        """
        Args:
            max_tracked_ips: Máximo número de IPs cuyo resultado guardamos en memoria.
            result_ttl_seconds: Tiempo (seg) que conservamos un resultado antes de descartarlo.
        """
        self._pending: Dict[str, Future] = {}      # ip → Future en vuelo
        self._results: Dict[str, _PredictionResult] = {}  # ip → último resultado
        self._lock = Lock()
        self._max_ips = max_tracked_ips
        self._ttl = result_ttl_seconds

    # ------------------------------------------------------------------
    # Interfaz pública
    # ------------------------------------------------------------------

    def check_and_fire(
        self,
        ai_engine,
        ip: str,
        payload: str,
        callback: Optional[Callable[[str, float, str], None]] = None,
    ) -> Optional[_PredictionResult]:
        """
        Comprueba el resultado del análisis ML anterior de esta IP y lanza
        uno nuevo de forma asíncrona.

        Args:
            ai_engine:  Instancia de AIEngine (o None si no está disponible).
            ip:         IP del cliente que hace el request actual.
            payload:    Texto a analizar (método + path + body truncado).
            callback:   Función opcional llamada cuando la predicción termina:
                        callback(label, confidence, ip).

        Returns:
            - `None` si no hay resultado previo o el anterior era benigno.
            - `_PredictionResult` con label='malicious' si el análisis ANTERIOR
              determinó que esta IP es una amenaza.
        """
        threat_result = self._pop_threat_result(ip)

        if ai_engine is not None:
            self._fire(ai_engine, ip, payload, callback)

        return threat_result

    def pending_count(self) -> int:
        """Número de predicciones actualmente en vuelo."""
        with self._lock:
            return sum(1 for f in self._pending.values() if not f.done())

    # ------------------------------------------------------------------
    # Métodos privados
    # ------------------------------------------------------------------

    def _fire(
        self,
        ai_engine,
        ip: str,
        payload: str,
        callback: Optional[Callable],
    ) -> None:
        """Lanza la predicción en el ThreadPoolExecutor (no bloquea)."""
        with self._lock:
            # Si ya hay un Future en vuelo para esta IP, no lanzar otro
            existing = self._pending.get(ip)
            if existing is not None and not existing.done():
                return

        def _predict() -> Tuple[str, float]:
            try:
                label, confidence = ai_engine.predict(payload)
                result = _PredictionResult(label, confidence, payload)

                with self._lock:
                    # Guardar resultado (solo si es amenaza para no llenar memoria)
                    if label == "malicious":
                        self._results[ip] = result
                        self._evict_if_needed()

                    # Limpiar el Future completado
                    self._pending.pop(ip, None)

                if callback:
                    try:
                        callback(label, confidence, ip)
                    except Exception as cb_err:
                        logger.error(f"ML async callback error: {cb_err}")

                return label, confidence

            except Exception as exc:
                logger.error(f"ML async prediction error for {ip}: {exc}")
                with self._lock:
                    self._pending.pop(ip, None)
                return "benign", 0.0

        future = _executor.submit(_predict)

        with self._lock:
            self._pending[ip] = future

    def _pop_threat_result(self, ip: str) -> Optional[_PredictionResult]:
        """
        Retorna y elimina el resultado de amenaza previo para esta IP.
        Descarta resultados más viejos que TTL segundos.
        """
        with self._lock:
            result = self._results.get(ip)
            if result is None:
                return None

            # Descartar si expiró
            if time.time() - result.timestamp > self._ttl:
                self._results.pop(ip, None)
                return None

            # Consumir el resultado (solo bloquear una vez)
            self._results.pop(ip, None)
            return result

    def _evict_if_needed(self) -> None:
        """Elimina los resultados más viejos cuando se supera `_max_ips`."""
        if len(self._results) <= self._max_ips:
            return

        # Ordenar por timestamp ascendente y eliminar la mitad más vieja
        sorted_ips = sorted(self._results, key=lambda k: self._results[k].timestamp)
        for old_ip in sorted_ips[: len(sorted_ips) // 2]:
            self._results.pop(old_ip, None)


# ---------------------------------------------------------------------------
# Instancia global (singleton)
# ---------------------------------------------------------------------------
ml_predictor = MLAsyncPredictor()
