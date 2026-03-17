"""
Scheduler de Backups Automáticos para AthenAI

Ejecuta backups automáticos en segundo plano:
- Backups diarios a las 2:00 AM
- Backups semanales los domingos a las 3:00 AM
- Backups mensuales el día 1 a las 4:00 AM
- Limpieza de backups antiguos diariamente a las 5:00 AM
"""

import threading
import time
import logging
from datetime import datetime, timedelta
from typing import Optional

logger = logging.getLogger(__name__)


class BackupScheduler:
    def __init__(self, backup_service):
        """
        Inicializa el scheduler de backups.
        
        Args:
            backup_service: Instancia de BackupService
        """
        self.backup_service = backup_service
        self.running = False
        self.thread = None
        
        # Configuración de horarios (hora UTC)
        self.schedules = {
            'daily': {'hour': 2, 'minute': 0},      # 2:00 AM
            'weekly': {'hour': 3, 'minute': 0, 'weekday': 6},  # Domingo 3:00 AM
            'monthly': {'hour': 4, 'minute': 0, 'day': 1}      # Día 1, 4:00 AM
        }
        
        # Última ejecución
        self.last_run = {
            'daily': None,
            'weekly': None,
            'monthly': None,
            'cleanup': None
        }
        
        logger.info("✅ Backup Scheduler inicializado")
    
    def start(self):
        """Inicia el scheduler en segundo plano"""
        if self.running:
            logger.warning("⚠️  Scheduler ya está corriendo")
            return
        
        self.running = True
        self.thread = threading.Thread(target=self._run_loop, daemon=True)
        self.thread.start()
        
        logger.info("✅ Backup Scheduler iniciado")
    
    def stop(self):
        """Detiene el scheduler"""
        if not self.running:
            return
        
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        
        logger.info("✅ Backup Scheduler detenido")
    
    def _run_loop(self):
        """Loop principal del scheduler"""
        while self.running:
            try:
                now = datetime.utcnow()
                
                # Verificar si es hora de backup diario
                if self._should_run_daily(now):
                    logger.info("⏰ Ejecutando backup diario...")
                    self._run_daily_backup()
                    self.last_run['daily'] = now
                
                # Verificar si es hora de backup semanal
                if self._should_run_weekly(now):
                    logger.info("⏰ Ejecutando backup semanal...")
                    self._run_weekly_backup()
                    self.last_run['weekly'] = now
                
                # Verificar si es hora de backup mensual
                if self._should_run_monthly(now):
                    logger.info("⏰ Ejecutando backup mensual...")
                    self._run_monthly_backup()
                    self.last_run['monthly'] = now
                
                # Verificar si es hora de limpieza (diariamente a las 5:00 AM)
                if self._should_run_cleanup(now):
                    logger.info("⏰ Ejecutando limpieza de backups...")
                    self._run_cleanup()
                    self.last_run['cleanup'] = now
                
                # Dormir 60 segundos antes de verificar de nuevo
                time.sleep(60)
            
            except Exception as e:
                logger.error(f"Error en scheduler loop: {e}")
                time.sleep(60)
    
    def _should_run_daily(self, now: datetime) -> bool:
        """Verifica si debe ejecutar backup diario"""
        schedule = self.schedules['daily']
        last_run = self.last_run['daily']
        
        # Si nunca se ha ejecutado, no ejecutar ahora (esperar horario)
        if last_run is None:
            return False
        
        # Verificar si es la hora correcta
        if now.hour != schedule['hour'] or now.minute != schedule['minute']:
            return False
        
        # Verificar si ya se ejecutó hoy
        if last_run and last_run.date() == now.date():
            return False
        
        return True
    
    def _should_run_weekly(self, now: datetime) -> bool:
        """Verifica si debe ejecutar backup semanal"""
        schedule = self.schedules['weekly']
        last_run = self.last_run['weekly']
        
        if last_run is None:
            return False
        
        # Verificar día de la semana (0=lunes, 6=domingo)
        if now.weekday() != schedule['weekday']:
            return False
        
        # Verificar hora
        if now.hour != schedule['hour'] or now.minute != schedule['minute']:
            return False
        
        # Verificar si ya se ejecutó esta semana
        if last_run:
            days_since_last = (now - last_run).days
            if days_since_last < 7:
                return False
        
        return True
    
    def _should_run_monthly(self, now: datetime) -> bool:
        """Verifica si debe ejecutar backup mensual"""
        schedule = self.schedules['monthly']
        last_run = self.last_run['monthly']
        
        if last_run is None:
            return False
        
        # Verificar día del mes
        if now.day != schedule['day']:
            return False
        
        # Verificar hora
        if now.hour != schedule['hour'] or now.minute != schedule['minute']:
            return False
        
        # Verificar si ya se ejecutó este mes
        if last_run and last_run.month == now.month and last_run.year == now.year:
            return False
        
        return True
    
    def _should_run_cleanup(self, now: datetime) -> bool:
        """Verifica si debe ejecutar limpieza"""
        last_run = self.last_run['cleanup']
        
        if last_run is None:
            return False
        
        # Ejecutar a las 5:00 AM
        if now.hour != 5 or now.minute != 0:
            return False
        
        # Verificar si ya se ejecutó hoy
        if last_run and last_run.date() == now.date():
            return False
        
        return True
    
    def _run_daily_backup(self):
        """Ejecuta backup diario"""
        try:
            logger.info("📦 Iniciando backup diario...")
            
            # Backup de todas las tablas DynamoDB
            results = self.backup_service.backup_all_dynamodb_tables('daily')
            
            # Backup de buckets S3 importantes
            important_buckets = ['athenai-alertas', 'athenai-sagemaker-models']
            for bucket in important_buckets:
                try:
                    self.backup_service.backup_s3_bucket(bucket, 'daily')
                except Exception as e:
                    logger.error(f"Error backing up bucket {bucket}: {e}")
            
            logger.info("✅ Backup diario completado")
        
        except Exception as e:
            logger.error(f"Error en backup diario: {e}")
    
    def _run_weekly_backup(self):
        """Ejecuta backup semanal"""
        try:
            logger.info("📦 Iniciando backup semanal...")
            
            # Backup de todas las tablas DynamoDB
            results = self.backup_service.backup_all_dynamodb_tables('weekly')
            
            # Backup de todos los buckets S3
            s3_response = self.backup_service.s3.list_buckets()
            for bucket in s3_response.get('Buckets', []):
                bucket_name = bucket['Name']
                if bucket_name != self.backup_service.backup_bucket:
                    try:
                        self.backup_service.backup_s3_bucket(bucket_name, 'weekly')
                    except Exception as e:
                        logger.error(f"Error backing up bucket {bucket_name}: {e}")
            
            logger.info("✅ Backup semanal completado")
        
        except Exception as e:
            logger.error(f"Error en backup semanal: {e}")
    
    def _run_monthly_backup(self):
        """Ejecuta backup mensual"""
        try:
            logger.info("📦 Iniciando backup mensual...")
            
            # Backup de todas las tablas DynamoDB
            results = self.backup_service.backup_all_dynamodb_tables('monthly')
            
            # Backup de todos los buckets S3
            s3_response = self.backup_service.s3.list_buckets()
            for bucket in s3_response.get('Buckets', []):
                bucket_name = bucket['Name']
                if bucket_name != self.backup_service.backup_bucket:
                    try:
                        self.backup_service.backup_s3_bucket(bucket_name, 'monthly')
                    except Exception as e:
                        logger.error(f"Error backing up bucket {bucket_name}: {e}")
            
            logger.info("✅ Backup mensual completado")
        
        except Exception as e:
            logger.error(f"Error en backup mensual: {e}")
    
    def _run_cleanup(self):
        """Ejecuta limpieza de backups antiguos"""
        try:
            self.backup_service.cleanup_old_backups()
        except Exception as e:
            logger.error(f"Error en limpieza: {e}")
    
    def run_manual_backup(self, backup_type: str = 'daily'):
        """
        Ejecuta un backup manual.
        
        Args:
            backup_type: Tipo de backup (daily, weekly, monthly)
        """
        try:
            logger.info(f"📦 Ejecutando backup manual ({backup_type})...")
            
            if backup_type == 'daily':
                self._run_daily_backup()
            elif backup_type == 'weekly':
                self._run_weekly_backup()
            elif backup_type == 'monthly':
                self._run_monthly_backup()
            else:
                logger.error(f"Tipo de backup inválido: {backup_type}")
                return False
            
            return True
        
        except Exception as e:
            logger.error(f"Error en backup manual: {e}")
            return False
