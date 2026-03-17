"""
System Health Monitor for AthenAI
Collects detailed system metrics: CPU, Memory, Disk, Redis, DynamoDB, S3, API, ML
"""

import os
import time
import shutil  # Para disk_usage en vez de psutil
import psutil
import redis
import boto3
from datetime import datetime
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)


class SystemHealthMonitor:
    """Monitors system health and collects metrics"""
    
    def __init__(self, use_localstack: bool = True):
        """Initialize health monitor"""
        self.use_localstack = use_localstack
        self.start_time = time.time()
        
        # Initialize clients
        self._init_redis()
        self._init_aws_clients()
        
        # Counters
        self.total_requests = 0
        self.total_errors = 0
        self.response_times = []
        
        logger.info("✅ System Health Monitor initialized")
    
    def _init_redis(self):
        """Initialize Redis client"""
        try:
            redis_host = os.getenv('REDIS_HOST', 'localhost')
            redis_port = int(os.getenv('REDIS_PORT', 6379))
            
            self.redis_client = redis.Redis(
                host=redis_host,
                port=redis_port,
                decode_responses=True,
                socket_connect_timeout=2
            )
            self.redis_client.ping()
            logger.info(f"✅ Redis connected: {redis_host}:{redis_port}")
        except Exception as e:
            logger.warning(f"⚠️  Redis not available: {e}")
            self.redis_client = None
    
    def _init_aws_clients(self):
        """Initialize AWS clients"""
        if self.use_localstack:
            endpoint_url = os.environ['AWS_ENDPOINT_URL']
            aws_config = {
                'endpoint_url': endpoint_url,
                'region_name': os.getenv('AWS_REGION', 'us-east-1'),
                'aws_access_key_id': os.environ['AWS_ACCESS_KEY_ID'],
                'aws_secret_access_key': os.environ['AWS_SECRET_ACCESS_KEY']
            }
        else:
            aws_config = {'region_name': os.getenv('AWS_REGION', 'us-east-1')}
        
        try:
            self.dynamodb = boto3.client('dynamodb', **aws_config)
            self.s3 = boto3.client('s3', **aws_config)
            self.cloudwatch = boto3.client('cloudwatch', **aws_config)
            logger.info("✅ AWS clients initialized")
        except Exception as e:
            logger.warning(f"⚠️  AWS clients error: {e}")
            self.dynamodb = None
            self.s3 = None
            self.cloudwatch = None
    
    def get_cpu_metrics(self) -> Dict[str, Any]:
        """Get CPU metrics"""
        try:
            cpu_percent = psutil.cpu_percent(interval=0.1)
            cpu_count = psutil.cpu_count()
            load_avg = psutil.getloadavg() if hasattr(psutil, 'getloadavg') else [0, 0, 0]
            
            return {
                "usage_percent": round(cpu_percent, 1),
                "cores": cpu_count,
                "load_average": [round(x, 2) for x in load_avg],
                "status": self._get_status(cpu_percent, 70, 90)
            }
        except Exception as e:
            logger.error(f"Error getting CPU metrics: {e}")
            return {"status": "error", "error": str(e)}
    
    def get_memory_metrics(self) -> Dict[str, Any]:
        """Get memory metrics"""
        try:
            mem = psutil.virtual_memory()
            
            return {
                "total_mb": round(mem.total / 1024 / 1024, 0),
                "used_mb": round(mem.used / 1024 / 1024, 0),
                "available_mb": round(mem.available / 1024 / 1024, 0),
                "usage_percent": round(mem.percent, 1),
                "status": self._get_status(mem.percent, 80, 95)
            }
        except Exception as e:
            logger.error(f"Error getting memory metrics: {e}")
            return {"status": "error", "error": str(e)}
    
    def get_disk_metrics(self) -> Dict[str, Any]:
        """Get disk metrics using shutil (cross-platform, more reliable than psutil for paths)"""
        try:
            # Usar el directorio actual para obtener el disco
            # shutil.disk_usage es más confiable en Windows que psutil para evitar problemas de formato
            usage = shutil.disk_usage('.')
            
            total_gb = usage.total / (1024**3)
            used_gb = usage.used / (1024**3)
            free_gb = usage.free / (1024**3)
            percent = (usage.used / usage.total) * 100
            
            return {
                "total_gb": round(total_gb, 1),
                "used_gb": round(used_gb, 1),
                "free_gb": round(free_gb, 1),
                "usage_percent": round(percent, 1),
                "status": self._get_status(percent, 80, 95),
                "path": os.path.abspath('.')
            }
        except Exception as e:
            logger.error(f"Error getting disk metrics: {e}")
            return {"status": "error", "error": str(e)}
    
    def get_process_metrics(self) -> Dict[str, Any]:
        """Get current process metrics"""
        try:
            process = psutil.Process()
            uptime = time.time() - self.start_time
            
            return {
                "pid": process.pid,
                "memory_mb": round(process.memory_info().rss / 1024 / 1024, 1),
                "cpu_percent": round(process.cpu_percent(interval=0.1), 1),
                "threads": process.num_threads(),
                "uptime_seconds": round(uptime, 0),
                "uptime_formatted": self._format_uptime(uptime),
                "status": "healthy"
            }
        except Exception as e:
            logger.error(f"Error getting process metrics: {e}")
            return {"status": "error", "error": str(e)}
    
    def get_redis_metrics(self) -> Dict[str, Any]:
        """Get Redis metrics"""
        if not self.redis_client:
            return {"status": "disconnected", "connected": False}
        
        try:
            info = self.redis_client.info()
            stats = self.redis_client.info('stats')
            
            # Calculate hit rate
            hits = stats.get('keyspace_hits', 0)
            misses = stats.get('keyspace_misses', 0)
            total = hits + misses
            hit_rate = (hits / total * 100) if total > 0 else 0
            
            return {
                "status": "healthy",
                "connected": True,
                "memory_used_mb": round(info.get('used_memory', 0) / 1024 / 1024, 1),
                "memory_peak_mb": round(info.get('used_memory_peak', 0) / 1024 / 1024, 1),
                "total_connections": info.get('total_connections_received', 0),
                "connected_clients": info.get('connected_clients', 0),
                "hit_rate_percent": round(hit_rate, 1),
                "total_commands": info.get('total_commands_processed', 0),
                "ops_per_sec": info.get('instantaneous_ops_per_sec', 0),
                "uptime_seconds": info.get('uptime_in_seconds', 0)
            }
        except Exception as e:
            logger.error(f"Error getting Redis metrics: {e}")
            return {"status": "error", "connected": False, "error": str(e)}
    
    def get_dynamodb_metrics(self) -> Dict[str, Any]:
        """Get DynamoDB metrics"""
        if not self.dynamodb:
            return {"status": "unavailable"}
        
        try:
            tables_data = {}
            # Nombres correctos de tablas DynamoDB (sin 'evidence_store' que es S3)
            table_names = ['athenai_traffic_logs', 'athenai_security_alerts', 'athenai_blocked_ips']
            
            for table_name in table_names:
                try:
                    response = self.dynamodb.describe_table(TableName=table_name)
                    table = response['Table']
                    
                    tables_data[table_name] = {
                        "item_count": table.get('ItemCount', 0),
                        "size_mb": round(table.get('TableSizeBytes', 0) / 1024 / 1024, 1),
                        "status": table.get('TableStatus', 'UNKNOWN')
                    }
                except Exception as e:
                    logger.warning(f"Table {table_name} not found: {e}")
                    tables_data[table_name] = {"status": "not_found"}
            
            return {
                "status": "healthy",
                "tables": tables_data,
                "total_tables": len([t for t in tables_data.values() if t.get('status') != 'not_found'])
            }
        except Exception as e:
            logger.error(f"Error getting DynamoDB metrics: {e}")
            return {"status": "error", "error": str(e)}
    
    def get_s3_metrics(self) -> Dict[str, Any]:
        """Get S3 metrics"""
        if not self.s3:
            return {"status": "unavailable"}
        
        try:
            buckets_data = {}
            bucket_name = 'athenai-evidence'
            
            try:
                # List objects in bucket
                response = self.s3.list_objects_v2(Bucket=bucket_name)
                objects = response.get('Contents', [])
                
                total_size = sum(obj.get('Size', 0) for obj in objects)
                last_modified = max([obj.get('LastModified') for obj in objects], default=None)
                
                buckets_data[bucket_name] = {
                    "objects_count": len(objects),
                    "size_mb": round(total_size / 1024 / 1024, 1),
                    "last_modified": last_modified.isoformat() if last_modified else None
                }
            except Exception as e:
                logger.warning(f"Bucket {bucket_name} error: {e}")
                buckets_data[bucket_name] = {"status": "not_found"}
            
            return {
                "status": "healthy",
                "buckets": buckets_data
            }
        except Exception as e:
            logger.error(f"Error getting S3 metrics: {e}")
            return {"status": "error", "error": str(e)}
    
    def get_api_metrics(self) -> Dict[str, Any]:
        """Get API metrics"""
        try:
            uptime = time.time() - self.start_time
            
            # Calculate average response time
            avg_response_time = 0
            if self.response_times:
                avg_response_time = sum(self.response_times[-100:]) / len(self.response_times[-100:])
            
            # Calculate error rate
            error_rate = 0
            if self.total_requests > 0:
                error_rate = (self.total_errors / self.total_requests) * 100
            
            # Calculate requests per minute
            rpm = 0
            if uptime > 0:
                rpm = (self.total_requests / uptime) * 60
            
            return {
                "status": "healthy",
                "uptime_seconds": round(uptime, 0),
                "uptime_formatted": self._format_uptime(uptime),
                "total_requests": self.total_requests,
                "requests_per_minute": round(rpm, 1),
                "avg_response_time_ms": round(avg_response_time, 1),
                "error_rate_percent": round(error_rate, 2),
                "total_errors": self.total_errors
            }
        except Exception as e:
            logger.error(f"Error getting API metrics: {e}")
            return {"status": "error", "error": str(e)}
    
    def get_ml_metrics(self) -> Dict[str, Any]:
        """Get ML models metrics"""
        try:
            # This would be populated by actual ML service
            # For now, return mock data
            return {
                "status": "healthy",
                "models_loaded": 2,
                "models": ["XGBoost", "Isolation Forest"],
                "total_predictions": 0,
                "avg_inference_time_ms": 0,
                "last_prediction": None
            }
        except Exception as e:
            logger.error(f"Error getting ML metrics: {e}")
            return {"status": "error", "error": str(e)}
    
    def get_all_metrics(self) -> Dict[str, Any]:
        """Get all system health metrics"""
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "cpu": self.get_cpu_metrics(),
            "memory": self.get_memory_metrics(),
            "disk": self.get_disk_metrics(),
            "process": self.get_process_metrics(),
            "redis": self.get_redis_metrics(),
            "dynamodb": self.get_dynamodb_metrics(),
            "s3": self.get_s3_metrics(),
            "api": self.get_api_metrics(),
            "ml": self.get_ml_metrics()
        }
    
    def record_request(self, response_time_ms: float, is_error: bool = False):
        """Record API request metrics"""
        self.total_requests += 1
        self.response_times.append(response_time_ms)
        
        # Keep only last 1000 response times
        if len(self.response_times) > 1000:
            self.response_times = self.response_times[-1000:]
        
        if is_error:
            self.total_errors += 1
    
    @staticmethod
    def _get_status(value: float, warning_threshold: float, critical_threshold: float) -> str:
        """Get status based on thresholds"""
        if value >= critical_threshold:
            return "critical"
        elif value >= warning_threshold:
            return "warning"
        else:
            return "healthy"
    
    @staticmethod
    def _format_uptime(seconds: float) -> str:
        """Format uptime in human-readable format"""
        days = int(seconds // 86400)
        hours = int((seconds % 86400) // 3600)
        minutes = int((seconds % 3600) // 60)
        
        if days > 0:
            return f"{days}d {hours}h {minutes}m"
        elif hours > 0:
            return f"{hours}h {minutes}m"
        else:
            return f"{minutes}m"


# Global instance
try:
    system_health_monitor = SystemHealthMonitor()
except Exception as e:
    logger.error(f"Error initializing System Health Monitor: {e}")
    system_health_monitor = None
