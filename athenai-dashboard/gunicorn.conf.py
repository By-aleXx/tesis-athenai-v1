"""Gunicorn configuration for AthenAI production."""
import multiprocessing

bind = '0.0.0.0:8000'
workers = multiprocessing.cpu_count() * 2 + 1
threads = 2
worker_class = 'gthread'
timeout = 30
graceful_timeout = 30
keepalive = 5

# V-08: solo confiar en XFF desde 127.0.0.1 (Nginx local)
forwarded_allow_ips = '127.0.0.1'
proxy_protocol = False

accesslog = '-'
errorlog = '-'
loglevel = 'info'
