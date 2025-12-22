# HookProbe Fortress - Gunicorn Configuration
# Production WSGI server settings for Flask application
#
# Version: 5.4.0
# License: AGPL-3.0

import os
import multiprocessing

# Server socket
bind = os.environ.get("GUNICORN_BIND", "0.0.0.0:8443")
backlog = 512

# SSL/TLS configuration
certfile = os.environ.get("SSL_CERT", "/app/certs/cert.pem")
keyfile = os.environ.get("SSL_KEY", "/app/certs/key.pem")

# Worker processes
workers = int(os.environ.get("GUNICORN_WORKERS", min(multiprocessing.cpu_count(), 4)))
worker_class = "sync"
threads = int(os.environ.get("GUNICORN_THREADS", 4))
worker_connections = 1000
max_requests = 1000
max_requests_jitter = 50

# Timeout
timeout = 30
graceful_timeout = 30
keepalive = 2

# Logging
accesslog = "-"  # stdout
errorlog = "-"   # stderr
loglevel = os.environ.get("GUNICORN_LOG_LEVEL", "info")
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# Process naming
proc_name = "fts-web"

# Server mechanics
daemon = False
pidfile = None
umask = 0o022
user = None
group = None
tmp_upload_dir = None

# Security
limit_request_line = 4094
limit_request_fields = 100
limit_request_field_size = 8190

# Pre-fork hooks
def on_starting(server):
    """Called just before the master process is initialized."""
    pass

def on_reload(server):
    """Called before reloading workers."""
    pass

def when_ready(server):
    """Called when server is ready to accept connections."""
    pass

def pre_fork(server, worker):
    """Called just before a worker is forked."""
    pass

def post_fork(server, worker):
    """Called just after a worker has been forked."""
    pass

def worker_exit(server, worker):
    """Called just after a worker exits."""
    pass
