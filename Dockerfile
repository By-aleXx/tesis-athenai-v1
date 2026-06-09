FROM python:3.13-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONUTF8=1

RUN useradd -u 10001 -m app

WORKDIR /app

COPY athenai-dashboard/requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

COPY --chown=app:app athenai-dashboard/ .

USER app

# V-08: sin proxy delante por defecto; poner TRUSTED_PROXY_HOPS=1 si hay Nginx/ALB
ENV TRUSTED_PROXY_HOPS=0
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health').status==200 else 1)"

CMD ["gunicorn", "-c", "gunicorn.conf.py", "wsgi:app"]
