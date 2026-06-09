"""
AthenAI - WSGI entry point para producción (Gunicorn).
No usar el dev server de Flask en producción (V-01).
"""
from api_backend import app

if __name__ == '__main__':
    app.run()
