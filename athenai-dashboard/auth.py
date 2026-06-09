import os
import bcrypt
import jwt
import datetime
import time
from functools import wraps
from flask import request, jsonify, g

# Configuration
_JWT_SECRET = os.getenv('JWT_SECRET_KEY', '')
if not _JWT_SECRET:
    raise ValueError("JWT_SECRET_KEY no configurada en variables de entorno")
SECRET_KEY = _JWT_SECRET
ACCESS_TOKEN_EXPIRE_MINUTES = 60
REFRESH_TOKEN_EXPIRE_DAYS = 7

# SECURITY WARNING: This module (auth.py) is DEPRECATED — use auth_service.py instead.
# These hashes correspond to trivial passwords (admin123, analyst123, viewer123).
# Do NOT use in production. This dict exists only for legacy compatibility.
USERS = {
    "admin": {
        "password_hash": "$2b$12$zCcueiFpNKMJswfA5o8IUeQPBIUSClaHKhouYTFzJlk/0ESXA4oGa",
        "role": "admin",
        "email": "admin@athenai.io"
    },
    "analyst": {
        "password_hash": "$2b$12$whiKMhcdczRmzFjeBIWsteKGJL7hijZWpseZygqcJMt8VqjVLeE2m",
        "role": "analyst",
        "email": "analyst@athenai.io"
    },
    "viewer": {
        "password_hash": "$2b$12$0ZWKdvzRMAmou25YydNqeuTFgIJ0S37dkNLUcSR5yKj2f4sbncjnK",
        "role": "viewer",
        "email": "viewer@athenai.io"
    }
}

class AuthManager:
    def __init__(self, secret_key=SECRET_KEY):
        import warnings
        warnings.warn(
            "auth.py AuthManager is deprecated and uses hardcoded credentials. Use auth_service.py instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        self.secret_key = secret_key

    def verify_password(self, username, password):
        """Verify password for a user"""
        user = USERS.get(username)
        if not user:
            return False
        return bcrypt.checkpw(password.encode(), user['password_hash'].encode())

    def create_access_token(self, username, role):
        """Create a new access token"""
        expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        to_encode = {
            "sub": username,
            "role": role,
            "exp": expire,
            "type": "access"
        }
        return jwt.encode(to_encode, self.secret_key, algorithm="HS256")

    def create_refresh_token(self, username, role):
        """Create a new refresh token"""
        expire = datetime.datetime.utcnow() + datetime.timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
        to_encode = {
            "sub": username,
            "role": role,
            "exp": expire,
            "type": "refresh"
        }
        return jwt.encode(to_encode, self.secret_key, algorithm="HS256")

    def decode_token(self, token):
        """Decode and verify token"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=["HS256"])
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None

    def get_user(self, username):
        """Get user details"""
        user = USERS.get(username)
        if user:
            return {"username": username, "role": user["role"], "email": user["email"]}
        return None

# Global instance
auth_manager = AuthManager()
