import jwt
import datetime
import time
from functools import wraps
from flask import request, jsonify, g

# Configuration
SECRET_KEY = "your-secret-key-change-in-production"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
REFRESH_TOKEN_EXPIRE_DAYS = 7

# Mock user database
USERS = {
    "admin": {
        "password_hash": "admin123", # In real app, use bcrypt hash
        "role": "admin",
        "email": "admin@athenai.io"
    },
    "analyst": {
        "password_hash": "analyst123",
        "role": "analyst",
        "email": "analyst@athenai.io"
    },
    "viewer": {
        "password_hash": "viewer123",
        "role": "viewer",
        "email": "viewer@athenai.io"
    }
}

class AuthManager:
    def __init__(self, secret_key=SECRET_KEY):
        self.secret_key = secret_key

    def verify_password(self, username, password):
        """Verify password for a user"""
        user = USERS.get(username)
        if not user:
            return False
        # In real app: return check_password_hash(user['password_hash'], password)
        return user['password_hash'] == password

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
