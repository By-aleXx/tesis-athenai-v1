"""
IAM (Identity and Access Management) Manager
Provides role-based access control for AthenAI
"""

from enum import Enum
from typing import List, Dict, Optional
from functools import wraps
from flask import request, jsonify

class Role(Enum):
    """User roles with different permission levels"""
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"
    API_USER = "api_user"

class Permission(Enum):
    """Granular permissions for different operations"""
    # Read permissions
    READ_STATS = "read:stats"
    READ_TRAFFIC = "read:traffic"
    READ_ALERTS = "read:alerts"
    READ_MODELS = "read:models"
    READ_LOGS = "read:logs"
    READ_SYSTEM_HEALTH = "read:system_health"
    
    # Write permissions
    WRITE_MODELS = "write:models"
    WRITE_POLICIES = "write:policies"
    WRITE_ALERTS = "write:alerts"
    
    # Action permissions
    BLOCK_IPS = "block:ips"
    UNBLOCK_IPS = "unblock:ips"
    MANAGE_WHITELIST = "manage:whitelist"
    TRIGGER_RETRAIN = "trigger:retrain"
    DEPLOY_MODEL = "deploy:model"
    
    # Admin permissions
    MANAGE_USERS = "manage:users"
    MANAGE_ROLES = "manage:roles"
    MANAGE_SECRETS = "manage:secrets"
    VIEW_SENSITIVE_DATA = "view:sensitive_data"
    MANAGE_AB_TESTING = "manage:ab_testing"

class IAMManager:
    """
    Manages roles and permissions
    
    Features:
    - Role-based access control (RBAC)
    - Permission checking
    - Role hierarchy
    - Audit logging
    """
    
    def __init__(self):
        # Define permissions for each role
        self.role_permissions = {
            Role.ADMIN: [p for p in Permission],  # All permissions
            
            Role.ANALYST: [
                # Read permissions
                Permission.READ_STATS,
                Permission.READ_TRAFFIC,
                Permission.READ_ALERTS,
                Permission.READ_MODELS,
                Permission.READ_LOGS,
                Permission.READ_SYSTEM_HEALTH,
                # Write permissions
                Permission.WRITE_ALERTS,
                # Action permissions
                Permission.BLOCK_IPS,
                Permission.UNBLOCK_IPS,
                Permission.MANAGE_WHITELIST,
                Permission.TRIGGER_RETRAIN,
                Permission.MANAGE_AB_TESTING,
            ],
            
            Role.VIEWER: [
                # Read-only permissions
                Permission.READ_STATS,
                Permission.READ_TRAFFIC,
                Permission.READ_ALERTS,
                Permission.READ_SYSTEM_HEALTH,
            ],
            
            Role.API_USER: [
                # API access only
                Permission.READ_STATS,
                Permission.READ_MODELS,
                Permission.READ_SYSTEM_HEALTH,
            ],
        }
        
        # Audit log
        self.audit_log = []
    
    def has_permission(self, role: Role, permission: Permission) -> bool:
        """
        Check if role has permission
        
        Args:
            role: User role
            permission: Required permission
            
        Returns:
            True if role has permission
        """
        return permission in self.role_permissions.get(role, [])
    
    def get_user_permissions(self, user_role: str) -> List[str]:
        """
        Get all permissions for a user role
        
        Args:
            user_role: Role name as string
            
        Returns:
            List of permission strings
        """
        try:
            role = Role(user_role)
            return [p.value for p in self.role_permissions.get(role, [])]
        except ValueError:
            return []
    
    def check_permission(self, user_role: str, permission: Permission) -> bool:
        """
        Check if user role has specific permission
        
        Args:
            user_role: Role name as string
            permission: Required permission
            
        Returns:
            True if user has permission
        """
        try:
            role = Role(user_role)
            return self.has_permission(role, permission)
        except ValueError:
            return False
    
    def log_access(self, user: str, role: str, action: str, resource: str, allowed: bool):
        """
        Log access attempt for audit trail
        
        Args:
            user: Username
            role: User role
            action: Action attempted
            resource: Resource accessed
            allowed: Whether access was allowed
        """
        from datetime import datetime
        
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'user': user,
            'role': role,
            'action': action,
            'resource': resource,
            'allowed': allowed,
        }
        
        self.audit_log.append(log_entry)
        
        # Keep only last 1000 entries
        if len(self.audit_log) > 1000:
            self.audit_log = self.audit_log[-1000:]
    
    def get_audit_log(self, limit: int = 100) -> List[Dict]:
        """Get recent audit log entries"""
        return self.audit_log[-limit:]

# Global instance
iam_manager = IAMManager()

def require_permission(permission: Permission):
    """
    Decorator to require specific permission for an endpoint
    
    Usage:
        @app.route('/api/models/deploy', methods=['POST'])
        @require_permission(Permission.DEPLOY_MODEL)
        def deploy_model():
            # ... endpoint code ...
    
    Args:
        permission: Required permission
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Get user from request context (set by auth middleware)
            user_data = getattr(request, 'user_data', None)
            
            if not user_data:
                # Try to get from Authorization header
                from auth_service import auth_service_instance
                import jwt as _jwt
                token = request.headers.get('Authorization', '').replace('Bearer ', '')
                if token:
                    try:
                        user_data = auth_service_instance.verify_access_token(token)
                    except (_jwt.ExpiredSignatureError, _jwt.InvalidTokenError, Exception):
                        user_data = None

                if not user_data:
                    iam_manager.log_access('unknown', 'unknown', f.__name__, request.path, False)
                    return jsonify({'error': 'Unauthorized'}), 401
            
            # Check permission
            user_role = user_data.get('role', 'viewer')
            username = user_data.get('username', 'unknown')
            
            if not iam_manager.check_permission(user_role, permission):
                iam_manager.log_access(username, user_role, f.__name__, request.path, False)
                return jsonify({
                    'error': 'Forbidden',
                    'message': f'Role "{user_role}" does not have permission "{permission.value}"'
                }), 403
            
            # Log successful access
            iam_manager.log_access(username, user_role, f.__name__, request.path, True)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def require_role(role: Role):
    """
    Decorator to require specific role for an endpoint
    
    Usage:
        @app.route('/api/admin/users', methods=['GET'])
        @require_role(Role.ADMIN)
        def get_users():
            # ... endpoint code ...
    
    Args:
        role: Required role
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Get user from request context
            user_data = getattr(request, 'user_data', None)
            
            if not user_data:
                # Try to get from Authorization header
                from auth_service import auth_service_instance
                import jwt as _jwt
                token = request.headers.get('Authorization', '').replace('Bearer ', '')
                if token:
                    try:
                        user_data = auth_service_instance.verify_access_token(token)
                    except (_jwt.ExpiredSignatureError, _jwt.InvalidTokenError, Exception):
                        user_data = None

                if not user_data:
                    return jsonify({'error': 'Unauthorized'}), 401
            
            # Check role
            user_role = user_data.get('role', 'viewer')
            username = user_data.get('username', 'unknown')
            
            if user_role != role.value:
                iam_manager.log_access(username, user_role, f.__name__, request.path, False)
                return jsonify({
                    'error': 'Forbidden',
                    'message': f'This endpoint requires role "{role.value}"'
                }), 403
            
            # Log successful access
            iam_manager.log_access(username, user_role, f.__name__, request.path, True)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

if __name__ == "__main__":
    # Test IAM manager
    print("Testing IAM Manager...")
    
    # Test permissions
    print("\nAdmin permissions:")
    print(iam_manager.get_user_permissions('admin'))
    
    print("\nAnalyst permissions:")
    print(iam_manager.get_user_permissions('analyst'))
    
    print("\nViewer permissions:")
    print(iam_manager.get_user_permissions('viewer'))
    
    # Test permission checking
    print("\nPermission checks:")
    print(f"Analyst can block IPs: {iam_manager.check_permission('analyst', Permission.BLOCK_IPS)}")
    print(f"Viewer can block IPs: {iam_manager.check_permission('viewer', Permission.BLOCK_IPS)}")
    print(f"Admin can manage users: {iam_manager.check_permission('admin', Permission.MANAGE_USERS)}")
    
    # Test audit logging
    iam_manager.log_access('john', 'analyst', 'block_ip', '/api/blocked-ips', True)
    iam_manager.log_access('jane', 'viewer', 'block_ip', '/api/blocked-ips', False)
    
    print("\nAudit log:")
    for entry in iam_manager.get_audit_log():
        print(f"  {entry['timestamp']}: {entry['user']} ({entry['role']}) - {entry['action']} on {entry['resource']} - {'ALLOWED' if entry['allowed'] else 'DENIED'}")
