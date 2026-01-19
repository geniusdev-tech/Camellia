from functools import wraps
from flask import request, jsonify, g
from core.iam.auth import AuthController
from core.iam.db import SessionLocal
import os

# Create a global instance or lazy load?
# Ideally we inject this. For decorators, we often just instantiate or import singleton.
# We'll use a helper that creates a fresh session.

def get_auth_controller():
    session = SessionLocal()
    return AuthController(session)

def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        token = None
        
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
        
        if not token:
             return jsonify({'error': 'Token is missing'}), 401
             
        controller = get_auth_controller()
        payload = controller.decode_token(token)
        
        if not payload:
             return jsonify({'error': 'Token is invalid or expired'}), 401
             
        # Store user info in g
        g.user_id = payload['sub']
        g.user_roles = payload.get('roles', [])
        
        return f(*args, **kwargs)
    return decorated_function

def require_role(role_name):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Ensure auth via require_auth or check here
            if not hasattr(g, 'user_roles'):
                 # Try to authenticate if not already done?
                 # Better to enforce require_auth usage first.
                 return jsonify({'error': 'Authentication required'}), 401
            
            # Simple check: assuming roles is a list of role names in the token
            # Or we might need to fetch from DB if we want real-time revocation.
            # For RBAC, typically checking the token claims is faster (stateless),
            # but for high security (Enterprise), we might want to check DB.
            # Current implementation puts role names in token for speed.
            
            if role_name not in g.user_roles and 'owner' not in g.user_roles:
                # Owner bypasses or we strictly enforce?
                # Let's say Owner has all access, but let's be explicit.
                if 'owner' in g.user_roles:
                    pass
                else:
                    return jsonify({'error': 'Insufficient permissions'}), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def require_permission(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not hasattr(g, 'user_id'):
                return jsonify({'error': 'Authentication required'}), 401
                
            # For permissions, we likely need to check the DB as they might be granular
            # and too large for JWT.
            session = SessionLocal()
            try:
                from core.iam.models import User
                user = session.query(User).get(g.user_id)
                if not user or not user.has_permission(permission):
                     return jsonify({'error': f'Missing permission: {permission}'}), 403
            finally:
                session.close()
                
            return f(*args, **kwargs)
        return decorated_function
    return decorator
