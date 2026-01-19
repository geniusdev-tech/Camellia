from flask import Blueprint, request, jsonify, session, g
from core.iam.db import SessionLocal
from core.iam.auth import AuthController
from core.iam.models import User
from core.iam.rbac import require_auth, get_auth_controller

auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('email')
    password = data.get('password')
    
    db = SessionLocal()
    try:
        user = db.query(User).filter_by(username=username).first()
        controller = AuthController(db)
        
        # 1. Verify Password
        if not user or not controller.verify_password(user.password_hash, password):
            return jsonify({'success': False, 'msg': 'Credenciais inválidas'}), 401
            
        if not user.is_active:
            return jsonify({'success': False, 'msg': 'Conta desativada'}), 403
            
        # 2. Unwrap Master Key
        master_key = None
        if user.wrapped_key:
            try:
                import json
                from core.crypto.engine import CryptoEngine
                crypto = CryptoEngine()
                wrapped_data = json.loads(user.wrapped_key)
                master_key = crypto.unwrap_master_key(wrapped_data, password)
            except Exception as e:
                # Log error
                print(f"Key Unwrap Failed: {e}")
                return jsonify({'success': False, 'msg': 'Erro crítico: Falha ao descriptografar Chave Mestra'}), 500

        # Check MFA
        if user.mfa_secret_enc:
            # Store MK temporarily in session or key_manager with "pending" flag?
            # Better: key_manager keyed by a temp pre-auth ID.
            session['pre_auth_user_id'] = user.id
            
            # Store MK in KeyManager temporarily? Or just keep in memory? 
            # If we don't store it, we can't get it after MFA without asking password again.
            # So we store it in KeyManager but maybe with a short TTL.
            if master_key:
                from core.iam.session import key_manager
                key_manager.store_key(f"pre_auth_{user.id}", master_key, ttl=300)
                
            return jsonify({
                'success': False,
                'msg': 'MFA Required',
                'requires_mfa': True,
                'user_id': user.id 
            })
            
        # Success - Generate Tokens
        access_token = controller.create_access_token(user.id, [user.role.name] if user.role else [])
        refresh_token = controller.create_refresh_token(user.id)
        
        if master_key:
            from core.iam.session import key_manager
            key_manager.store_key(user.id, master_key)
        
        return jsonify({
            'success': True,
            'access_token': access_token,
            'refresh_token': refresh_token,
            'email': user.username,
            'role': user.role.name if user.role else None
        })
    finally:
        db.close()

@auth_bp.route('/login/mfa', methods=['POST'])
def login_mfa():
    data = request.json
    code = data.get('code')
    user_id = session.get('pre_auth_user_id') or data.get('user_id')
    
    if not user_id:
        return jsonify({'success': False, 'msg': 'Sessão inválida. Faça login novamente.'}), 401
        
    db = SessionLocal()
    try:
        user = db.query(User).get(user_id)
        controller = AuthController(db)
        
        if not user or not user.mfa_secret_enc:
             return jsonify({'success': False, 'msg': 'Erro na validação MFA'}), 400
             
        # In a real scenario we decrypt mfa_secret logic here if it was encrypted with master key.
        # But for now assuming `mfa_secret_enc` stores the secret (or we add logic to decrypt).
        # Our `models.py` says `mfa_secret_enc`. 
        # CAUTION: If we implemented Master Key encryption for this secret, we need the Master Key.
        # For Phase 1, we might store it "at rest encrypted" but need logic to unwrap.
        # Given `auth.py` implementation of `verify_totp_token` expects the raw secret.
        # Let's assume for this MVP step `mfa_secret_enc` holds the secret, or we need to manage encryption.
        # Current logic: `controller.verify_totp_token(user.mfa_secret_enc, code)`
        
        if controller.verify_totp_token(user.mfa_secret_enc, code):
            session.pop('pre_auth_user_id', None)
            
            # Promote Master Key from Pending to Active
            from core.iam.session import key_manager
            pending_key = key_manager.get_key(f"pre_auth_{user.id}")
            if pending_key:
                key_manager.store_key(user.id, pending_key)
                key_manager.clear_key(f"pre_auth_{user.id}")
            else:
                # Critical edge case: Key expired or lost?
                # Without password we can't recover it.
                return jsonify({'success': False, 'msg': 'Sessão expirada. Faça login novamente.'}), 401
            
            access_token = controller.create_access_token(user.id, [user.role.name] if user.role else [])
            refresh_token = controller.create_refresh_token(user.id)
            
            return jsonify({
                'success': True,
                'access_token': access_token,
                'refresh_token': refresh_token,
                'email': user.username,
                'role': user.role.name if user.role else None
            })
        else:
            return jsonify({'success': False, 'msg': 'Código MFA inválido'}), 401
    finally:
        db.close()

@auth_bp.route('/mfa/setup', methods=['POST'])
@require_auth
def setup_mfa():
    # User is in g.user_id
    db = SessionLocal()
    try:
        user = db.query(User).get(g.user_id)
        controller = AuthController(db)
        
        secret, qr_b64 = controller.generate_mfa_secret(user.username)
        
        # We don't save yet, we verify first
        # Store secret in session temporarily
        session['mfa_pending_secret'] = secret
        
        return jsonify({
            'success': True,
            'secret': secret,
            'qr_code': f"data:image/png;base64,{qr_b64}"
        })
    finally:
        db.close()

@auth_bp.route('/mfa/verify', methods=['POST'])
@require_auth
def verify_mfa_setup():
    data = request.json
    code = data.get('code')
    secret = session.get('mfa_pending_secret')
    
    if not secret:
        return jsonify({'success': False, 'msg': 'Nenhuma configuração MFA iniciada'}), 400
        
    db = SessionLocal()
    try:
        controller = AuthController(db)
        if controller.verify_totp_token(secret, code):
            # Safe to save
            user = db.query(User).get(g.user_id)
            user.mfa_secret_enc = secret
            db.commit()
            session.pop('mfa_pending_secret', None)
            return jsonify({'success': True, 'msg': 'MFA ativado com sucesso'})
        else:
             return jsonify({'success': False, 'msg': 'Código inválido'}), 400
    finally:
        db.close()

@auth_bp.route('/mfa/disable', methods=['POST'])
@require_auth
def disable_mfa():
    db = SessionLocal()
    try:
        user = db.query(User).get(g.user_id)
        if not user.mfa_secret_enc:
            return jsonify({'success': False, 'msg': 'MFA não está ativado'}), 400
            
        user.mfa_secret_enc = None
        db.commit()
        return jsonify({'success': True, 'msg': 'MFA desativado com sucesso'})
    finally:
        db.close()

@auth_bp.route('/status')
@require_auth
def status():
    # Since require_auth passed, token is valid
    return jsonify({
        'authenticated': True, 
        'user_id': g.user_id,
        'roles': g.user_roles
    })
