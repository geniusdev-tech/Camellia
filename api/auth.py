from flask import Blueprint, request, jsonify, session

auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')

def _get_auth_manager():
    from services import auth_manager
    return auth_manager

@auth_bp.route('/login', methods=['POST'])
def login():
    auth_manager = _get_auth_manager()
    data = request.json
    email = data.get('email')
    success, msg = auth_manager.login(email, data.get('password'))
    
    if success:
        session['user_email'] = email
        
        # Get 2FA status for frontend
        has_2fa = False
        import sqlite3
        try:
            c = sqlite3.connect(auth_manager.db_path).cursor()
            row = c.execute("SELECT totp_secret FROM users WHERE email=?", (email,)).fetchone()
            if row and row[0]:
                has_2fa = True
        except:
            pass
        
        return jsonify({
            'success': True,
            'msg': msg,
            'email': email,
            'has_2fa': has_2fa
        })
    elif msg == "AUTH_2FA_REQUIRED":
        session['pending_email'] = email
        return jsonify({'success': False, 'msg': msg, 'requires_2fa': True})
    return jsonify({'success': False, 'msg': msg})

@auth_bp.route('/register', methods=['POST'])
def register():
    auth_manager = _get_auth_manager()
    data = request.json
    success, msg = auth_manager.register(data.get('email'), data.get('password'))
    return jsonify({'success': success, 'msg': msg})

@auth_bp.route('/2fa/verify', methods=['POST'])
def verify_2fa():
    auth_manager = _get_auth_manager()
    data = request.json
    email = session.get('pending_email')
    if not email:
        return jsonify({'success': False, 'msg': 'Session expired or invalid'}), 401

    success, msg = auth_manager.verify_2fa(email, data.get('code'))
    if success:
        session.pop('pending_email', None)
        session['user_email'] = auth_manager.get_session()['email']
        return jsonify({'success': True, 'msg': msg})
    return jsonify({'success': False, 'msg': msg})

@auth_bp.route('/2fa/setup', methods=['POST'])
def setup_2fa():
    auth_manager = _get_auth_manager()
    # Ensure user is logged in
    s = auth_manager.get_session()
    if not s:
        return jsonify({'success': False, 'msg': 'Not authenticated'}), 401
    
    secret, qr_b64 = auth_manager.generate_2fa_secret(s['email'])
    return jsonify({
        'success': True,
        'secret': secret,
        'qr_code': f"data:image/png;base64,{qr_b64}"
    })

@auth_bp.route('/2fa/confirm', methods=['POST'])
def confirm_2fa():
    auth_manager = _get_auth_manager()
    s = auth_manager.get_session()
    if not s:
        return jsonify({'success': False, 'msg': 'Not authenticated'}), 401
    
    data = request.json
    success, msg = auth_manager.enable_2fa(s['email'], data.get('secret'), data.get('code'))
    return jsonify({'success': success, 'msg': msg})

@auth_bp.route('/2fa/disable', methods=['POST'])
def disable_2fa():
    auth_manager = _get_auth_manager()
    s = auth_manager.get_session()
    if not s:
        return jsonify({'success': False, 'msg': 'Not authenticated'}), 401
        
    success, msg = auth_manager.disable_2fa(s['email'])
    return jsonify({'success': success, 'msg': msg})

@auth_bp.route('/status')
def status():
    auth_manager = _get_auth_manager()
    s = auth_manager.get_session()
    if s:
        # Check if 2FA is enabled for UI state?
        # We might need to expose that info.
        conn = _get_conn_safe(auth_manager) # Helper access to db if needed, or better: add is_2fa_enabled to AuthManager
        # For now, let's just return what we have. 
        # Ideally we update AuthManager to return 2fa status in session or separate check.
        # Let's add a quick check using auth_manager internals (bit hacky but fast) or query DB.
        # Better: Update AuthManager later. For now, frontend just enables button if logged in.
        # Wait, if I want to show "Disable 2FA" vs "Enable 2FA", I need to know.
        # I'll add `has_2fa` to the response by querying DB.
        has_2fa = False
        import sqlite3
        try:
            c = sqlite3.connect(auth_manager.db_path).cursor()
            row = c.execute("SELECT totp_secret FROM users WHERE email=?", (s['email'],)).fetchone()
            if row and row[0]:
                has_2fa = True
        except:
            pass
            
        return jsonify({'authenticated': True, 'email': s['email'], 'has_2fa': has_2fa})
    return jsonify({'authenticated': False})

@auth_bp.route('/logout', methods=['POST'])
def logout():
    auth_manager = _get_auth_manager()
    auth_manager.logout()
    session.clear()
    # Also clean up pending logins for this email if possible?
    # Manager doesn't have a specific way to clean pending logins on logout,
    # but they will expire anyway.
    return jsonify({'success': True})

def _get_conn_safe(manager):
    # Just a helper placeholder if needed
    pass
