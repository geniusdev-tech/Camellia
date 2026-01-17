from flask import Blueprint, request, jsonify
import os
import shutil
from core.sys.fs import PathValidator

vault_bp = Blueprint('vault', __name__, url_prefix='/api')

ROOT_DIR = str(PathValidator.get_fallback())

def _get_managers():
    from services import auth_manager, vault_manager, task_manager
    # New Device Manager
    # We should add it to services.py or instantiate here?
    # Better to have it in services.py to be consistent.
    # For now, instantiate on demand since it's stateless-ish
    from core.sys.devices import DeviceManager
    device_manager = DeviceManager()
    return auth_manager, vault_manager, task_manager, device_manager

@vault_bp.route('/files/list', methods=['POST'])
def list_files():
    auth, vault, _, _ = _get_managers()
    if not auth.get_session():
        return jsonify({'success': False, 'msg': "Vault Locked"}), 401
    
    raw_path = request.json.get('path')
    if raw_path == "home": raw_path = None # triggers fallback in validate

    # 1. Centralized Validation & Fallback
    # If path is invalid/missing, this returns (False, HOME_PATH, error_msg)
    is_valid, path_obj, error_msg = PathValidator.validate(raw_path, require_dir=True)
    
    final_path = str(path_obj)
    user_warning = None

    if not is_valid:
        # Fallback triggered
        print(f"[Security] Path fallback triggered. Request: {raw_path}. Reason: {error_msg}")
        user_warning = "Previous location unavailable. Redirected to Home."

    try:
        # 2. Safe List Execution
        items = vault.list_files(final_path)
        items.sort(key=lambda x: (not x.get('is_dir', False), x['name'].lower()))
        parent = os.path.dirname(final_path)
        
        response = {
            'success': True, 
            'items': items, 
            'current_path': final_path, 
            'parent_path': parent
        }
        
        # 3. Add warning to UX if fallback occurred
        if user_warning:
            response['msg'] = user_warning
            
        return jsonify(response)
        
    except Exception as e:
        # Logic error (e.g. permission denied on existing folder calling scandir)
        return jsonify({'success': False, 'msg': f"System Error: {str(e)}"}), 500

@vault_bp.route('/files/action', methods=['POST'])
def file_action():
    auth, _, _, _ = _get_managers()
    if not auth.get_session():
        return jsonify({'success': False, 'msg': "Vault Locked"}), 401

    data = request.json
    action = data.get('action')
    raw_path = data.get('path')
    
    # Validate target path exists and is safe
    is_valid, path_obj, err_msg = PathValidator.validate(raw_path, require_exists=True)
    
    if not is_valid:
        return jsonify({'success': False, 'msg': f"Invalid target: {err_msg}"}), 400
        
    path = str(path_obj)
    
    try:
        if action == 'delete':
            # Add safety check here or in VaultManager?
            # Basic os remove for now, manager might need delete_file method to handle manifest cleanup
            # TODO: Implement vault_manager.delete_file for safe manifest update
            if os.path.isfile(path):
                os.remove(path)
            else:
                shutil.rmtree(path)
            return jsonify({'success': True, 'msg': "Deleted"})
            
        elif action == 'rename':
             new_name = data.get('new_name')
             # Sanitize new_name to prevent traversal
             if not new_name or '..' in new_name or '/' in new_name or '\\' in new_name:
                 return jsonify({'success': False, 'msg': "Invalid filename"}), 400
                 
             new_path = os.path.join(os.path.dirname(path), new_name)
             
             # Check if new path blocks exist
             if os.path.exists(new_path):
                  return jsonify({'success': False, 'msg': "Destination already exists"}), 400

             os.rename(path, new_path)
             return jsonify({'success': True, 'msg': "Renamed"})
             
    except Exception as e:
        return jsonify({'success': False, 'msg': str(e)}), 500

@vault_bp.route('/process/start', methods=['POST'])
def start_process():
    auth, _, tasks, _ = _get_managers()
    if not auth.get_session():
        return jsonify({'success': False, 'msg': "Vault Locked"}), 401
        
    data = request.json
    raw_path = data.get('path')
    encrypt = data.get('encrypt')
    uuid_target = data.get('uuid')
    device_id = data.get('device_id', 'local')
    
    # Validação do Path
    # Se temos uuid e decrypt, o path é virtual/interno? 
    # O frontend envia path para consistência.
    # Vamos validar que o path da request é seguro.
    is_valid, path_obj, err_msg = PathValidator.validate(raw_path, require_exists=True)
    
    if not is_valid:
        return jsonify({'success': False, 'msg': f"File access error: {err_msg}"}), 400
        
    path = str(path_obj)
    
    action = "encrypt" if encrypt else "decrypt"
    
    task_id = tasks.start_task(action, path, uuid=uuid_target, device_id=device_id)
    return jsonify({'success': True, 'task_id': task_id})

@vault_bp.route('/process/batch', methods=['POST'])
def batch_process():
    auth, _, tasks, _ = _get_managers()
    if not auth.get_session():
        return jsonify({'success': False, 'msg': "Vault Locked"}), 401
        
    data = request.json
    targets = data.get('targets', [])
    recursive = data.get('recursive', False)
    device_id = data.get('device_id', 'local')
    encrypt = data.get('encrypt', True)
    
    # Validate all targets
    valid_targets = []
    errors = []
    
    for t in targets:
        v, p, msg = PathValidator.validate(t, require_exists=True)
        if v:
            valid_targets.append(str(p))
        else:
            errors.append(f"{t}: {msg}")
            
    if not valid_targets:
        return jsonify({'success': False, 'msg': "No valid targets found", 'errors': errors}), 400
    
    action = "batch_encrypt" if encrypt else "batch_decrypt"
        
    task_id = tasks.start_task(action, valid_targets, recursive=recursive, device_id=device_id)
    return jsonify({'success': True, 'task_id': task_id})

@vault_bp.route('/process/cancel', methods=['POST'])
def cancel_process():
    auth, _, tasks, _ = _get_managers()
    if not auth.get_session(): return jsonify({'success': False}), 401
    
    task_id = request.json.get('task_id')
    success = tasks.cancel_task(task_id)
    return jsonify({'success': success})

@vault_bp.route('/process/status/<task_id>')
def process_status(task_id):
    _, _, tasks, _ = _get_managers()
    task = tasks.get_task(task_id)
    if not task:
        return jsonify({'success': False}), 404
        
    return jsonify({
        'progress': task.progress,
        'status': task.status,
        'logs': task.logs,
        'done': task.status in ["Completed", "Error", "Cancelled"]
    })

@vault_bp.route('/devices/list', methods=['GET'])
def listing_devices():
    auth, _, _, dev_man = _get_managers()
    if not auth.get_session(): return jsonify({'success': False}), 401
    
    try:
        devices = dev_man.list_devices()
        return jsonify({'success': True, 'devices': devices})
    except Exception as e:
        return jsonify({'success': False, 'msg': str(e)}), 500

@vault_bp.route('/security/scan', methods=['POST'])
def scan_file():
    from core.security.integrity import IntegrityInspector
    auth, _, _, _ = _get_managers()
    if not auth.get_session(): return jsonify({'success': False}), 401
    
    data = request.json
    raw_path = data.get('path')
    
    is_valid, path_obj, err_msg = PathValidator.validate(raw_path, require_exists=True)
    
    if not is_valid:
        return jsonify({'success': False, 'msg': f"File error: {err_msg}"}), 400
        
    path = str(path_obj)
    
    try:
        report = IntegrityInspector.inspect_file(path)
        return jsonify(report)
    except Exception as e:
        return jsonify({'success': False, 'msg': str(e)}), 500
