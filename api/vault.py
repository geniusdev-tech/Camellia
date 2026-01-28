from flask import Blueprint, request, jsonify, g
import os
import shutil
from core.sys.fs import PathValidator
from core.iam.rbac import require_auth, require_permission

vault_bp = Blueprint('vault', __name__, url_prefix='/api')

ROOT_DIR = str(PathValidator.get_fallback())

def _get_managers():
    from services import auth_manager, vault_manager, task_manager
    from core.sys.devices import DeviceManager
    device_manager = DeviceManager()
    return auth_manager, vault_manager, task_manager, device_manager

@vault_bp.route('/files/list', methods=['POST'])
@require_auth
@require_permission('vault:read')
def list_files():
    # auth_manager not needed for auth anymore, but vault_manager needs user_id
    _, vault, _, _ = _get_managers()
    
    raw_path = request.json.get('path')
    if raw_path == "home": raw_path = None 

    is_valid, path_obj, error_msg = PathValidator.validate(raw_path, require_dir=True)
    
    final_path = str(path_obj)
    user_warning = None

    if not is_valid:
        print(f"[Security] Path fallback triggered. Request: {raw_path}. Reason: {error_msg}")
        user_warning = "Previous location unavailable. Redirected to Home."

    try:
        items = vault.list_files(final_path, user_id=g.user_id)
        items.sort(key=lambda x: (not x.get('is_dir', False), x['name'].lower()))
        parent = os.path.dirname(final_path)
        
        response = {
            'success': True, 
            'items': items, 
            'current_path': final_path, 
            'parent_path': parent
        }
        
        if user_warning:
            response['msg'] = user_warning
            
        return jsonify(response)
        
    except PermissionError:
        return jsonify({'success': False, 'msg': "Vault Locked or Session Expired"}), 401
    except Exception as e:
        print(f"[Vault Error] {str(e)}")
        return jsonify({'success': False, 'msg': "System Error: Operation failed"}), 500

@vault_bp.route('/files/action', methods=['POST'])
@require_auth
@require_permission('vault:write')
def file_action():
    _, _, _, _ = _get_managers()

    data = request.json
    action = data.get('action')
    raw_path = data.get('path')
    
    is_valid, path_obj, err_msg = PathValidator.validate(raw_path, require_exists=True)
    
    if not is_valid:
        return jsonify({'success': False, 'msg': f"Invalid target: {err_msg}"}), 400
        
    path = str(path_obj)
    
    try:
        if action == 'delete':
            _, vault, _, _ = _get_managers()
            # Use delete_item from VaultManager to ensure manifest consistency
            success, msg = vault.delete_item(path, user_id=g.user_id)
            return jsonify({'success': success, 'msg': msg})
            
        elif action == 'rename':
             new_name = data.get('new_name')
             if not new_name or '..' in new_name or '/' in new_name or '\\' in new_name:
                 return jsonify({'success': False, 'msg': "Invalid filename"}), 400
                 
             new_path = os.path.join(os.path.dirname(path), new_name)
             
             if os.path.exists(new_path):
                  return jsonify({'success': False, 'msg': "Destination already exists"}), 400

             os.rename(path, new_path)
             return jsonify({'success': True, 'msg': "Renamed"})
             
    except Exception as e:
        print(f"[Vault Action Error] {str(e)}")
        return jsonify({'success': False, 'msg': "Operation failed"}), 500

@vault_bp.route('/process/start', methods=['POST'])
@require_auth
@require_permission('vault:write')
def start_process():
    _, _, tasks, _ = _get_managers()
        
    data = request.json
    raw_path = data.get('path')
    encrypt = data.get('encrypt')
    uuid_target = data.get('uuid')
    device_id = data.get('device_id', 'local')
    
    is_valid, path_obj, err_msg = PathValidator.validate(raw_path, require_exists=True)
    
    if not is_valid:
        return jsonify({'success': False, 'msg': f"File access error: {err_msg}"}), 400
        
    path = str(path_obj)
    action = "encrypt" if encrypt else "decrypt"
    
    # Pass user_id to task metadata or context!
    # TaskManager needs update to forward user_id to vault_manager calls
    task_id = tasks.start_task(action, path, uuid=uuid_target, device_id=device_id, user_id=g.user_id)
    return jsonify({'success': True, 'task_id': task_id})

@vault_bp.route('/process/batch', methods=['POST'])
@require_auth
@require_permission('vault:write')
def batch_process():
    _, _, tasks, _ = _get_managers()
        
    data = request.json
    targets = data.get('targets', [])
    recursive = data.get('recursive', False)
    device_id = data.get('device_id', 'local')
    encrypt = data.get('encrypt', True)
    
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
        
    task_id = tasks.start_task(action, valid_targets, recursive=recursive, device_id=device_id, user_id=g.user_id)
    return jsonify({'success': True, 'task_id': task_id})

@vault_bp.route('/process/cancel', methods=['POST'])
@require_auth
def cancel_process():
    _, _, tasks, _ = _get_managers()
    task_id = request.json.get('task_id')
    success = tasks.cancel_task(task_id)
    return jsonify({'success': success})

@vault_bp.route('/process/status/<task_id>')
@require_auth
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
@require_auth
def listing_devices():
    _, _, _, dev_man = _get_managers()
    try:
        devices = dev_man.list_devices()
        return jsonify({'success': True, 'devices': devices})
    except Exception as e:
        print(f"[Device List Error] {str(e)}")
        return jsonify({'success': False, 'msg': "Failed to list devices"}), 500

@vault_bp.route('/security/scan', methods=['POST'])
@require_auth
@require_permission('audit:read') 
# Maybe vault:read? Scanning is analysis. Let's say audit:read or vault:read.
# Reverting to vault:read as integrity check is basic vault op.
def scan_file():
    from core.security.integrity import IntegrityInspector
    
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
        print(f"[Scan Error] {str(e)}")
        return jsonify({'success': False, 'msg': "Security scan failed"}), 500
