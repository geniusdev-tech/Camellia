"""
Vault API Blueprint — file listing, encrypt/decrypt, scan, devices.
All endpoints require JWT auth via require_auth decorator.
"""
import os
from flask import Blueprint, request, jsonify, g
from core.sys.fs import PathValidator
from core.iam.session import key_manager
from core.iam.rbac import require_auth, require_permission

vault_bp = Blueprint("vault", __name__, url_prefix="/api")


def _get_managers():
    from services import auth_manager, vault_manager, task_manager
    from core.sys.devices import DeviceManager
    return auth_manager, vault_manager, task_manager, DeviceManager()


def _ensure_unlocked():
    if not key_manager.get_key(getattr(g, "user_id", None)):
        return jsonify({"success": False, "msg": "Vault bloqueado ou sessão expirada. Faça login novamente."}), 401
    return None


# ── Files ─────────────────────────────────────────────────────────────────────

@vault_bp.route("/files/list", methods=["POST"])
@require_auth
@require_permission("vault:read")
def list_files():
    _, vault, _, _ = _get_managers()

    data     = request.get_json(silent=True) or {}
    raw_path = data.get("path")
    if raw_path in (None, "", "home"):
        raw_path = None

    is_valid, path_obj, error_msg = PathValidator.validate(
        str(path_obj_fallback := PathValidator.get_fallback()) if raw_path is None else raw_path,
        require_dir=True,
    )

    if raw_path is None:
        # Explicitly use home
        is_valid = True
        path_obj = PathValidator.get_fallback()

    final_path   = str(path_obj)
    user_warning = None

    if not is_valid:
        user_warning = "Localização anterior indisponível. Redirecionado para Home."

    try:
        items = vault.list_files(final_path, user_id=g.user_id)
        items.sort(key=lambda x: (not x.get("is_dir", False), x["name"].startswith("."), x["name"].lower()))
        parent = os.path.dirname(final_path)

        response: dict = {
            "success": True,
            "items":   items,
            "current_path": final_path,
            "parent_path":  parent if parent != final_path else None,
        }
        if user_warning:
            response["msg"] = user_warning
        return jsonify(response)

    except PermissionError:
        return jsonify({"success": False, "msg": "Vault bloqueado ou sessão expirada"}), 401
    except Exception as e:
        return jsonify({"success": False, "msg": f"Erro do sistema: {e}"}), 500


@vault_bp.route("/files/action", methods=["POST"])
@require_auth
@require_permission("vault:write")
def file_action():
    data   = request.get_json(silent=True) or {}
    action = data.get("action")
    raw    = data.get("path")

    is_valid, path_obj, err = PathValidator.validate(raw, require_exists=True)
    if not is_valid:
        return jsonify({"success": False, "msg": f"Caminho inválido: {err}"}), 400

    path = str(path_obj)

    try:
        if action == "delete":
            _, vault, _, _ = _get_managers()
            ok, msg = vault.delete_item(path, user_id=g.user_id)
            return jsonify({"success": ok, "msg": msg})

        elif action == "rename":
            new_name = data.get("new_name", "")
            if not new_name or ".." in new_name or "/" in new_name or "\\" in new_name:
                return jsonify({"success": False, "msg": "Nome de arquivo inválido"}), 400
            new_path = os.path.join(os.path.dirname(path), new_name)
            if os.path.exists(new_path):
                return jsonify({"success": False, "msg": "Destino já existe"}), 409
            os.rename(path, new_path)
            return jsonify({"success": True, "msg": "Renomeado"})

        return jsonify({"success": False, "msg": f"Ação desconhecida: {action}"}), 400

    except Exception as e:
        return jsonify({"success": False, "msg": str(e)}), 500


# ── Process ───────────────────────────────────────────────────────────────────

@vault_bp.route("/process/start", methods=["POST"])
@require_auth
@require_permission("vault:write")
def start_process():
    _, _, tasks, _ = _get_managers()
    unlocked = _ensure_unlocked()
    if unlocked:
        return unlocked
    data    = request.get_json(silent=True) or {}
    raw     = data.get("path")
    encrypt = data.get("encrypt", True)
    uuid_t  = data.get("uuid")
    dev_id  = data.get("device_id", "local")

    is_valid, path_obj, err = PathValidator.validate(raw, require_exists=True)
    if not is_valid:
        return jsonify({"success": False, "msg": f"Erro de acesso: {err}"}), 400

    action  = "encrypt" if encrypt else "decrypt"
    task_id = tasks.start_task(action, str(path_obj), uuid=uuid_t, device_id=dev_id, user_id=g.user_id)
    return jsonify({"success": True, "task_id": task_id})


@vault_bp.route("/process/batch", methods=["POST"])
@require_auth
@require_permission("vault:write")
def batch_process():
    _, _, tasks, _ = _get_managers()
    unlocked = _ensure_unlocked()
    if unlocked:
        return unlocked
    data      = request.get_json(silent=True) or {}
    targets   = data.get("targets", [])
    recursive = data.get("recursive", False)
    dev_id    = data.get("device_id", "local")
    encrypt   = data.get("encrypt", True)

    valid_targets, errors = [], []
    for t in targets:
        ok, p, msg = PathValidator.validate(t, require_exists=True)
        if ok:
            valid_targets.append(str(p))
        else:
            errors.append(f"{t}: {msg}")

    if not valid_targets:
        return jsonify({"success": False, "msg": "Nenhum alvo válido", "errors": errors}), 400

    action  = "batch_encrypt" if encrypt else "batch_decrypt"
    task_id = tasks.start_task(action, valid_targets, recursive=recursive, device_id=dev_id, user_id=g.user_id)
    return jsonify({"success": True, "task_id": task_id})


@vault_bp.route("/process/cancel", methods=["POST"])
@require_auth
def cancel_process():
    _, _, tasks, _ = _get_managers()
    task_id = (request.get_json(silent=True) or {}).get("task_id")
    ok = tasks.cancel_task(task_id) if task_id else False
    return jsonify({"success": ok})


@vault_bp.route("/process/status/<task_id>")
@require_auth
def process_status(task_id: str):
    _, _, tasks, _ = _get_managers()
    task = tasks.get_task(task_id)
    if not task:
        return jsonify({"success": False}), 404
    return jsonify({
        "progress": task.progress,
        "status":   task.status,
        "logs":     task.logs,
        "done":     task.status in ("Completed", "Error", "Cancelled"),
    })


# ── Devices ───────────────────────────────────────────────────────────────────

@vault_bp.route("/devices/list", methods=["GET"])
@require_auth
def list_devices():
    _, _, _, dev_man = _get_managers()
    try:
        return jsonify({"success": True, "devices": dev_man.list_devices()})
    except Exception as e:
        return jsonify({"success": False, "msg": str(e)}), 500


# ── Security scan ─────────────────────────────────────────────────────────────

@vault_bp.route("/security/scan", methods=["POST"])
@require_auth
@require_permission("vault:read")
def scan_file():
    from core.security.integrity import IntegrityInspector

    raw = (request.get_json(silent=True) or {}).get("path")
    is_valid, path_obj, err = PathValidator.validate(raw, require_exists=True)
    if not is_valid:
        return jsonify({"success": False, "msg": f"Erro: {err}"}), 400

    try:
        return jsonify(IntegrityInspector.inspect_file(str(path_obj)))
    except Exception as e:
        return jsonify({"success": False, "msg": str(e)}), 500
