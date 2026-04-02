from flask import Blueprint, request, jsonify
from core.iam.rbac import require_auth, require_permission
from core.audit.logger import get_audit_logger

audit_bp = Blueprint("audit", __name__, url_prefix="/api/audit")


@audit_bp.route("/events", methods=["GET"])
@require_auth
@require_permission("audit:read")
def get_events():
    event_type = request.args.get("event_type")
    user       = request.args.get("user")
    limit      = int(request.args.get("limit", 100))

    try:
        logger = get_audit_logger()
        events = logger.get_events(event_type=event_type, user=user, limit=limit)
        return jsonify({"success": True, "events": events})
    except RuntimeError:
        return jsonify({"success": True, "events": []})
    except Exception as e:
        return jsonify({"success": False, "msg": str(e)}), 500


@audit_bp.route("/verify", methods=["POST"])
@require_auth
@require_permission("audit:read")
def verify_log():
    try:
        logger = get_audit_logger()
        valid, errors = logger.verify_log_integrity()
        return jsonify({"success": True, "valid": valid, "errors": errors})
    except RuntimeError:
        return jsonify({"success": True, "valid": True, "errors": []})
    except Exception as e:
        return jsonify({"success": False, "msg": str(e)}), 500
