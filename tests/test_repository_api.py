import importlib
import io
import json
import sys
import time
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def _zip_payload(name: str = "README.txt", content: str = "hello") -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(name, content)
    return buffer.getvalue()


@pytest.fixture()
def client(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    audit_path = tmp_path / "audit.log"

    monkeypatch.setenv("FLASK_ENV", "development")
    monkeypatch.setenv("SECRET_KEY", "test-secret")
    monkeypatch.setenv("IAM_DB_PATH", str(db_path))
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("IAM_DATABASE_URL", raising=False)
    monkeypatch.setenv("SUPABASE_URL", "https://example.supabase.co")
    monkeypatch.setenv("SUPABASE_SERVICE_KEY", "service-key")
    monkeypatch.setenv("SUPABASE_BUCKET", "projects")
    monkeypatch.setenv("AUDIT_LOG_PATH", str(audit_path))
    monkeypatch.setenv("GATESTACK_DEV_EMAIL", "owner@example.com")
    monkeypatch.setenv("GATESTACK_DEV_PASSWORD", "Owner-pass-123!")
    monkeypatch.setenv("GATESTACK_ASYNC_POLL_SECONDS", "0.05")

    import core.async_jobs as async_jobs_module
    import core.iam.db as db_module
    import core.iam.rbac as rbac_module
    import core.observability as observability_module
    import utils.supabase_storage as storage_module
    import api.access as access_module
    import api.ops as ops_module
    import api.projects as projects_module
    import api.auth as auth_module
    import app as app_module

    importlib.reload(async_jobs_module)
    importlib.reload(db_module)
    importlib.reload(rbac_module)
    importlib.reload(observability_module)
    importlib.reload(storage_module)
    importlib.reload(access_module)
    importlib.reload(ops_module)
    importlib.reload(auth_module)
    importlib.reload(projects_module)
    importlib.reload(app_module)
    observability_module.metrics_registry.reset()

    uploads: dict[str, bytes] = {}

    def fake_upload(bucket, filename, file_obj, content_type):
        uploads[filename] = file_obj.read()
        return {"Key": filename, "bucket": bucket, "content_type": content_type}

    def fake_signed_url(bucket, storage_key, expires_in=900):
        return f"https://example.supabase.co/storage/v1/object/sign/{bucket}/{storage_key}?expires={expires_in}"

    def fake_delete(bucket, storage_key):
        uploads.pop(storage_key, None)

    monkeypatch.setattr(projects_module, "upload_file_to_supabase", fake_upload)
    monkeypatch.setattr(projects_module, "create_signed_download_url", fake_signed_url)
    monkeypatch.setattr(projects_module, "delete_from_supabase", fake_delete)

    flask_app = app_module.create_app()
    flask_app.config.update(TESTING=True)
    test_client = flask_app.test_client()
    test_client.uploads = uploads
    return test_client


def _login(client, email: str, password: str) -> str:
    response = client.post("/api/auth/login", json={"email": email, "password": password})
    payload = response.get_json()
    assert response.status_code == 200, payload
    return payload["access_token"]


def _auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_owner_can_upload_list_detail_download_and_delete(client):
    token = _login(client, "owner@example.com", "Owner-pass-123!")

    response = client.post(
        "/api/projects/upload",
        headers=_auth_headers(token),
        data={
            "package_name": "alpha",
            "package_version": "1.0.0",
            "description": "initial release",
            "visibility": "public",
            "metadata": json.dumps({"channel": "stable"}),
            "file": (io.BytesIO(_zip_payload()), "alpha.zip"),
        },
        content_type="multipart/form-data",
    )
    payload = response.get_json()
    assert response.status_code == 200, payload
    project_id = payload["project"]["id"]
    assert payload["project"]["checksum_sha256"]
    assert payload["project"]["lifecycle_status"] == "approved"

    publish = client.patch(
        f"/api/projects/{project_id}",
        headers=_auth_headers(token),
        json={"lifecycle_status": "published", "status_reason": "ready"},
    )
    assert publish.status_code == 200, publish.get_json()

    response = client.get("/api/projects/list?search=alpha", headers=_auth_headers(token))
    payload = response.get_json()
    assert response.status_code == 200, payload
    assert payload["pagination"]["total"] == 1
    assert payload["projects"][0]["id"] == project_id

    response = client.get(f"/api/projects/{project_id}", headers=_auth_headers(token))
    payload = response.get_json()
    assert response.status_code == 200, payload
    assert payload["project"]["metadata"]["channel"] == "stable"

    response = client.get(f"/api/projects/{project_id}/download", headers=_auth_headers(token))
    payload = response.get_json()
    assert response.status_code == 200, payload
    assert "download_url" in payload
    assert payload["project"]["download_count"] == 1

    response = client.delete(f"/api/projects/{project_id}", headers=_auth_headers(token))
    assert response.status_code == 200, response.get_json()


def test_duplicate_upload_is_deduplicated(client):
    token = _login(client, "owner@example.com", "Owner-pass-123!")
    zip_bytes = _zip_payload("dup.txt", "same")

    first = client.post(
        "/api/projects/upload",
        headers=_auth_headers(token),
        data={
            "package_name": "dup-pkg",
            "package_version": "1.0.0",
            "file": (io.BytesIO(zip_bytes), "dup.zip"),
        },
        content_type="multipart/form-data",
    ).get_json()

    second_response = client.post(
        "/api/projects/upload",
        headers=_auth_headers(token),
        data={
            "package_name": "dup-pkg",
            "package_version": "1.0.0",
            "file": (io.BytesIO(zip_bytes), "dup-again.zip"),
        },
        content_type="multipart/form-data",
    )
    second = second_response.get_json()
    assert second_response.status_code == 200, second
    assert second["deduplicated"] is True
    assert second["project"]["id"] == first["project"]["id"]


def test_non_owner_cannot_publish_private_package_and_public_published_is_visible(client):
    owner_token = _login(client, "owner@example.com", "Owner-pass-123!")

    register = client.post(
        "/api/auth/register",
        json={"email": "user@example.com", "password": "User-pass-123!"},
    )
    assert register.status_code == 200, register.get_json()
    user_token = _login(client, "user@example.com", "User-pass-123!")

    upload = client.post(
        "/api/projects/upload",
        headers=_auth_headers(user_token),
        data={
            "package_name": "beta",
            "package_version": "2.0.0",
            "visibility": "public",
            "file": (io.BytesIO(_zip_payload("beta.txt", "beta")), "beta.zip"),
        },
        content_type="multipart/form-data",
    )
    payload = upload.get_json()
    assert upload.status_code == 200, payload
    project_id = payload["project"]["id"]
    assert payload["project"]["lifecycle_status"] == "draft"

    submit = client.patch(
        f"/api/projects/{project_id}",
        headers=_auth_headers(user_token),
        json={"lifecycle_status": "submitted"},
    )
    assert submit.status_code == 200, submit.get_json()

    publish_attempt = client.patch(
        f"/api/projects/{project_id}",
        headers=_auth_headers(user_token),
        json={"lifecycle_status": "published"},
    )
    assert publish_attempt.status_code == 403, publish_attempt.get_json()

    approve_as_owner = client.patch(
        f"/api/projects/{project_id}",
        headers=_auth_headers(owner_token),
        json={"lifecycle_status": "approved", "status_reason": "validated"},
    )
    assert approve_as_owner.status_code == 200, approve_as_owner.get_json()

    publish_as_owner = client.patch(
        f"/api/projects/{project_id}",
        headers=_auth_headers(owner_token),
        json={"lifecycle_status": "published"},
    )
    assert publish_as_owner.status_code == 200, publish_as_owner.get_json()

    list_as_owner = client.get("/api/projects/list?scope=all&package_name=beta", headers=_auth_headers(owner_token))
    assert list_as_owner.status_code == 200, list_as_owner.get_json()
    assert list_as_owner.get_json()["pagination"]["total"] == 1

    public_read = client.get(f"/api/projects/{project_id}", headers=_auth_headers(owner_token))
    assert public_read.status_code == 200, public_read.get_json()


def test_shared_visibility_allows_explicit_recipient_and_filters_work(client):
    owner_token = _login(client, "owner@example.com", "Owner-pass-123!")

    register_user = client.post(
        "/api/auth/register",
        json={"email": "alice@example.com", "password": "Alice-pass-123!"},
    )
    register_peer = client.post(
        "/api/auth/register",
        json={"email": "bob@example.com", "password": "Bob-pass-123!"},
    )
    assert register_user.status_code == 200, register_user.get_json()
    assert register_peer.status_code == 200, register_peer.get_json()

    alice_token = _login(client, "alice@example.com", "Alice-pass-123!")
    bob_token = _login(client, "bob@example.com", "Bob-pass-123!")

    bob_status = client.get("/api/auth/status", headers=_auth_headers(bob_token))
    bob_id = bob_status.get_json()["user_id"]

    upload = client.post(
        "/api/projects/upload",
        headers=_auth_headers(alice_token),
        data={
            "package_name": "shared-pkg",
            "package_version": "3.1.4",
            "visibility": "shared",
            "shared_with": str(bob_id),
            "metadata": json.dumps({"channel": "beta", "team": "mobile"}),
            "file": (io.BytesIO(_zip_payload("shared.txt", "shared")), "shared.zip"),
        },
        content_type="multipart/form-data",
    )
    payload = upload.get_json()
    assert upload.status_code == 200, payload
    project_id = payload["project"]["id"]

    bob_detail = client.get(f"/api/projects/{project_id}", headers=_auth_headers(bob_token))
    assert bob_detail.status_code == 200, bob_detail.get_json()

    filtered = client.get(
        "/api/projects/list?search=shared&visibility=shared&page=1&page_size=5",
        headers=_auth_headers(bob_token),
    )
    filtered_payload = filtered.get_json()
    assert filtered.status_code == 200, filtered_payload
    assert filtered_payload["pagination"]["page_size"] == 5
    assert filtered_payload["pagination"]["total"] >= 1
    assert filtered_payload["projects"][0]["package_name"] == "shared-pkg"

    owner_scope = client.get(
        "/api/projects/list?scope=all&status=draft&package_name=shared-pkg",
        headers=_auth_headers(owner_token),
    )
    assert owner_scope.status_code == 200, owner_scope.get_json()
    assert owner_scope.get_json()["pagination"]["total"] == 1


def test_relational_share_grants_support_role_and_expiration(client):
    owner_token = _login(client, "owner@example.com", "Owner-pass-123!")

    client.post(
        "/api/auth/register",
        json={"email": "grantor@example.com", "password": "Grantor-pass-123!"},
    )
    client.post(
        "/api/auth/register",
        json={"email": "viewer@example.com", "password": "Viewer-pass-123!"},
    )
    grantor_token = _login(client, "grantor@example.com", "Grantor-pass-123!")
    viewer_token = _login(client, "viewer@example.com", "Viewer-pass-123!")
    viewer_id = client.get("/api/auth/status", headers=_auth_headers(viewer_token)).get_json()["user_id"]

    upload = client.post(
        "/api/projects/upload",
        headers=_auth_headers(grantor_token),
        data={
            "package_name": "acl-pkg",
            "package_version": "0.9.0",
            "file": (io.BytesIO(_zip_payload("acl.txt", "acl")), "acl.zip"),
        },
        content_type="multipart/form-data",
    )
    assert upload.status_code == 200, upload.get_json()
    project_id = upload.get_json()["project"]["id"]

    grant_patch = client.patch(
        f"/api/projects/{project_id}",
        headers=_auth_headers(grantor_token),
        json={
            "visibility": "shared",
            "share_grants": [
                {
                    "user_id": viewer_id,
                    "grant_role": "editor",
                    "expires_at": (
                        datetime.now(timezone.utc) + timedelta(days=1)
                    ).isoformat(),
                }
            ]
        },
    )
    grant_payload = grant_patch.get_json()
    assert grant_patch.status_code == 200, grant_payload
    assert grant_payload["project"]["share_grants"][0]["grant_role"] == "editor"

    viewer_detail = client.get(
        f"/api/projects/{project_id}",
        headers=_auth_headers(viewer_token),
    )
    assert viewer_detail.status_code == 200, viewer_detail.get_json()

    expired_patch = client.patch(
        f"/api/projects/{project_id}",
        headers=_auth_headers(grantor_token),
        json={
            "visibility": "shared",
            "share_grants": [
                {
                    "user_id": viewer_id,
                    "grant_role": "editor",
                    "expires_at": (
                        datetime.now(timezone.utc) - timedelta(days=1)
                    ).isoformat(),
                }
            ]
        },
    )
    assert expired_patch.status_code == 200, expired_patch.get_json()

    viewer_after_expiry = client.get(
        f"/api/projects/{project_id}",
        headers=_auth_headers(viewer_token),
    )
    assert viewer_after_expiry.status_code == 403, viewer_after_expiry.get_json()


def test_invalid_zip_is_rejected_and_user_can_archive_own_package(client):
    register = client.post(
        "/api/auth/register",
        json={"email": "worker@example.com", "password": "Worker-pass-123!"},
    )
    assert register.status_code == 200, register.get_json()
    worker_token = _login(client, "worker@example.com", "Worker-pass-123!")

    invalid_upload = client.post(
        "/api/projects/upload",
        headers=_auth_headers(worker_token),
        data={
            "package_name": "broken",
            "package_version": "0.0.1",
            "file": (io.BytesIO(b"not-a-zip"), "broken.zip"),
        },
        content_type="multipart/form-data",
    )
    invalid_payload = invalid_upload.get_json()
    assert invalid_upload.status_code == 400, invalid_payload
    assert "zip" in invalid_payload["msg"].lower()

    valid_upload = client.post(
        "/api/projects/upload",
        headers=_auth_headers(worker_token),
        data={
            "package_name": "draft-pkg",
            "package_version": "0.0.2",
            "file": (io.BytesIO(_zip_payload("draft.txt", "draft")), "draft.zip"),
        },
        content_type="multipart/form-data",
    )
    valid_payload = valid_upload.get_json()
    assert valid_upload.status_code == 200, valid_payload
    project_id = valid_payload["project"]["id"]
    assert valid_payload["project"]["lifecycle_status"] == "draft"

    archive = client.patch(
        f"/api/projects/{project_id}",
        headers=_auth_headers(worker_token),
        json={"lifecycle_status": "archived"},
    )
    archive_payload = archive.get_json()
    assert archive.status_code == 200, archive_payload
    assert archive_payload["project"]["lifecycle_status"] == "archived"


def test_refresh_rotation_logout_all_and_public_catalog(client):
    login = client.post(
        "/api/auth/login",
        json={"email": "owner@example.com", "password": "Owner-pass-123!"},
    )
    login_payload = login.get_json()
    assert login.status_code == 200, login_payload

    refresh_1 = login_payload["refresh_token"]
    refresh = client.post("/api/auth/refresh", json={"refresh_token": refresh_1})
    refresh_payload = refresh.get_json()
    assert refresh.status_code == 200, refresh_payload
    refresh_2 = refresh_payload["refresh_token"]
    assert refresh_2 != refresh_1

    reuse = client.post("/api/auth/refresh", json={"refresh_token": refresh_1})
    assert reuse.status_code == 401, reuse.get_json()

    owner_token = refresh_payload["access_token"]
    upload = client.post(
        "/api/projects/upload",
        headers=_auth_headers(owner_token),
        data={
            "package_name": "catalog-pkg",
            "package_version": "1.2.3",
            "visibility": "public",
            "description": "catalog entry",
            "changelog": "first public release",
            "file": (io.BytesIO(_zip_payload("catalog.txt", "catalog")), "catalog.zip"),
        },
        content_type="multipart/form-data",
    )
    project_id = upload.get_json()["project"]["id"]
    approve = client.patch(
        f"/api/projects/{project_id}",
        headers=_auth_headers(owner_token),
        json={"lifecycle_status": "published"},
    )
    assert approve.status_code == 200, approve.get_json()

    catalog = client.get("/api/public/packages?search=catalog")
    assert catalog.status_code == 200, catalog.get_json()
    assert catalog.get_json()["pagination"]["total"] == 1

    latest = client.get("/api/public/packages/catalog-pkg/latest")
    assert latest.status_code == 200, latest.get_json()
    assert latest.get_json()["release"]["is_latest"] is True

    version_detail = client.get("/api/public/packages/catalog-pkg/versions/1.2.3")
    assert version_detail.status_code == 200, version_detail.get_json()

    download = client.get("/api/public/packages/catalog-pkg/versions/1.2.3/download")
    assert download.status_code == 200, download.get_json()

    logout_all = client.post("/api/auth/logout-all", headers=_auth_headers(owner_token))
    assert logout_all.status_code == 200, logout_all.get_json()

    refresh_after_logout_all = client.post("/api/auth/refresh", json={"refresh_token": refresh_2})
    assert refresh_after_logout_all.status_code == 401, refresh_after_logout_all.get_json()


def test_team_invite_accept_and_team_grant_allows_access(client):
    owner_token = _login(client, "owner@example.com", "Owner-pass-123!")

    client.post(
        "/api/auth/register",
        json={"email": "maintainer@example.com", "password": "Maintainer-pass-123!"},
    )
    client.post(
        "/api/auth/register",
        json={"email": "teammate@example.com", "password": "Teammate-pass-123!"},
    )
    maintainer_token = _login(client, "maintainer@example.com", "Maintainer-pass-123!")
    teammate_token = _login(client, "teammate@example.com", "Teammate-pass-123!")

    team_create = client.post(
        "/api/access/teams",
        headers=_auth_headers(owner_token),
        json={"name": "platform"},
    )
    assert team_create.status_code == 200, team_create.get_json()
    team_id = team_create.get_json()["team"]["id"]

    invite = client.post(
        f"/api/access/teams/{team_id}/invites",
        headers=_auth_headers(owner_token),
        json={"email": "teammate@example.com", "role": "member"},
    )
    assert invite.status_code == 200, invite.get_json()
    token = invite.get_json()["invite"]["token"]

    accept = client.post(
        f"/api/access/invites/{token}/accept",
        headers=_auth_headers(teammate_token),
    )
    assert accept.status_code == 200, accept.get_json()
    teammate_id = client.get("/api/auth/status", headers=_auth_headers(teammate_token)).get_json()["user_id"]
    assert teammate_id in [member["user_id"] for member in accept.get_json()["team"]["members"]]

    upload = client.post(
        "/api/projects/upload",
        headers=_auth_headers(maintainer_token),
        data={
            "package_name": "team-pkg",
            "package_version": "1.0.0",
            "file": (io.BytesIO(_zip_payload("team.txt", "team")), "team.zip"),
        },
        content_type="multipart/form-data",
    )
    assert upload.status_code == 200, upload.get_json()
    project_id = upload.get_json()["project"]["id"]

    grant = client.post(
        f"/api/access/projects/{project_id}/team-grants",
        headers=_auth_headers(maintainer_token),
        json={"team_id": team_id, "grant_role": "viewer"},
    )
    assert grant.status_code == 200, grant.get_json()

    detail = client.get(f"/api/projects/{project_id}", headers=_auth_headers(teammate_token))
    assert detail.status_code == 200, detail.get_json()
    assert detail.get_json()["project"]["visibility"] == "shared"


def test_metrics_and_async_publish_job_flow(client):
    owner_token = _login(client, "owner@example.com", "Owner-pass-123!")

    upload = client.post(
        "/api/projects/upload",
        headers=_auth_headers(owner_token),
        data={
            "package_name": "async-pkg",
            "package_version": "1.0.1",
            "visibility": "public",
            "file": (io.BytesIO(_zip_payload("async.txt", "async")), "async.zip"),
        },
        content_type="multipart/form-data",
    )
    upload_payload = upload.get_json()
    assert upload.status_code == 200, upload_payload
    assert upload.headers.get("X-Request-Id")
    assert upload.headers.get("X-Response-Time-Ms")

    project_id = upload_payload["project"]["id"]
    scan_job_id = upload_payload["scan_job_id"]

    scan_job = None
    for _ in range(40):
        response = client.get(f"/api/ops/jobs/{scan_job_id}", headers=_auth_headers(owner_token))
        assert response.status_code == 200, response.get_json()
        scan_job = response.get_json()["job"]
        if scan_job["status"] == "completed":
            break
        time.sleep(0.05)
    assert scan_job is not None
    assert scan_job["status"] == "completed"

    publish = client.post(
        f"/api/ops/projects/{project_id}/publish",
        headers=_auth_headers(owner_token),
    )
    assert publish.status_code == 200, publish.get_json()
    publish_job_id = publish.get_json()["job_id"]

    publish_job = None
    for _ in range(40):
        response = client.get(f"/api/ops/jobs/{publish_job_id}", headers=_auth_headers(owner_token))
        assert response.status_code == 200, response.get_json()
        publish_job = response.get_json()["job"]
        if publish_job["status"] == "completed":
            break
        time.sleep(0.05)
    assert publish_job is not None
    assert publish_job["status"] == "completed"

    latest = client.get("/api/public/packages/async-pkg/latest")
    assert latest.status_code == 200, latest.get_json()
    assert latest.get_json()["release"]["package_version"] == "1.0.1"

    metrics = client.get("/api/ops/metrics", headers=_auth_headers(owner_token))
    assert metrics.status_code == 200, metrics.get_json()
    assert metrics.get_json()["metrics"]["requests"]
