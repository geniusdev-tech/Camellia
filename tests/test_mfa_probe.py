import sys
import os
import pytest

# Set environment to development to avoid some protections and for easier testing
os.environ['FLASK_ENV'] = 'development'
os.environ['SECRET_KEY'] = 'test-secret'

from app import create_app

@pytest.fixture
def client():
    app = create_app()
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_mfa_probe_session_required(client):
    print("Probing user 1 without session...")
    response = client.post("/api/auth/login/mfa", json={"user_id": 1, "code": "123456"})
    assert response.status_code == 401
    assert response.get_json()['msg'] == 'Sessão inválida ou expirada'

def test_mfa_probe_non_existent_user(client):
    print("\nProbing non-existent user 999 without session...")
    response = client.post("/api/auth/login/mfa", json={"user_id": 999, "code": "123456"})
    assert response.status_code == 401
    assert response.get_json()['msg'] == 'Sessão inválida ou expirada'

def test_login_generic_error_non_existent_user(client):
    print("\nProbing login with non-existent user...")
    response = client.post("/api/auth/login", json={"email": "nonexistent@example.com", "password": "wrong"})
    assert response.status_code == 401
    assert response.get_json()['msg'] == 'Credenciais inválidas'

def test_login_generic_error_deactivated_user(client, monkeypatch):
    # We can use the DB to deactivate user 1 or mock it.
    # Given we already initialized the DB, let's just use it but ensure it's reverted if needed.
    # Actually, the plan says we reset the DB before running all tests.

    from core.iam.db import SessionLocal
    from core.iam.models import User

    db = SessionLocal()
    user = db.query(User).get(1)
    if user:
        original_state = user.is_active
        user.is_active = False
        db.commit()

        try:
            print("\nProbing login with deactivated user 1...")
            response = client.post("/api/auth/login", json={"email": "admin@rodrigo.mail", "password": "wrong"})
            assert response.status_code == 401
            assert response.get_json()['msg'] == 'Credenciais inválidas'
        finally:
            user.is_active = original_state
            db.commit()
            db.close()
