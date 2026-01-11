import os
import sys
import time
from unittest.mock import patch, Mock

# Ensure project root is importable for tests
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from auth import AuthPollingThread


def test_auth_polling_success(monkeypatch):
    # Simulate a successful token response on first poll
    mock_resp = Mock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"access_token": "token"}

    with patch('requests.post', return_value=mock_resp):
        thread = AuthPollingThread('cid', 'secret', 'device', interval=0.1, timeout=5)
        # run in same thread for test
        thread.running = True
        thread.run()
        # if no exception, success path executed


def test_auth_polling_network_error(monkeypatch):
    # Simulate network error
    import requests

    def raise_err(*a, **k):
        raise requests.RequestException('network')

    with patch('requests.post', side_effect=raise_err):
        thread = AuthPollingThread('cid', 'secret', 'device', interval=0.1, timeout=1)
        thread.running = True
        thread.run()
