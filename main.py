import sys
import os
import threading
import webview
import socket
import time
import requests
from dotenv import load_dotenv

# Load ENV early
load_dotenv()

# Force development mode for local desktop app to avoid strict HTTPS/security headers
# that might break the webview loading
os.environ['FLASK_ENV'] = 'development'
os.environ['DESKTOP_MODE'] = '1'

# Import app after env is loaded
from app import app

def get_free_port():
    """Find a free port on localhost"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

def wait_for_server(port, timeout=10):
    """Wait for server to be responsive"""
    start_time = time.time()
    url = f'http://127.0.0.1:{port}/api/auth/status'
    while time.time() - start_time < timeout:
        try:
            requests.get(url, timeout=1)
            return True
        except (requests.ConnectionError, requests.Timeout):
            time.sleep(0.1)
    return False

def start_flask(port):
    """Run Flask in specific port"""
    # Disable reloader and debugger for the desktop thread
    app.run(host='127.0.0.1', port=port, debug=False, use_reloader=False)

if __name__ == '__main__':
    # Find free port
    port = get_free_port()
    
    # Start Flask in background thread
    t = threading.Thread(target=start_flask, args=(port,), daemon=True)
    t.start()

    # Wait for server to be up
    if wait_for_server(port):
        # Create window
        webview.create_window(
            'Camellia Shield', 
            f'http://127.0.0.1:{port}',
            width=1280,
            height=800,
            resizable=True,
            min_size=(800, 600)
        )
        
        # Start webview
        webview.start(debug=True)
    else:
        print(f"Error: Failed to start server on port {port}")
        sys.exit(1)