import sys
import os
import threading
import webview
from dotenv import load_dotenv

# Load ENV early so FLASK_ENV is available before creating the app
load_dotenv()

# Desktop mode detection: set `DESKTOP_MODE=1` in your env when launching
# via webview. If set, we enable development mode to avoid enforcing HTTPS
# redirects from security middleware (Talisman) which is inappropriate
# for the local embedded webview. If not set, respect existing FLASK_ENV.
desktop_mode = os.getenv('DESKTOP_MODE', '0').lower()
if desktop_mode in ('1', 'true', 'yes'):
    os.environ.setdefault('FLASK_ENV', 'development')

# Import app after env is loaded
from app import app

def start_flask(port: int):
    # Run the flask app in a background thread. Disable the reloader
    # to avoid signal handling errors when not running in the main thread.
    app.run(host='127.0.0.1', port=port, debug=False, use_reloader=False)

if __name__ == '__main__':
    # Start Flask in a separate thread using configured PORT
    port = int(os.getenv('PORT', 5000))
    flask_thread = threading.Thread(target=start_flask, args=(port,), daemon=True)
    flask_thread.start()

    # Create window pointing to the Flask server port
    url = f'http://127.0.0.1:{port}'
    webview.create_window('Camellia Shield', url, width=1200, height=800, resizable=True)
    
    # Start webview
    webview.start(debug=True)