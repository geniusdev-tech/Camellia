"""
Application-level singleton instances.
Imported by API blueprints.
"""
import os
from core.auth.manager import AuthManager
from core.vault.manager import VaultManager
from core.tasks import TaskManager

ROOT_DIR = os.path.expanduser("~")
DB_PATH  = os.path.join(ROOT_DIR, ".camellia_enterprise.db")

auth_manager  = AuthManager(DB_PATH)
vault_manager = VaultManager(ROOT_DIR, auth_manager)
task_manager  = TaskManager(vault_manager)
