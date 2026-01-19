import time
from typing import Dict, Optional

class SessionKeyManager:
    """
    Singleton to hold sensitive keys in memory.
    Maps session_id or user_id -> master_key.
    """
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(SessionKeyManager, cls).__new__(cls)
            cls._instance.keys = {} # user_id -> {key: bytes, expires: timestamp}
        return cls._instance

    def store_key(self, user_id, key: bytes, ttl: int = 300):
        self.keys[str(user_id)] = {
            "key": key,
            "expires": time.time() + ttl
        }

    def get_key(self, user_id) -> Optional[bytes]:
        data = self.keys.get(str(user_id))
        if not data:
            return None
        
        if time.time() > data["expires"]:
            del self.keys[user_id]
            return None
            
        # Refresh TTL on access?
        data["expires"] = time.time() + 300
        return data["key"]
        
    def clear_key(self, user_id):
        uid = str(user_id)
        if uid in self.keys:
            del self.keys[uid]

key_manager = SessionKeyManager()
