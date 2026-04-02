from core.iam.db import init_db


class AuthManager:
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        init_db()
