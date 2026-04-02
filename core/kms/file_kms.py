import os


class FileKMS:
    def __init__(self, path: str) -> None:
        self.path = path
        directory = os.path.dirname(path) or "."
        os.makedirs(directory, exist_ok=True)
        if not os.path.exists(path):
            with open(path, "wb") as handle:
                handle.write(os.urandom(32))

    def get_key(self) -> bytes:
        with open(self.path, "rb") as handle:
            return handle.read()
