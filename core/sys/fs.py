import os
from pathlib import Path


class PathValidator:
    @staticmethod
    def get_fallback() -> Path:
        return Path.home()

    @staticmethod
    def validate(
        raw_path: str | None,
        require_exists: bool = False,
        require_dir: bool = False,
    ) -> tuple[bool, Path, str | None]:
        if not raw_path or raw_path == "home":
            path = PathValidator.get_fallback()
        else:
            path = Path(raw_path).expanduser().resolve()

        if require_exists and not path.exists():
            return False, path, "Caminho não existe"
        if require_dir and not path.is_dir():
            return False, path, "Diretório inválido"
        return True, path, None

    @staticmethod
    def list_dir(path: str) -> list[Path]:
        return sorted(Path(path).iterdir(), key=lambda item: (not item.is_dir(), item.name.lower()))
