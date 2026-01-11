import os
import re

_FILENAME_SAFE = re.compile(r"[^A-Za-z0-9._-]")

def sanitize_filename(name: str, max_len: int = 255) -> str:
    """Remove unsafe characters and enforce max length."""
    base = os.path.basename(name)
    cleaned = _FILENAME_SAFE.sub('_', base)
    if len(cleaned) > max_len:
        cleaned = cleaned[:max_len]
    return cleaned


def sanitize_path(path: str) -> str:
    """Normalize path, remove .. and resolve absolute safely."""
    # Remove null bytes
    path = path.replace('\x00', '')
    # Collapse and normalize
    norm = os.path.normpath(path)
    # If original path was absolute, preserve leading slash and collapse safely
    if os.path.isabs(path):
        parts = []
        for p in norm.split(os.sep):
            if p in ('', '.'): 
                continue
            if p == '..':
                if parts:
                    parts.pop()
                continue
            parts.append(p)
        return os.sep + os.path.join(*parts) if parts else os.sep

    # Relative paths: remove .. and empty parts
    parts = [p for p in norm.split(os.sep) if p not in ('..', '')]
    return os.sep.join(parts)
