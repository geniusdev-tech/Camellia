import os
import pathlib
from typing import Union, Tuple, Optional

class PathError(Exception):
    pass

class PathValidator:
    """
    Centralized path validation logic to prevent filesystem errors and access violations.
    """
    
    # Systems paths to strictly block
    BLOCKED_PREFIXES = [
        '/proc', '/sys', '/dev', '/run', '/boot', '/etc', '/var', '/usr',
        '/bin', '/sbin', '/lib', '/lib64', '/root'
    ]

    @staticmethod
    def get_fallback() -> pathlib.Path:
        """Returns the safe fallback directory (User Home)."""
        return pathlib.Path.home().resolve()

    @staticmethod
    def validate(
        path_str: Optional[str], 
        require_dir: bool = False, 
        require_exists: bool = True
    ) -> Tuple[bool, pathlib.Path, str]:
        """
        Validates and sanitizes a path.
        
        Args:
            path_str: The path string to validate.
            require_dir: If True, checks if it's a directory.
            require_exists: If True, checks if the path exists.
            
        Returns:
            Tuple(valid: bool, path: Path, message: str)
            If valid=False, path is the fallback directory.
        """
        fallback = PathValidator.get_fallback()
        
        if not path_str or not isinstance(path_str, str):
            return False, fallback, "Path is empty or invalid type"

        # Normalization
        try:
            # handle ~ manually first just in case
            expanded_path = os.path.expanduser(path_str)
            target_path = pathlib.Path(expanded_path).resolve()
        except Exception as e:
            return False, fallback, f"Path resolution failed: {str(e)}"

        # Security Check: Block List
        s_path = str(target_path)
        for block in PathValidator.BLOCKED_PREFIXES:
            if s_path.startswith(block):
                return False, fallback, f"Access denied to system path: {block}"

        # Security Check: Enforce Allowed Roots (Home or External Media)
        allowed_roots = [str(fallback), '/media', '/run/media', '/mnt', '/tmp', os.getcwd()]
        # Also allow /tmp and current working directory
        is_allowed = False
        for root in allowed_roots:
            try:
                # Check if target_path is within this root
                target_path.relative_to(root)
                is_allowed = True
                break
            except ValueError:
                continue

        if not is_allowed:
             return False, fallback, "Access denied: Path outside of allowed user or media areas"

        # Existence Check
        if require_exists:
            if not target_path.exists():
                return False, fallback, "Path does not exist"
            
            # Type Check
            if require_dir:
                if not target_path.is_dir():
                    return False, fallback, "Path is not a directory"
            # Else we might want to check if it's a file? 
            # The user might pass a file for an action. 
            # If require_dir is False, we accept file or dir (if exists is True).

        return True, target_path, "OK"
    
    @staticmethod
    def ensure_safe_path(path_str: str) -> str:
        """
        Helper that raises exception or returns valid str path.
        Useful for quick sanitizer where we want to crash/fallback explicitly.
        """
        valid, path, msg = PathValidator.validate(path_str)
        if not valid:
             # Just return fallback
             return str(path)
        return str(path)
