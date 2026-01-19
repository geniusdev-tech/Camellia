import hashlib
import math
import os
from typing import Tuple, Dict, List

class IntegrityInspector:
    """
    Deep Integrity Inspection (DII) Engine
    Performs cryptographic validation, magic byte checking, and heuristic entropy analysis.
    """

    # Common Magic Bytes for file types
    MAGIC_NUMBERS: Dict[str, bytes] = {
        'jpg': b'\xFF\xD8\xFF',
        'jpeg': b'\xFF\xD8\xFF',
        'png': b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A',
        'gif': b'\x47\x49\x46\x38',
        'pdf': b'\x25\x50\x44\x46', # %PDF
        'zip': b'\x50\x4B\x03\x04',
        'exe': b'\x4D\x5A', # MZ
        'elf': b'\x7F\x45\x4C\x46', # .ELF
        'docx': b'\x50\x4B\x03\x04', # ZIP-based
        'mp4': b'\x00\x00\x00', # Often starts with ftyp, varies slightly but check first bytes
        'py': None, # Text files are harder to check by magic bytes purely
        'txt': None
    }

    # Threshold for High Entropy (Shannon Entropy > 7.8 is suspicious for non-media files)
    ENTROPY_THRESHOLD = 7.8 

    @staticmethod
    def calculate_hashes(file_path: str) -> Dict[str, str]:
        """Calculates SHA-256 and BLAKE2b hashes for the file."""
        sha256 = hashlib.sha256()
        blake2b = hashlib.blake2b()
        
        try:
            with open(file_path, "rb") as f:
                while chunk := f.read(8192):
                    sha256.update(chunk)
                    blake2b.update(chunk)
            
            return {
                'sha256': sha256.hexdigest(),
                'blake2b': blake2b.hexdigest()
            }
        except Exception as e:
            return {'error': str(e)}

    @staticmethod
    def calculate_entropy(file_path: str) -> float:
        """
        Calculates Shannon Entropy of the file in chunks to prevent memory bloat.
        Returns a float between 0.0 and 8.0.
        """
        try:
            freq_list = [0] * 256
            total_length = 0

            with open(file_path, "rb") as f:
                while chunk := f.read(65536): # 64KB chunks
                    total_length += len(chunk)
                    for b in chunk:
                        freq_list[b] += 1

            if total_length == 0:
                return 0.0

            entropy = 0.0
            for count in freq_list:
                if count > 0:
                    prob = float(count) / total_length
                    entropy -= prob * math.log(prob, 2)

            return entropy
        except Exception:
            return 0.0

    @staticmethod
    def verify_magic_bytes(file_path: str) -> Tuple[bool, str]:
        """
        Verifies if the file content matches its extension.
        Returns (is_valid, message).
        """
        ext = file_path.split('.')[-1].lower() if '.' in file_path else ''
        expected_magic = IntegrityInspector.MAGIC_NUMBERS.get(ext)

        if expected_magic is None:
            # No magic signature known or text file, skip validation (assume valid)
            return True, "No signature check for this type"

        try:
            with open(file_path, "rb") as f:
                header = f.read(len(expected_magic))
                
            if header.startswith(expected_magic):
                return True, "Signature matches extension"
            
            # Special case: DOCX is a ZIP
            if ext == 'docx' and header.startswith(b'\x50\x4B\x03\x04'):
                 return True, "Signature matches (ZIP-based)"

            return False, f"Signature Mismatch: Expected {expected_magic.hex().upper()} but got {header.hex().upper()}"
        except Exception as e:
            return False, f"Read error: {str(e)}"

    @staticmethod
    def inspect_file(file_path: str) -> Dict:
        """
        Full Deep Integrity Inspection.
        """
        if not os.path.exists(file_path):
             return {'success': False, 'msg': 'File not found'}

        # 1. Hashing
        hashes = IntegrityInspector.calculate_hashes(file_path)
        
        # 2. Magic Bytes
        signature_valid, sig_msg = IntegrityInspector.verify_magic_bytes(file_path)
        
        # 3. Entropy
        entropy = IntegrityInspector.calculate_entropy(file_path)
        
        # 4. Risk Analysis
        risk_level = "LOW"
        risk_factors = []
        
        if not signature_valid:
            risk_level = "HIGH"
            risk_factors.append("File signature mismatch (Possible spoofing)")
        
        # Double extension check
        filename = os.path.basename(file_path)
        if filename.count('.') > 1:
            exts = filename.split('.')[-2:]
            if exts[1] in ['exe', 'bat', 'sh'] and exts[0] in ['pdf', 'jpg', 'doc']:
                risk_level = "CRITICAL"
                risk_factors.append(f"Suspicious double extension: .{exts[0]}.{exts[1]}")
        
        # High entropy for non-compressed types
        ext = filename.split('.')[-1].lower()
        if entropy > 7.8 and ext in ['txt', 'bat', 'ps1', 'py', 'js']:
             risk_level = "HIGH"
             risk_factors.append("High entropy in script/text file (Possible Obfuscation/Packing)")

        return {
            'success': True,
            'filename': filename,
            'hashes': hashes,
            'integrity': {
                'signature_valid': signature_valid,
                'signature_msg': sig_msg,
                'entropy': round(entropy, 3)
            },
            'risk_analysis': {
                'level': risk_level,
                'factors': risk_factors
            }
        }
