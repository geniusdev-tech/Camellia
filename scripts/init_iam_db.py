from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.iam.db import init_db


if __name__ == "__main__":
    init_db()
    print("IAM database initialized.")
