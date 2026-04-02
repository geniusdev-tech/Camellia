import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from core.audit.logger import get_audit_logger


@dataclass
class TaskState:
    task_id: str
    status: str = "Queued"
    progress: float = 0.0
    logs: list[str] = field(default_factory=list)
    cancel_requested: bool = False


class TaskManager:
    def __init__(self, vault_manager) -> None:
        self.vault_manager = vault_manager
        self.tasks: dict[str, TaskState] = {}
        self._lock = threading.Lock()

    def start_task(self, action: str, target, **kwargs) -> str:
        task_id = kwargs.get("uuid") or str(uuid.uuid4())
        task = TaskState(task_id=task_id)
        with self._lock:
            self.tasks[task_id] = task
        thread = threading.Thread(
            target=self._run_task,
            args=(task_id, action, target, kwargs),
            daemon=True,
        )
        thread.start()
        return task_id

    def get_task(self, task_id: str) -> TaskState | None:
        return self.tasks.get(task_id)

    def cancel_task(self, task_id: str) -> bool:
        task = self.tasks.get(task_id)
        if not task:
            return False
        task.cancel_requested = True
        task.status = "Cancelled"
        task.logs.append("Cancelamento solicitado")
        return True

    def _expand_targets(self, targets, recursive: bool) -> list[str]:
        expanded: list[str] = []
        for raw in targets:
            path = Path(raw)
            try:
                if path.is_dir() and recursive:
                    expanded.extend(str(child) for child in path.rglob("*") if child.is_file())
                else:
                    expanded.append(str(path))
            except Exception:
                expanded.append(str(path))
        return expanded

    def _run_task(self, task_id: str, action: str, target, kwargs) -> None:
        task = self.tasks[task_id]
        recursive = kwargs.get("recursive", False)
        user_id = kwargs.get("user_id", "dev-user")
        encrypt = action in ("encrypt", "batch_encrypt")
        targets = target if isinstance(target, list) else [target]
        files = self._expand_targets(targets, recursive)
        total = max(len(files), 1)
        task.status = "Running"
        success_count = 0
        error_count = 0

        try:
            for index, file_path in enumerate(files, start=1):
                if task.cancel_requested:
                    return
                try:
                    result = self.vault_manager.transform_path(
                        file_path,
                        encrypt=encrypt,
                        user_id=user_id,
                    )
                    verb = "encrypt" if encrypt else "decrypt"
                    task.logs.append(f"{verb}:{file_path} -> {result}")
                    success_count += 1
                except Exception as exc:
                    error_count += 1
                    task.logs.append(f"error:{file_path} -> {exc}")
                finally:
                    task.progress = index / total * 100
                    time.sleep(0.05)
        except Exception as exc:
            task.status = "Error"
            task.logs.append(f"fatal -> {exc}")
            task.progress = 100
            return

        task.status = "Completed" if success_count > 0 else "Error"
        task.progress = 100
        if error_count:
            task.logs.append(f"summary -> success:{success_count} error:{error_count}")
        try:
            logger = get_audit_logger()
            logger.log_event(
                f"crypto.file.{'encrypt' if encrypt else 'decrypt'}",
                str(user_id),
                details={"files": len(files), "success": success_count, "errors": error_count},
            )
        except Exception:
            pass
