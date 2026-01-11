import threading
import time
import uuid
import os

class Task:
    def __init__(self, task_id, action, target):
        self.id = task_id
        self.action = action
        self.target = target # Can be path (str) or list of paths
        self.progress = 0
        self.status = "Pending"
        self.logs = []
        self.paused = False
        self.cancelled = False
        self._lock = threading.Lock()

    def log(self, msg):
        with self._lock:
            self.logs.append(f"[{time.strftime('%H:%M:%S')}] {msg}")
    
    def set_progress(self, val):
        self.progress = val

class TaskManager:
    def __init__(self, vault_manager):
        self.vault_manager = vault_manager
        self.tasks = {}
        self.lock = threading.Lock()

    def start_task(self, action, target, **kwargs):
        task_id = str(uuid.uuid4().hex[:8])
        task = Task(task_id, action, target)
        
        with self.lock:
            self.tasks[task_id] = task
            
        if action.startswith("batch_"):
            thread = threading.Thread(target=self._run_batch_task, args=(task, kwargs))
        else:
            thread = threading.Thread(target=self._run_task, args=(task, kwargs))
            
        thread.daemon = True
        thread.start()
        return task_id

    def get_task(self, task_id):
        with self.lock:
            return self.tasks.get(task_id)

    def cancel_task(self, task_id):
        task = self.get_task(task_id)
        if task and task.status in ["Running", "Pending"]:
            task.cancelled = True
            task.log("Cancellation Requested...")
            return True
        return False

    def _run_batch_task(self, task, kwargs):
        try:
            task.status = "Running"
            task.log(f"Started {task.action} on {len(task.target)} items")
            recursive = kwargs.get('recursive', False)
            device_id = kwargs.get('device_id', 'local')
            
            if task.action == "batch_encrypt":
                gen = self.vault_manager.encrypt_batch(task.target, device_id=device_id, recursive=recursive)
            elif task.action == "batch_decrypt":
                gen = self.vault_manager.decrypt_batch(task.target, recursive=recursive)
            
            for update in gen:
                if task.cancelled:
                    task.status = "Cancelled"
                    task.log("Task Cancelled by User")
                    return
                
                if update['status'] == 'success':
                    task.log(f"Success: {os.path.basename(update['msg'] if task.action == 'batch_decrypt' else update['file'])}")
                elif update['status'] == 'skipped':
                    task.log(f"Skipped: {os.path.basename(update['file'])} ({update['msg']})")
                else:
                    task.log(f"Error {os.path.basename(update['file'])}: {update['msg']}")
                    
                task.progress = update['progress_global']
                
            task.progress = 100
            task.status = "Completed"
            task.log("Batch Process Finished")
            
        except Exception as e:
            task.status = "Error"
            task.log(f"Critical Batch Error: {str(e)}")

    def _run_task(self, task, kwargs):
        try:
            task.status = "Running"
            
            # Progress callback adapter
            def cb(curr, total, file_uuid):
                if task.cancelled: raise InterruptedError("Cancelled")
                if total > 0:
                    task.progress = (curr / total) * 100
            
            if task.action == "encrypt":
                task.log(f"Encrypting {os.path.basename(task.target)}")
                success, res = self.vault_manager.encrypt_file(
                    task.target, 
                    progress_callback=cb,
                    device_id=kwargs.get('device_id', 'local')
                )
                
                if success:
                    task.progress = 100
                    task.status = "Completed"
                    task.log("Encryption Successful")
                else:
                    task.status = "Error"
                    task.log(f"Error: {res}")
                    
            elif task.action == "decrypt":
                uuid_target = kwargs.get('uuid') or os.path.basename(task.target)
                task.log(f"Decrypting {uuid_target}")
                success, res = self.vault_manager.decrypt_file(
                    uuid_target, 
                    progress_callback=cb
                )
                
                if success:
                    task.progress = 100
                    task.status = "Completed"
                    task.log(f"Decrypted to {res}")
                else:
                    task.status = "Error"
                    task.log(f"Error: {res}")

        except InterruptedError:
            task.status = "Cancelled"
            task.log("Operation Cancelled")
        except Exception as e:
            task.status = "Error"
            task.log(f"Critical Error: {str(e)}")
