
import os
import shutil
import getpass

class DeviceManager:
    def __init__(self):
        self.user = getpass.getuser()
        self.uid =  os.getuid()
        
    def list_devices(self):
        """
        Detects external storage devices.
        1. USB Mass Storage (via /proc/mounts filtered for external media)
        2. MTP/PTP Devices (via GVFS)
        """
        devices = []
        
        # 1. USB Storage (Heuristic: Mounted in /media/USER or /run/media/USER)
        # Note: Linux automount paths differ. Common: /media/<user>/<label>, /run/media/<user>/<label>
        
        mounts_data = self._read_mounts()
        potential_roots = [
            f"/media/{self.user}",
            f"/run/media/{self.user}"
        ]
        
        for mount in mounts_data:
            path = mount['path']
            
            # Check if mount point starts with known automount roots
            is_external = any(path.startswith(root) for root in potential_roots)
            
            if is_external:
                 devices.append({
                     "id": f"usb:{mount['device']}", # Device node e.g. /dev/sdb1
                     "name": os.path.basename(path) or mount['device'],
                     "path": path,
                     "type": "usb",
                     "fs": mount['fs']
                 })

        # 2. MTP Devices (GVFS)
        # GVFS mounts usually at /run/user/$UID/gvfs/
        gvfs_root = f"/run/user/{self.uid}/gvfs"
        if os.path.exists(gvfs_root):
            try:
                for entry in os.scandir(gvfs_root):
                    if entry.is_dir():
                        # MTP folder usually has colons or is named 'mtp:...'
                        # Example: mtp:host=Xiaomi_...
                        friendly_name = entry.name.replace("mtp:host=", "MTP: ")
                        devices.append({
                            "id": f"mtp:{entry.name}",
                            "name": friendly_name,
                            "path": entry.path,
                            "type": "mtp",
                            "fs": "fuse.gvfsd-fuse"
                        })
            except (PermissionError, OSError):
                pass
                
        # Add Local Machine as default (if frontend needs explicit option)
        # devices.insert(0, {"id": "local", "name": "Local Computer", "path": "/", "type": "local"})
        
        return devices

    def _read_mounts(self):
        mounts = []
        try:
            with open('/proc/mounts', 'r') as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 3:
                        device, path, fs = parts[0], parts[1], parts[2]
                        # Filter out system pseudo-fs
                        if device.startswith('/') and not path.startswith('/snap'):
                            mounts.append({'device': device, 'path': path, 'fs': fs})
        except:
            pass
        return mounts

    def get_device_info(self, path):
        # Reverse lookup path to find device?
        # For now, just simplistic check
        devices = self.list_devices()
        for dev in devices:
            if path.startswith(dev['path']):
                return dev
        return {"id": "local", "type": "local"}
