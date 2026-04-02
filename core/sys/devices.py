from pathlib import Path


class DeviceManager:
    def list_devices(self) -> list[dict[str, str]]:
        devices: list[dict[str, str]] = []
        seen: set[str] = set()

        def add_device(device_id: str, name: str, path: Path, device_type: str = "local") -> None:
            resolved = str(path.resolve())
            if resolved in seen or not path.exists() or not path.is_dir():
                return
            seen.add(resolved)
            devices.append(
                {
                    "id": device_id,
                    "name": name,
                    "type": device_type,
                    "path": resolved,
                }
            )

        home = Path.home()
        add_device("system:root", "Root", Path("/"))
        add_device("system:home", "Home", Path("/home"))
        add_device("system:user-home", home.name or "Usuario", home)

        for base in (Path("/media"), Path("/run/media")):
            if not base.exists():
                continue
            for path in base.rglob("*"):
                if path.is_dir():
                    add_device(f"mnt:{path}", path.name, path, "usb")

        return sorted(
            devices,
            key=lambda item: (
                0 if item["id"] == "system:user-home" else 1 if item["id"] == "system:home" else 2 if item["id"] == "system:root" else 3,
                item["name"].lower(),
            ),
        )
