export class UI {
    constructor() {
        this.selectedItems = new Map();
    }

    renderDeviceList(devices, selectorEl) {
        selectorEl.innerHTML = '<option value="home" data-id="local">💻 Local</option>';
        devices.forEach(dev => {
            const opt = document.createElement('option');
            opt.value = dev.path;
            opt.textContent = `${this.getDeviceIcon(dev.type)} ${dev.name}`;
            opt.dataset.id = dev.id;
            selectorEl.appendChild(opt);
        });
    }

    getDeviceIcon(type) {
        if (type === 'usb') return '🔌';
        if (type === 'mtp') return '📱';
        return '💾';
    }

    renderFileList(items, containerEl, onSelect, onNavigate, onContextMenu) {
        containerEl.innerHTML = "";
        this.selectedItems.clear(); // Reset on reload? Yes usually.

        if (items.length === 0) {
            containerEl.innerHTML = '<div class="empty-state">Pasta vazia</div>';
            return;
        }

        items.forEach(item => {
            const div = document.createElement('div');
            div.className = 'file-item';
            div.dataset.path = item.path;

            let icon = item.is_dir ? '📁' : '📄';
            if (item.name.endsWith('.enc') || item.is_encrypted) {
                icon = '🔒';
                div.classList.add('encrypted');
            }

            // Checkbox
            const checkbox = document.createElement('input');
            checkbox.type = 'checkbox';
            checkbox.className = 'file-checkbox';
            checkbox.onclick = (e) => {
                e.stopPropagation();
                this.toggleSelection(item, checkbox.checked);
                if (onSelect) onSelect(this.selectedItems);
            };

            const content = `
                <div class="file-icon">${icon}</div>
                <div class="file-info">
                    <div class="file-name" title="${item.name}">${item.name}</div>
                    <div class="file-meta">
                        <span class="file-size">${item.is_dir ? 'Pasta' : this.formatSize(item.size)}</span>
                    </div>
                </div>
            `;

            div.innerHTML = content;
            div.prepend(checkbox);

            // Row click = toggle check (UX preference)
            div.onclick = (e) => {
                // If clicking the div, toggle checkbox
                checkbox.checked = !checkbox.checked;
                this.toggleSelection(item, checkbox.checked);
                if (onSelect) onSelect(this.selectedItems);
            };

            div.ondblclick = () => {
                if (item.is_dir && onNavigate) onNavigate(item.path);
            };

            div.oncontextmenu = (e) => {
                e.preventDefault();
                if (onContextMenu) onContextMenu(e, item);
            };

            containerEl.appendChild(div);
        });
    }

    toggleSelection(item, isSelected) {
        if (isSelected) this.selectedItems.set(item.path, item);
        else this.selectedItems.delete(item.path);

        // Visual class
        // Find element? We are redrawing often, but for live update:
        // In virtual DOM frameworks this is handled, here vanilla:
        // We rely on render refresh or we can toggle class on the row element passed in context?
        // Since we don't hold ref to rows here easily without query, we skip specific row class toggle for now unless requested.
    }

    formatSize(bytes) {
        if (!bytes && bytes !== 0) return '--';
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }
}
