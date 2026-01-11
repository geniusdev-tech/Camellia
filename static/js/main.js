const API = {
    login: '/api/auth/login',
    register: '/api/auth/register',
    status: '/api/auth/status',
    logout: '/api/auth/logout',
    setup2FA: '/api/auth/2fa/setup',
    verify2FA: '/api/auth/2fa/verify',
    confirm2FA: '/api/auth/2fa/confirm',
    disable2FA: '/api/auth/2fa/disable',
    listFiles: '/api/files/list',
    fileAction: '/api/files/action',
    startProcess: '/api/process/start',
    batchProcess: '/api/process/batch',
    cancelProcess: '/api/process/cancel',
    processStatus: (id) => `/api/process/status/${id}`,
    processControl: '/api/process/control',
    listDevices: '/api/devices/list'
};

let currentPath = "home";
let currentDevice = "local";
let selectedItems = new Map(); // Path -> Item
let currentTaskId = null;
let pollInterval = null;

const el = (id) => document.getElementById(id);

document.addEventListener('DOMContentLoaded', () => {
    checkAuth();
    loadDevices();
    loadFiles(currentPath);
    setupEventListeners();
});

function setupEventListeners() {
    el('loginBtn').addEventListener('click', login);
    el('registerBtn').addEventListener('click', register);
    el('logoutBtn').addEventListener('click', logout);
    el('setup2faBtn').addEventListener('click', setup2FA);
    el('disable2faBtn').addEventListener('click', disable2FA);

    el('btnUp').addEventListener('click', () => {
        if (currentPath !== "/") {
            loadFiles(el('parentPath').value || "home");
        }
    });
    el('refreshBtn').addEventListener('click', () => {
        loadDevices();
        loadFiles(currentPath);
    });

    el('startProcessBtn').addEventListener('click', startProcess);
    el('pauseProcessBtn').addEventListener('click', () => alert("Pause not implemented yet"));
    el('resumeProcessBtn').addEventListener('click', () => alert("Resume not implemented yet"));
    el('cancelProcessBtn').addEventListener('click', cancelTask);
    el('organizeBtn').addEventListener('click', organizeFolder);

    // Device Selector
    el('deviceSelector').addEventListener('change', (e) => {
        const devPath = e.target.value;
        currentDevice = e.target.options[e.target.selectedIndex].dataset.id;
        loadFiles(devPath);
    });
}

// --- Devices ---
async function loadDevices() {
    try {
        const res = await fetch(API.listDevices);
        const data = await res.json();
        if (data.success) {
            const sel = el('deviceSelector');
            sel.innerHTML = '<option value="home" data-id="local">💻 Local</option>';
            data.devices.forEach(dev => {
                const opt = document.createElement('option');
                opt.value = dev.path;
                opt.textContent = `${getDeviceIcon(dev.type)} ${dev.name}`;
                opt.dataset.id = dev.id;
                sel.appendChild(opt);
            });
        }
    } catch (e) { console.error(e); }
}

function getDeviceIcon(type) {
    if (type === 'usb') return '🔌';
    if (type === 'mtp') return '📱';
    return '💾';
}

// --- Auth ---
async function checkAuth() {
    const res = await fetch(API.status);
    const data = await res.json();
    if (data.authenticated) {
        showAuthenticated(data);
    } else {
        showLogin();
    }
}

function showAuthenticated(data) {
    el('authForms').style.display = 'none';
    el('userInfo').style.display = 'block';
    el('userEmailDisplay').textContent = data.email;
    el('processPanel').classList.remove('disabled');

    // Toggle 2FA buttons
    if (data.has_2fa) {
        el('setup2faBtn').style.display = 'none';
        el('disable2faBtn').style.display = 'block';
    } else {
        el('setup2faBtn').style.display = 'block';
        el('disable2faBtn').style.display = 'none';
    }
}

function showLogin() {
    el('authForms').style.display = 'block';
    el('userInfo').style.display = 'none';
    el('processPanel').classList.add('disabled');
}

async function login() {
    const email = el('emailInput').value;
    const pwd = el('pwdInput').value;
    if (!email || !pwd) return alert('Preencha os campos');
    const res = await fetch(API.login, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password: pwd })
    });
    const data = await res.json();
    if (data.success) {
        checkAuth();
        log("Login realizado.");
    } else if (data.requires_2fa) {
        const code = prompt("Código 2FA:");
        if (code) verify2FAToken(code);
    } else {
        alert(data.msg);
    }
}

async function verify2FAToken(code) {
    const res = await fetch(API.verify2FA, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code })
    });
    const data = await res.json();
    if (data.success) {
        checkAuth();
        log("2FA Confirmado.");
    } else {
        alert(data.msg);
    }
}

async function register() {
    const email = el('emailInput').value;
    const pwd = el('pwdInput').value;
    if (!email || !pwd) return alert('Preencha os campos');
    const res = await fetch(API.register, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password: pwd })
    });
    const data = await res.json();
    alert(data.msg);
}

async function logout() {
    await fetch(API.logout, { method: 'POST' });
    checkAuth();
    log("Logout realizado.");
}

async function setup2FA() {
    const res = await fetch(API.setup2FA, { method: 'POST' });
    const data = await res.json();
    if (data.success) {
        el('qrImage').src = data.qr_code;
        el('secretCode').textContent = data.secret;
        el('qrModal').style.display = 'flex';
        // Remove previous listeners to avoid duplicates if reopened
        const newConfirmBtn = el('confirm2faBtn').cloneNode(true);
        el('confirm2faBtn').parentNode.replaceChild(newConfirmBtn, el('confirm2faBtn'));

        newConfirmBtn.addEventListener('click', () => confirm2FASetup(data.secret));

        const closeBtn = el('closeModalBtn');
        closeBtn.onclick = () => el('qrModal').style.display = 'none';
    } else {
        alert("Erro ao iniciar setup 2FA: " + data.msg);
    }
}

async function confirm2FASetup(secret) {
    const code = el('qrCodeInput').value;
    if (!code) return alert("Digite o código");

    const res = await fetch(API.confirm2FA, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ secret, code })
    });
    const data = await res.json();
    if (data.success) {
        alert("2FA Ativado com sucesso!");
        el('qrModal').style.display = 'none';
        checkAuth();
    } else {
        alert(data.msg);
    }
}

async function disable2FA() {
    if (!confirm("Tem certeza que deseja desativar o 2FA? Isso reduzirá sua segurança.")) return;

    const res = await fetch(API.disable2FA, { method: 'POST' });
    const data = await res.json();
    if (data.success) {
        alert("2FA Desativado.");
        checkAuth();
    } else {
        alert("Erro: " + data.msg);
    }
}

// --- File Functions ---
async function loadFiles(path) {
    const res = await fetch(API.listFiles, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ path, device_id: currentDevice })
    });
    if (res.status === 401) {
        el('fileList').innerHTML = '<div style="padding:20px; text-align:center;">🔒 Vault Locked. Please Login.</div>';
        return;
    }
    const data = await res.json();

    if (data.success) {
        currentPath = data.current_path;
        el('currentPathDisplay').textContent = currentPath;
        el('parentPath').value = data.parent_path || "";

        const list = el('fileList');
        list.innerHTML = "";
        selectedItems.clear();
        updateSelectionUI();

        data.items.forEach(item => {
            const div = document.createElement('div');
            div.className = 'file-item';
            div.dataset.path = item.path;

            let icon = item.is_dir ? '📁' : '📄';
            let nameClass = 'file-name';
            if (item.is_encrypted) {
                icon = '🔒';
                nameClass += ' encrypted';
            }

            // Checkbox for multi-select
            const checkbox = document.createElement('input');
            checkbox.type = 'checkbox';
            checkbox.style.marginRight = '10px';
            checkbox.onchange = (e) => toggleSelection(item, e.target.checked);

            div.innerHTML = `
                <div class="file-icon">${icon}</div>
                <div class="${nameClass}">${item.name}</div>
                <div class="file-size">${item.is_dir ? '' : formatSize(item.size)}</div>
            `;
            div.prepend(checkbox);

            div.onclick = (e) => {
                if (e.target !== checkbox) {
                    checkbox.checked = !checkbox.checked;
                    toggleSelection(item, checkbox.checked);
                }
            };

            div.ondblclick = () => {
                if (item.is_dir) loadFiles(item.path);
            };

            div.oncontextmenu = (e) => {
                e.preventDefault();
                showContextMenu(e.pageX, e.pageY, item);
            };

            list.appendChild(div);
        });
    } else {
        log("Error loading files: " + data.msg);
    }
}

function formatSize(bytes) {
    if (!bytes && bytes !== 0) return 'AES'; // Legacy
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function toggleSelection(item, isSelected) {
    if (isSelected) selectedItems.set(item.path, item);
    else selectedItems.delete(item.path);
    updateSelectionUI();
}

function updateSelectionUI() {
    const count = selectedItems.size;
    el('processTarget').textContent = count > 0 ? `${count} itens selecionados` : "Nenhum";
}

async function startProcess() {
    if (selectedItems.size === 0) return alert("Selecione itens");

    const encrypt = el('encryptRadio').checked;
    const recursive = true; // Default to recursive for folders in batch
    const targets = Array.from(selectedItems.keys());

    // Validation
    const mode = encrypt ? "Criptografar" : "Descriptografar";
    if (!confirm(`${mode} ${targets.length} itens?`)) return;

    // Use Batch Endpoint if > 1 or Folder, else standard? 
    // Batch endpoint handles single too.

    const res = await fetch(API.batchProcess, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            targets: targets,
            recursive: recursive,
            device_id: currentDevice,
            encrypt: encrypt
        })
    });

    const data = await res.json();
    if (data.success) {
        log("Batch iniciado: " + data.task_id);
        currentTaskId = data.task_id;
        el('startProcessBtn').disabled = true;
        el('cancelProcessBtn').disabled = false;
        pollInterval = setInterval(pollStatus, 500);
    } else {
        alert("Erro: " + data.msg);
    }
}

async function cancelTask() {
    if (!currentTaskId) return;
    await fetch(API.cancelProcess, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ task_id: currentTaskId })
    });
    log("Solicitado cancelamento...");
}

async function pollStatus() {
    if (!currentTaskId) return;
    const res = await fetch(API.processStatus(currentTaskId));
    const data = await res.json();

    if (data) {
        el('progressBarFill').style.width = data.progress + "%";
        if (data.logs && data.logs.length) {
            const logPanel = el('logPanel');
            // Show last few logs
            const newLogs = data.logs.slice(-5);
            logPanel.innerHTML = newLogs.map(l => `<div class="log-entry">${l}</div>`).join('');
            logPanel.scrollTop = logPanel.scrollHeight;
        }

        if (data.done) {
            clearInterval(pollInterval);
            pollInterval = null;
            el('startProcessBtn').disabled = false;
            el('cancelProcessBtn').disabled = true;
            currentTaskId = null;
            log("Finalizado: " + data.status);
            loadFiles(currentPath);
            selectedItems.clear(); // Reset selection
            updateSelectionUI();
        }
    }
}

function controlProcess(action) { }
function log(msg) {
    const p = document.createElement('div');
    p.className = 'log-entry';
    p.textContent = `[System] ${msg}`;
    el('logPanel').appendChild(p);
}
function organizeFolder() { }

// Context Menu
const ctxMenu = document.createElement('div');
ctxMenu.style.position = 'absolute';
ctxMenu.style.background = '#333';
ctxMenu.style.border = '1px solid #555';
ctxMenu.style.padding = '5px';
ctxMenu.style.display = 'none';
ctxMenu.style.zIndex = 1000;
document.body.appendChild(ctxMenu);

document.addEventListener('click', () => ctxMenu.style.display = 'none');

function showContextMenu(x, y, item) {
    ctxMenu.innerHTML = '';
    const actions = [
        { label: 'Renomear', action: () => promptRename(item) },
        { label: 'Deletar', action: () => confirmDelete(item) }
    ];

    actions.forEach(act => {
        const btn = document.createElement('div');
        btn.textContent = act.label;
        btn.style.padding = '5px 15px';
        btn.style.cursor = 'pointer';
        btn.style.color = '#fff';
        btn.onmouseover = () => btn.style.background = '#555';
        btn.onmouseout = () => btn.style.background = 'transparent';
        btn.onclick = act.action;
        ctxMenu.appendChild(btn);
    });

    ctxMenu.style.left = x + 'px';
    ctxMenu.style.top = y + 'px';
    ctxMenu.style.display = 'block';
}

function promptRename(item) {
    const newName = prompt("Novo nome:", item.name);
    if (newName && newName !== item.name) {
        fetch(API.fileAction, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: 'rename', path: item.path, new_name: newName })
        }).then(() => loadFiles(currentPath));
    }
}

function confirmDelete(item) {
    // SAFE DELETE IMPLEMENTATION
    const confirmation = prompt(`ATENÇÃO: Ação irreversível!\nPara deletar '${item.name}', digite DELETE abaixo:`);
    if (confirmation === "DELETE") {
        fetch(API.fileAction, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: 'delete', path: item.path })
        }).then(() => loadFiles(currentPath));
    } else if (confirmation !== null) {
        alert("Confirmação incorreta. Arquivo mantido.");
    }
}
