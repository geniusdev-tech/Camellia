import { API_ENDPOINTS, ApiService } from './api.js';
import { UI } from './ui/ui.js';
import { ProgressBarController } from './progress/progressBar.js';

// Global State
const state = {
    currentPath: "home",
    selectedItems: new Map(),
    currentTaskId: null,
    pollInterval: null,
    device: "local"
};

// Controllers
const ui = new UI();
let progressBar;

document.addEventListener('DOMContentLoaded', async () => {
    progressBar = new ProgressBarController({
        container: document.getElementById('progressBarContainer'),
        fill: document.getElementById('progressBarFill'),
        percentage: document.getElementById('progPercentage'),
        files: document.getElementById('progFiles'),
        time: document.getElementById('progTime'),
        eta: document.getElementById('progETA'),
        status: document.getElementById('progStatus')
    });

    setupEventListeners();
    await loadDevices();
    checkAuth(); // Initial check
    loadFiles("home");
});

function setupEventListeners() {
    // Navigation
    document.getElementById('refreshBtn').onclick = () => loadFiles(state.currentPath);
    document.getElementById('btnUp').onclick = () => {
        const parent = document.getElementById('parentPath').value;
        if (parent) loadFiles(parent);
    };

    // Auth Toggles (Simplification vs old main.js)
    // We can reuse the DOM IDs from old html or new ones. Assuming similar IDs.

    // Process
    document.getElementById('startProcessBtn').onclick = startBatchProcess;
    document.getElementById('cancelProcessBtn').onclick = cancelTask;

    // Devices
    document.getElementById('deviceSelector').onchange = (e) => {
        const opt = e.target.options[e.target.selectedIndex];
        state.device = opt.dataset.id;
        loadFiles(e.target.value);
    };
}

// Logic - File Loading
async function loadFiles(path) {
    // UI Loading state?
    try {
        const data = await ApiService.post(API_ENDPOINTS.listFiles, {
            path: path,
            device_id: state.device
        });

        if (data.success) {
            state.currentPath = data.current_path;

            // Update Toolbar
            document.getElementById('currentPathDisplay').textContent = truncatePath(state.currentPath);
            document.getElementById('parentPath').value = data.parent_path;

            ui.renderFileList(data.items, document.getElementById('fileList'), (selected) => {
                state.selectedItems = selected;
                updateSelectionCount();
            }, (dirPath) => {
                loadFiles(dirPath);
            }, (e, item) => {
                // Context menu placeholder
                console.log("Context menu", item);
            });
        }
    } catch (e) {
        console.error(e);
        if (e.message === "Unauthorized") showLogin();
    }
}

function updateSelectionCount() {
    const count = state.selectedItems.size;
    const targetsEl = document.getElementById('processTarget');
    if (targetsEl) targetsEl.textContent = count > 0 ? `${count} itens` : "Nenhum";
}

function truncatePath(path) {
    if (path.length > 40) return "..." + path.slice(-37);
    return path;
}

// Logic - Devices
async function loadDevices() {
    try {
        const data = await ApiService.get(API_ENDPOINTS.listDevices);
        if (data.success) {
            ui.renderDeviceList(data.devices, document.getElementById('deviceSelector'));
        }
    } catch (e) { console.error(e); }
}

// Logic - Process
async function startBatchProcess() {
    if (state.selectedItems.size === 0) return alert("Selecione itens");

    const encrypt = document.getElementById('encryptRadio').checked;
    const targets = Array.from(state.selectedItems.keys());

    if (!confirm(`Confirmar operação em ${targets.length} arquivos?`)) return;

    try {
        const data = await ApiService.post(API_ENDPOINTS.batchProcess, {
            targets: targets,
            recursive: true,
            device_id: state.device,
            encrypt: encrypt
        });

        if (data.success) {
            state.currentTaskId = data.task_id;

            // UI Update
            document.getElementById('startProcessBtn').disabled = true;
            document.getElementById('cancelProcessBtn').disabled = false;

            progressBar.reset();
            progressBar.show();

            state.pollInterval = setInterval(pollStatus, 500);
        } else {
            alert("Erro: " + data.msg);
        }
    } catch (e) { alert(e.message); }
}

async function pollStatus() {
    if (!state.currentTaskId) return;

    try {
        const data = await ApiService.get(API_ENDPOINTS.processStatus(state.currentTaskId));

        // Update Progress Bar
        // Backend returns: status, progress, logs, done
        // We simulate counts for calculation if missing

        progressBar.update({
            progress: data.progress,
            status: data.status,
            // Mock counts
            processed: Math.floor((data.progress / 100) * state.selectedItems.size),
            total: state.selectedItems.size
        });

        if (data.done) {
            clearInterval(state.pollInterval);
            state.currentTaskId = null;
            document.getElementById('startProcessBtn').disabled = false;
            document.getElementById('cancelProcessBtn').disabled = true;

            setTimeout(() => {
                progressBar.hide();
                loadFiles(state.currentPath);
            }, 1000);
        }
    } catch (e) { console.error(e); }
}

async function cancelTask() {
    if (!state.currentTaskId) return;
    await ApiService.post(API_ENDPOINTS.cancelProcess, { task_id: state.currentTaskId });
}

// Auth Logic
async function checkAuth() {
    try {
        const data = await ApiService.get(API_ENDPOINTS.status);
        if (data.authenticated) {
            updateAuthState(true, data);
        } else {
            updateAuthState(false);
        }
    } catch (e) { updateAuthState(false); }
}

function updateAuthState(isAuthenticated, userData) {
    const authWidget = document.getElementById('authWidget');
    const authForms = document.getElementById('authForms');
    const userInfo = document.getElementById('userInfo');

    if (isAuthenticated) {
        authForms.style.display = 'none';
        userInfo.classList.remove('hidden');
        if (userData) document.getElementById('userEmailDisplay').textContent = userData.email;
        // 2FA Buttons could be handled here if added to the new HTML
    } else {
        authForms.style.display = 'block';
        userInfo.classList.add('hidden');
    }
}

// Event Listeners for Auth
document.getElementById('loginBtn').addEventListener('click', async () => {
    const email = document.getElementById('emailInput').value;
    const pwd = document.getElementById('pwdInput').value;
    if (!email || !pwd) return alert("Preencha as credenciais");

    try {
        const data = await ApiService.post(API_ENDPOINTS.login, { email, password: pwd });
        if (data.success) {
            checkAuth();
        } else if (data.requires_mfa) {
            // Store user_id for the second step
            const userId = data.user_id;
            const code = prompt("Digite o código MFA do seu app autenticador:");
            if (code) {
                await performMfaLogin(code, userId);
            }
        } else {
            alert(data.msg);
        }
    } catch (e) {
        console.error(e);
        alert("Erro no login: " + e.message);
    }
});

async function performMfaLogin(code, userId) {
    try {
        const data = await ApiService.post(API_ENDPOINTS.loginMFA, {
            code: code,
            user_id: userId
        });
        if (data.success) {
            checkAuth();
        } else {
            alert(data.msg || "Falha no MFA");
        }
    } catch (e) {
        alert("Erro no MFA: " + e.message);
    }
}

document.getElementById('registerBtn').addEventListener('click', async () => {
    const email = document.getElementById('emailInput').value;
    const pwd = document.getElementById('pwdInput').value;
    try {
        const data = await ApiService.post(API_ENDPOINTS.register, { email, password: pwd });
        alert(data.msg);
    } catch (e) { alert(e.message); }
});

document.getElementById('logoutBtn').addEventListener('click', async () => {
    await ApiService.post(API_ENDPOINTS.logout, {});
    checkAuth();
});

async function verifyMFA(code) {
    const data = await ApiService.post(API_ENDPOINTS.verifyMFA, { code });
    if (data.success) {
        alert("MFA Configurado com sucesso!");
        checkAuth();
    } else {
        alert(data.msg);
    }
}
