// API Module
const API_ENDPOINTS = {
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

export class ApiService {
    static async get(endpoint) {
        try {
            const res = await fetch(endpoint);
            if (res.status === 401) throw new Error("Unauthorized");
            return await res.json();
        } catch (e) {
            console.error("API Get Error:", e);
            throw e;
        }
    }

    static async post(endpoint, body) {
        try {
            const res = await fetch(endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body)
            });
            if (res.status === 401) throw new Error("Unauthorized");
            return await res.json();
        } catch (e) {
            console.error("API Post Error:", e);
            throw e;
        }
    }
}

export { API_ENDPOINTS };
