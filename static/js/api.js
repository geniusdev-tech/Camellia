// API Module
const API_ENDPOINTS = {
    login: '/api/auth/login',
    loginMFA: '/api/auth/login/mfa',
    register: '/api/auth/register',
    status: '/api/auth/status',
    logout: '/api/auth/logout',
    setupMFA: '/api/auth/mfa/setup',
    verifyMFA: '/api/auth/mfa/verify',
    confirmMFA: '/api/auth/mfa/confirm',
    disableMFA: '/api/auth/mfa/disable',
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
