const API_BASE_URL = 'http://localhost:8000/api/v1';

const Api = {

    getHeaders() {
        const token = Utils.getToken();
        return {
            'Content-Type': 'application/json',
            'Authorization': token ? `Bearer ${token}` : ''
        };
    },

    async request(endpoint, options = {}) {
        const url = `${API_BASE_URL}${endpoint}`;
        const headers = {
            ...this.getHeaders(),
            ...options.headers
        };

        const config = {
            ...options,
            headers
        };

        try {
            const response = await fetch(url, config);
            const data = await response.json();

            if (!response.ok) {
                const error = new Error(data.detail || 'Request failed');
                error.status = response.status;
                
                // If unauthorized, clear auth and stop auto-refresh
                if (response.status === 401) {
                    Utils.removeToken();
                    Utils.removeUser();
                    if (window.App) {
                        window.App.stopAutoRefresh();
                        window.App.showLoginSection();
                        window.App.updateAuthNav();
                    }
                    Utils.showToast('Session expired. Please login again.', 'warning');
                }
                
                throw error;
            }

            return data;
        } catch (error) {
            console.error('API Error:', error);
            throw error;
        }
    },

    // ==================== USERS ====================
    async login(username, password) {
        const formData = new FormData();
        formData.append('username', username);
        formData.append('password', password);

        const response = await fetch(`${API_BASE_URL}/users/login`, {
            method: 'POST',
            body: formData
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.detail || 'Login failed');
        }

        return data;
    },

    async register(userData) {
        return this.request('/users/register', {
            method: 'POST',
            body: JSON.stringify(userData)
        });
    },

    async getProfile() {
        return this.request('/users/profile');
    },

    async forgotPassword(email) {
        return this.request('/users/forgot-password', {
            method: 'POST',
            body: JSON.stringify({ email })
        });
    },

    async requestInvite(email) {
        return this.request('/users/demande_invite', {
            method: 'POST',
            body: JSON.stringify({ email: email })
        });
    },

    async resetPassword(token, newPassword) {
        return this.request('/users/reset-password', {
            method: 'POST',
            body: JSON.stringify({ token, new_password: newPassword })
        });
    },

    async createInvite(inviteData) {
        return this.request('/users/invite', {
            method: 'POST',
            body: JSON.stringify(inviteData)
        });
    },

    async getUsage() {
        return this.request('/users/usage');
    },

    // ==================== API KEYS ====================
    async getApiKeys() {
        return this.request('/api-keys');
    },

    async createApiKey(keyData) {
        return this.request('/api-keys', {
            method: 'POST',
            body: JSON.stringify(keyData)
        });
    },

    async revokeApiKey(keyId) {
        return this.request(`/api-keys/${keyId}`, {
            method: 'DELETE'
        });
    },

    // ==================== BILLING ====================
    async getSubscription() {
        return this.request('/billing/subscription');
    },

    async createPortalSession() {
        return this.request('/billing/portal', {
            method: 'POST'
        });
    },

    // ==================== STATS ====================
    async getSystemInfo() {
        return this.request('/stats/system_info');
    },

    async getFullSystemStats() {
        return this.request('/stats/full');
    },

    // ==================== HEALTH ====================
    async getHealth() {
        return fetch(`${API_BASE_URL}/healthz`).then(r => r.json());
    },

    async getReadiness() {
        return fetch(`${API_BASE_URL}/readyz`).then(r => r.json());
    },

    // ==================== LOGS ====================
    async getLogs(skip = 0, limit = 100) {
        return this.request(`/logs/?skip=${skip}&limit=${limit}`);
    },

    async getLog(logId) {
        return this.request(`/logs/${logId}`);
    },

    async uploadLogFile(file, onProgress) {
        return new Promise((resolve, reject) => {
            const token = Utils.getToken();
            const formData = new FormData();
            formData.append('file', file);

            const xhr = new XMLHttpRequest();

            xhr.upload.addEventListener('progress', (e) => {
                if (e.lengthComputable && onProgress) {
                    const percent = Math.round((e.loaded / e.total) * 100);
                    onProgress(percent);
                }
            });

            xhr.addEventListener('load', () => {
                try {
                    const data = JSON.parse(xhr.responseText);
                    if (xhr.status >= 200 && xhr.status < 300) {
                        resolve(data);
                    } else {
                        reject(new Error(data.detail || 'Upload failed'));
                    }
                } catch (e) {
                    reject(new Error('Invalid response'));
                }
            });

            xhr.addEventListener('error', () => {
                reject(new Error('Upload failed'));
            });

            xhr.open('POST', `${API_BASE_URL}/logs/upload`);
            if (token) {
                xhr.setRequestHeader('Authorization', `Bearer ${token}`);
            }
            xhr.send(formData);
        });
    },

    async deleteLog(logId) {
        return this.request(`/logs/${logId}`, {
            method: 'DELETE'
        });
    },

    async getUserResultsByLog(logId) {
        return this.request(`/logs/${logId}/results`);
    },

    async getLogResults(logId) {
        return this.request(`/admin/results/by-log/${logId}`);
    },

    // ==================== ADMIN DASHBOARD ====================
    async getDashboardStats() {
        return this.request('/admin/dashboard/stats');
    },

    async getRecentActivity(days = 7) {
        return this.request(`/admin/dashboard/activity?days=${days}`);
    },

    async getErrorStatistics() {
        return this.request('/admin/dashboard/errors');
    },

    async getUserStatistics() {
        return this.request('/admin/dashboard/users');
    },

    async getAllTables() {
        return this.request('/admin/tables');
    },

    // ==================== ADMIN LOGS ====================
    async getAdminLogs(skip = 0, limit = 100) {
        return this.request(`/admin/logs?skip=${skip}&limit=${limit}`);
    },

    async getAdminLog(logId) {
        return this.request(`/admin/logs/${logId}`);
    },

    async updateAdminLog(logId, data) {
        return this.request(`/admin/logs/${logId}`, {
            method: 'PUT',
            body: JSON.stringify(data)
        });
    },

    async deleteAdminLog(logId) {
        return this.request(`/admin/logs/${logId}`, {
            method: 'DELETE'
        });
    },

    async bulkDeleteLogs(ids) {
        return this.request('/admin/logs/bulk-delete', {
            method: 'POST',
            body: JSON.stringify({ ids })
        });
    },

    async verifyEmail(token) {
        return this.request(`/users/verify_email?token=${token}`);
    },

    // ==================== ADMIN USERS ====================
    async getAdminUsers(skip = 0, limit = 100, role = null, isActive = null) {
        let url = `/admin/users?skip=${skip}&limit=${limit}`;
        if (role) url += `&role=${role}`;
        if (isActive !== null) url += `&is_active=${isActive}`;
        return this.request(url);
    },

    async getAllAdminUsers(skip = 0, limit = 100) {
        return this.request(`/admin/users/all?skip=${skip}&limit=${limit}`);
    },

    async getAdminUser(userId) {
        return this.request(`/admin/users/${userId}`);
    },

    async createUser(userData) {
        return this.request('/admin/users', {
            method: 'POST',
            body: JSON.stringify(userData)
        });
    },

    async updateUser(userId, userData) {
        return this.request(`/admin/users/${userId}`, {
            method: 'PUT',
            body: JSON.stringify(userData)
        });
    },

    async deleteUser(userId) {
        return this.request(`/admin/users/${userId}`, {
            method: 'DELETE'
        });
    },

    async toggleUserActive(userId) {
        return this.request(`/admin/users/${userId}/toggle-active`, {
            method: 'PATCH'
        });
    },

    async changeUserRole(userId, role) {
        return this.request(`/admin/users/${userId}/role`, {
            method: 'PATCH',
            body: JSON.stringify({ role })
        });
    },

    // ==================== ADMIN INVITES ====================
    async getInvites(skip = 0, limit = 100) {
        return this.request(`/admin/invites?skip=${skip}&limit=${limit}`);
    },

    async getInvite(email) {
        return this.request(`/admin/invites/${email}`);
    },

    async createInvite(inviteData) {
        return this.request('/admin/invites', {
            method: 'POST',
            body: JSON.stringify(inviteData)
        });
    },

    async deleteInvite(email) {
        return this.request(`/admin/invites/${email}`, {
            method: 'DELETE'
        });
    },

    async updateInviteStatus(email, status) {
        return this.request(`/admin/invites/${email}/status`, {
            method: 'PATCH',
            body: JSON.stringify({ status })
        });
    },

    async bulkDeleteInvites(ids) {
        return this.request('/admin/invites/bulk-delete', {
            method: 'POST',
            body: JSON.stringify({ ids })
        });
    },
    async getResults(skip = 0, limit = 100, level = null) {
        let url = `/admin/results?skip=${skip}&limit=${limit}`;
        if (level) url += `&level=${level}`;
        return this.request(url);
    },

    async getResult(resultId) {
        return this.request(`/admin/results/${resultId}`);
    },

    async createResult(resultData) {
        return this.request('/admin/results', {
            method: 'POST',
            body: JSON.stringify(resultData)
        });
    },

    async updateResult(resultId, resultData) {
        return this.request(`/admin/results/${resultId}`, {
            method: 'PUT',
            body: JSON.stringify(resultData)
        });
    },

    async deleteResult(resultId) {
        return this.request(`/admin/results/${resultId}`, {
            method: 'DELETE'
        });
    },

    async getResultsByLog(logId) {
        return this.request(`/admin/results/by-log/${logId}`);
    },

    async getResultsByUser(userId) {
        return this.request(`/admin/results/by-user/${userId}`);
    },

    async bulkDeleteResults(ids) {
        return this.request('/admin/results/bulk-delete', {
            method: 'POST',
            body: JSON.stringify({ ids })
        });
    }
};

window.Api = Api;
