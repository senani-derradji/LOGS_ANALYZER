const Utils = {
    showToast(message, type = 'success') {
        const toastTypes = {
            success: 'success',
            error: 'error',
            warning: 'warning',
            info: 'info'
        };
        
        toastr[toastTypes[type] || 'success'](message);
    },

    showSwal(title, text, icon = 'success') {
        return Swal.fire({
            title: title,
            text: text,
            icon: icon,
            confirmButtonText: 'OK'
        });
    },

    confirmSwal(title, text) {
        return Swal.fire({
            title: title,
            text: text,
            icon: 'warning',
            showCancelButton: true,
            confirmButtonColor: '#22c55e',
            cancelButtonColor: '#ef4444',
            confirmButtonText: 'Yes',
            cancelButtonText: 'No'
        });
    },

    formatDate(dateString) {
        if (!dateString) return '-';
        const date = new Date(dateString);
        return new Intl.DateTimeFormat('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        }).format(date);
    },

    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    },

    getStatusBadge(status) {
        const badges = {
            'completed': '<span class="badge bg-success">Completed</span>',
            'processing': '<span class="badge bg-primary">Processing</span>',
            'pending': '<span class="badge bg-warning">Pending</span>',
            'failed': '<span class="badge bg-danger">Failed</span>',
            'active': '<span class="badge bg-success">Active</span>',
            'inactive': '<span class="badge bg-secondary">Inactive</span>',
            'PENDING': '<span class="badge bg-warning">Pending</span>',
            'COMPLETED': '<span class="badge bg-success">Completed</span>',
            'REJECTED': '<span class="badge bg-danger">Rejected</span>'
        };
        return badges[status] || `<span class="badge bg-secondary">${status}</span>`;
    },

    getInviteStatusBadge(status) {
        const statusUpper = status ? status.toUpperCase() : '';
        const badges = {
            'PENDING': '<span class="badge bg-warning">Pending</span>',
            'COMPLETED': '<span class="badge bg-success">Completed</span>',
            'REJECTED': '<span class="badge bg-danger">Rejected</span>',
            'ACTIVATED': '<span class="badge bg-primary">Activated</span>'
        };
        return badges[statusUpper] || `<span class="badge bg-secondary">${Utils.escapeHtml(status)}</span>`;
    },

    getRoleBadge(role) {
        const badges = {
            'admin': '<span class="badge bg-danger">Admin</span>',
            'user': '<span class="badge bg-primary">User</span>',
            'guest': '<span class="badge bg-secondary">Guest</span>'
        };
        return badges[role] || `<span class="badge bg-secondary">${role}</span>`;
    },

    getLevelBadge(level) {
        const levelConfig = {
            'ERROR': { class: 'bg-danger', icon: 'fa-times-circle' },
            'WARNING': { class: 'bg-warning', icon: 'fa-exclamation-triangle' },
            'INFO': { class: 'bg-info', icon: 'fa-info-circle' },
            'DEBUG': { class: 'bg-secondary', icon: 'fa-debug' },
            'UNKNOWN': { class: 'bg-dark', icon: 'fa-question-circle' }
        };
        const config = levelConfig[level] || levelConfig['UNKNOWN'];
        return `<span class="badge ${config.class}"><i class="fas ${config.icon} me-1"></i>${level}</span>`;
    },

    showLoader() {
        const loader = document.createElement('div');
        loader.className = 'loader-overlay';
        loader.id = 'loader';
        loader.innerHTML = '<div class="spinner"></div>';
        document.body.appendChild(loader);
    },

    hideLoader() {
        const loader = document.getElementById('loader');
        if (loader) {
            loader.remove();
        }
    },

    isValidFile(file) {
        const allowedExtensions = ['.log', '.txt', '.csv'];
        const fileName = file.name.toLowerCase();
        return allowedExtensions.some(ext => fileName.endsWith(ext));
    },

    debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    },

    storeToken(token) {
        localStorage.setItem('auth_token', token);
    },

    getToken() {
        return localStorage.getItem('auth_token');
    },

    removeToken() {
        localStorage.removeItem('auth_token');
    },

    storeUser(user) {
        localStorage.setItem('user_data', JSON.stringify(user));
    },

    getUser() {
        const userData = localStorage.getItem('user_data');
        return userData ? JSON.parse(userData) : null;
    },

    removeUser() {
        localStorage.removeItem('user_data');
    },

    isAdmin() {
        const user = this.getUser();
        return user && user.role === 'admin';
    },

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
};

window.Utils = Utils;