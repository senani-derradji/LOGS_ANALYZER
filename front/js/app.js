const App = {
    currentUser: null,
    errorChart: null,
    activityChart: null,
    autoRefreshInterval: null,
    _allResults: [],
    logs: [],
    _currentLogResults: [],
    _currentLogId: null,
     init() {
         console.log('App initializing...');
         try {
             this.bindEvents();
             this.checkAuth();
             console.log('App initialized successfully');
          this.testApi();
          this.checkUrlParams();
      } catch (error) {
          console.error('App init error:', error);
          this.showLoginSection();
      }
  },

  checkUrlParams() {
      const params = new URLSearchParams(window.location.search);
      const inviteToken = params.get('invite_token');
      const verifyToken = params.get('verify_token');

      if (inviteToken) {
          const tokenInput = document.getElementById('regInviteToken');
          if (tokenInput) {
              tokenInput.value = inviteToken;
              document.getElementById('register-tab').click();
          }
      }

      if (verifyToken) {
          const tokenInput = document.getElementById('verifyToken');
          if (tokenInput) {
              tokenInput.value = verifyToken;
              // Open verification modal
              const modalEl = document.getElementById('verifyEmailModal');
              if (modalEl) {
                  const modal = new bootstrap.Modal(modalEl);
                  modal.show();
              }
          }
      }
  },

     testApi() {
         console.log('Testing API_BASE_URL:', API_BASE_URL);
         fetch(API_BASE_URL + '/healthz')
             .then(r => r.json())
             .then(d => console.log('Health check:', d))
             .catch(e => console.error('Health check failed:', e));
     },

      bindEvents() {
         console.log('Binding events...');
         // Login forms
         const loginForm = document.getElementById('loginForm');
         console.log('loginForm element:', loginForm);
         loginForm?.addEventListener('submit', (e) => this.handleLogin(e));
         const loginModalForm = document.getElementById('loginModalForm');
         console.log('loginModalForm element:', loginModalForm);
         loginModalForm?.addEventListener('submit', (e) => this.handleLogin(e));

         // Registration
         const registerForm = document.getElementById('registerForm');
         console.log('registerForm element:', registerForm);
         registerForm?.addEventListener('submit', (e) => this.handleRegister(e));

         // Forgot Password
         const forgotPasswordForm = document.getElementById('forgotPasswordForm');
         console.log('forgotPasswordForm element:', forgotPasswordForm);
         forgotPasswordForm?.addEventListener('submit', (e) => this.handleForgotPassword(e));

         // Request Invite
         const requestInviteForm = document.getElementById('requestInviteForm');
         console.log('requestInviteForm element:', requestInviteForm);
         requestInviteForm?.addEventListener('submit', (e) => this.handleRequestInvite(e));

         // Verify Email
         const verifyEmailForm = document.getElementById('verifyEmailForm');
         console.log('verifyEmailForm element:', verifyEmailForm);
         verifyEmailForm?.addEventListener('submit', (e) => this.handleVerifyEmail(e));

         // Upload
         document.getElementById('uploadForm')?.addEventListener('submit', (e) => this.handleUpload(e));
         document.getElementById('refreshLogsBtn')?.addEventListener('click', () => this.loadLogs());

         // Profile
         document.getElementById('viewProfileBtn')?.addEventListener('click', () => this.showProfile());

         // API Keys
         document.getElementById('createApiKeyBtn')?.addEventListener('click', () => this.openCreateApiKeyModal());
         document.getElementById('createApiKeyForm')?.addEventListener('submit', (e) => this.handleCreateApiKey(e));

        // Drop zone
        const dropZone = document.getElementById('dropZone');
        if (dropZone) {
            dropZone.addEventListener('dragover', (e) => {
                e.preventDefault();
                dropZone.classList.add('dragover');
            });
            dropZone.addEventListener('dragleave', () => {
                dropZone.classList.remove('dragover');
            });
            dropZone.addEventListener('drop', (e) => {
                e.preventDefault();
                dropZone.classList.remove('dragover');
                const fileInput = document.getElementById('logFile');
                if (e.dataTransfer.files.length > 0) {
                    fileInput.files = e.dataTransfer.files;
                    this.handleUpload(e);
                }
            });
        }

         // Admin events
         document.getElementById('refreshAdminLogsBtn')?.addEventListener('click', () => this.loadAdminLogs());
         document.getElementById('refreshUsersBtn')?.addEventListener('click', () => this.loadAdminUsers());
         document.getElementById('refreshInvitesBtn')?.addEventListener('click', () => this.loadInvites());
         document.getElementById('refreshResultsBtn')?.addEventListener('click', () => this.loadResults());
         document.getElementById('bulkDeleteLogsBtn')?.addEventListener('click', () => this.bulkDeleteLogs());

        // API Keys
        document.getElementById('refreshApiKeysBtn')?.addEventListener('click', () => this.loadApiKeys());

        // Create user
        document.getElementById('createUserForm')?.addEventListener('submit', (e) => this.handleCreateUser(e));

        // Admin upload
        document.getElementById('uploadFormAdmin')?.addEventListener('submit', (e) => this.handleUploadAdmin(e));

        const dropZoneAdmin = document.getElementById('dropZoneAdmin');
        if (dropZoneAdmin) {
            dropZoneAdmin.addEventListener('dragover', (e) => {
                e.preventDefault();
                dropZoneAdmin.classList.add('dragover');
            });
            dropZoneAdmin.addEventListener('dragleave', () => {
                dropZoneAdmin.classList.remove('dragover');
            });
            dropZoneAdmin.addEventListener('drop', (e) => {
                e.preventDefault();
                dropZoneAdmin.classList.remove('dragover');
                const fileInput = document.getElementById('logFileAdmin');
                if (e.dataTransfer.files.length > 0) {
                    fileInput.files = e.dataTransfer.files;
                    this.handleUploadAdmin(e);
                }
            });
        }

        // Select all logs checkbox
        document.getElementById('selectAllLogs')?.addEventListener('change', (e) => {
            const checkboxes = document.querySelectorAll('.log-checkbox');
            checkboxes.forEach(cb => cb.checked = e.target.checked);
        });

        // Results search and filter
        document.getElementById('resultsSearch')?.addEventListener('input', Utils.debounce(() => this.filterResults(), 300));
        document.getElementById('resultsLevelFilter')?.addEventListener('change', () => this.filterResults());
        document.getElementById('resultsTypeFilter')?.addEventListener('change', () => this.filterResults());

        // Log statistics filters
        document.getElementById('statsSearch')?.addEventListener('input', Utils.debounce(() => this.filterLogStatistics(), 300));
        document.getElementById('statsLevelFilter')?.addEventListener('change', () => this.filterLogStatistics());
        document.getElementById('statsTypeFilter')?.addEventListener('change', () => this.filterLogStatistics());

        // Hook up statistics modal show event
        const logStatisticsModal = document.getElementById('logStatisticsModal');
        if (logStatisticsModal) {
            logStatisticsModal.addEventListener('shown.bs.modal', () => {
                this.loadLogStatistics();
            });
        }
    },

    checkAuth() {
        const token = Utils.getToken();
        if (token) {
            this.loadUserProfile();
        } else {
            this.showLoginSection();
        }
    },

    async loadUserProfile() {
        try {
            console.log('Fetching profile...');

            let userData;
            // Try profile endpoint
            try {
                const response = await Api.getProfile();
                const userObj = response.user || response;
                const userInfo = userObj.UserData || userObj;
                userData = {
                    sub: userInfo.email,
                    email: userInfo.email,
                    name: userInfo.name,
                    role: userInfo.role || 'user'
                };
            } catch (e) {
                // If /users/profile fails, try to decode from token
                const token = Utils.getToken();
                if (!token) throw e;

                const payload = JSON.parse(atob(token.split('.')[1]));
                userData = {
                    sub: payload.sub || payload.username || payload.email,
                    email: payload.email || payload.sub,
                    name: payload.name || payload.sub?.split('@')[0] || 'User',
                    role: payload.role || 'user'
                };
            }
            this.currentUser = userData;

            // Ensure role is properly extracted
            let role = userData?.role;
            console.log('Initial role from userData:', role);
            if (!role && userData?.sub) {
                role = 'user';
            }
            if (!role) {
                role = 'user';
            }
            // Override: if email is admin@localhost.com, force admin
            if (userData?.email === 'admin@localhost.com' || userData?.sub === 'admin@localhost.com') {
                role = 'admin';
                userData.role = 'admin';
            }
            console.log('Final role decision:', role);
            console.log('User data full:', JSON.stringify(userData));

            console.log('User data:', this.currentUser);
            console.log('Detected role:', role);

            Utils.storeUser(this.currentUser);

            if (role === 'admin') {
                console.log('Showing admin section');
              this.showAdminSection();
          } else {
              console.log('Showing dashboard section');
              this.showDashboardSection();
          }

          this.updateAuthNav();
      } catch (error) {
          console.error('Profile error:', error);
          Utils.removeToken();
          Utils.removeUser();
          this.showLoginSection();
          Utils.showToast('Session expired. Please login again.', 'warning');
      }
  },

  showAdminSection() {
      try {
          this.stopAutoRefresh();
          console.log('Showing admin section');
          const loginSec = document.getElementById('loginSection');
          const dashboardSec = document.getElementById('dashboardSection');
          const adminSec = document.getElementById('adminSection');
          console.log('Elements before - login:', !!loginSec, 'dashboard:', !!dashboardSec, 'admin:', !!adminSec);
          if (loginSec) {
              loginSec.style.display = 'none';
              console.log('loginSec display set to none');
          }
          if (dashboardSec) {
              dashboardSec.style.display = 'none';
              console.log('dashboardSec display set to none');
          }
           if (adminSec) {
               adminSec.style.display = '';
               console.log('adminSec display set to empty, computed style:', getComputedStyle(adminSec).display, 'offsetParent:', adminSec.offsetParent);
          } else {
              console.error('adminSec element NOT FOUND!');
          }
          this.loadAdminStats();
          this.startAutoRefresh(() => this.loadAdminStats());
          console.log('showAdminSection completed without error');
      } catch (err) {
          console.error('Error in showAdminSection:', err);
          throw err; // rethrow so loadUserProfile catch will handle
      }
  },

    async handleLogin(e) {
        console.log('handleLogin called');
        e.preventDefault();
        const form = e.target;
        const inputs = form.querySelectorAll('input');
        const username = inputs[0]?.value;
        const password = inputs[1]?.value;
        console.log('Form values - username:', username ? 'set' : 'empty', 'password:', password ? 'set' : 'empty');

        if (!username || !password) {
            Utils.showToast('Please fill in all fields', 'error');
            return;
        }

        try {
            Utils.showLoader();
            console.log('Logging in with username:', username);

            const data = await Api.login(username, password);
            console.log('Login response:', data);

            Utils.storeToken(data.access_token);
            console.log('Token stored:', data.access_token ? 'yes' : 'no');

            await this.loadUserProfile();

            console.log('Login flow completed. Current user role:', this.currentUser?.role);

            Utils.showToast('Login successful!', 'success');

            const modalEl = document.getElementById('loginModal');
            if (modalEl) {
                const modal = bootstrap.Modal.getInstance(modalEl);
                modal?.hide();
            }
            form.reset();
        } catch (error) {
            console.error('Login error:', error);
            Utils.showToast(error.message || 'Login failed', 'error');
        } finally {
            Utils.hideLoader();
        }
    },

     async handleRegister(e) {
         e.preventDefault();
         const name = document.getElementById('regName').value;
         const email = document.getElementById('regEmail').value;
         const password = document.getElementById('regPassword').value;
         const confirmPassword = document.getElementById('regConfirmPassword').value;
         const telegram = document.getElementById('regTelegram').value || null;
         const inviteToken = document.getElementById('regInviteToken').value || null;

         if (!name || !email || !password || !confirmPassword) {
             Utils.showToast('Please fill in all required fields', 'error');
             return;
         }

         if (password !== confirmPassword) {
             Utils.showToast('Passwords do not match', 'error');
             return;
         }

         try {
             Utils.showLoader();

             const payload = {
                 name,
                 email,
                 password,
                 subscription_tier: 'free'
             };
             if (telegram) payload.telegram_chat_id = telegram;
             if (inviteToken) payload.invitation_token = inviteToken;

             const result = await Api.register(payload);

              // Registration succeeded — if invite token was used, auto-login
              if (inviteToken) {
                  try {
                      // Use name for login (backend expects username)
                      const loginResult = await Api.login(name, password);
                      Utils.storeToken(loginResult.access_token);

                      // Fetch full profile
                      const profileData = await Api.getProfile();
                      const userObj = profileData.user || profileData;
                      const userInfo = userObj.UserData || userObj;

                      this.currentUser = {
                          sub: userInfo.email,
                          email: userInfo.email,
                          name: userInfo.name,
                          role: userInfo.role || 'user'
                      };

                      Utils.storeUser(this.currentUser);
                      this.updateAuthNav();

                      // Show welcome and redirect to dashboard
                      Swal.fire({
                          title: 'Welcome aboard! 🎉',
                          html: `Your account has been created successfully.<br><br><strong>Welcome, ${Utils.escapeHtml(name)}!</strong><br>You are now logged in.`,
                          icon: 'success',
                          confirmButtonText: 'Go to Dashboard'
                      }).then(() => {
                          document.getElementById('registerForm').reset();
                          this.showDashboardSection();
                      });
                  } catch (loginError) {
                      // Auto-login failed — fall back to manual login
                      console.error('Auto-login failed:', loginError);
                      Utils.showToast('Account created! Please check your email to verify your account, then log in.', 'success');
                      document.getElementById('registerForm').reset();
                      document.getElementById('login-tab').click();
                  }
              } else {
                  // Standard registration (no invite token)
                  Utils.showToast('Registration successful! Please check your email to verify your account.', 'success');
                  document.getElementById('registerForm').reset();
                  document.getElementById('login-tab').click();
              }
         } catch (error) {
             Utils.showToast(error.message || 'Registration failed', 'error');
         } finally {
             Utils.hideLoader();
         }
     },

    async handleForgotPassword(e) {
        e.preventDefault();
        const email = document.getElementById('forgotEmail').value;

        if (!email) {
            Utils.showToast('Please enter your email', 'error');
            return;
        }

        try {
            Utils.showLoader();
            const result = await Api.forgotPassword(email);
            Utils.showToast('If the email exists, a reset link has been sent.', 'success');
            bootstrap.Modal.getInstance(document.getElementById('forgotPasswordModal'))?.hide();
            document.getElementById('forgotPasswordForm').reset();
        } catch (error) {
            Utils.showToast(error.message || 'Request failed', 'error');
        } finally {
            Utils.hideLoader();
        }
    },

     async handleRequestInvite(e) {
         e.preventDefault();
         const email = document.getElementById('inviteEmail').value;

         if (!email) {
             Utils.showToast('Please enter your email', 'error');
             return;
         }

         try {
             Utils.showLoader();
             const result = await Api.requestInvite(email);

             Swal.fire({
                 title: 'Request Submitted!',
                 html: `Your invite request for <strong>${Utils.escapeHtml(email)}</strong> has been sent to the admin for approval.<br><br>You'll receive an email with your invite link once approved.`,
                 icon: 'success',
                 confirmButtonText: 'OK'
             });

             bootstrap.Modal.getInstance(document.getElementById('requestInviteModal'))?.hide();
             document.getElementById('requestInviteForm').reset();
         } catch (error) {
             Swal.fire({
                 title: 'Request Failed',
                 text: error.message || 'Failed to submit invite request. Please try again.',
                 icon: 'error',
                 confirmButtonText: 'OK'
             });
         } finally {
             Utils.hideLoader();
         }
     },

     async handleVerifyEmail(e) {
         e.preventDefault();
         const token = document.getElementById('verifyToken').value;

         if (!token) {
             Utils.showToast('Please enter a verification token', 'error');
             return;
         }

         try {
             Utils.showLoader();
             const result = await Api.verifyEmail(token);

             Swal.fire({
                 title: 'Email Verified! 🎉',
                 html: 'Your email has been successfully verified.<br>You can now log in.',
                 icon: 'success',
                 confirmButtonText: 'OK'
             });

             bootstrap.Modal.getInstance(document.getElementById('verifyEmailModal'))?.hide();
             document.getElementById('verifyEmailForm').reset();
         } catch (error) {
             Swal.fire({
                 title: 'Verification Failed',
                 text: error.message || 'Invalid or expired token. Please try again.',
                 icon: 'error',
                 confirmButtonText: 'OK'
             });
         } finally {
             Utils.hideLoader();
         }
     },

    handleLogout() {
        this.stopAutoRefresh();
        Utils.removeToken();
        Utils.removeUser();
        this.currentUser = null;
        this.showLoginSection();
        this.updateAuthNav();
        Utils.showToast('Logged out successfully', 'success');
    },

    updateAuthNav() {
        const nav = document.getElementById('authNav');
        if (!nav) return;

        if (this.currentUser) {
            const isAdmin = this.currentUser.role === 'admin';
            const userName = this.currentUser.sub || this.currentUser.name || 'User';
            const userEmail = this.currentUser.email || this.currentUser.sub || '';

            nav.innerHTML = `
                <li class="nav-item dropdown">
                    <a class="nav-link dropdown-toggle d-flex align-items-center" href="#" role="button" data-bs-toggle="dropdown">
                        <i class="fas fa-user-circle me-2"></i>
                        <span>${Utils.escapeHtml(userName)}</span>
                    </a>
                    <ul class="dropdown-menu dropdown-menu-end">
                        <li><span class="dropdown-item-text text-muted small">${Utils.escapeHtml(userEmail)}</span></li>
                        <li><span class="dropdown-item-text small"><strong>Role:</strong> ${isAdmin ? 'Admin' : 'User'}</span></li>
                        <li><hr class="dropdown-divider"></li>
                        <li><a class="dropdown-item" href="#" id="profileBtn"><i class="fas fa-user me-2"></i>My Profile</a></li>
                        <li><a class="dropdown-item" href="#" id="logoutBtn"><i class="fas fa-sign-out-alt me-2"></i>Logout</a></li>
                    </ul>
                </li>
            `;

            document.getElementById('profileBtn')?.addEventListener('click', (e) => {
                e.preventDefault();
                App.showProfile();
            });
            document.getElementById('logoutBtn')?.addEventListener('click', () => this.handleLogout());
        } else {
            nav.innerHTML = `
                <li class="nav-item">
                    <a class="nav-link" href="#" data-bs-toggle="modal" data-bs-target="#loginModal">
                        <i class="fas fa-sign-in-alt me-1"></i> Login
                    </a>
                </li>
            `;
        }
    },

    showLoginSection() {
        console.log('Showing login section');
        const loginSection = document.getElementById('loginSection');
        const dashboardSection = document.getElementById('dashboardSection');
        const adminSection = document.getElementById('adminSection');

        if (loginSection) loginSection.style.display = '';
        if (dashboardSection) dashboardSection.style.display = 'none';
        if (adminSection) adminSection.style.display = 'none';
    },

    showDashboardSection() {
        try {
            this.stopAutoRefresh();
            console.log('Showing dashboard section');
            const loginSec = document.getElementById('loginSection');
            const dashboardSec = document.getElementById('dashboardSection');
            const adminSec = document.getElementById('adminSection');
            console.log('Elements before - login:', !!loginSec, 'dashboard:', !!dashboardSec, 'admin:', !!adminSec);
            if (loginSec) {
                loginSec.style.display = 'none';
                console.log('loginSec display set to none');
            }
            if (dashboardSec) {
                dashboardSec.style.display = '';
                console.log('dashboardSec display set to empty, computed:', getComputedStyle(dashboardSec).display);
            }
            if (adminSec) adminSec.style.display = 'none';
            this.loadLogs();
            this.loadApiKeys();
            this.startAutoRefresh(() => {
                this.loadLogs();
                this.loadApiKeys();
            });
            console.log('showDashboardSection completed without error');
        } catch (err) {
            console.error('Error in showDashboardSection:', err);
            throw err;
        }
    },

    async loadApiKeys() {
        try {
            const keys = await Api.getApiKeys();
            const tbody = document.getElementById('apiKeysTableBody');
            tbody.innerHTML = '';

            const keysArray = Array.isArray(keys) ? keys : [];
            if (keysArray.length === 0) {
                tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted">No API keys found. Create one to use for programmatic log uploads.</td></tr>';
                return;
            }

            keysArray.forEach(key => {
                const row = document.createElement('tr');
                row.id = `api-key-row-${key.id}`;
                row.innerHTML = `
                    <td>${key.id}</td>
                    <td>${Utils.escapeHtml(key.name)}</td>
                    <td><code class="bg-light px-2 py-1 rounded">${Utils.escapeHtml(key.prefix)}...</code></td>
                    <td>${key.is_active ? '<span class="badge bg-success">Active</span>' : '<span class="badge bg-secondary">Inactive</span>'}</td>
                    <td>${Utils.formatDate(key.created_at)}</td>
                    <td>${Utils.formatDate(key.expires_at)}</td>
                    <td>
                        <button class="btn btn-sm btn-outline-danger" onclick="App.revokeApiKey(${key.id})" title="Revoke">
                            <i class="fas fa-trash"></i> Revoke
                        </button>
                    </td>
                `;
                tbody.appendChild(row);
            });
        } catch (error) {
            console.error('Error loading API keys:', error);
            const tbody = document.getElementById('apiKeysTableBody');
            if (tbody) {
                tbody.innerHTML = '<tr><td colspan="7" class="text-center text-danger">Error loading API keys</td></tr>';
            }
        }
    },

    openCreateApiKeyModal() {
        document.getElementById('createApiKeyForm').reset();
        const modalEl = document.getElementById('createApiKeyModal');
        const modal = new bootstrap.Modal(modalEl);
        modal.show();
    },
async handleCreateApiKey(e) {
    e.preventDefault();
    const name = document.getElementById('apiKeyName').value;

    if (!name || !name.trim()) {
        Utils.showToast('Please enter a name for the API key', 'error');
        return;
    }

    try {
        Utils.showLoader();

        // Call the API
        const response = await Api.createApiKey({ name: name.trim() });
        console.log('API Key creation response:', response);

        // Validate response
        if (!response || !response.api_key) {
            throw new Error('Invalid response from server');
        }

        // Hide the create modal
        const createModal = bootstrap.Modal.getInstance(document.getElementById('createApiKeyModal'));
        if (createModal) {
            createModal.hide();
        }

        // Clear the form
        document.getElementById('apiKeyName').value = '';

        // Populate the display modal
        document.getElementById('createdKeyName').textContent = name.trim();
        document.getElementById('createdApiKey').value = response.api_key;
        document.getElementById('createdKeyId').textContent = response.key_id || 'N/A';

        // Generate code examples
        this.populateCodeExamples(response.api_key);

        // Show the display modal
        const displayModalEl = document.getElementById('apiKeyDisplayModal');
        if (displayModalEl) {
            const displayModal = new bootstrap.Modal(displayModalEl);
            displayModal.show();
        } else {
            // Fallback: Show Swal if modal doesn't exist
            await Swal.fire({
                title: 'API Key Created',
                html: `
                    <div class="alert alert-warning">
                        <strong>Important:</strong> Copy your API key now. You won't be able to see it again!
                    </div>
                    <div class="mb-3">
                        <label class="form-label fw-bold">API Key:</label>
                        <div class="input-group">
                            <input type="text" class="form-control" id="swal-api-key" value="${response.api_key}" readonly>
                            <button class="btn btn-outline-secondary" onclick="document.getElementById('swal-api-key').select(); document.execCommand('copy'); Swal.fire({title:'Copied!', text:'API key copied to clipboard', icon:'success', timer:1500})">
                                <i class="fas fa-copy"></i> Copy
                            </button>
                        </div>
                    </div>
                `,
                icon: 'success',
                confirmButtonText: 'Close'
            });
        }

        // Refresh the API keys lists
        await Promise.all([
            this.loadApiKeys(),
            this.loadProfileApiKeys()
        ]);

        Utils.showToast('API key created successfully!', 'success');

    } catch (error) {
        console.error('Error creating API key:', error);
        Utils.showToast(error.message || 'Failed to create API key', 'error');
    } finally {
        Utils.hideLoader();
    }
},
populateCodeExamples(apiKey) {
    const BASE_URL = API_BASE_URL;

    // Get all code elements
    const pythonCodeElem = document.getElementById('pythonCode');
    const jsCodeElem = document.getElementById('jsCode');
    const goCodeElem = document.getElementById('goCode');
    const curlCodeElem = document.getElementById('curlCode');

    // Python
    if (pythonCodeElem) {
        pythonCodeElem.textContent = `import requests

# Your API key - keep this secret!
API_KEY = "${apiKey}"
API_URL = "${BASE_URL}/logs/upload"

def upload_log_file(file_path):
    with open(file_path, 'rb') as f:
        files = {'file': f}
        headers = {'Authorization': f'Bearer {API_KEY}'}
        response = requests.post(API_URL, headers=headers, files=files)
        return response.json()

# Usage
result = upload_log_file('your_log_file.log')
print(result)`;
    }

    // JavaScript
    if (jsCodeElem) {
        jsCodeElem.textContent = `// Your API key - keep this secret!
const API_KEY = "${apiKey}";
const API_URL = "${BASE_URL}/logs/upload";

async function uploadLogFile(file) {
    const formData = new FormData();
    formData.append('file', file);

    const response = await fetch(API_URL, {
        method: 'POST',
        headers: {
            'Authorization': \`Bearer \${API_KEY}\`
        },
        body: formData
    });

    return await response.json();
}

// Usage with file input
const fileInput = document.querySelector('input[type="file"]');
const result = await uploadLogFile(fileInput.files[0]);
console.log(result);`;
    }

    // Go
    if (goCodeElem) {
        goCodeElem.textContent = `package main

import (
    "bytes"
    "fmt"
    "io"
    "mime/multipart"
    "net/http"
    "os"
)

func uploadLogFile(filePath string, apiKey string) error {
    file, err := os.Open(filePath)
    if err != nil {
        return err
    }
    defer file.Close()

    body := &bytes.Buffer{}
    writer := multipart.NewWriter(body)
    part, err := writer.CreateFormFile("file", filePath)
    if err != nil {
        return err
    }
    io.Copy(part, file)
    writer.Close()

    req, err := http.NewRequest("POST", "${BASE_URL}/logs/upload", body)
    if err != nil {
        return err
    }
    req.Header.Set("Authorization", "Bearer "+apiKey)
    req.Header.Set("Content-Type", writer.FormDataContentType())

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    fmt.Println("Status:", resp.Status)
    return nil
}

func main() {
    apiKey := "${apiKey}"
    err := uploadLogFile("your_log_file.log", apiKey)
    if err != nil {
        fmt.Println("Error:", err)
    }
}`;
    }

    // cURL
    if (curlCodeElem) {
        curlCodeElem.textContent = `#!/bin/bash

API_KEY="${apiKey}"
API_URL="${BASE_URL}/logs/upload"
FILE="your_log_file.log"

curl -X POST "$API_URL" \\
  -H "Authorization: Bearer $API_KEY" \\
  -F "file=@$FILE"`;
    }
},


    async revokeApiKey(keyId) {
        const confirmed = await Utils.confirmSwal('Revoke API Key', 'Are you sure you want to revoke this API key? It will no longer work for uploads.');

        if (!confirmed.isConfirmed) return;

        try {
            await Api.revokeApiKey(keyId);
            Utils.showToast('API key revoked successfully', 'success');
            await Promise.all([
                this.loadApiKeys(),
                this.loadProfileApiKeys()
            ]);
        } catch (error) {
            Utils.showToast(error.message || 'Failed to revoke API key', 'error');
        }
    },

    async viewAdminLogResults(logId) {
        try {
            const results = await Api.getLogResults(logId);
            const content = document.getElementById('logResultsContent');

            if (!results || results.length === 0) {
                content.innerHTML = '<div class="text-center text-muted p-4"><i class="fas fa-inbox fa-2x mb-2 d-block"></i>No results found for this log</div>';
            } else {
                const getLevelColor = (level) => {
                    const colors = {
                        'ERROR': 'border-start border-4 border-danger',
                        'WARNING': 'border-start border-4 border-warning',
                        'INFO': 'border-start border-4 border-info',
                        'DEBUG': 'border-start border-4 border-secondary',
                        'UNKNOWN': 'border-start border-4 border-dark'
                    };
                    return colors[level] || colors['UNKNOWN'];
                };

                content.innerHTML = results.map(r => `
                    <div class="result-card ${getLevelColor(r.level)} p-3 mb-2 mx-2" style="border-left: 4px solid;">
                        <div class="d-flex justify-content-between align-items-start mb-2">
                            <div>
                                <span class="fw-bold">#${r.id}</span>
                                <span class="text-muted small ms-2">Line ${r.line_number || '?'}</span>
                                <span class="badge bg-secondary ms-2">${r.detected_type || 'log'}</span>
                            </div>
                            ${Utils.getLevelBadge(r.level)}
                        </div>
                        <div class="mb-2">
                            <strong>Message:</strong>
                            <p class="mb-1 text-break">${Utils.escapeHtml(r.message || '-')}</p>
                        </div>
                        ${r.template ? `
                        <div class="mb-2">
                            <strong>Template:</strong>
                            <p class="mb-1 text-break text-muted small">${Utils.escapeHtml(r.template)}</p>
                        </div>` : ''}
                        ${r.signature ? `
                        <div class="mb-2">
                            <strong>Signature:</strong>
                            <p class="mb-1 text-break text-muted small"><code>${Utils.escapeHtml(r.signature)}</code></p>
                        </div>` : ''}
                        ${r.confidence ? `
                        <div class="mb-2">
                            <strong>Confidence:</strong> ${(r.confidence * 100).toFixed(1)}%
                        </div>` : ''}
                        ${r.event_category ? `
                        <div class="mb-2">
                            <strong>Category:</strong> <span class="badge bg-light text-dark">${Utils.escapeHtml(r.event_category)}</span>
                        </div>` : ''}
                        ${r.timestamp ? `
                        <div class="text-muted small">
                            Timestamp: ${Utils.escapeHtml(r.timestamp)}
                        </div>` : ''}
                    </div>
                `).join('');
            }

            const modalEl = document.getElementById('logResultsModal');
            const modal = new bootstrap.Modal(modalEl);
            modal.show();
        } catch (error) {
            Utils.showToast(error.message || 'Failed to load log details', 'error');
        }
    },

    async showLogStatistics(logId) {
        this._currentLogId = logId;
        this._currentLogResults = [];
        // Reset filters
        const searchInput = document.getElementById('statsSearch');
        const levelFilter = document.getElementById('statsLevelFilter');
        const typeFilter = document.getElementById('statsTypeFilter');
        if (searchInput) searchInput.value = '';
        if (levelFilter) levelFilter.value = '';
        if (typeFilter) typeFilter.value = '';

        const modalEl = document.getElementById('logStatisticsModal');
        const modal = new bootstrap.Modal(modalEl);
        modal.show();
    },

    async loadLogStatistics() {
        try {
            const currentLogId = this._currentLogId; // Capture to avoid race
            if (!currentLogId) return;

            const results = await Api.getUserResultsByLog(currentLogId);
            // Only update if still the same log
            if (this._currentLogId !== currentLogId) return;
            this._currentLogResults = Array.isArray(results) ? results : [];

            // Find log filename
            const log = this.logs.find(l => l.id === currentLogId);
            document.getElementById('statsFileName').textContent = log ? log.file_name : `Log #${currentLogId}`;

            this.updateLogStatsSummary(this._currentLogResults);
            this.filterLogStatistics();
        } catch (error) {
            console.error('Error loading log statistics:', error);
            Utils.showToast('Failed to load statistics', 'error');
            document.getElementById('logStatsContent').innerHTML =
                '<div class="text-center text-danger p-4">Error loading statistics</div>';
        }
    },

    updateLogStatsSummary(results) {
        const total = results.length;
        const errors = results.filter(r => r.level === 'ERROR').length;
        const warnings = results.filter(r => r.level === 'WARNING').length;
        const info = results.filter(r => r.level === 'INFO').length;

        document.getElementById('statTotalResults').textContent = total;
        document.getElementById('statErrors').textContent = errors;
        document.getElementById('statWarnings').textContent = warnings;
        document.getElementById('statInfo').textContent = info;
    },

    filterLogStatistics() {
        const searchTerm = document.getElementById('statsSearch')?.value?.toLowerCase() || '';
        const levelFilter = document.getElementById('statsLevelFilter')?.value || '';
        const typeFilter = document.getElementById('statsTypeFilter')?.value || '';

        let filtered = this._currentLogResults || [];

        if (searchTerm) {
            filtered = filtered.filter(r =>
                (r.message || '').toLowerCase().includes(searchTerm) ||
                (r.source || r.detected_type || '').toLowerCase().includes(searchTerm)
            );
        }

        if (typeFilter) {
            filtered = filtered.filter(r => ((r.source || r.detected_type || '').toLowerCase() === typeFilter.toLowerCase()));
        }

        if (levelFilter) {
            filtered = filtered.filter(r => r.level === levelFilter);
        }

        this.renderLogStatistics(filtered);
    },

    renderLogStatistics(results) {
        const container = document.getElementById('logStatsContent');

        if (!results || results.length === 0) {
            container.innerHTML = '<div class="text-center text-muted p-4"><i class="fas fa-inbox fa-2x mb-2 d-block"></i>No results match current filters</div>';
            return;
        }

        container.innerHTML = results.map(result => `
            <div class="result-card border-start border-4 ${this.getLevelBorderClass(result.level)} p-3 mb-2 rounded bg-light">
                <div class="d-flex justify-content-between align-items-start mb-2">
                    <div>
                        <span class="fw-bold">#${result.id}</span>
                    </div>
                    <div class="d-flex align-items-center gap-2">
                        ${Utils.getLevelBadge(result.level)}
                        <button class="btn btn-sm btn-outline-info" onclick="App.showResultDetails(${result.id})" title="Details">
                            <i class="fas fa-info-circle"></i>
                        </button>
                    </div>
                </div>
                <div class="result-message mb-2" style="word-break: break-word;">${Utils.escapeHtml(result.message || '-')}</div>
                <div class="d-flex justify-content-between text-muted small">
                    <span><i class="fas fa-tag me-1"></i>${Utils.escapeHtml(result.source || result.detected_type || '-')}</span>
                    <span><i class="fas fa-clock me-1"></i>${Utils.formatDate(result.created_at)}</span>
                </div>
            </div>
        `).join('');
    },

    getLevelBorderClass(level) {
        const classes = {
            'ERROR': 'border-danger',
            'WARNING': 'border-warning',
            'INFO': 'border-info',
            'DEBUG': 'border-secondary',
            'UNKNOWN': 'border-dark'
        };
        return classes[level] || classes['UNKNOWN'];
    },


    copyApiKeyToClipboard() {
        const keyInput = document.getElementById('createdApiKey');
        keyInput.select();
        keyInput.setSelectionRange(0, 99999);
        navigator.clipboard.writeText(keyInput.value).then(() => {
            Utils.showToast('API key copied to clipboard', 'success');
        }).catch(err => {
            console.error('Failed to copy:', err);
            Utils.showToast('Failed to copy to clipboard', 'error');
        });
    },
copyCodeToClipboard(elementId) {
    const codeEl = document.getElementById(elementId);
    if (!codeEl) return;

    const text = codeEl.textContent;
    navigator.clipboard.writeText(text).then(() => {
        Utils.showToast('Code copied to clipboard!', 'success');
    }).catch(err => {
        console.error('Failed to copy code:', err);
        Utils.showToast('Failed to copy code', 'error');
    });
},

    async showProfile() {
        try {
            Utils.showLoader();
            const response = await Api.getProfile();
            console.log('Profile API response:', response);

            // Response structure: { message: "...", user: { UserData: {...}, Usage: {...} } }
            const userObj = response.user || response;
            const userData = userObj.UserData || userObj;
            const usage = userObj.Usage || userObj.usage || {};

            // Populate profile fields
            document.getElementById('profileName').textContent = userData.name || '-';
            document.getElementById('profileEmail').textContent = userData.email || '-';
            document.getElementById('profileRole').innerHTML = userData.role ?
                Utils.getRoleBadge(userData.role) : '<span class="badge bg-secondary">user</span>';
            document.getElementById('profileIsActive').innerHTML = userData.is_active ?
                '<span class="badge bg-success">Active</span>' : '<span class="badge bg-danger">Inactive</span>';
            document.getElementById('profileEmailVerified').innerHTML = userData.email_verified ?
                '<span class="badge bg-success">Verified</span>' : '<span class="badge bg-warning">Not Verified</span>';
            document.getElementById('profileTenantId').textContent = userData.tenant_id || '-';
            document.getElementById('profileTelegram').textContent = userData.telegram_chat_id || 'Not set';

            // Usage & Subscription
            const usageCurrent = usage.usage !== undefined ? usage.usage : (userData.api_usage_current_month ?? 0);
            const quota = usage.quota !== undefined ? usage.quota : (userData.monthly_quota ?? 0);
            const remaining = usage.remaining !== undefined ? usage.remaining : (quota - usageCurrent);

            document.getElementById('profileUsageCurrent').textContent = usageCurrent;
            document.getElementById('profileQuota').textContent = quota;
            document.getElementById('profileRemaining').textContent = remaining;

            // Tier
            const tier = (usage.tier || userData.subscription_tier || 'free').toLowerCase();
            let tierBadge = '<span class="badge bg-secondary">free</span>';
            if (tier === 'pro') tierBadge = '<span class="badge bg-primary">pro</span>';
            if (tier === 'premium') tierBadge = '<span class="badge bg-primary">premium</span>';
            if (tier === 'enterprise') tierBadge = '<span class="badge bg-dark">enterprise</span>';
            document.getElementById('profileTier').innerHTML = tierBadge;

            // Dates
            document.getElementById('profileUsageReset').textContent = Utils.formatDate(userData.api_usage_reset_at);
            document.getElementById('profileSubExpires').textContent = Utils.formatDate(userData.subscription_expires_at);

            // Load API keys in profile
            await this.loadProfileApiKeys();

            // Show profile page overlay
            document.getElementById('profilePage').style.display = 'block';
        } catch (error) {
            console.error('Error loading profile:', error);
            Utils.showToast(error.message || 'Failed to load profile', 'error');
        } finally {
            Utils.hideLoader();
        }
    },

    closeProfile() {
        document.getElementById('profilePage').style.display = 'none';
    },

    async loadProfileApiKeys() {
        try {
            const keys = await Api.getApiKeys();
            const tbody = document.getElementById('profileApiKeysTableBody');
            tbody.innerHTML = '';

            const keysArray = Array.isArray(keys) ? keys : [];
            if (keysArray.length === 0) {
                tbody.innerHTML = '<tr><td colspan="4" class="text-center text-muted">No API keys created</td></tr>';
                return;
            }

            keysArray.forEach(key => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${Utils.escapeHtml(key.name)}</td>
                    <td><code>${Utils.escapeHtml(key.prefix)}...</code></td>
                    <td>${key.is_active ? '<span class="badge bg-success">Active</span>' : '<span class="badge bg-secondary">Inactive</span>'}</td>
                    <td>${Utils.formatDate(key.expires_at)}</td>
                `;
                tbody.appendChild(row);
            });
        } catch (error) {
            console.error('Error loading profile API keys:', error);
            const tbody = document.getElementById('profileApiKeysTableBody');
            if (tbody) {
                tbody.innerHTML = '<tr><td colspan="4" class="text-center text-danger">Error loading keys</td></tr>';
            }
        }
    },

    showAdminSection() {
        try {
            this.stopAutoRefresh();
            console.log('Showing admin section');
            const loginSec = document.getElementById('loginSection');
            const dashboardSec = document.getElementById('dashboardSection');
            const adminSec = document.getElementById('adminSection');
            console.log('Elements before - login:', !!loginSec, 'dashboard:', !!dashboardSec, 'admin:', !!adminSec);
            if (loginSec) {
                loginSec.style.display = 'none';
                console.log('loginSec display set to none');
            }
            if (dashboardSec) {
                dashboardSec.style.display = 'none';
                console.log('dashboardSec display set to none');
            }
            if (adminSec) {
                adminSec.style.display = 'block';
                console.log('adminSec display set to block, computed style:', getComputedStyle(adminSec).display, 'offsetParent:', adminSec.offsetParent);
            } else {
                console.error('adminSec element NOT FOUND!');
            }
            this.loadAdminStats();
            this.startAutoRefresh(() => this.loadAdminStats());
            console.log('showAdminSection completed without error');
        } catch (err) {
            console.error('Error in showAdminSection:', err);
            throw err; // rethrow so loadUserProfile catch will handle
        }
    },

    startAutoRefresh(callback) {
        this.stopAutoRefresh();
        this.autoRefreshInterval = setInterval(callback, 30000); // 30 seconds
    },

    stopAutoRefresh() {
        if (this.autoRefreshInterval) {
            clearInterval(this.autoRefreshInterval);
            this.autoRefreshInterval = null;
        }
    },

    async handleUpload(e) {
        e.preventDefault();
        const fileInput = document.getElementById('logFile');
        const file = fileInput.files[0];

        console.log('Upload started, file:', file);

        if (!file) {
            Utils.showToast('Please select a file', 'error');
            return;
        }

        if (!Utils.isValidFile(file)) {
            Utils.showToast('Invalid file type. Allowed: .log, .txt, .csv', 'error');
            return;
        }

        const progressDiv = document.getElementById('uploadProgress');
        const progressBar = progressDiv.querySelector('.progress-bar');

        try {
            progressDiv.style.display = 'block';
            progressBar.style.width = '0%';

            console.log('Uploading file to:', `${API_BASE_URL}/logs/upload`);

            const result = await Api.uploadLogFile(file, (percent) => {
                console.log('Upload progress:', percent + '%');
                progressBar.style.width = `${percent}%`;
            });

            console.log('Upload result:', result);

            Utils.showToast('File uploaded successfully!', 'success');
            fileInput.value = '';
            progressDiv.style.display = 'none';

            this.loadLogs();
        } catch (error) {
            Utils.showToast(error.message || 'Upload failed', 'error');
            progressDiv.style.display = 'none';
        }
    },

    async handleUploadAdmin(e) {
        e.preventDefault();
        const fileInput = document.getElementById('logFileAdmin');
        const file = fileInput.files[0];

        if (!file) {
            Utils.showToast('Please select a file', 'error');
            return;
        }

        if (!Utils.isValidFile(file)) {
            Utils.showToast('Invalid file type. Allowed: .log, .txt, .csv', 'error');
            return;
        }

        const progressDiv = document.getElementById('uploadProgressAdmin');
        const progressBar = progressDiv.querySelector('.progress-bar');

        try {
            progressDiv.style.display = 'block';
            progressBar.style.width = '0%';

            const result = await Api.uploadLogFile(file, (percent) => {
                progressBar.style.width = `${percent}%`;
            });

            Utils.showToast('File uploaded successfully!', 'success');
            fileInput.value = '';
            progressDiv.style.display = 'none';

            this.loadAdminStats();
        } catch (error) {
            Utils.showToast(error.message || 'Upload failed', 'error');
            progressDiv.style.display = 'none';
        }
    },

    async loadLogs() {
        try {
            console.log('Loading logs...');
            const logs = await Api.getLogs();
            console.log('Logs received:', logs);

            // Ensure logs is always an array
            this.logs = Array.isArray(logs) ? logs : [];
            console.log('Logs stored in this.logs:', this.logs);

            const tbody = document.getElementById('logsTableBody');
            tbody.innerHTML = '';

            if (!this.logs || this.logs.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No logs found. Upload a file to get started.</td></tr>';
                return;
            }

            this.logs.forEach(log => {
                const row = document.createElement('tr');
                row.id = `log-row-${log.id}`;
                row.innerHTML = `
                    <td>${log.id}</td>
                    <td>${Utils.escapeHtml(log.file_name)}</td>
                    <td>${Utils.getStatusBadge(log.status)}</td>
                    <td>${Utils.formatDate(log.created_at)}</td>
                    <td>
                        <button class="btn btn-sm btn-info" onclick="App.showLogStatistics(${log.id})" title="Statistics">
                            <i class="fas fa-chart-bar"></i> Statistics
                        </button>
                        <button class="btn btn-sm btn-danger ms-1" onclick="App.deleteLog(${log.id})" title="Delete">
                            <i class="fas fa-trash"></i>
                        </button>
                    </td>
                `;
                tbody.appendChild(row);
            });

            this.updateLogStats(this.logs);
        } catch (error) {
            console.error('Error loading logs:', error);
            this.logs = [];
            const tbody = document.getElementById('logsTableBody');
            tbody.innerHTML = '<tr><td colspan="5" class="text-center text-danger">Error loading logs: ' + error.message + '</td></tr>';
        }
    },

    updateLogStats(logs) {
        if (!logs) return;

        const total = logs.length;
        const processed = logs.filter(l => l.status === 'completed').length;
        const pending = logs.filter(l => l.status === 'pending' || l.status === 'processing').length;
        const errors = logs.filter(l => l.status === 'failed').length;

        document.getElementById('totalLogs').textContent = total;
        document.getElementById('processedLogs').textContent = processed;
        document.getElementById('pendingLogs').textContent = pending;
        document.getElementById('errorLogs').textContent = errors;
    },

    async deleteLog(logId) {
        const confirmed = await Utils.confirmSwal('Delete Log', 'Are you sure you want to delete this log?');

        if (!confirmed.isConfirmed) return;

        try {
            await Api.deleteLog(logId);
            Utils.showToast('Log deleted successfully', 'success');
            this.loadLogs();
        } catch (error) {
            Utils.showToast(error.message || 'Delete failed', 'error');
        }
    },

    async viewLogDetails(logId) {
        try {
            const log = await Api.getLog(logId);
            const content = document.getElementById('logDetailsContent');

            content.innerHTML = `
                <div class="row">
                    <div class="col-md-6 mb-3">
                        <label class="form-label text-muted">ID</label>
                        <p class="fw-bold">#${log.id}</p>
                    </div>
                    <div class="col-md-6 mb-3">
                        <label class="form-label text-muted">Filename</label>
                        <p class="fw-bold">${Utils.escapeHtml(log.file_name)}</p>
                    </div>
                    <div class="col-md-6 mb-3">
                        <label class="form-label text-muted">Status</label>
                        <p>${Utils.getStatusBadge(log.status)}</p>
                    </div>
                    <div class="col-md-6 mb-3">
                        <label class="form-label text-muted">File Size</label>
                        <p>${log.file_size ? (log.file_size / 1024).toFixed(2) + ' KB' : '-'}</p>
                    </div>
                    <div class="col-md-6 mb-3">
                        <label class="form-label text-muted">Storage Size</label>
                        <p>${log.storage_size ? (log.storage_size / 1024).toFixed(2) + ' KB' : '-'}</p>
                    </div>
                    <div class="col-md-6 mb-3">
                        <label class="form-label text-muted">Total Lines</label>
                        <p>${log.total_lines || '-'}</p>
                    </div>
                    <div class="col-md-6 mb-3">
                        <label class="form-label text-muted">Parsed Lines</label>
                        <p>${log.parsed_lines || '-'}</p>
                    </div>
                    <div class="col-md-6 mb-3">
                        <label class="form-label text-muted">Unknown Lines</label>
                        <p>${log.unknown_lines || '-'}</p>
                    </div>
                    <div class="col-md-6 mb-3">
                        <label class="form-label text-muted">Started At</label>
                        <p>${Utils.formatDate(log.started_at)}</p>
                    </div>
                    <div class="col-md-6 mb-3">
                        <label class="form-label text-muted">Completed At</label>
                        <p>${Utils.formatDate(log.completed_at)}</p>
                    </div>
                    <div class="col-md-6 mb-3">
                        <label class="form-label text-muted">Created At</label>
                        <p>${Utils.formatDate(log.created_at)}</p>
                    </div>
                    <div class="col-12 mb-3">
                        <label class="form-label text-muted">File Path</label>
                        <p class="small text-break">${Utils.escapeHtml(log.file_path)}</p>
                    </div>
                    ${log.summary ? `
                        <div class="col-12 mb-3">
                            <label class="form-label text-muted">Summary</label>
                            <pre class="bg-light p-2 rounded" style="max-height: 200px; overflow: auto;">${Utils.escapeHtml(JSON.stringify(log.summary, null, 2))}</pre>
                        </div>
                    ` : ''}
                    ${log.levels_summary ? `
                        <div class="col-12 mb-3">
                            <label class="form-label text-muted">Levels Summary</label>
                            <pre class="bg-light p-2 rounded" style="max-height: 200px; overflow: auto;">${Utils.escapeHtml(JSON.stringify(log.levels_summary, null, 2))}</pre>
                        </div>
                    ` : ''}
                </div>
            `;

            const modalEl = document.getElementById('logDetailsModal');
            const modal = new bootstrap.Modal(modalEl);
            modal.show();
        } catch (error) {
            Utils.showToast(error.message || 'Failed to load log details', 'error');
        }
    },

    async viewAdminLogDetails(logId) {
        try {
            const log = await Api.getAdminLog(logId);
            const content = document.getElementById('logDetailsContent');

            const formatJson = (data) => {
                if (!data) return '-';
                return `<pre class="bg-light p-2 rounded" style="max-height: 200px; overflow: auto;"><code>${Utils.escapeHtml(JSON.stringify(data, null, 2))}</code></pre>`;
            };

            content.innerHTML = `
                <div class="row">
                    <div class="col-md-6 mb-3">
                        <label class="form-label text-muted">ID</label>
                        <p class="fw-bold">#${log.id}</p>
                    </div>
                    <div class="col-md-6 mb-3">
                        <label class="form-label text-muted">Filename</label>
                        <p class="fw-bold">${Utils.escapeHtml(log.file_name)}</p>
                    </div>
                    <div class="col-md-6 mb-3">
                        <label class="form-label text-muted">Status</label>
                        <p>${Utils.getStatusBadge(log.status)}</p>
                    </div>
                    <div class="col-md-6 mb-3">
                        <label class="form-label text-muted">File Size</label>
                        <p>${log.file_size ? (log.file_size / 1024).toFixed(2) + ' KB' : '-'}</p>
                    </div>
                    <div class="col-md-6 mb-3">
                        <label class="form-label text-muted">Storage Size</label>
                        <p>${log.storage_size ? (log.storage_size / 1024).toFixed(2) + ' KB' : '-'}</p>
                    </div>
                    <div class="col-md-6 mb-3">
                        <label class="form-label text-muted">Total Lines</label>
                        <p>${log.total_lines || '-'}</p>
                    </div>
                    <div class="col-md-6 mb-3">
                        <label class="form-label text-muted">Parsed Lines</label>
                        <p>${log.parsed_lines || '-'}</p>
                    </div>
                    <div class="col-md-6 mb-3">
                        <label class="form-label text-muted">Unknown Lines</label>
                        <p>${log.unknown_lines || '-'}</p>
                    </div>
                    <div class="col-md-6 mb-3">
                        <label class="form-label text-muted">Started At</label>
                        <p>${Utils.formatDate(log.started_at)}</p>
                    </div>
                    <div class="col-md-6 mb-3">
                        <label class="form-label text-muted">Completed At</label>
                        <p>${Utils.formatDate(log.completed_at)}</p>
                    </div>
                    <div class="col-md-6 mb-3">
                        <label class="form-label text-muted">Created At</label>
                        <p>${Utils.formatDate(log.created_at)}</p>
                    </div>
                    <div class="col-12 mb-3">
                        <label class="form-label text-muted">File Path</label>
                        <p class="small text-break">${Utils.escapeHtml(log.file_path)}</p>
                    </div>
                    ${log.summary ? `
                        <div class="col-12 mb-3">
                            <label class="form-label text-muted">Summary</label>
                            <pre class="bg-light p-2 rounded" style="max-height: 200px; overflow: auto;">${Utils.escapeHtml(JSON.stringify(log.summary, null, 2))}</pre>
                        </div>
                    ` : ''}
                    ${log.levels_summary ? `
                        <div class="col-12 mb-3">
                            <label class="form-label text-muted">Levels Summary</label>
                            <pre class="bg-light p-2 rounded" style="max-height: 200px; overflow: auto;">${Utils.escapeHtml(JSON.stringify(log.levels_summary, null, 2))}</pre>
                        </div>
                    ` : ''}
                </div>
            `;

            const modalEl = document.getElementById('logDetailsModal');
            const modal = new bootstrap.Modal(modalEl);
            modal.show();
        } catch (error) {
            Utils.showToast(error.message || 'Failed to load log details', 'error');
        }
    },

     async loadAdminStats() {
         try {
             const [stats, activity, errors, users, systemStats, results] = await Promise.all([
                 Api.getDashboardStats(),
                 Api.getRecentActivity(),
                 Api.getErrorStatistics(),
                 Api.getUserStatistics(),
                 Api.getFullSystemStats(),
                 Api.getResults()
             ]);

             document.getElementById('totalUsers').textContent = users.total_users || 0;
             document.getElementById('activeUsers').textContent = users.active_users || 0;
             document.getElementById('adminTotalLogs').textContent = stats.total_logs || 0;
             document.getElementById('totalErrors').textContent = errors.total_errors || 0;

             this.renderErrorChart(errors);
             this.renderActivityChart(activity);
             this.loadAdminLogs();
             this.loadAdminUsers();
             this.loadInvites();
             // Results already fetched above, no duplicate call
             this._allResults = Array.isArray(results) ? results : [];
             this.filterResults();
             this.renderSystemInfo(systemStats);
         } catch (error) {
             console.error('Error loading admin stats:', error);
             // If unauthorized, stop auto-refresh and redirect to login
             if (error.message && (error.message.includes('401') || error.message.includes('Unauthorized') || error.message.includes('Not authenticated'))) {
                 this.stopAutoRefresh();
                 Utils.removeToken();
                 Utils.removeUser();
                 this.currentUser = null;
                 this.showLoginSection();
                 this.updateAuthNav();
                 Utils.showToast('Session expired. Please login again.', 'warning');
             }
         }
     },

    renderSystemInfo(data) {
        if (!data) return;

        const formatBytes = (bytes) => {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        };

        const formatPercent = (val) => val ? val.toFixed(1) + '%' : '-';

        let html = '';

        if (data.system) {
            html += `<tr><td><strong>Hostname</strong></td><td>${data.system.hostname || '-'}</td></tr>`;
            html += `<tr><td><strong>OS</strong></td><td>${data.system.os || '-'}</td></tr>`;
            html += `<tr><td><strong>Version</strong></td><td>${data.system.os_version || '-'}</td></tr>`;
            html += `<tr><td><strong>Architecture</strong></td><td>${data.system.architecture || '-'}</td></tr>`;
            html += `<tr><td><strong>Boot Time</strong></td><td>${data.system.boot_time || '-'}</td></tr>`;
        }
        document.getElementById('systemTableBody').innerHTML = html;

        let cpuHtml = '';
        if (data.cpu) {
            cpuHtml += `<tr><td><strong>Physical Cores</strong></td><td>${data.cpu.physical_cores || '-'}</td></tr>`;
            cpuHtml += `<tr><td><strong>Total Cores</strong></td><td>${data.cpu.total_cores || '-'}</td></tr>`;
            cpuHtml += `<tr><td><strong>Usage</strong></td><td>${formatPercent(data.cpu.usage_percent)}</td></tr>`;
            if (data.cpu.per_core_usage && data.cpu.per_core_usage.length > 0) {
                data.cpu.per_core_usage.forEach((usage, i) => {
                    cpuHtml += `<tr><td>Core ${i}</td><td>${formatPercent(usage)}</td></tr>`;
                });
            }
        }
        document.getElementById('cpuTableBody').innerHTML = cpuHtml;

        let memHtml = '';
        if (data.memory) {
            memHtml += `<tr><td><strong>Total</strong></td><td>${formatBytes(data.memory.total)}</td></tr>`;
            memHtml += `<tr><td><strong>Available</strong></td><td>${formatBytes(data.memory.available)}</td></tr>`;
            memHtml += `<tr><td><strong>Used</strong></td><td>${formatBytes(data.memory.used)}</td></tr>`;
            memHtml += `<tr><td><strong>Usage</strong></td><td>${formatPercent(data.memory.percent)}</td></tr>`;
        }
        if (data.swap) {
            memHtml += `<tr><td><strong>Swap Total</strong></td><td>${formatBytes(data.swap.total)}</td></tr>`;
            memHtml += `<tr><td><strong>Swap Used</strong></td><td>${formatBytes(data.swap.used)}</td></tr>`;
            memHtml += `<tr><td><strong>Swap Usage</strong></td><td>${formatPercent(data.swap.percent)}</td></tr>`;
        }
        document.getElementById('memoryTableBody').innerHTML = memHtml;

        let diskHtml = '';
        if (data.disk && data.disk.length > 0) {
            data.disk.forEach((d, i) => {
                diskHtml += `<tr><td><strong>${d.device}</strong></td><td>${d.mountpoint}</td></tr>`;
                diskHtml += `<tr><td>Filesystem</td><td>${d.filesystem}</td></tr>`;
                diskHtml += `<tr><td>Total</td><td>${formatBytes(d.total)}</td></tr>`;
                diskHtml += `<tr><td>Used</td><td>${formatBytes(d.used)} (${formatPercent(d.percent)})</td></tr>`;
                diskHtml += `<tr><td>Free</td><td>${formatBytes(d.free)}</td></tr>`;
            });
        }
        document.getElementById('diskTableBody').innerHTML = diskHtml;

        let netHtml = '';
        if (data.network) {
            netHtml += `<tr><td><strong>Bytes Sent</strong></td><td>${formatBytes(data.network.bytes_sent)}</td></tr>`;
            netHtml += `<tr><td><strong>Bytes Received</strong></td><td>${formatBytes(data.network.bytes_recv)}</td></tr>`;
            netHtml += `<tr><td><strong>Packets Sent</strong></td><td>${data.network.packets_sent || 0}</td></tr>`;
            netHtml += `<tr><td><strong>Packets Received</strong></td><td>${data.network.packets_recv || 0}</td></tr>`;
        }
        document.getElementById('networkTableBody').innerHTML = netHtml;

        let redisHtml = '';
        if (data.redis) {
            if (data.redis.status === 'connected') {
                redisHtml += `<tr><td><strong>Status</strong></td><td><span class="badge bg-success">Connected</span></td></tr>`;
                redisHtml += `<tr><td><strong>Version</strong></td><td>${data.redis.version || '-'}</td></tr>`;
                redisHtml += `<tr><td><strong>Uptime</strong></td><td>${data.redis.uptime_seconds ? Math.floor(data.redis.uptime_seconds / 3600) + 'h' : '-'}</td></tr>`;
                redisHtml += `<tr><td><strong>Memory Used</strong></td><td>${data.redis.used_memory || '-'}</td></tr>`;
                redisHtml += `<tr><td><strong>Memory Peak</strong></td><td>${data.redis.used_memory_peak || '-'}</td></tr>`;
                redisHtml += `<tr><td><strong>Keys</strong></td><td>${data.redis.keyspace || 0}</td></tr>`;
                redisHtml += `<tr><td><strong>Clients</strong></td><td>${data.redis.connected_clients || 0}</td></tr>`;
            } else if (data.redis.status === 'disconnected') {
                redisHtml += `<tr><td><strong>Status</strong></td><td><span class="badge bg-danger">Disconnected</span></td></tr>`;
            } else {
                redisHtml += `<tr><td><strong>Status</strong></td><td><span class="badge bg-warning">${data.redis.status}</span></td></tr>`;
                if (data.redis.message) {
                    redisHtml += `<tr><td><strong>Error</strong></td><td>${data.redis.message}</td></tr>`;
                }
            }
        } else {
            redisHtml += `<tr><td colspan="2" class="text-muted">No Redis data</td></tr>`;
        }
        document.getElementById('redisTableBody').innerHTML = redisHtml;
    },

    renderErrorChart(data) {
        const canvas = document.getElementById('errorChart');
        if (!canvas) return;

        if (this.errorChart) {
            this.errorChart.destroy();
        }

        this.errorChart = new Chart(canvas, {
            type: 'doughnut',
            data: {
                labels: ['ERROR', 'WARNING', 'INFO', 'DEBUG'],
                datasets: [{
                    data: [
                        data.error_count || 0,
                        data.warning_count || 0,
                        data.info_count || 0,
                        data.debug_count || 0
                    ],
                    backgroundColor: ['#ef4444', '#f59e0b', '#22c55e', '#64748b']
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        });
    },

    renderActivityChart(data) {
        const canvas = document.getElementById('activityChart');
        if (!canvas) return;

        if (this.activityChart) {
            this.activityChart.destroy();
        }

        const labels = [];
        const values = [];

        if (data.daily_stats) {
            data.daily_stats.forEach(stat => {
                labels.push(stat.date);
                values.push(stat.count);
            });
        }

        this.activityChart = new Chart(canvas, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Logs Processed',
                    data: values,
                    backgroundColor: '#2563eb'
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        display: false
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
    },

    async loadAdminLogs() {
        try {
            const logs = await Api.getAdminLogs();
            const tbody = document.getElementById('allLogsTableBody');
            tbody.innerHTML = '';

            const logsArray = Array.isArray(logs) ? logs : [];
            if (logsArray.length === 0) {
                tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted">No logs found</td></tr>';
                return;
            }

            logsArray.forEach(log => {
                const row = document.createElement('tr');
                row.id = `admin-log-row-${log.id}`;
                row.innerHTML = `
                    <td><input type="checkbox" class="log-checkbox" value="${log.id}"></td>
                    <td>${log.id}</td>
                    <td>${Utils.escapeHtml(log.file_name)}</td>
                    <td>${log.user_name || '-'}</td>
                    <td>${Utils.getStatusBadge(log.status)}</td>
                    <td>${Utils.formatDate(log.created_at)}</td>
                    <td>
                        <button class="btn btn-sm btn-outline-primary" onclick="App.viewAdminLogDetails(${log.id})" title="View Log Details">
                            <i class="fas fa-file-alt"></i>
                        </button>
                        <button class="btn btn-sm btn-outline-info" onclick="App.viewAdminLogResults(${log.id})" title="View Results">
                            <i class="fas fa-list-ul"></i>
                        </button>
                        <button class="btn btn-sm btn-danger" onclick="App.deleteAdminLog(${log.id})" title="Delete">
                            <i class="fas fa-trash"></i>
                        </button>
                    </td>
                `;
                tbody.appendChild(row);
            });
        } catch (error) {
            console.error('Error loading admin logs:', error);
        }
    },

    async deleteAdminLog(logId) {
        const confirmed = await Utils.confirmSwal('Delete Log', 'Are you sure you want to delete this log?');

        if (!confirmed.isConfirmed) return;

        try {
            await Api.deleteAdminLog(logId);
            Utils.showToast('Log deleted successfully', 'success');
            this.loadAdminLogs();
        } catch (error) {
            Utils.showToast(error.message || 'Delete failed', 'error');
        }
    },

     async loadAdminUsers() {
         try {
             const users = await Api.getAllAdminUsers();

             const tbody = document.getElementById('usersTableBody');
             tbody.innerHTML = '';

             if (!users || users.length === 0) {
                 tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted">No users found</td></tr>';
                 return;
             }

             users.forEach(user => {
                 const row = document.createElement('tr');
                 row.innerHTML = `
                     <td>${user.id}</td>
                     <td>${Utils.escapeHtml(user.name)}</td>
                     <td>${Utils.escapeHtml(user.email)}</td>
                     <td>${Utils.getRoleBadge(user.role)}</td>
                     <td>${Utils.getStatusBadge(user.is_active ? 'active' : 'inactive')}</td>
                     <td>${Utils.formatDate(user.created_at)}</td>
                     <td>
                         <button class="btn btn-sm btn-outline-info" onclick="App.viewUserDetails(${user.id})" title="View Details">
                             <i class="fas fa-eye"></i> View
                         </button>
                         <button class="btn btn-sm btn-warning" onclick="App.toggleUser(${user.id})">Toggle</button>
                         <button class="btn btn-sm btn-danger" onclick="App.deleteUser(${user.id})">Delete</button>
                     </td>
                 `;
                 tbody.appendChild(row);
             });
         } catch (error) {
             console.error('Error loading users:', error);
         }
     },

      async viewUserDetails(userId) {
          try {
              Utils.showLoader();
              const user = await Api.getAdminUser(userId);

              const formatDate = (date) => {
                  if (!date) return '-';
                  return new Date(date).toLocaleString();
              };

              const content = document.getElementById('userDetailsContent');

              content.innerHTML = `
                  <div class="row">
                      <div class="col-md-6 mb-3">
                          <label class="form-label text-muted">ID</label>
                          <p class="fw-bold">#${user.id}</p>
                      </div>
                      <div class="col-md-6 mb-3">
                          <label class="form-label text-muted">Name</label>
                          <p class="fw-bold">${Utils.escapeHtml(user.name)}</p>
                      </div>
                      <div class="col-md-6 mb-3">
                          <label class="form-label text-muted">Email</label>
                          <p>${Utils.escapeHtml(user.email)}</p>
                      </div>
                      <div class="col-md-6 mb-3">
                          <label class="form-label text-muted">Role</label>
                          <p>${Utils.getRoleBadge(user.role)}</p>
                      </div>
                      <div class="col-md-6 mb-3">
                          <label class="form-label text-muted">Status</label>
                          <p>${Utils.getStatusBadge(user.is_active ? 'active' : 'inactive')}</p>
                      </div>
                      <div class="col-md-6 mb-3">
                          <label class="form-label text-muted">Tenant ID</label>
                          <p><code class="bg-light px-2 py-1 rounded">${user.tenant_id || '-'}</code></p>
                      </div>
                      <div class="col-md-6 mb-3">
                          <label class="form-label text-muted">Telegram Chat ID</label>
                          <p>${user.telegram_chat_id || 'Not set'}</p>
                      </div>
                      <div class="col-md-6 mb-3">
                          <label class="form-label text-muted">Email Verified</label>
                          <p>${user.email_verified ? '<span class="badge bg-success">Verified</span>' : '<span class="badge bg-warning">Not Verified</span>'}</p>
                      </div>
                      <div class="col-md-6 mb-3">
                          <label class="form-label text-muted">Created At</label>
                          <p>${formatDate(user.created_at)}</p>
                      </div>
                      <div class="col-md-6 mb-3">
                          <label class="form-label text-muted">Last Login</label>
                          <p>${formatDate(user.last_login)}</p>
                      </div>
                      <div class="col-md-6 mb-3">
                          <label class="form-label text-muted">Subscription Tier</label>
                          <p><span class="badge bg-info">${(user.subscription_tier || 'free').toUpperCase()}</span></p>
                      </div>
                      <div class="col-md-6 mb-3">
                          <label class="form-label text-muted">Monthly Quota</label>
                          <p>${user.monthly_quota || 0} logs</p>
                      </div>
                      <div class="col-md-6 mb-3">
                          <label class="form-label text-muted">Current Usage</label>
                          <p>${user.api_usage_current_month || 0} logs</p>
                      </div>
                      <div class="col-md-6 mb-3">
                          <label class="form-label text-muted">Usage Reset At</label>
                          <p>${formatDate(user.api_usage_reset_at)}</p>
                      </div>
                      <div class="col-md-6 mb-3">
                          <label class="form-label text-muted">Subscription Expires At</label>
                          <p>${formatDate(user.subscription_expires_at)}</p>
                      </div>
                  </div>
              `;

              const modalEl = document.getElementById('userDetailsModal');
              const modal = new bootstrap.Modal(modalEl);
              modal.show();
          } catch (error) {
              console.error('Error loading user details:', error);
              Utils.showToast(error.message || 'Failed to load user details', 'error');
          } finally {
              Utils.hideLoader();
          }
      },

      async toggleUser(userId) {
          try {
              await Api.toggleUserActive(userId);
              Utils.showToast('User status updated', 'success');
              this.loadAdminUsers();
          } catch (error) {
              Utils.showToast(error.message || 'Update failed', 'error');
          }
      },

     async deleteUser(userId) {
         const confirmed = await Utils.confirmSwal('Delete User', 'Are you sure you want to delete this user?');

         if (!confirmed.isConfirmed) return;

         try {
             await Api.deleteUser(userId);
             Utils.showToast('User deleted successfully', 'success');
             this.loadAdminUsers();
         } catch (error) {
             Utils.showToast(error.message || 'Delete failed', 'error');
         }
     },

     async loadInvites() {
         try {
             const invites = await Api.getInvites();

             const tbody = document.getElementById('invitesTableBody');
             tbody.innerHTML = '';

             if (!invites || invites.length === 0) {
                 tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No invite requests found</td></tr>';
                 return;
             }

             invites.forEach(invite => {
                 const row = document.createElement('tr');
                 row.innerHTML = `
                     <td>${invite.id}</td>
                     <td>${Utils.escapeHtml(invite.email)}</td>
                     <td>${Utils.getInviteStatusBadge(invite.status)}</td>
                     <td>${Utils.formatDate(invite.created_at)}</td>
                     <td>
                         ${invite.status === 'PENDING' ? `
                             <button class="btn btn-sm btn-success" onclick="App.approveInvite('${encodeURIComponent(invite.email)}')" title="Approve & Send Invite">
                                 <i class="fas fa-check"></i> Approve
                             </button>
                         ` : '<span class="badge bg-secondary">No Actions</span>'}
                         <button class="btn btn-sm btn-danger" onclick="App.deleteInvite('${encodeURIComponent(invite.email)}')" title="Delete">
                             <i class="fas fa-trash"></i>
                         </button>
                     </td>
                 `;
                 tbody.appendChild(row);
             });
         } catch (error) {
             console.error('Error loading invites:', error);
         }
     },

      async approveInvite(email) {
          const decodedEmail = decodeURIComponent(email);
          try {
              const result = await Api.createInvite({ email: decodedEmail });
              Utils.showToast('Invite sent successfully!', 'success');
              this.loadInvites();
          } catch (error) {
              Utils.showToast(error.message || 'Failed to send invite', 'error');
          }
      },

     async deleteInvite(email) {
         const decodedEmail = decodeURIComponent(email);
         const confirmed = await Utils.confirmSwal('Delete Invite', `Are you sure you want to delete the invite request for ${decodedEmail}?`);

         if (!confirmed.isConfirmed) return;

         try {
             await Api.deleteInvite(decodedEmail);
             Utils.showToast('Invite request deleted', 'success');
             this.loadInvites();
         } catch (error) {
             Utils.showToast(error.message || 'Delete failed', 'error');
         }
     },

     async handleCreateUser(e) {
        e.preventDefault();
        const name = document.getElementById('newUserName').value;
        const email = document.getElementById('newUserEmail').value;
        const password = document.getElementById('newUserPassword').value;
        const role = document.getElementById('newUserRole').value;

        try {
            await Api.createUser({ name, email, password, role });
            Utils.showToast('User created successfully', 'success');
            document.getElementById('createUserForm').reset();
            bootstrap.Modal.getInstance(document.getElementById('createUserModal')).hide();
            this.loadAdminUsers();
        } catch (error) {
            Utils.showToast(error.message || 'Create failed', 'error');
        }
    },

    async bulkDeleteLogs() {
        const checkboxes = document.querySelectorAll('.log-checkbox:checked');
        const ids = Array.from(checkboxes).map(cb => parseInt(cb.value));

        if (ids.length === 0) {
            Utils.showToast('Please select logs to delete', 'warning');
            return;
        }

        const confirmed = await Utils.confirmSwal('Delete Logs', `Are you sure you want to delete ${ids.length} logs?`);

        if (!confirmed.isConfirmed) return;

        try {
            await Api.bulkDeleteLogs(ids);
            Utils.showToast('Logs deleted successfully', 'success');
            this.loadAdminLogs();
        } catch (error) {
            Utils.showToast(error.message || 'Delete failed', 'error');
        }
    },

    async loadResults() {
        try {
            const results = await Api.getResults();
            this._allResults = Array.isArray(results) ? results : [];
            this.filterResults();
        } catch (error) {
            console.error('Error loading results:', error);
            this._allResults = [];
            document.getElementById('resultsTableBody').innerHTML =
                '<div class="text-center text-danger p-4">Error loading results: ' + error.message + '</div>';
        }
    },


    filterResults() {
        const searchTerm = document.getElementById('resultsSearch')?.value?.toLowerCase() || '';
        const levelFilter = document.getElementById('resultsLevelFilter')?.value || '';
        const typeFilter = document.getElementById('resultsTypeFilter')?.value || '';

        let filtered = this._allResults || [];

        if (searchTerm) {
            filtered = filtered.filter(r =>
                (r.message || '').toLowerCase().includes(searchTerm) ||
                (r.source || '').toLowerCase().includes(searchTerm)
            );
        }

        if (typeFilter) {
            filtered = filtered.filter(r => (r.source || '').toLowerCase() === typeFilter);
        }

        if (levelFilter) {
            filtered = filtered.filter(r => r.level === levelFilter);
        }

        this.renderResults(filtered);
    },


    renderResults(results) {
        const container = document.getElementById('resultsTableBody');

        if (!results || results.length === 0) {
            container.innerHTML = '<div class="text-center text-muted p-4"><i class="fas fa-inbox fa-2x mb-2 d-block"></i>No results found</div>';
            return;
        }

        const getLevelColor = (level) => {
            const colors = {
                'ERROR': 'border-start border-4 border-danger',
                'WARNING': 'border-start border-4 border-warning',
                'INFO': 'border-start border-4 border-info',
                'DEBUG': 'border-start border-4 border-secondary',
                'UNKNOWN': 'border-start border-4 border-dark'
            };
            return colors[level] || colors['UNKNOWN'];
        };

        container.innerHTML = results.map(result => `
            <div class="result-card ${getLevelColor(result.level)} p-3 mb-2 rounded bg-light">
                <div class="d-flex justify-content-between align-items-start mb-2">
                    <div>
                        <span class="fw-bold">#${result.id}</span>
                        <span class="badge bg-secondary ms-2">Log: ${result.log_id}</span>
                    </div>
                    <div class="d-flex align-items-center gap-2">
                        ${Utils.getLevelBadge(result.level)}
                        <button class="btn btn-sm btn-outline-info" onclick="App.showResultDetails(${result.id})" title="Details">
                            <i class="fas fa-info-circle"></i>
                        </button>
                        <button class="btn btn-sm btn-outline-danger" onclick="App.deleteResult(${result.id})" title="Delete">
                            <i class="fas fa-trash"></i>
                        </button>
                    </div>
                </div>
                <div class="result-message mb-2" style="word-break: break-word;">${Utils.escapeHtml(result.message || '-')}</div>
                <div class="d-flex justify-content-between text-muted small">
                    <span><i class="fas fa-tag me-1"></i>${Utils.escapeHtml(result.source || '-')}</span>
                    <span><i class="fas fa-clock me-1"></i>${Utils.formatDate(result.created_at)}</span>
                </div>
            </div>
        `).join('');
    },


    async deleteResult(resultId) {
        const confirmed = await Utils.confirmSwal('Delete Result', 'Are you sure you want to delete this result?');

        if (!confirmed.isConfirmed) return;

        try {
            await Api.deleteResult(resultId);
            Utils.showToast('Result deleted successfully', 'success');
            this.loadResults();
        } catch (error) {
            Utils.showToast(error.message || 'Delete failed', 'error');
        }
    },

    async showResultDetails(resultId) {
        try {
            const result = await Api.getResult(resultId);
            const content = document.getElementById('resultDetailsContent');

            const formatJson = (data) => {
                if (!data) return '-';
                return `<pre class="bg-light p-2 rounded" style="max-height: 200px; overflow: auto;"><code>${Utils.escapeHtml(JSON.stringify(data, null, 2))}</code></pre>`;
            };

            content.innerHTML = `
                <div class="row">
                    <div class="col-md-4 mb-3">
                        <label class="form-label text-muted">ID</label>
                        <p class="fw-bold">#${result.id}</p>
                    </div>
                    <div class="col-md-4 mb-3">
                        <label class="form-label text-muted">Log ID</label>
                        <p class="fw-bold">${result.log_id}</p>
                    </div>
                    <div class="col-md-4 mb-3">
                        <label class="form-label text-muted">Level</label>
                        <p>${Utils.getLevelBadge(result.level)}</p>
                    </div>
                    <div class="col-md-4 mb-3">
                        <label class="form-label text-muted">User ID</label>
                        <p>${result.user_id || '-'}</p>
                    </div>
                    <div class="col-md-4 mb-3">
                        <label class="form-label text-muted">Confidence</label>
                        <p>${result.confidence ?? '-'}</p>
                    </div>
                    <div class="col-md-4 mb-3">
                        <label class="form-label text-muted">Detected Type</label>
                        <p>${result.detected_type || '-'}</p>
                    </div>
                    <div class="col-md-6 mb-3">
                        <label class="form-label text-muted">Event Category</label>
                        <p>${result.event_category || '-'}</p>
                    </div>
                    <div class="col-md-6 mb-3">
                        <label class="form-label text-muted">Line Number</label>
                        <p>${result.line_number ?? '-'}</p>
                    </div>
                    <div class="col-12 mb-3">
                        <label class="form-label text-muted">Message</label>
                        <div class="p-3 bg-light rounded border" style="word-break: break-word;">${Utils.escapeHtml(result.message || '-')}</div>
                    </div>
                    <div class="col-12 mb-3">
                        <label class="form-label text-muted">Template</label>
                        <div class="p-2 bg-light rounded">${Utils.escapeHtml(result.template || '-')}</div>
                    </div>
                    <div class="col-12 mb-3">
                        <label class="form-label text-muted">AI Note</label>
                        <div class="p-2 bg-info bg-opacity-10 rounded">${Utils.escapeHtml(result.ai_note || '-')}</div>
                    </div>
                    <div class="col-md-6 mb-3">
                        <label class="form-label text-muted">Signature</label>
                        <p class="small text-muted">${result.signature || '-'}</p>
                    </div>
                    <div class="col-md-6 mb-3">
                        <label class="form-label text-muted">Timestamp</label>
                        <p>${result.timestamp || '-'}</p>
                    </div>
                    <div class="col-md-6 mb-3">
                        <label class="form-label text-muted">Epoch</label>
                        <p>${result.epoch ?? '-'}</p>
                    </div>
                    <div class="col-md-6 mb-3">
                        <label class="form-label text-muted">Created At</label>
                        <p>${Utils.formatDate(result.created_at)}</p>
                    </div>
                    <div class="col-12 mb-3">
                        <label class="form-label text-muted">Details</label>
                        ${formatJson(result.details)}
                    </div>
                    <div class="col-12 mb-3">
                        <label class="form-label text-muted">Extra</label>
                        ${formatJson(result.extra)}
                    </div>
                    <div class="col-12 mb-3">
                        <label class="form-label text-muted">Correlation</label>
                        ${formatJson(result.correlation)}
                    </div>
                    <div class="col-12 mb-3">
                        <label class="form-label text-muted">Signals</label>
                        <div class="p-2 bg-light rounded">${(result.signals || []).map(s => `<span class="badge bg-secondary me-1 mb-1">${Utils.escapeHtml(s)}</span>`).join('')}</div>
                    </div>
                </div>
            `;

            const modalEl = document.getElementById('resultDetailsModal');
            const modal = new bootstrap.Modal(modalEl);
            modal.show();
        } catch (error) {
            Utils.showToast(error.message || 'Failed to load result details', 'error');
        }
    }
};

window.addEventListener('error', (event) => {
    console.error('Global error:', event.error, 'at', event.filename, ':', event.lineno);
});

window.addEventListener('unhandledrejection', (event) => {
    console.error('Unhandled promise rejection:', event.reason);
});

document.addEventListener('DOMContentLoaded', () => {
    console.log('DOMContentLoaded fired, initializing App');
    // Observe adminSection style changes
    const adminSec = document.getElementById('adminSection');
    if (adminSec) {
        const observer = new MutationObserver((mutations) => {
            mutations.forEach(m => {
                console.log('adminSection attribute changed:', m.attributeName, 'new value:', adminSec.getAttribute(m.attributeName));
            });
        });
        observer.observe(adminSec, { attributes: true });
        console.log('Set up MutationObserver for adminSection');
    }
    App.init();
});

window.App = App;