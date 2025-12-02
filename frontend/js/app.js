// File Storage Lab - Main Application Logic

class FileStorageApp {
    constructor() {
        // Use relative API base to avoid cross-origin and cookie domain issues
        this.apiBase = '/api';
        this.currentUser = null;
        this.currentSession = null;
        this.currentActiveUsers = 800; // Base for animation
        this.currentFiles = 5000; // Base for animation
        this.flagFileId = null; // Store flag file UUID
        this.firstFileId = null; // Store first file UUID
        this.activityFeedInterval = null;
        this.countersInterval = null;
        this.init();
    }

    init() {
        this.checkAuthStatus();
        this.loadStats();
        this.setupEventListeners();
    }

    setupEventListeners() {
        // File upload drag and drop
        const fileInput = document.getElementById('fileInput');
        if (fileInput) {
            fileInput.addEventListener('change', this.handleFileSelect.bind(this));
        }

        // Auto-refresh stats every 30 seconds
        setInterval(() => {
            this.loadStats();
        }, 30000);
    }

    async checkAuthStatus() {
        try {
            // Check if user has valid session
            const response = await fetch(`${this.apiBase}/session/validate`, {
                credentials: 'include'
            });
            
            if (response.ok) {
                // User is authenticated, load user data and show authenticated UI
                await this.loadUserData();
            } else {
                // Not authenticated, show welcome screen
                this.showWelcomeScreen();
            }
        } catch (error) {
            console.error('Auth check failed:', error);
            // On error, show welcome screen
            this.showWelcomeScreen();
        }
    }

    async loadUserData() {
        try {
            // Validate session and get user info
            const response = await fetch(`${this.apiBase}/session/validate`, {
                credentials: 'include'
            });
            
            if (response.ok) {
                const userData = await response.json();
                this.currentUser = userData;
                this.showAuthenticatedScreen();
                await this.loadFiles();
                await this.loadAdminData();
            } else {
                this.showWelcomeScreen();
            }
        } catch (error) {
            console.error('Failed to load user data:', error);
            this.showWelcomeScreen();
        }
    }

    showWelcomeScreen() {
        // Clear user state
        this.currentUser = null;
        this.currentSession = null;
        
        // Stop activity feed and counters
        this.stopActivityFeed();
        this.stopCountersAnimation();
        
        // Show/hide appropriate sections - match initial HTML state
        const welcomeSection = document.getElementById('welcome-section');
        const fileSection = document.getElementById('file-section');
        const adminSection = document.getElementById('admin-section');
        const attackToolsSection = document.getElementById('attack-tools-section');
        
        // Reset welcome section to initial state (no display style, just visible)
        if (welcomeSection) {
            welcomeSection.style.display = '';
            welcomeSection.style.visibility = '';
        }
        
        // Hide other sections (match initial HTML)
        if (fileSection) {
            fileSection.style.display = 'none';
            fileSection.style.visibility = '';
        }
        if (adminSection) {
            adminSection.style.display = 'none';
            adminSection.style.visibility = '';
        }
        if (attackToolsSection) {
            attackToolsSection.style.display = 'none';
            attackToolsSection.style.visibility = '';
        }
        
        // Clear file lists and containers
        const filesContainer = document.getElementById('files-container');
        if (filesContainer) {
            filesContainer.innerHTML = '<div class="text-center text-muted"><i class="fas fa-spinner fa-spin fa-2x mb-3"></i><p>Loading files...</p></div>';
        }
        
        const activityFeed = document.getElementById('activity-feed');
        if (activityFeed) {
            activityFeed.innerHTML = '<div class="text-center text-muted"><i class="fas fa-spinner fa-spin mb-2"></i><p class="small mb-0">Loading activity...</p></div>';
        }
        
        const statsContainer = document.getElementById('stats-container');
        if (statsContainer) {
            statsContainer.innerHTML = '<div class="text-center text-muted"><i class="fas fa-spinner fa-spin fa-2x mb-3"></i><p>Loading statistics...</p></div>';
        }
        
        const adminFilesContainer = document.getElementById('admin-files-container');
        if (adminFilesContainer) {
            adminFilesContainer.innerHTML = '<div class="text-center text-muted"><i class="fas fa-spinner fa-spin fa-2x mb-3"></i><p>Loading files...</p></div>';
        }
        
        // Show login/register buttons, hide user menu - match initial HTML state
        const authButtons = document.getElementById('auth-buttons');
        const userMenu = document.getElementById('user-menu');
        
        if (authButtons) {
            authButtons.style.display = 'flex';
            authButtons.style.visibility = 'visible';
            authButtons.style.opacity = '1';
            authButtons.removeAttribute('hidden');
            // Force reflow to ensure it's shown
            authButtons.offsetHeight;
        }
        if (userMenu) {
            userMenu.style.display = 'none';
            userMenu.style.visibility = 'hidden';
            userMenu.style.opacity = '0';
            userMenu.setAttribute('hidden', 'true');
            // Force reflow to ensure it's hidden
            userMenu.offsetHeight;
        }
        
        // Double-check UI state after a brief delay to ensure it's correct
        setTimeout(() => {
            const checkUserMenu = document.getElementById('user-menu');
            const checkAuthButtons = document.getElementById('auth-buttons');
            if (checkUserMenu) {
                checkUserMenu.style.display = 'none';
                checkUserMenu.style.visibility = 'hidden';
                checkUserMenu.style.opacity = '0';
                checkUserMenu.setAttribute('hidden', 'true');
            }
            if (checkAuthButtons) {
                checkAuthButtons.style.display = 'flex';
                checkAuthButtons.style.visibility = 'visible';
                checkAuthButtons.style.opacity = '1';
                checkAuthButtons.removeAttribute('hidden');
            }
        }, 50);
        
        // Clear username and role badge
        const usernameElement = document.getElementById('current-username');
        const roleBadge = document.getElementById('user-role-badge');
        
        if (usernameElement) {
            usernameElement.textContent = '';
        }
        if (roleBadge) {
            roleBadge.textContent = '';
            roleBadge.className = 'badge';
        }
        
        // Clear all forms
        const loginForm = document.getElementById('loginForm');
        if (loginForm) {
            loginForm.reset();
        }
        const registerForm = document.getElementById('registerForm');
        if (registerForm) {
            registerForm.reset();
        }
        
        // Don't auto-show login modal - let user choose when to login
    }

    showAuthenticatedScreen() {
        // Ensure currentUser exists before showing authenticated screen
        if (!this.currentUser) {
            console.warn('showAuthenticatedScreen called without currentUser');
            return;
        }
        
        // Hide welcome section and show file section
        const welcomeSection = document.getElementById('welcome-section');
        const fileSection = document.getElementById('file-section');
        const authButtons = document.getElementById('auth-buttons');
        const userMenu = document.getElementById('user-menu');
        
        if (welcomeSection) {
            welcomeSection.style.display = 'none';
            welcomeSection.style.visibility = 'hidden';
        }
        if (fileSection) {
            fileSection.style.display = 'block';
            fileSection.style.visibility = 'visible';
        }
        
        // Hide login/register buttons, show user menu - ensure logout button is visible
        if (authButtons) {
            authButtons.style.display = 'none';
            authButtons.style.visibility = 'hidden';
            authButtons.style.opacity = '0';
            authButtons.setAttribute('hidden', 'true');
        }
        if (userMenu) {
            userMenu.style.display = 'flex';
            userMenu.style.visibility = 'visible';
            userMenu.style.opacity = '1';
            userMenu.removeAttribute('hidden');
            // Force reflow to ensure it's shown
            userMenu.offsetHeight;
        }
        
        // Only show attack tools for admin users
        const attackToolsSection = document.getElementById('attack-tools-section');
        if (attackToolsSection) {
            if (this.currentUser?.role === 'admin') {
                attackToolsSection.style.display = 'block';
            } else {
                attackToolsSection.style.display = 'none';
            }
        }
        
        // Update username display - ensure it's set
        const usernameElement = document.getElementById('current-username');
        const roleBadge = document.getElementById('user-role-badge');
        
        if (usernameElement) {
            usernameElement.textContent = this.currentUser?.username || 'User';
        }
        if (roleBadge) {
            roleBadge.textContent = this.currentUser?.role || 'user';
            roleBadge.className = `badge ${this.currentUser?.role === 'admin' ? 'badge-admin' : 'badge-user'}`;
        }
        
        // Double-check UI state after a brief delay to ensure logout button is visible
        setTimeout(() => {
            const checkUserMenu = document.getElementById('user-menu');
            const checkAuthButtons = document.getElementById('auth-buttons');
            if (checkUserMenu) {
                checkUserMenu.style.display = 'flex';
                checkUserMenu.style.visibility = 'visible';
                checkUserMenu.style.opacity = '1';
                checkUserMenu.removeAttribute('hidden');
            }
            if (checkAuthButtons) {
                checkAuthButtons.style.display = 'none';
                checkAuthButtons.style.visibility = 'hidden';
                checkAuthButtons.style.opacity = '0';
                checkAuthButtons.setAttribute('hidden', 'true');
            }
        }, 50);
        
        // Start activity feed and animated counters
        this.startActivityFeed();
        this.startCountersAnimation();
    }

    async loadFiles() {
        try {
            const response = await fetch(`${this.apiBase}/files`, {
                credentials: 'include'
            });
            
            if (response.ok) {
                const data = await response.json();
                this.displayFiles(data.files);
            } else {
                this.showError('Failed to load files');
            }
        } catch (error) {
            console.error('Failed to load files:', error);
            this.showError('Failed to load files');
        }
    }

    displayFiles(files) {
        const container = document.getElementById('files-container');
        
        if (files.length === 0) {
            container.innerHTML = `
                <div class="text-center text-muted">
                    <i class="fas fa-folder-open fa-3x mb-3"></i>
                    <p>No files uploaded yet.</p>
                    <button class="btn btn-primary" onclick="showUploadModal()">
                        <i class="fas fa-upload me-1"></i>Upload Your First File
                    </button>
                </div>
            `;
            return;
        }

        container.innerHTML = `
            ${files.map(file => `
            <div class="file-card fade-in">
                <div class="d-flex align-items-center">
                    <div class="file-type-icon ${this.getFileTypeClass(file.mime_type)}">
                        <i class="fas ${this.getFileIcon(file.mime_type)}"></i>
                    </div>
                    <div class="file-info flex-grow-1">
                        <h6>${file.original_filename}</h6>
                        <div class="file-meta d-flex flex-wrap align-items-center gap-2">
                            <span>
                                <i class="fas fa-hdd me-1"></i>
                                ${this.formatFileSize(file.file_size)}
                            </span>
                            <span>
                                <i class="fas fa-calendar me-1"></i>
                                ${new Date(file.created_at).toLocaleDateString()}
                            </span>
                            <span class="uuid-display" title="${file.file_id}">
                                <i class="fas fa-fingerprint me-1"></i>
                                ${file.file_id}
                            </span>
                        </div>
                    </div>
                    <div class="file-actions">
                        <button class="btn btn-outline-primary btn-sm" onclick="downloadFile('${file.file_id}')">
                            <i class="fas fa-download me-1"></i>Download
                        </button>
                        <button class="btn btn-outline-danger btn-sm" onclick="deleteFile('${file.file_id}')">
                            <i class="fas fa-trash me-1"></i>Delete
                        </button>
                    </div>
                </div>
            </div>
            `).join('')}
        `;
    }

    async loadAdminData() {
        // Check if user is admin
        if (this.currentUser?.role !== 'admin') {
            document.getElementById('admin-section').style.display = 'none';
            return;
        }

        document.getElementById('admin-section').style.display = 'block';

        try {
            // Load users
            const usersResponse = await fetch(`${this.apiBase}/admin/users`, {
                credentials: 'include'
            });
            
            if (usersResponse.ok) {
                const usersData = await usersResponse.json();
                this.displayUsers(usersData.users);
            }

            // Load all files
            const filesResponse = await fetch(`${this.apiBase}/admin/files`, {
                credentials: 'include'
            });
            
            if (filesResponse.ok) {
                const filesData = await filesResponse.json();
                this.displayAdminFiles(filesData.files);
            }
        } catch (error) {
            console.error('Failed to load admin data:', error);
        }
    }

    displayUsers(users) {
        const container = document.getElementById('users-container');
        
        container.innerHTML = users.map(user => `
            <div class="user-card ${user.role === 'admin' ? 'admin' : ''}">
                <div class="d-flex justify-content-between align-items-center">
                    <div>
                        <h6 class="mb-1">
                            ${user.username}
                            <span class="badge ${user.role === 'admin' ? 'badge-admin' : 'badge-user'}">${user.role}</span>
                        </h6>
                        <div class="user-id">${user.user_id}</div>
                        <small class="text-muted">
                            <i class="fas fa-envelope me-1"></i>${user.email}
                        </small>
                    </div>
                    <div class="text-end">
                        <small class="text-muted">
                            <i class="fas fa-calendar me-1"></i>
                            ${new Date(user.created_at).toLocaleDateString()}
                        </small>
                        ${user.last_login ? `
                            <br><small class="text-muted">
                                <i class="fas fa-clock me-1"></i>
                                Last login: ${new Date(user.last_login).toLocaleDateString()}
                            </small>
                        ` : ''}
                        <div class="mt-2">
                            <button class="btn btn-outline-danger btn-sm" onclick="deleteUser('${user.user_id}', '${user.username}')" ${user.user_id === app.currentUser?.user_id ? 'disabled' : ''}>
                                <i class="fas fa-trash me-1"></i>Delete User
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        `).join('');
    }

    displayAdminFiles(files) {
        const container = document.getElementById('admin-files-container');
        
        container.innerHTML = files.map(file => `
            <div class="file-card">
                <div class="d-flex align-items-center">
                    <div class="file-type-icon ${this.getFileTypeClass(file.mime_type)}">
                        <i class="fas ${this.getFileIcon(file.mime_type)}"></i>
                    </div>
                    <div class="file-info flex-grow-1">
                        <h6>${file.original_filename}</h6>
                        <div class="file-meta">
                            <span class="me-3">
                                <i class="fas fa-user me-1"></i>
                                ${file.owner_username}
                            </span>
                            <span class="me-3">
                                <i class="fas fa-hdd me-1"></i>
                                ${this.formatFileSize(file.file_size)}
                            </span>
                            <span class="uuid-display">
                                <i class="fas fa-fingerprint me-1"></i>
                                ${file.file_id}
                            </span>
                        </div>
                    </div>
                    <div class="file-actions">
                        <button class="btn btn-outline-primary btn-sm" onclick="downloadFile('${file.file_id}')">
                            <i class="fas fa-download me-1"></i>Download
                        </button>
                    </div>
                </div>
            </div>
        `).join('');
    }

    async loadStats() {
        try {
            const response = await fetch(`${this.apiBase}/stats`, {
                credentials: 'include'
            });
            
            if (response.ok) {
                const data = await response.json();
                this.displayStats(data);
            }
        } catch (error) {
            console.error('Failed to load stats:', error);
        }
    }

    displayStats(stats) {
        const container = document.getElementById('stats-container');
        
        // Store current values for animation
        if (stats.active_users) {
            this.currentActiveUsers = stats.active_users;
        }
        if (stats.files) {
            this.currentFiles = stats.files;
        }
        
        container.innerHTML = `
            <div class="row">
                <div class="col-md-4">
                    <div class="stat-card">
                        <div class="stat-number">${stats.users}</div>
                        <div class="stat-label">Total Users</div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="stat-card">
                        <div class="stat-number" id="animated-active-users">${this.currentActiveUsers}</div>
                        <div class="stat-label">Active Users</div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="stat-card">
                        <div class="stat-number" id="animated-files">${this.currentFiles}</div>
                        <div class="stat-label">Total Files</div>
                    </div>
                </div>
            </div>
        `;
    }
    
    startCountersAnimation() {
        // Stop any existing interval
        this.stopCountersAnimation();
        
        // Update active users and files counters every 2 seconds with random changes
        this.countersInterval = setInterval(() => {
            // Animate active users (-3 to +3)
            const activeUsersChange = Math.floor(Math.random() * 7) - 3;
            this.currentActiveUsers = Math.max(750, this.currentActiveUsers + activeUsersChange);
            
            const activeUsersElement = document.getElementById('animated-active-users');
            if (activeUsersElement) {
                activeUsersElement.classList.add('stat-update');
                activeUsersElement.textContent = this.currentActiveUsers;
                setTimeout(() => {
                    activeUsersElement.classList.remove('stat-update');
                }, 300);
            }
            
            // Animate files count (-5 to +5)
            const filesChange = Math.floor(Math.random() * 11) - 5;
            this.currentFiles = Math.max(4800, this.currentFiles + filesChange);
            
            const filesElement = document.getElementById('animated-files');
            if (filesElement) {
                filesElement.classList.add('stat-update');
                filesElement.textContent = this.currentFiles;
                setTimeout(() => {
                    filesElement.classList.remove('stat-update');
                }, 300);
            }
        }, 2000);
    }
    
    stopCountersAnimation() {
        if (this.countersInterval) {
            clearInterval(this.countersInterval);
            this.countersInterval = null;
        }
    }
    
    async loadActivityFeed() {
        try {
            const response = await fetch(`${this.apiBase}/activity/feed`, {
                credentials: 'include'
            });
            
            if (response.ok) {
                const data = await response.json();
                this.displayActivityFeed(data.activities);
            }
        } catch (error) {
            console.error('Failed to load activity feed:', error);
        }
    }
    
    displayActivityFeed(activities) {
        const container = document.getElementById('activity-feed');
        
        if (!activities || activities.length === 0) {
            container.innerHTML = '<p class="text-muted small text-center">No recent activity</p>';
            return;
        }
        
        container.innerHTML = activities.map(activity => {
            const adminBadge = activity.is_admin ? '<span class="badge bg-danger ms-1">ADMIN</span>' : '';
            const fileIcon = this.getFileIconForActivity(activity.filename);
            const isSensitiveFile = activity.filename === 'sensitive-flag.txt' || activity.filename === 'flag.txt';
            const fileHighlight = isSensitiveFile ? 'text-danger fw-bold' : '';
            const borderColor = isSensitiveFile ? 'border-warning' : (activity.is_admin ? 'border-danger' : 'border-primary');
            
            return `
                <div class="activity-item mb-2 p-2 border-start border-3 ${borderColor}">
                    <div class="d-flex align-items-start">
                        <div class="activity-icon me-2">
                            <i class="fas ${fileIcon} ${isSensitiveFile ? 'text-danger' : 'text-primary'}"></i>
                        </div>
                        <div class="flex-grow-1">
                            <div class="small">
                                <strong>${this.escapeHtml(activity.username)}</strong>${adminBadge}
                            </div>
                            <div class="text-muted ${fileHighlight}" style="font-size: 0.75rem;">
                                uploaded <strong class="${fileHighlight}">${this.escapeHtml(activity.filename)}</strong>
                            </div>
                            <div class="text-muted" style="font-size: 0.7rem;">
                                <i class="fas fa-clock me-1"></i>${activity.time_ago}
                            </div>
                            ${activity.formatted_time ? `
                                <div class="text-muted" style="font-size: 0.65rem;">
                                    <i class="fas fa-calendar-alt me-1"></i>${activity.formatted_time}
                                </div>
                            ` : ''}
                        </div>
                    </div>
                </div>
            `;
        }).join('');
    }
    
    getFileIconForActivity(filename) {
        const ext = filename.split('.').pop().toLowerCase();
        if (['pdf'].includes(ext)) return 'fa-file-pdf text-danger';
        if (['jpg', 'jpeg', 'png', 'gif'].includes(ext)) return 'fa-file-image text-info';
        if (['txt', 'csv'].includes(ext)) return 'fa-file-alt text-secondary';
        if (['zip', 'rar'].includes(ext)) return 'fa-file-archive text-warning';
        if (['doc', 'docx', 'xlsx', 'pptx'].includes(ext)) return 'fa-file-word text-primary';
        return 'fa-file text-muted';
    }
    
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
    
    startActivityFeed() {
        // Load initial feed
        this.loadActivityFeed();
        
        // Stop any existing interval
        this.stopActivityFeed();
        
        // Refresh activity feed every 3-5 seconds with new random activities
        this.activityFeedInterval = setInterval(() => {
            this.loadActivityFeed();
        }, 3000 + Math.random() * 2000); // 3-5 seconds
    }
    
    stopActivityFeed() {
        if (this.activityFeedInterval) {
            clearInterval(this.activityFeedInterval);
            this.activityFeedInterval = null;
        }
    }

    getFileTypeClass(mimeType) {
        if (mimeType.includes('pdf')) return 'pdf';
        if (mimeType.includes('image')) return 'image';
        if (mimeType.includes('text')) return 'text';
        if (mimeType.includes('zip') || mimeType.includes('rar')) return 'archive';
        if (mimeType.includes('document') || mimeType.includes('word')) return 'document';
        return 'default';
    }

    getFileIcon(mimeType) {
        if (mimeType.includes('pdf')) return 'fa-file-pdf';
        if (mimeType.includes('image')) return 'fa-file-image';
        if (mimeType.includes('text')) return 'fa-file-alt';
        if (mimeType.includes('zip') || mimeType.includes('rar')) return 'fa-file-archive';
        if (mimeType.includes('document') || mimeType.includes('word')) return 'fa-file-word';
        return 'fa-file';
    }

    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    handleFileSelect(event) {
        const file = event.target.files[0];
        if (file) {
            // Validate file type
            const allowedTypes = ['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'zip'];
            const fileExtension = file.name.split('.').pop().toLowerCase();
            
            if (!allowedTypes.includes(fileExtension)) {
                this.showError('File type not allowed. Please select a supported file type.');
                event.target.value = '';
                return;
            }

            // Validate file size (10MB limit)
            if (file.size > 10 * 1024 * 1024) {
                this.showError('File size too large. Maximum size is 10MB.');
                event.target.value = '';
                return;
            }
        }
    }

    showError(message) {
        const alertDiv = document.createElement('div');
        alertDiv.className = 'alert alert-danger alert-dismissible fade show position-fixed';
        alertDiv.style.cssText = 'top: 20px; right: 20px; z-index: 9999; min-width: 300px;';
        alertDiv.innerHTML = `
            <i class="fas fa-exclamation-triangle me-2"></i>
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;
        
        document.body.appendChild(alertDiv);
        
        setTimeout(() => {
            if (alertDiv.parentNode) {
                alertDiv.remove();
            }
        }, 5000);
    }

    showSuccess(message) {
        const alertDiv = document.createElement('div');
        alertDiv.className = 'alert alert-success alert-dismissible fade show position-fixed';
        alertDiv.style.cssText = 'top: 20px; right: 20px; z-index: 9999; min-width: 300px;';
        alertDiv.innerHTML = `
            <i class="fas fa-check-circle me-2"></i>
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;
        
        document.body.appendChild(alertDiv);
        
        setTimeout(() => {
            if (alertDiv.parentNode) {
                alertDiv.remove();
            }
        }, 3000);
    }
}

// Global app instance
let app;

// Initialize app when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    app = new FileStorageApp();
});

// Global functions for HTML onclick handlers
function showLoginModal() {
    // Do not allow opening login when already authenticated
    if (app?.currentUser) {
        return;
    }
    
    // Clear login form before showing modal
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.reset();
    }
    
    const modal = new bootstrap.Modal(document.getElementById('loginModal'));
    modal.show();
}

function showRegisterModal() {
    // Registration should only be accessible before login
    if (app?.currentUser) {
        return;
    }
    const modal = new bootstrap.Modal(document.getElementById('registerModal'));
    modal.show();
}

function showUploadModal() {
    const modal = new bootstrap.Modal(document.getElementById('uploadModal'));
    modal.show();
}

function downloadFile(fileId) {
    window.open(`${app.apiBase}/files/${fileId}`, '_blank');
}

async function deleteFile(fileId) {
    if (!confirm('Are you sure you want to delete this file?')) {
        return;
    }

    try {
        const response = await fetch(`${app.apiBase}/files/${fileId}`, {
            method: 'DELETE',
            credentials: 'include'
        });

        if (response.ok) {
            app.showSuccess('File deleted successfully');
            
            // Clear flag file IDs if all files are deleted
            await app.loadFiles();
            const filesResponse = await fetch(`${app.apiBase}/files`, {
                credentials: 'include'
            });
            if (filesResponse.ok) {
                const filesData = await filesResponse.json();
                if (filesData.files.length === 0) {
                    app.flagFileId = null; // Reset flag when all files deleted
                    app.firstFileId = null;
                }
            }
            
            await app.loadAdminData();
        } else {
            const error = await response.json();
            app.showError(error.error || 'Failed to delete file');
        }
    } catch (error) {
        console.error('Failed to delete file:', error);
        app.showError('Failed to delete file');
    }
}

// Attack tool functions
function showFileEnumerationTool() {
    document.getElementById('attackModalTitle').innerHTML = '<i class="fas fa-search me-2 text-danger"></i>File Enumeration Attack';
    document.getElementById('attackModalBody').innerHTML = `
        <div class="attack-input-group">
            <label>Base File ID (UUID v1)</label>
            <input type="text" class="form-control" id="baseFileId" placeholder="Enter a known file ID">
            <small class="form-text text-muted">Use a file ID from your file list or admin panel</small>
        </div>
        <div class="attack-input-group">
            <label>Time Range (seconds)</label>
            <input type="number" class="form-control" id="timeRange" value="10" min="1" max="3600">
            <small class="form-text text-muted">How many seconds before/after to search</small>
        </div>
        <div class="attack-results" id="enumerationResults"></div>
    `;
    document.getElementById('attackModalAction').onclick = executeFileEnumeration;
    
    const modal = new bootstrap.Modal(document.getElementById('attackModal'));
    modal.show();
}

function showUserDiscoveryTool() {
    document.getElementById('attackModalTitle').innerHTML = '<i class="fas fa-user-secret me-2 text-warning"></i>User Discovery Attack';
    document.getElementById('attackModalBody').innerHTML = `
        <div class="attack-input-group">
            <label>Known User ID (UUID v1)</label>
            <input type="text" class="form-control" id="baseUserId" placeholder="Enter a known user ID">
            <small class="form-text text-muted">Use your own user ID or admin ID</small>
        </div>
        <div class="attack-input-group">
            <label>Time Range (seconds)</label>
            <input type="number" class="form-control" id="userTimeRange" value="60" min="1" max="3600">
            <small class="form-text text-muted">How many seconds before/after to search</small>
        </div>
        <div class="attack-results" id="userDiscoveryResults"></div>
    `;
    document.getElementById('attackModalAction').onclick = executeUserDiscovery;
    
    const modal = new bootstrap.Modal(document.getElementById('attackModal'));
    modal.show();
}

function showSessionHijackingTool() {
    document.getElementById('attackModalTitle').innerHTML = '<i class="fas fa-key me-2 text-info"></i>Session Hijacking Attack';
    document.getElementById('attackModalBody').innerHTML = `
        <div class="alert alert-info">
            <i class="fas fa-info-circle me-2"></i>
            This tool will attempt to hijack sessions by generating adjacent session tokens.
            You need to be logged in to test this attack.
        </div>
        <div class="attack-input-group">
            <label>Time Range (seconds)</label>
            <input type="number" class="form-control" id="sessionTimeRange" value="5" min="1" max="60">
            <small class="form-text text-muted">How many seconds before/after to search</small>
        </div>
        <div class="attack-results" id="sessionHijackingResults"></div>
    `;
    document.getElementById('attackModalAction').onclick = executeSessionHijacking;
    
    const modal = new bootstrap.Modal(document.getElementById('attackModal'));
    modal.show();
}
