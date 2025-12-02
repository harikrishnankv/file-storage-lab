// File Storage Lab - File Management Logic

// Additional file management functions can be added here
// Currently, most file operations are handled in app.js and auth.js

// Utility function to format file sizes
function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];
    
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

// Utility function to get file type from MIME type
function getFileTypeFromMime(mimeType) {
    const mimeMap = {
        'application/pdf': 'PDF Document',
        'image/jpeg': 'JPEG Image',
        'image/png': 'PNG Image',
        'image/gif': 'GIF Image',
        'text/plain': 'Text File',
        'application/zip': 'ZIP Archive',
        'application/msword': 'Word Document',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'Word Document'
    };
    
    return mimeMap[mimeType] || 'Unknown File Type';
}

// Utility function to validate file before upload
function validateFile(file) {
    const errors = [];
    
    // Check file size (10MB limit)
    if (file.size > 10 * 1024 * 1024) {
        errors.push('File size must be less than 10MB');
    }
    
    // Check file type
    const allowedTypes = ['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'zip'];
    const fileExtension = file.name.split('.').pop().toLowerCase();
    
    if (!allowedTypes.includes(fileExtension)) {
        errors.push(`File type .${fileExtension} is not allowed`);
    }
    
    // Check filename
    if (file.name.length > 255) {
        errors.push('Filename is too long (max 255 characters)');
    }
    
    return errors;
}

// Function to show file preview (for images)
function showFilePreview(fileId, mimeType) {
    if (!mimeType.startsWith('image/')) {
        return;
    }
    
    // Create preview modal
    const modalHtml = `
        <div class="modal fade" id="previewModal" tabindex="-1">
            <div class="modal-dialog modal-lg">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">File Preview</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body text-center">
                        <img src="${app.apiBase}/files/${fileId}" class="img-fluid" alt="File preview">
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                        <button type="button" class="btn btn-primary" onclick="downloadFile('${fileId}')">
                            <i class="fas fa-download me-1"></i>Download
                        </button>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    // Remove existing preview modal if any
    const existingModal = document.getElementById('previewModal');
    if (existingModal) {
        existingModal.remove();
    }
    
    // Add new modal to DOM
    document.body.insertAdjacentHTML('beforeend', modalHtml);
    
    // Show modal
    const modal = new bootstrap.Modal(document.getElementById('previewModal'));
    modal.show();
}

// Function to copy UUID to clipboard
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        app.showSuccess('Copied to clipboard');
    }).catch(err => {
        console.error('Failed to copy: ', err);
        app.showError('Failed to copy to clipboard');
    });
}

// Function to generate UUID v1 for testing
function generateTestUUID() {
    // This is a simplified UUID v1 generator for demonstration
    // In a real attack, you would use proper UUID v1 generation
    const now = Date.now();
    const timestamp = Math.floor(now / 1000) * 10000000 + 122192928000000000; // Convert to UUID v1 timestamp
    const timestampHex = timestamp.toString(16).padStart(12, '0');
    
    // Generate random node ID (MAC address simulation)
    const nodeId = Array.from({length: 6}, () => Math.floor(Math.random() * 256).toString(16).padStart(2, '0')).join('');
    
    // Generate random clock sequence
    const clockSeq = Math.floor(Math.random() * 4096).toString(16).padStart(3, '0');
    
    // Construct UUID v1
    const uuid = `${timestampHex.slice(0,8)}-${timestampHex.slice(8,12)}-1${clockSeq}-${nodeId.slice(0,4)}-${nodeId.slice(4)}`;
    
    return uuid;
}

// Function to parse UUID v1 timestamp
function parseUUIDTimestamp(uuid) {
    try {
        const parts = uuid.split('-');
        if (parts.length !== 5) {
            throw new Error('Invalid UUID format');
        }
        
        const timestampHex = parts[0] + parts[1] + parts[2];
        const timestamp = parseInt(timestampHex, 16);
        
        // Convert UUID v1 timestamp to JavaScript timestamp
        const jsTimestamp = (timestamp - 122192928000000000) / 10000;
        
        return new Date(jsTimestamp);
    } catch (error) {
        console.error('Failed to parse UUID timestamp:', error);
        return null;
    }
}

// Function to generate adjacent UUIDs
function generateAdjacentUUIDs(baseUuid, count = 5, timeOffsetSeconds = 1) {
    try {
        const parts = baseUuid.split('-');
        if (parts.length !== 5) {
            throw new Error('Invalid UUID format');
        }
        
        const timestampHex = parts[0] + parts[1] + parts[2];
        const baseTimestamp = parseInt(timestampHex, 16);
        
        const adjacentUuids = [];
        
        for (let i = -count; i <= count; i++) {
            if (i === 0) continue; // Skip the base UUID
            
            const offsetTime = baseTimestamp + (i * timeOffsetSeconds * 10000000); // Convert to 100ns units
            const offsetTimeHex = offsetTime.toString(16).padStart(12, '0');
            
            const newUuid = `${offsetTimeHex.slice(0,8)}-${offsetTimeHex.slice(8,12)}-1${offsetTimeHex.slice(12,15)}-${parts[3]}-${parts[4]}`;
            adjacentUuids.push({
                uuid: newUuid,
                offset: i * timeOffsetSeconds,
                timestamp: parseUUIDTimestamp(newUuid)
            });
        }
        
        return adjacentUuids;
    } catch (error) {
        console.error('Failed to generate adjacent UUIDs:', error);
        return [];
    }
}

// Export functions for use in other modules
window.FileManager = {
    formatBytes,
    getFileTypeFromMime,
    validateFile,
    showFilePreview,
    copyToClipboard,
    generateTestUUID,
    parseUUIDTimestamp,
    generateAdjacentUUIDs
};
