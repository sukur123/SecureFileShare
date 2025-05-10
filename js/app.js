// DOM Elements
const themeSwitch = document.getElementById('theme-switch');
const tabButtons = document.querySelectorAll('.tab-btn');
const tabPanes = document.querySelectorAll('.tab-pane');
const statusMessage = document.getElementById('status-message');

// Encrypt elements
const encryptUploadArea = document.getElementById('encrypt-upload-area');
const encryptFileInput = document.getElementById('encrypt-file-input');
const encryptFileInfo = document.getElementById('encrypt-file-info');
const encryptFileName = document.getElementById('encrypt-file-name');
const encryptFileSize = document.getElementById('encrypt-file-size');
const encryptClearBtn = document.getElementById('encrypt-clear-btn');
const encryptPassword = document.getElementById('encrypt-password');
const encryptConfirmPassword = document.getElementById('encrypt-confirm-password');
const encryptBtn = document.getElementById('encrypt-btn');
const encryptProgressContainer = document.getElementById('encrypt-progress-container');
const encryptProgressBar = document.getElementById('encrypt-progress-bar');

// Decrypt elements
const decryptUploadArea = document.getElementById('decrypt-upload-area');
const decryptFileInput = document.getElementById('decrypt-file-input');
const decryptFileInfo = document.getElementById('decrypt-file-info');
const decryptFileName = document.getElementById('decrypt-file-name');
const decryptFileSize = document.getElementById('decrypt-file-size');
const decryptClearBtn = document.getElementById('decrypt-clear-btn');
const decryptPassword = document.getElementById('decrypt-password');
const decryptBtn = document.getElementById('decrypt-btn');
const decryptProgressContainer = document.getElementById('decrypt-progress-container');
const decryptProgressBar = document.getElementById('decrypt-progress-bar');

// Share elements
const shareUploadArea = document.getElementById('share-upload-area');
const shareFileInput = document.getElementById('share-file-input');
const sharedFilesList = document.getElementById('shared-files-list');
const noSharedFilesMessage = document.getElementById('no-shared-files-message');
const filesList = document.getElementById('files-list');
const noFilesMessage = document.getElementById('no-files-message');
const peerIdInput = document.getElementById('peer-id');
const customPeerIdInput = document.getElementById('custom-peer-id');
const createCustomIdBtn = document.getElementById('create-custom-id-btn');
const copyIdBtn = document.getElementById('copy-id-btn');
const connectPeerIdInput = document.getElementById('connect-peer-id');
const connectBtn = document.getElementById('connect-btn');
const connectionStatus = document.getElementById('connection-status');

// Variables to store file data
let encryptFile = null;
let decryptFile = null;

// PeerJS variables
let peer = null;
let connection = null;
let sharedFiles = [];
let availableFiles = [];

// Check for dark mode preference
if (localStorage.getItem('darkMode') === 'enabled' || 
    (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches && 
     localStorage.getItem('darkMode') !== 'disabled')) {
    document.body.classList.add('dark-mode');
    themeSwitch.checked = true;
}

// Event Listeners
themeSwitch.addEventListener('change', toggleTheme);
tabButtons.forEach(button => button.addEventListener('click', switchTab));

// File upload events
encryptFileInput.addEventListener('change', handleEncryptFileSelect);
decryptFileInput.addEventListener('change', handleDecryptFileSelect);

// Drag and drop for encrypt
encryptUploadArea.addEventListener('dragover', handleDragOver);
encryptUploadArea.addEventListener('dragleave', handleDragLeave);
encryptUploadArea.addEventListener('drop', handleEncryptFileDrop);
encryptUploadArea.addEventListener('click', () => encryptFileInput.click());

// Drag and drop for decrypt
decryptUploadArea.addEventListener('dragover', handleDragOver);
decryptUploadArea.addEventListener('dragleave', handleDragLeave);
decryptUploadArea.addEventListener('drop', handleDecryptFileDrop);
decryptUploadArea.addEventListener('click', () => decryptFileInput.click());

// Clear file buttons
encryptClearBtn.addEventListener('click', clearEncryptFile);
decryptClearBtn.addEventListener('click', clearDecryptFile);

// Password field events
encryptPassword.addEventListener('input', validateEncryptForm);
encryptConfirmPassword.addEventListener('input', validateEncryptForm);
decryptPassword.addEventListener('input', validateDecryptForm);

// Action buttons
encryptBtn.addEventListener('click', encryptAndDownload);
decryptBtn.addEventListener('click', decryptAndDownload);

// Share file upload events
shareFileInput.addEventListener('change', handleShareFileSelect);
shareUploadArea.addEventListener('dragover', handleDragOver);
shareUploadArea.addEventListener('dragleave', handleDragLeave);
shareUploadArea.addEventListener('drop', handleShareFileDrop);
shareUploadArea.addEventListener('click', () => shareFileInput.click());

// P2P connection events
copyIdBtn.addEventListener('click', copyPeerId);
connectBtn.addEventListener('click', connectToPeer);
createCustomIdBtn.addEventListener('click', createWithCustomId);

// Functions
function toggleTheme() {
    if (themeSwitch.checked) {
        document.body.classList.add('dark-mode');
        localStorage.setItem('darkMode', 'enabled');
    } else {
        document.body.classList.remove('dark-mode');
        localStorage.setItem('darkMode', 'disabled');
    }
}

function switchTab(e) {
    // Remove active class from all tabs
    tabButtons.forEach(button => button.classList.remove('active'));
    tabPanes.forEach(pane => pane.classList.remove('active'));
    
    // Add active class to clicked tab
    e.target.classList.add('active');
    
    // Activate corresponding tab pane
    const tabId = e.target.getAttribute('data-tab');
    document.getElementById(`${tabId}-tab`).classList.add('active');
    
    // Initialize PeerJS when the share tab is selected
    if (tabId === 'share') {
        initPeer();
    }
}

function handleDragOver(e) {
    e.preventDefault();
    e.stopPropagation();
    this.classList.add('drag-over');
}

function handleDragLeave(e) {
    e.preventDefault();
    e.stopPropagation();
    this.classList.remove('drag-over');
}

function handleEncryptFileDrop(e) {
    e.preventDefault();
    e.stopPropagation();
    this.classList.remove('drag-over');
    
    if (e.dataTransfer.files.length > 0) {
        encryptFile = e.dataTransfer.files[0];
        displayEncryptFileInfo();
        validateEncryptForm();
    }
}

function handleDecryptFileDrop(e) {
    e.preventDefault();
    e.stopPropagation();
    this.classList.remove('drag-over');
    
    if (e.dataTransfer.files.length > 0) {
        decryptFile = e.dataTransfer.files[0];
        displayDecryptFileInfo();
        validateDecryptForm();
    }
}

function handleShareFileDrop(e) {
    e.preventDefault();
    e.stopPropagation();
    this.classList.remove('drag-over');
    
    if (e.dataTransfer.files.length > 0) {
        addFilesToShare(Array.from(e.dataTransfer.files));
    }
}

function handleEncryptFileSelect(e) {
    if (e.target.files.length > 0) {
        encryptFile = e.target.files[0];
        displayEncryptFileInfo();
        validateEncryptForm();
    }
}

function handleDecryptFileSelect(e) {
    if (e.target.files.length > 0) {
        decryptFile = e.target.files[0];
        displayDecryptFileInfo();
        validateDecryptForm();
    }
}

function handleShareFileSelect(e) {
    if (e.target.files.length > 0) {
        addFilesToShare(Array.from(e.target.files));
    }
}

function displayEncryptFileInfo() {
    encryptFileName.textContent = encryptFile.name;
    encryptFileSize.textContent = formatFileSize(encryptFile.size);
    encryptFileInfo.style.display = 'flex';
    encryptUploadArea.style.display = 'none';
}

function displayDecryptFileInfo() {
    decryptFileName.textContent = decryptFile.name;
    decryptFileSize.textContent = formatFileSize(decryptFile.size);
    decryptFileInfo.style.display = 'flex';
    decryptUploadArea.style.display = 'none';
}

function clearEncryptFile() {
    encryptFile = null;
    encryptFileInput.value = '';
    encryptFileInfo.style.display = 'none';
    encryptUploadArea.style.display = 'block';
    validateEncryptForm();
}

function clearDecryptFile() {
    decryptFile = null;
    decryptFileInput.value = '';
    decryptFileInfo.style.display = 'none';
    decryptUploadArea.style.display = 'block';
    validateDecryptForm();
}

function validateEncryptForm() {
    const password = encryptPassword.value;
    const confirmPassword = encryptConfirmPassword.value;
    
    if (encryptFile && password && confirmPassword && password === confirmPassword) {
        encryptBtn.disabled = false;
    } else {
        encryptBtn.disabled = true;
    }
}

function validateDecryptForm() {
    if (decryptFile && decryptPassword.value) {
        decryptBtn.disabled = false;
    } else {
        decryptBtn.disabled = true;
    }
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function showStatus(message, type) {
    statusMessage.textContent = message;
    statusMessage.className = '';
    statusMessage.classList.add(type);
    
    setTimeout(() => {
        statusMessage.className = '';
    }, 5000);
}

function updateProgress(progressBar, percentage) {
    progressBar.style.width = `${percentage}%`;
}

// Function to generate a random salt
function generateSalt() {
    // Create a 16-byte random salt (32 characters in hex)
    const array = new Uint8Array(16);
    window.crypto.getRandomValues(array);
    return array;
}

// Function to derive a key from password using PBKDF2
async function deriveKey(password, salt) {
    const encoder = new TextEncoder();
    const passwordData = encoder.encode(password);
    
    // Import the password as a key
    const passwordKey = await window.crypto.subtle.importKey(
        'raw',
        passwordData,
        { name: 'PBKDF2' },
        false,
        ['deriveKey']
    );
    
    // Derive a key from the password
    const aesKey = await window.crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: 100000,
            hash: 'SHA-256'
        },
        passwordKey,
        {
            name: 'AES-GCM',
            length: 256
        },
        true,
        ['encrypt', 'decrypt']
    );
    
    return aesKey;
}

// Function to encrypt a file
async function encryptFileData(file, password) {
    try {
        encryptProgressContainer.style.display = 'block';
        updateProgress(encryptProgressBar, 10);
        
        // Generate a random salt and IV
        const salt = generateSalt();
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const key = await deriveKey(password, salt);
        
        updateProgress(encryptProgressBar, 20);
        
        // Read the file
        const fileData = await readFile(file);
        updateProgress(encryptProgressBar, 50);
        
        // Encrypt the file data
        const encryptedData = await window.crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: iv
            },
            key,
            fileData
        );
        
        updateProgress(encryptProgressBar, 80);
        
        // Create a header with metadata
        const header = new Uint8Array([
            ...new TextEncoder().encode('SECFS'), // Magic identifier (5 bytes)
            ...salt,                              // Salt (16 bytes)
            ...iv                                 // IV (12 bytes)
        ]);
        
        // Combine header and encrypted data
        const encryptedFile = new Blob([header, encryptedData], { type: 'application/octet-stream' });
        
        updateProgress(encryptProgressBar, 100);
        
        return encryptedFile;
    } catch (error) {
        console.error('Encryption error:', error);
        throw error;
    }
}

// Function to decrypt a file
async function decryptFileData(file, password) {
    try {
        decryptProgressContainer.style.display = 'block';
        updateProgress(decryptProgressBar, 10);
        
        // Read the file
        const fileData = await readFile(file);
        updateProgress(decryptProgressBar, 30);
        
        // Extract the header information
        const headerBytes = new Uint8Array(fileData.slice(0, 33)); // 5 (magic) + 16 (salt) + 12 (iv)
        
        // Validate the magic identifier
        const magicBytes = headerBytes.slice(0, 5);
        const magic = new TextDecoder().decode(magicBytes);
        
        if (magic !== 'SECFS') {
            throw new Error('Invalid file format');
        }
        
        // Extract salt and iv
        const salt = headerBytes.slice(5, 21);  // 16 bytes of salt
        const iv = headerBytes.slice(21, 33);   // 12 bytes of iv
        
        // Derive the key from the password and salt
        const key = await deriveKey(password, salt);
        updateProgress(decryptProgressBar, 50);
        
        // Decrypt the data
        const encryptedData = fileData.slice(33);
        const decryptedData = await window.crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: iv
            },
            key,
            encryptedData
        );
        
        updateProgress(decryptProgressBar, 90);
        
        // Get the original file extension
        let fileName = file.name;
        if (fileName.endsWith('.encrypted')) {
            fileName = fileName.substring(0, fileName.length - 10);
        }
        
        // Create a blob from the decrypted data
        const decryptedFile = new Blob([decryptedData], { type: 'application/octet-stream' });
        updateProgress(decryptProgressBar, 100);
        
        return { file: decryptedFile, name: fileName };
    } catch (error) {
        console.error('Decryption error:', error);
        throw error;
    }
}

// Function to read a file as ArrayBuffer
function readFile(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        
        reader.onload = () => {
            resolve(reader.result);
        };
        
        reader.onerror = () => {
            reject(new Error('Error reading file'));
        };
        
        reader.readAsArrayBuffer(file);
    });
}

// Function to download a file
function downloadFile(blob, fileName) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = fileName;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

// Function to handle errors more descriptively
function handleError(error, operation) {
    console.error(`${operation} error:`, error);
    
    let errorMessage = error.message;
    
    // Provide more user-friendly error messages
    if (error.name === 'SecurityError') {
        errorMessage = 'Security error: This app must be served over HTTPS or from localhost for encryption features to work.';
    } else if (error.name === 'NotAllowedError') {
        errorMessage = 'Access denied: The operation is not allowed in this context.';
    } else if (error.message.includes('Forbidden')) {
        errorMessage = 'Access forbidden: You may need to open this app differently. Try opening the HTML file directly in your browser.';
    }
    
    showStatus(`${operation} failed: ${errorMessage}`, 'error');
    return error;
}

// Function to encrypt and download
async function encryptAndDownload() {
    if (!encryptFile || !encryptPassword.value) return;
    
    try {
        const encryptedFile = await encryptFileData(encryptFile, encryptPassword.value);
        
        // Create a filename for the encrypted file
        const originalName = encryptFile.name;
        const encryptedName = `${originalName}.encrypted`;
        
        // Download the encrypted file
        downloadFile(encryptedFile, encryptedName);
        
        // Show success message
        showStatus('File encrypted and downloaded successfully!', 'success');
        
        // Clear form after successful encryption
        clearEncryptFile();
        encryptPassword.value = '';
        encryptConfirmPassword.value = '';
        encryptBtn.disabled = true;
    } catch (error) {
        handleError(error, 'Encryption');
    } finally {
        encryptProgressContainer.style.display = 'none';
        encryptProgressBar.style.width = '0';
    }
}

// Function to decrypt and download
async function decryptAndDownload() {
    if (!decryptFile || !decryptPassword.value) return;
    
    try {
        const { file, name } = await decryptFileData(decryptFile, decryptPassword.value);
        
        // Download the decrypted file
        downloadFile(file, name);
        
        // Show success message
        showStatus('File decrypted and downloaded successfully!', 'success');
        
        // Clear form after successful decryption
        clearDecryptFile();
        decryptPassword.value = '';
        decryptBtn.disabled = true;
    } catch (error) {
        handleError(error, 'Decryption');
    } finally {
        decryptProgressContainer.style.display = 'none';
        decryptProgressBar.style.width = '0';
    }
}

// Initialize PeerJS
function initPeer() {
    // Only initialize PeerJS when the share tab is active
    if (!peer) {
        try {
            console.log("Initializing PeerJS connection...");
            // Generate a random ID for this peer
            const randomId = Math.random().toString(36).substring(2, 15) + 
                             Math.random().toString(36).substring(2, 15);
            
            // First, try using our preferred server
            initPeerWithServer(randomId, {
                host: 'peerjs.cloudaccess4all.com',
                port: 443,
                secure: true,
                debug: 3
            }, () => {
                // If that fails, try the default PeerJS server as fallback
                console.log("Trying fallback PeerJS server...");
                initPeerWithServer(randomId, {
                    // The default PeerJS server
                    host: '0.peerjs.com',
                    port: 443,
                    secure: true,
                    debug: 3
                }, () => {
                    // If both fail, try connecting without a specific server (using the default)
                    console.log("Trying connection without specific server...");
                    initPeerWithServer(randomId, {
                        debug: 3
                    }, () => {
                        // All connection attempts failed
                        showStatus('Failed to connect to any PeerJS server. Please try again later.', 'error');
                    });
                });
            });
        } catch (error) {
            console.error('Failed to initialize PeerJS:', error);
            handleError(error, 'Connection');
        }
    }
}

// Helper function to initialize PeerJS with a specific server configuration
function initPeerWithServer(id, options, onError) {
    try {
        // Show connecting status
        updateConnectionStatus('Connecting to server...', 'connecting');
        
        // Add common STUN servers to help with NAT traversal
        if (!options.config) {
            options.config = {
                'iceServers': [
                    { urls: 'stun:stun.l.google.com:19302' },
                    { urls: 'stun:stun1.l.google.com:19302' },
                    { urls: 'stun:stun2.l.google.com:19302' },
                    { urls: 'stun:stun3.l.google.com:19302' }
                ]
            };
        }
        
        // Create the Peer instance
        peer = new Peer(id, options);
        
        // Set a timeout for connection
        const connectionTimeout = setTimeout(() => {
            if (peerIdInput.value === '') {
                console.log("Connection timeout");
                if (peer) {
                    peer.destroy();
                    peer = null;
                }
                if (typeof onError === 'function') onError();
            }
        }, 10000); // 10 second timeout
        
        // Update UI with peer ID once connected to the PeerJS server
        peer.on('open', (id) => {
            clearTimeout(connectionTimeout);
            console.log("PeerJS connection established with ID:", id);
            peerIdInput.value = id;
            updateConnectionStatus('Ready to connect', 'disconnected');
            showStatus('Share ID generated successfully. You can now share files with other devices.', 'success');
        });
        
        // Handle incoming connections
        peer.on('connection', (conn) => {
            console.log("Incoming connection from:", conn.peer);
            handleConnection(conn);
        });
        
        // Handle errors
        peer.on('error', (err) => {
            console.error('PeerJS error:', err);
            
            // Handle specific error types
            if (err.type === 'peer-unavailable') {
                showStatus('Connection failed: The Share ID you entered could not be found.', 'error');
            } else if (err.type === 'network' || err.type === 'server-error') {
                showStatus('Connection error: Network or server issue. Please try again.', 'error');
                
                // If it's a server error, try the fallback
                if (typeof onError === 'function') {
                    if (peer) {
                        peer.destroy();
                        peer = null;
                    }
                    onError();
                }
            } else {
                handleError(err, 'Connection');
            }
            
            updateConnectionStatus('Connection error', 'disconnected');
        });
    } catch (error) {
        console.error('Failed to initialize PeerJS with server:', options, error);
        if (typeof onError === 'function') onError();
    }
}

// Function to handle incoming connections
function handleConnection(conn) {
    // Close any existing connection
    if (connection) {
        connection.close();
    }
    
    connection = conn;
    updateConnectionStatus('Connected to: ' + connection.peer, 'connected');
    
    // Handle data received from the other peer
    connection.on('data', (data) => {
        if (data.type === 'file-list') {
            // Received a list of available files from the other peer
            availableFiles = data.files;
            updateAvailableFilesList();
        } else if (data.type === 'file-data') {
            // Received a file from the other peer
            receiveFile(data);
        } else if (data.type === 'file-request') {
            // The other peer is requesting a file
            sendRequestedFile(data.fileId);
        }
    });
    
    // Send our shared files list to the new connection
    sendFileList();
    
    // Handle connection close
    connection.on('close', () => {
        connection = null;
        availableFiles = [];
        updateAvailableFilesList();
        updateConnectionStatus('Disconnected', 'disconnected');
    });
    
    // Handle connection errors
    connection.on('error', (err) => {
        console.error('Connection error:', err);
        handleError(err, 'Connection');
    });
}

// Function to connect to another peer
function connectToPeer() {
    const peerId = connectPeerIdInput.value.trim();
    
    if (peerId === '') {
        showStatus('Please enter a valid Share ID', 'error');
        return;
    }
    
    try {
        updateConnectionStatus('Connecting...', 'connecting');
        
        // Connect to the remote peer
        const conn = peer.connect(peerId, {
            reliable: true
        });
        
        // Handle connection open
        conn.on('open', () => {
            handleConnection(conn);
        });
    } catch (error) {
        console.error('Connection error:', error);
        handleError(error, 'Connection');
        updateConnectionStatus('Connection failed', 'disconnected');
    }
}

// Function to copy the peer ID to clipboard
function copyPeerId() {
    peerIdInput.select();
    document.execCommand('copy');
    showStatus('Share ID copied to clipboard', 'success');
}

// Function to update the connection status
function updateConnectionStatus(message, state) {
    connectionStatus.textContent = message;
    connectionStatus.className = '';
    connectionStatus.classList.add(state);
}

// Function to add files to the shared files list
function addFilesToShare(files) {
    for (const file of files) {
        const fileId = Date.now() + '-' + Math.random().toString(36).substring(2, 9);
        
        sharedFiles.push({
            id: fileId,
            name: file.name,
            size: file.size,
            type: file.type,
            data: file
        });
    }
    
    updateSharedFilesList();
    
    // Send updated file list to connected peer
    if (connection) {
        sendFileList();
    }
}

// Function to update the shared files list UI
function updateSharedFilesList() {
    if (sharedFiles.length === 0) {
        noSharedFilesMessage.style.display = 'block';
        sharedFilesList.innerHTML = '';
        return;
    }
    
    noSharedFilesMessage.style.display = 'none';
    sharedFilesList.innerHTML = '';
    
    for (const file of sharedFiles) {
        const fileItem = document.createElement('div');
        fileItem.className = 'file-item';
        fileItem.innerHTML = `
            <div class="file-item-info">
                <div class="file-item-name">${file.name}</div>
                <div class="file-item-size">${formatFileSize(file.size)}</div>
            </div>
            <div class="file-item-actions">
                <button class="remove-btn" title="Remove from shared files">×</button>
            </div>
        `;
        
        // Add remove button event listener
        const removeBtn = fileItem.querySelector('.remove-btn');
        removeBtn.addEventListener('click', () => {
            sharedFiles = sharedFiles.filter(f => f.id !== file.id);
            updateSharedFilesList();
            
            // Send updated file list to connected peer
            if (connection) {
                sendFileList();
            }
        });
        
        sharedFilesList.appendChild(fileItem);
    }
}

// Function to update the available files list UI
function updateAvailableFilesList() {
    if (availableFiles.length === 0) {
        noFilesMessage.style.display = 'block';
        filesList.innerHTML = '';
        return;
    }
    
    noFilesMessage.style.display = 'none';
    filesList.innerHTML = '';
    
    for (const file of availableFiles) {
        const fileItem = document.createElement('div');
        fileItem.className = 'file-item';
        fileItem.innerHTML = `
            <div class="file-item-info">
                <div class="file-item-name">${file.name}</div>
                <div class="file-item-size">${formatFileSize(file.size)}</div>
            </div>
            <div class="file-item-actions">
                <button class="download-btn" title="Download file">
                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24"><path fill="none" d="M0 0h24v24H0z"/><path d="M19 9h-4V3H9v6H5l7 7 7-7zM5 18v2h14v-2H5z"/></svg>
                </button>
            </div>
        `;
        
        // Add download button event listener
        const downloadBtn = fileItem.querySelector('.download-btn');
        downloadBtn.addEventListener('click', () => {
            requestFile(file.id);
        });
        
        filesList.appendChild(fileItem);
    }
}

// Function to send the list of shared files to the connected peer
function sendFileList() {
    if (!connection) return;
    
    const fileList = sharedFiles.map(file => ({
        id: file.id,
        name: file.name,
        size: file.size,
        type: file.type
    }));
    
    connection.send({
        type: 'file-list',
        files: fileList
    });
}

// Function to request a file from the connected peer
function requestFile(fileId) {
    if (!connection) return;
    
    showStatus('Requesting file...', 'success');
    
    connection.send({
        type: 'file-request',
        fileId: fileId
    });
}

// Function to send a requested file to the connected peer
async function sendRequestedFile(fileId) {
    if (!connection) return;
    
    const file = sharedFiles.find(f => f.id === fileId);
    if (!file) return;
    
    showStatus('Sending file...', 'success');
    
    try {
        // Read the file data
        const fileData = await readFile(file.data);
        
        // Send file data to the connected peer
        connection.send({
            type: 'file-data',
            file: {
                id: file.id,
                name: file.name,
                size: file.size,
                type: file.type,
                data: fileData
            }
        });
        
        showStatus('File sent successfully', 'success');
    } catch (error) {
        console.error('Error sending file:', error);
        handleError(error, 'File sending');
    }
}

// Function to receive a file from the connected peer
function receiveFile(data) {
    const file = data.file;
    
    // Create a blob from the file data
    const blob = new Blob([file.data], { type: file.type || 'application/octet-stream' });
    
    // Download the file
    downloadFile(blob, file.name);
    
    showStatus('File received and downloaded', 'success');
}

// Function to create a connection with a custom ID
function createWithCustomId() {
    // Close any existing peer connection
    if (peer) {
        peer.destroy();
        peer = null;
    }
    
    // Get the custom ID
    const customId = customPeerIdInput.value.trim();
    
    if (customId === '') {
        showStatus('Please enter a custom Share ID', 'error');
        return;
    }
    
    // Check if the custom ID is valid
    if (!/^[a-zA-Z0-9_-]+$/.test(customId)) {
        showStatus('Custom Share ID must contain only letters, numbers, underscores, and hyphens', 'error');
        return;
    }
    
    try {
        // Show connecting status
        updateConnectionStatus('Creating custom Share ID...', 'connecting');
        
        // Try to connect with the custom ID
        const options = {
            host: 'peerjs.cloudaccess4all.com',
            port: 443,
            secure: true,
            debug: 3,
            config: {
                'iceServers': [
                    { urls: 'stun:stun.l.google.com:19302' },
                    { urls: 'stun:stun1.l.google.com:19302' },
                    { urls: 'stun:stun2.l.google.com:19302' },
                    { urls: 'stun:stun3.l.google.com:19302' }
                ]
            }
        };
        
        // Create the Peer instance with the custom ID
        peer = new Peer(customId, options);
        
        // Set a timeout for connection
        const connectionTimeout = setTimeout(() => {
            if (peerIdInput.value !== customId) {
                console.log("Custom ID connection timeout");
                if (peer) {
                    peer.destroy();
                    peer = null;
                }
                
                // Try again with a different server
                tryCustomIdWithFallbackServer(customId);
            }
        }, 8000); // 8 second timeout
        
        // Update UI with custom ID once connected
        peer.on('open', (id) => {
            clearTimeout(connectionTimeout);
            console.log("PeerJS connection established with custom ID:", id);
            peerIdInput.value = id;
            updateConnectionStatus('Ready to connect', 'disconnected');
            showStatus('Custom Share ID created successfully. You can now share files with other devices.', 'success');
        });
        
        // Handle incoming connections
        peer.on('connection', (conn) => {
            console.log("Incoming connection from:", conn.peer);
            handleConnection(conn);
        });
        
        // Handle errors
        peer.on('error', (err) => {
            console.error('PeerJS error with custom ID:', err);
            
            // Handle specific error types
            if (err.type === 'unavailable-id') {
                showStatus('Custom Share ID is already in use. Please try a different ID.', 'error');
                clearTimeout(connectionTimeout);
                if (peer) {
                    peer.destroy();
                    peer = null;
                }
                
                // Return to random ID mode
                initPeer();
            } else if (err.type === 'network' || err.type === 'server-error') {
                // If it's a server error, try the fallback
                clearTimeout(connectionTimeout);
                if (peer) {
                    peer.destroy();
                    peer = null;
                }
                
                // Try again with a different server
                tryCustomIdWithFallbackServer(customId);
            } else {
                handleError(err, 'Connection');
            }
        });
    } catch (error) {
        console.error('Failed to create connection with custom ID:', error);
        handleError(error, 'Connection');
        
        // Try again with a different server
        tryCustomIdWithFallbackServer(customId);
    }
}

// Helper function to try connecting with a custom ID using a fallback server
function tryCustomIdWithFallbackServer(customId) {
    try {
        updateConnectionStatus('Trying alternative server...', 'connecting');
        
        // Try the default PeerJS server as fallback
        const options = {
            host: '0.peerjs.com',
            port: 443,
            secure: true,
            debug: 3,
            config: {
                'iceServers': [
                    { urls: 'stun:stun.l.google.com:19302' },
                    { urls: 'stun:stun1.l.google.com:19302' }
                ]
            }
        };
        
        // Create the Peer instance with the custom ID
        peer = new Peer(customId, options);
        
        // Update UI with custom ID once connected
        peer.on('open', (id) => {
            console.log("PeerJS connection established with custom ID on fallback server:", id);
            peerIdInput.value = id;
            updateConnectionStatus('Ready to connect', 'disconnected');
            showStatus('Custom Share ID created successfully using alternative server.', 'success');
        });
        
        // Handle incoming connections
        peer.on('connection', (conn) => {
            console.log("Incoming connection from:", conn.peer);
            handleConnection(conn);
        });
        
        // Handle errors
        peer.on('error', (err) => {
            console.error('PeerJS error with custom ID on fallback server:', err);
            
            if (err.type === 'unavailable-id') {
                showStatus('Custom Share ID is already in use. Please try a different ID.', 'error');
                if (peer) {
                    peer.destroy();
                    peer = null;
                }
                
                // Return to random ID mode
                initPeer();
            } else {
                handleError(err, 'Connection');
                updateConnectionStatus('Connection error', 'disconnected');
                
                // Return to random ID mode
                if (peer) {
                    peer.destroy();
                    peer = null;
                }
                initPeer();
            }
        });
    } catch (error) {
        console.error('Failed to create connection with custom ID on fallback server:', error);
        handleError(error, 'Connection');
        
        // Return to random ID mode
        initPeer();
    }
}

// Event listener for tab switching to initialize peer connection when needed
tabButtons.forEach(button => {
    button.addEventListener('click', (e) => {
        if (e.target.getAttribute('data-tab') === 'share') {
            // Initialize PeerJS when the share tab is selected
            initPeer();
        }
    });
});