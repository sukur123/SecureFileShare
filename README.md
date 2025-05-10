# Secure FileShare

A client-side web application for securely encrypting, decrypting, and sharing files with end-to-end encryption. All cryptographic operations happen in your browser - no server involved.

## Features

### File Encryption & Decryption
- Upload and encrypt any file with AES-256 encryption
- Password-based encryption with PBKDF2 key derivation (100,000 iterations)
- Secure client-side decryption of previously encrypted files
- Support for files up to 100MB in size

### Secure Sharing
- Share encrypted files with other devices on the same network
- Peer-to-peer file transfer using WebRTC (no server storage)
- Custom Share IDs for easy reconnection
- Live status updates during file transfers

### User Experience
- Modern, responsive design that works on desktop and mobile
- Dark mode support with system preference detection
- Drag-and-drop file upload
- Progress indicators during encryption/decryption
- Success/error status messages

## Security Features

- **AES-256 Encryption**: Military-grade encryption for your files
- **Client-Side Only**: All operations happen in your browser, no data is sent to any server
- **No Storage**: Files are never stored on any server
- **End-to-End Encryption**: Only you and your recipient can access the decrypted files
- **WebRTC Security**: Peer connections are encrypted using DTLS

## How to Use

### Encrypting a File

1. Open the application in a modern web browser
2. Drag and drop a file onto the upload area or click to browse files
3. Enter a strong password and confirm it
4. Click "Encrypt & Download" to save the encrypted file
5. Share the encrypted file through any method you prefer

### Decrypting a File

1. Switch to the "Decrypt" tab
2. Upload an encrypted file
3. Enter the password used to encrypt the file
4. Click "Decrypt & Download" to retrieve the original file

### Sharing Files Directly

1. Switch to the "Share" tab
2. Optionally create a custom Share ID for easier reconnection
3. Share your ID with another user
4. Upload files to share
5. The other user can connect using your Share ID and download files directly

## Technical Details

- Uses the Web Crypto API for cryptographic operations
- Files are encrypted with AES-GCM which provides both confidentiality and integrity
- Encrypted files include metadata (salt and IV) in the header
- WebRTC for peer-to-peer connections via the PeerJS library
- Pure JavaScript, HTML, and CSS - no server-side components

## Installation

No installation required! Simply open the `index.html` file in a modern web browser.

For the best experience and to ensure all features work correctly:
- Use the latest version of Chrome, Firefox, Safari, or Edge
- Open the file directly using the `file://` protocol or serve it locally

## Browser Compatibility

Secure FileShare works on all modern browsers that support:
- Web Crypto API
- WebRTC
- File API

This includes:
- Chrome/Chromium 49+
- Firefox 42+
- Safari 11+
- Edge 79+

## Troubleshooting

### Connection Issues
- Ensure you're using a modern browser with WebRTC support
- Try using a different PeerJS server by creating a custom Share ID
- Check that both devices are on the same network or have public access

### Encryption/Decryption Issues
- Make sure you're entering the exact password used for encryption
- For security reasons, there's no way to recover a forgotten password
- If decryption fails with "Invalid file format," the file might be corrupted

## Privacy

Secure FileShare was designed with privacy in mind:
- No analytics or tracking
- No data collection
- No server storage
- All encryption/decryption happens locally in your browser

## License

MIT License

## Contributing

Contributions are welcome! Feel free to submit a pull request or open an issue for bugs and feature requests.

## Credits

Created by SukurBabaev
