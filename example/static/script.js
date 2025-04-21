// First, check if WebAuthn is supported and if we're in a secure context
if (!window.PublicKeyCredential) {
    alert("WebAuthn is not supported in this browser. Please try a newer browser.");
    document.getElementById('status').innerHTML = "<strong style='color:red'>Error:</strong> WebAuthn is not supported in this browser.";
} else if (!window.isSecureContext) {
    alert("WebAuthn requires a secure context (HTTPS or localhost). Your current context is not secure.");
    document.getElementById('status').innerHTML = "<strong style='color:red'>Error:</strong> Not in a secure context. WebAuthn requires HTTPS or localhost.";
}

// Helper functions for base64url encoding/decoding
function base64urlToBuffer(base64url) {
    // Convert base64url to base64 by replacing URL-safe chars and adding padding
    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    const paddingLength = (4 - (base64.length % 4)) % 4;
    const padded = base64 + '='.repeat(paddingLength);

    // Convert base64 to binary string
    const binary = atob(padded);

    // Convert binary string to buffer
    const buffer = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        buffer[i] = binary.charCodeAt(i);
    }
    return buffer;
}

function bufferToBase64url(buffer) {
    // Convert buffer to binary string
    let binary = '';
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }

    // Convert binary string to base64
    const base64 = btoa(binary);

    // Convert base64 to base64url
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

// Logging function
function log(message, isError = false) {
    const logEl = document.getElementById('log');
    logEl.textContent += message + '\n';
    logEl.scrollTop = logEl.scrollHeight;

    const statusEl = document.getElementById('status');
    statusEl.textContent = message;
    statusEl.className = isError ? 'status error' : 'status success';
}

// Registration
async function register() {
    try {
        log('Starting registration...');

        // Get username and email from input fields
        const username = document.getElementById('username').value;
        const email = document.getElementById('email').value;
        if (!username || !email || !email.includes('@')) {
            throw new Error('Username and email are required for registration.');
        }

        // Get registration options from server
        const optionsResponse = await fetch('/register/begin', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({username, email})
        });

        if (!optionsResponse.ok) {
            throw new Error(`Server error: ${optionsResponse.status}`);
        }

        const options = await optionsResponse.json();
        log('Received registration options from server');
        console.log('Raw options from server:', options);

        // Convert data for WebAuthn API
        const publicKey = {
            ...options,
            challenge: base64urlToBuffer(options.challenge),
            user: {
                ...options.user,
                id: base64urlToBuffer(options.user.id),
            }
        };

        console.log("Converted challenge for WebAuthn API:", publicKey.challenge);
        console.log("Converted publicKey object:", publicKey);

        // Create credentials
        log('Creating credential - please follow your browser/authenticator prompts');
        try {
            const credential = await navigator.credentials.create({
                publicKey
            });

            console.log("Raw credential response:", credential);

            // Prepare response for server
            const response = {
                id: credential.id,
                attestationObject: bufferToBase64url(credential.response.attestationObject),
                clientDataJSON: bufferToBase64url(credential.response.clientDataJSON)
            };


            console.log("Credential response created:", {
                id_type: typeof response.id,
                id_length: response.id.length,
                attestationObject_length: response.attestationObject.length,
                clientDataJSON_length: response.clientDataJSON.length
            });


            const decodedClientData = JSON.parse(new TextDecoder().decode(base64urlToBuffer(response.clientDataJSON)));
            console.log("Decoded clientDataJSON:", decodedClientData);

            log('Credential created. Sending to server...');

            // Send response to server
            const registerResponse = await fetch('/register/finish', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(response)
            });

            if (!registerResponse.ok) {
                const errorText = await registerResponse.text();
                throw new Error(`Registration failed: ${errorText}`);
            }

            const result = await registerResponse.json();
            log(`Registration successful! Authenticator: ${result.authenticatorName}`);

            // Show AAGUID and Name if available
            if (result.aaguid) {
                log(`AAGUID: ${result.aaguid} (Name: ${result.authenticatorName || 'N/A'})`);
                console.log("AAGUID:", result.aaguid, "Name:", result.authenticatorName);
            }
        } catch (credentialError) {
            if (credentialError.name === 'AbortError') {
                throw new Error('WebAuthn operation was aborted by the user or timed out');
            } else if (credentialError.name === 'NotAllowedError') {
                throw new Error('WebAuthn operation not allowed. This might be due to security restrictions, lack of user verification, or user cancellation');
            } else {
                throw credentialError;
            }
        }
    } catch (error) {
        log(`Error: ${error.message}`, true);
        console.error(error);
    }
}

// Login
async function login() {
    try {
        log('Starting login...');

        // Get email from input field
        const email = document.getElementById('email').value;
        if (!email) {
            throw new Error('Email is required for login.');
        }

        // Get login options from server
        const optionsResponse = await fetch('/login/begin', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({email: email}) // Send email
        });

        if (!optionsResponse.ok) {
            const errorText = await optionsResponse.text(); // Read error text
            throw new Error(`Server error getting login options: ${optionsResponse.status} - ${errorText}`);
        }

        const options = await optionsResponse.json();
        log('Received login options from server');
        console.log('Raw login options from server:', options);

        // Convert challenge and credential IDs for WebAuthn API
        const publicKey = {
            ...options,
            challenge: base64urlToBuffer(options.challenge),
            allowCredentials: options.allowCredentials?.map(credential => {
                console.log("Processing credential:", credential);
                return {
                    ...credential,
                    id: base64urlToBuffer(credential.id)
                };
            })
        };

        console.log("Converted challenge for login:", publicKey.challenge);
        console.log("Processed publicKey for login:", publicKey);

        // Get credentials
        log('Getting credential - please follow your browser/authenticator prompts');
        const credential = await navigator.credentials.get({
            publicKey
        });

        console.log("Raw login credential response:", credential);

        // Prepare response for server
        const response = {
            id: credential.id,
            authenticatorData: bufferToBase64url(credential.response.authenticatorData),
            clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
            signature: bufferToBase64url(credential.response.signature),
            userHandle: credential.response.userHandle ? bufferToBase64url(credential.response.userHandle) : null
        };

        // Debug ClientDataJSON for login
        const decodedLoginClientData = JSON.parse(new TextDecoder().decode(base64urlToBuffer(response.clientDataJSON)));
        console.log("Decoded login clientDataJSON:", decodedLoginClientData);

        log('Credential verified. Sending to server...');

        // Send response to server
        const loginResponse = await fetch('/login/finish', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(response)
        });

        if (!loginResponse.ok) {
            const errorText = await loginResponse.text();
            throw new Error(`Login failed: ${errorText}`);
        }

        const result = await loginResponse.json();
        log(`Login successful! Welcome, ${result.username}`);

    } catch (error) {
        log(`Error: ${error.message}`, true);
        console.error(error);
    }
}

// Event listeners
document.getElementById('register').addEventListener('click', register);
document.getElementById('login').addEventListener('click', login);

// Initial log message
log('WebAuthn demo ready. Click "Register" to start.');
