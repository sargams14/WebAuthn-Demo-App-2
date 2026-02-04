const logEl = document.getElementById("log");
const usernameEl = document.getElementById("username");
const displayNameEl = document.getElementById("displayName");
const registerBtn = document.getElementById("registerBtn");
const authBtn = document.getElementById("authBtn");

function log(message) {
    logEl.textContent = message;
}

// Converts Base64 encoded object to an Array Buffer
function base64urlToBuffer(base64url) {
    const padding = "=".repeat((4 - (base64url.length % 4)) % 4);
    const base64 = (base64url + padding).replace(/-/g, "+").replace(/_/g, "/");
    const raw = atob(base64);
    const bytes = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i += 1) {
        bytes[i] = raw.charCodeAt(i);
    }
    return bytes.buffer;
}

function normalizeCreationOptions(options) {
    if (PublicKeyCredential.parseCreationOptionsFromJSON) {
        return PublicKeyCredential.parseCreationOptionsFromJSON(options);
    }
    // In case browser's parseCreationOptionsFromJSON() method is not found, we fallback to manual ArrayBuffer creation
    return {
        ...options,
        challenge: base64urlToBuffer(options.challenge),
        user: {
            ...options.user, // Has the entire options.user object copied as it is
            id: base64urlToBuffer(options.user.id) // id is appended to the object after conversion
        },
        excludeCredentials: (options.excludeCredentials || []).map((cred) => ({
            ...cred,
            id: base64urlToBuffer(cred.id)
        }))
    };
}

function normalizeRequestOptions(options) {
    const sanitized = { ...options };
    if (sanitized.allowCredentials == null) {
        delete sanitized.allowCredentials;
    }
    if (sanitized.hints == null) {
        delete sanitized.hints;
    }
    if (PublicKeyCredential.parseRequestOptionsFromJSON) {
        return PublicKeyCredential.parseRequestOptionsFromJSON(sanitized);
    }
    return {
        ...sanitized,
        challenge: base64urlToBuffer(sanitized.challenge),
        allowCredentials: (sanitized.allowCredentials || []).map((cred) => ({
            ...cred,
            id: base64urlToBuffer(cred.id)
        }))
    };
}

async function postJson(url, payload) {
    const response = await fetch(url, {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(payload)
    });

    const contentType = response.headers.get("content-type") || "";
    if (!response.ok) {
        const errorBody = contentType.includes("application/json")
            ? await response.json()
            : await response.text();
        const message = typeof errorBody === "string" ? errorBody : errorBody.error;
        throw new Error(message || "Request failed");
    }

    if (contentType.includes("application/json")) {
        return response.json();
    }
    return response.text();
}

// This is getting invoked if Register button is clicked
async function registerPasskey() {
    if (!window.PublicKeyCredential) {
        log("WebAuthn is not supported in this browser.");
        return;
    }

    const username = usernameEl.value.trim();
    if (!username) {
        log("Enter the username first.");
        return;
    }

    const displayName = displayNameEl.value.trim();
    log("Requesting registration options (Invoking register options controller).");

    // Register options controller being invoked with username & displayName
    const options = await postJson("/webauthn/register/options", {
        username,
        displayName: displayName || null
    });

    // We get the options in the exact format that the webAuthn API expects
    const publicKey = normalizeCreationOptions(options);
    log("Creating credential on device...");
    const credential = await navigator.credentials.create({ publicKey });

    if (!credential) {
        log("No credential created.");
        return;
    }

    log("Sending registration response (Invoking register finish controller).");
    const result = await postJson("/webauthn/register/finish", {
        username,
        credential: credential.toJSON()
    });

    log(`Registration complete. CredentialId: ${result.credentialId}`);
}

async function authenticate() {
    if (!window.PublicKeyCredential) {
        log("WebAuthn is not supported in this browser.");
        return;
    }

    const username = usernameEl.value.trim();
    if (!username) {
        log("Enter a username first.");
        return;
    }

    log("Requesting authentication options...");
    const options = await postJson("/webauthn/authenticate/options", { username });

    const publicKey = normalizeRequestOptions(options);
    log("Requesting assertion from device...");
    const assertion = await navigator.credentials.get({ publicKey });

    if (!assertion) {
        log("No assertion returned.");
        return;
    }

    log("Sending authentication response...");
    const result = await postJson("/webauthn/authenticate/finish", {
        username,
        credential: assertion.toJSON()
    });

    log(`Authentication complete. CredentialId: ${result.credentialId}`);
}

registerBtn.addEventListener("click", () => {
    registerPasskey().catch((error) => {
        log(`Registration failed: ${error.message}`);
    });
});

authBtn.addEventListener("click", () => {
    authenticate().catch((error) => {
        log(`Authentication failed: ${error.message}`);
    });
});
