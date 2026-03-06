// --- UTILITIES ---
const pack = (salt, iv, cipher) => {
    const combined = new Uint8Array(salt.length + iv.length + cipher.length);
    combined.set(salt, 0);
    combined.set(iv, salt.length);
    combined.set(cipher, salt.length + iv.length);
    return btoa(String.fromCharCode(...combined)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};

const unpack = (str) => {
    const base64 = str.replace(/-/g, '+').replace(/_/g, '/').padEnd(str.length + (4 - str.length % 4) % 4, '=');
    const bin = atob(base64);
    const buf = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
    return { salt: buf.slice(0, 16), iv: buf.slice(16, 28), cipher: buf.slice(28) };
};

// --- CRYPTO ---
async function deriveKey(pass, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(pass), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
        { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
}

// --- APP LOGIC ---
async function handleEncrypt() {
    const text = document.getElementById('msg').value;
    const pass = document.getElementById('pass').value;
    if (!text || !pass) return alert("Fill everything in!");

    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKey(pass, salt);
    
    const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(text));
    const token = pack(salt, iv, new Uint8Array(cipher));
    
    const url = window.location.origin + window.location.pathname + "#" + token;
    document.getElementById('share-url').value = url;
    document.getElementById('result-area').classList.remove('hidden');
}

async function handleDecrypt() {
    const pass = document.getElementById('decrypt-pass').value;
    const token = window.location.hash.substring(1);
    const { salt, iv, cipher } = unpack(token);

    try {
        const key = await deriveKey(pass, salt);
        const decoded = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, cipher);
        document.getElementById('decrypted-text').innerText = new TextDecoder().decode(decoded);
        document.getElementById('secret-output').classList.remove('hidden');
    } catch (e) {
        alert("Wrong passphrase!");
    }
}

// Check if we are in "Read Mode" on load
window.onload = () => {
    if (window.location.hash) {
        document.getElementById('create-mode').classList.add('hidden');
        document.getElementById('decrypt-mode').classList.remove('hidden');
    }
};

function copyLink() {
    const copyText = document.getElementById("share-url");
    copyText.select();
    navigator.clipboard.writeText(copyText.value);
    alert("Copied to clipboard!");
}