// --- UTILITIES: URL PACKING ---
const pack = (salt, iv, cipher) => {
    const combined = new Uint8Array(salt.length + iv.length + cipher.length);
    combined.set(salt, 0);
    combined.set(iv, salt.length);
    combined.set(cipher, salt.length + iv.length);
    // URL-safe Base64
    return btoa(String.fromCharCode(...combined))
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};

const unpack = (str) => {
    const base64 = str.replace(/-/g, '+').replace(/_/g, '/').padEnd(str.length + (4 - str.length % 4) % 4, '=');
    const bin = atob(base64);
    const buf = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
    return { salt: buf.slice(0, 16), iv: buf.slice(16, 28), cipher: buf.slice(28) };
};

// --- CRYPTO ENGINE ---
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

// --- UI LOGIC ---
function updateCharCount(el) {
    const count = el.value.length;
    const label = document.getElementById('char-count');
    label.innerText = `${count} / 1500 characters`;
    label.style.color = count > 1400 ? '#f87171' : '#64748b';
}

function togglePass(inputId, iconId) {
    const input = document.getElementById(inputId);
    const icon = document.getElementById(iconId);
    if (input.type === "password") {
        input.type = "text";
        icon.innerHTML = `<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line>`;
    } else {
        input.type = "password";
        icon.innerHTML = `<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle>`;
    }
}

function checkStrength(pass) {
    const bar = document.getElementById('strength-bar');
    let score = 0;
    if (!pass) { bar.style.width = '0%'; return; }
    if (pass.length > 8) score++;
    if (pass.length > 12) score++;
    if (/[A-Z]/.test(pass)) score++;
    if (/[0-9]/.test(pass)) score++;
    if (/[^A-Za-z0-9]/.test(pass)) score++;

    const colors = ['bg-red-500', 'bg-orange-500', 'bg-yellow-500', 'bg-blue-500', 'bg-emerald-500'];
    bar.className = `h-full transition-all duration-500 ${colors[Math.min(score, 4)]}`;
    bar.style.width = `${(score + 1) * 20}%`;
}

// --- ACTIONS ---
async function handleEncrypt() {
    const text = document.getElementById('msg').value;
    const pass = document.getElementById('pass').value;
    if (!text || !pass) return alert("Please enter both a message and a passphrase.");

    try {
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const key = await deriveKey(pass, salt);
        const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(text));
        
        const token = pack(salt, iv, new Uint8Array(cipher));
        const url = window.location.origin + window.location.pathname + "#" + token;
        
        document.getElementById('share-url').value = url;
        document.getElementById('result-area').classList.remove('hidden');
    } catch (e) {
        alert("Encryption failed. Check browser console.");
    }
}

async function handleDecrypt() {
    const pass = document.getElementById('decrypt-pass').value;
    const token = window.location.hash.substring(1);
    if (!pass) return alert("Enter the passphrase.");

    try {
        const { salt, iv, cipher } = unpack(token);
        const key = await deriveKey(pass, salt);
        const decoded = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, cipher);
        
        document.getElementById('decrypted-text').innerText = new TextDecoder().decode(decoded);
        document.getElementById('secret-output').classList.remove('hidden');
    } catch (e) {
        alert("Incorrect passphrase. Decryption failed.");
    }
}

function copyLink() {
    const copyText = document.getElementById("share-url");
    copyText.select();
    navigator.clipboard.writeText(copyText.value);
    alert("Link copied!");
}

// Routing on Load
window.onload = () => {
    if (window.location.hash && window.location.hash.length > 10) {
        document.getElementById('create-mode').classList.add('hidden');
        document.getElementById('decrypt-mode').classList.remove('hidden');
    }
};
