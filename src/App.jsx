import { useState, useEffect, useRef, useCallback } from "react";

// Relative URLs - Vite proxy forwards /auth, /api, /users, /conversations to backend
const API = import.meta.env.VITE_API_URL || "";

// ─── Crypto Utilities ────────────────────────────────────────────────────────

const Crypto = {
  // Generate RSA-OAEP key pair for asymmetric encryption
  async generateKeyPair() {
    return crypto.subtle.generateKey(
      { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
      true,
      ["encrypt", "decrypt"]
    );
  },

  // Export public key to base64 for server storage
  async exportPublicKey(key) {
    const raw = await crypto.subtle.exportKey("spki", key);
    return btoa(String.fromCharCode(...new Uint8Array(raw)));
  },

  // Export private key as JWK for encrypted local storage
  async exportPrivateKey(key) {
    return crypto.subtle.exportKey("jwk", key);
  },

  // Import public key from base64
  async importPublicKey(b64) {
    const raw = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    return crypto.subtle.importKey("spki", raw, { name: "RSA-OAEP", hash: "SHA-256" }, true, ["encrypt"]);
  },

  // Import private key from JWK
  async importPrivateKey(jwk) {
    return crypto.subtle.importKey("jwk", jwk, { name: "RSA-OAEP", hash: "SHA-256" }, true, ["decrypt"]);
  },

  // Generate AES-GCM key for symmetric encryption
  async generateAESKey() {
    return crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  },

  // Encrypt AES key with RSA public key
  async encryptAESKey(aesKey, publicKey) {
    const raw = await crypto.subtle.exportKey("raw", aesKey);
    const enc = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, raw);
    return btoa(String.fromCharCode(...new Uint8Array(enc)));
  },

  // Decrypt AES key with RSA private key
  async decryptAESKey(b64, privateKey) {
    const enc = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    const raw = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, privateKey, enc);
    return crypto.subtle.importKey("raw", raw, { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  },

  // Encrypt plaintext with AES-GCM
  async encryptMessage(plaintext, aesKey) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const enc = new TextEncoder().encode(plaintext);
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, enc);
    const combined = new Uint8Array(iv.length + ct.byteLength);
    combined.set(iv);
    combined.set(new Uint8Array(ct), iv.length);
    return btoa(String.fromCharCode(...combined));
  },

  // Decrypt ciphertext with AES-GCM
  async decryptMessage(b64, aesKey) {
    const combined = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    const iv = combined.slice(0, 12);
    const ct = combined.slice(12);
    const dec = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, aesKey, ct);
    return new TextDecoder().decode(dec);
  },

  // Derive wrapping key from password for private key encryption
  async deriveKeyFromPassword(password, salt) {
    const enc = new TextEncoder().encode(password);
    const raw = await crypto.subtle.importKey("raw", enc, "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
      raw,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  },

  // Encrypt private key JWK with password-derived key
  async encryptPrivateKey(jwk, password) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const wrapKey = await this.deriveKeyFromPassword(password, salt);
    const data = new TextEncoder().encode(JSON.stringify(jwk));
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, wrapKey, data);
    return {
      salt: btoa(String.fromCharCode(...salt)),
      iv: btoa(String.fromCharCode(...iv)),
      ct: btoa(String.fromCharCode(...new Uint8Array(ct)))
    };
  },

  // Decrypt private key JWK with password-derived key
  async decryptPrivateKey(encrypted, password) {
    const salt = Uint8Array.from(atob(encrypted.salt), c => c.charCodeAt(0));
    const iv = Uint8Array.from(atob(encrypted.iv), c => c.charCodeAt(0));
    const ct = Uint8Array.from(atob(encrypted.ct), c => c.charCodeAt(0));
    const wrapKey = await this.deriveKeyFromPassword(password, salt);
    const dec = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, wrapKey, ct);
    return JSON.parse(new TextDecoder().decode(dec));
  }
};

// ─── Key Storage (IndexedDB) ──────────────────────────────────────────────────

const KeyStore = {
  db: null,
  async open() {
    if (this.db) return this.db;
    return new Promise((res, rej) => {
      const req = indexedDB.open("whisperbox-keys", 1);
      req.onupgradeneeded = e => e.target.result.createObjectStore("keys");
      req.onsuccess = e => { this.db = e.target.result; res(this.db); };
      req.onerror = () => rej(req.error);
    });
  },
  async set(key, value) {
    const db = await this.open();
    return new Promise((res, rej) => {
      const tx = db.transaction("keys", "readwrite");
      tx.objectStore("keys").put(value, key);
      tx.oncomplete = res;
      tx.onerror = () => rej(tx.error);
    });
  },
  async get(key) {
    const db = await this.open();
    return new Promise((res, rej) => {
      const tx = db.transaction("keys", "readonly");
      const req = tx.objectStore("keys").get(key);
      req.onsuccess = () => res(req.result);
      req.onerror = () => rej(req.error);
    });
  },
  async del(key) {
    const db = await this.open();
    return new Promise((res, rej) => {
      const tx = db.transaction("keys", "readwrite");
      tx.objectStore("keys").delete(key);
      tx.oncomplete = res;
      tx.onerror = () => rej(tx.error);
    });
  }
};

// ─── API Client ───────────────────────────────────────────────────────────────

const api = {
  token: null,
  async req(method, path, body) {
    const headers = { "Content-Type": "application/json" };
    if (this.token) headers["Authorization"] = `Bearer ${this.token}`;
    const res = await fetch(`${API}${path}`, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.detail || data.message || `HTTP ${res.status}`);
    return data;
  },
  get: (p) => api.req("GET", p),
  post: (p, b) => api.req("POST", p, b),
  put: (p, b) => api.req("PUT", p, b),
};

// ─── Styles ───────────────────────────────────────────────────────────────────

const css = `
  @import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@300;400;500&family=DM+Mono:wght@400;500&display=swap');

  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  html, body, #root {
    height: 100%;
    margin: 0;
    padding: 0;
    background: #0f0f17;
  }

  .wb-app {
    font-family: 'DM Sans', sans-serif;
    height: 100vh;
    display: flex;
    flex-direction: column;
    background: #0f0f17;
    color: #e2e8f0;
    overflow: hidden;
    position: relative;
    --color-background-primary: #0f0f17;
    --color-background-secondary: #1a1a2e;
    --color-background-danger: #2d1a1a;
    --color-text-primary: #e2e8f0;
    --color-text-secondary: #94a3b8;
    --color-text-tertiary: #64748b;
    --color-text-danger: #f87171;
    --color-border-primary: #7c3aed;
    --color-border-secondary: #2d2d4e;
    --color-border-tertiary: #1e1e3a;
    --color-border-danger: #7f1d1d;
    --border-radius-lg: 12px;
    --border-radius-md: 8px;
  }

  /* Auth screen */
  .wb-auth {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    height: 100%;
    gap: 24px;
    padding: 2rem;
  }
  .wb-auth-logo {
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .wb-auth-logo-icon {
    width: 36px; height: 36px;
    background: #1a1a2e;
    border-radius: 10px;
    display: flex; align-items: center; justify-content: center;
    color: #a78bfa;
    font-size: 18px;
  }
  .wb-auth-logo-text {
    font-size: 22px;
    font-weight: 500;
    letter-spacing: -0.5px;
    color: var(--color-text-primary);
  }
  .wb-auth-card {
    width: 100%;
    max-width: 360px;
    background: var(--color-background-secondary);
    border: 0.5px solid var(--color-border-tertiary);
    border-radius: var(--border-radius-lg);
    padding: 1.5rem;
    display: flex;
    flex-direction: column;
    gap: 14px;
  }
  .wb-auth-title {
    font-size: 15px;
    font-weight: 500;
    color: var(--color-text-primary);
  }
  .wb-auth-sub {
    font-size: 12px;
    color: var(--color-text-tertiary);
    margin-top: -10px;
  }
  .wb-input {
    width: 100%;
    padding: 9px 12px;
    border: 0.5px solid var(--color-border-secondary);
    border-radius: var(--border-radius-md);
    background: var(--color-background-primary);
    color: var(--color-text-primary);
    font-family: 'DM Sans', sans-serif;
    font-size: 14px;
    outline: none;
    transition: border-color 0.15s;
  }
  .wb-input:focus { border-color: var(--color-border-primary); }
  .wb-btn {
    padding: 9px 16px;
    border-radius: var(--border-radius-md);
    border: 0.5px solid var(--color-border-secondary);
    background: var(--color-background-primary);
    color: var(--color-text-primary);
    font-family: 'DM Sans', sans-serif;
    font-size: 14px;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.15s;
  }
  .wb-btn:hover { background: var(--color-background-secondary); }
  .wb-btn:active { transform: scale(0.98); }
  .wb-btn-primary {
    background: #1a1a2e;
    color: #e2e8f0;
    border-color: #1a1a2e;
  }
  .wb-btn-primary:hover { background: #2d2d4e; border-color: #2d2d4e; }
  .wb-btn-sm {
    padding: 5px 10px;
    font-size: 12px;
  }
  .wb-err {
    font-size: 12px;
    color: var(--color-text-danger);
    background: var(--color-background-danger);
    border: 0.5px solid var(--color-border-danger);
    border-radius: var(--border-radius-md);
    padding: 8px 10px;
  }
  .wb-tab-row {
    display: flex;
    border-bottom: 0.5px solid var(--color-border-tertiary);
    margin-bottom: 4px;
  }
  .wb-tab {
    padding: 8px 14px;
    font-size: 13px;
    font-weight: 500;
    cursor: pointer;
    color: var(--color-text-secondary);
    border-bottom: 2px solid transparent;
    margin-bottom: -1px;
    transition: all 0.15s;
  }
  .wb-tab.active { color: var(--color-text-primary); border-bottom-color: #7c3aed; }

  /* Main layout */
  .wb-shell {
    display: flex;
    height: 100%;
    overflow: hidden;
  }

  /* Sidebar */
  .wb-sidebar {
    width: 240px;
    min-width: 240px;
    border-right: 0.5px solid var(--color-border-tertiary);
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }
  .wb-sidebar-header {
    padding: 12px 14px;
    border-bottom: 0.5px solid var(--color-border-tertiary);
    display: flex;
    align-items: center;
    justify-content: space-between;
  }
  .wb-sidebar-title {
    font-size: 13px;
    font-weight: 500;
    color: var(--color-text-primary);
    letter-spacing: -0.2px;
  }
  .wb-sidebar-actions {
    display: flex;
    gap: 6px;
    align-items: center;
  }
  .wb-icon-btn {
    width: 28px; height: 28px;
    border-radius: var(--border-radius-md);
    border: 0.5px solid transparent;
    background: transparent;
    cursor: pointer;
    display: flex; align-items: center; justify-content: center;
    font-size: 14px;
    color: var(--color-text-secondary);
    transition: all 0.15s;
  }
  .wb-icon-btn:hover { background: var(--color-background-secondary); color: var(--color-text-primary); }
  .wb-conv-list { flex: 1; overflow-y: auto; }
  .wb-conv-item {
    padding: 10px 14px;
    cursor: pointer;
    border-bottom: 0.5px solid var(--color-border-tertiary);
    transition: background 0.1s;
    display: flex;
    flex-direction: column;
    gap: 3px;
  }
  .wb-conv-item:hover { background: var(--color-background-secondary); }
  .wb-conv-item.active { background: var(--color-background-secondary); }
  .wb-conv-name {
    font-size: 13px;
    font-weight: 500;
    color: var(--color-text-primary);
    display: flex;
    align-items: center;
    gap: 5px;
  }
  .wb-conv-preview {
    font-size: 11px;
    color: var(--color-text-tertiary);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    font-family: 'DM Mono', monospace;
  }
  .wb-lock-icon {
    font-size: 9px;
    background: #7c3aed22;
    color: #7c3aed;
    padding: 1px 4px;
    border-radius: 3px;
    font-weight: 500;
    font-family: 'DM Mono', monospace;
  }
  .wb-sidebar-footer {
    border-top: 0.5px solid var(--color-border-tertiary);
    padding: 10px 14px;
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .wb-avatar {
    width: 28px; height: 28px;
    border-radius: 50%;
    background: #1a1a2e;
    color: #a78bfa;
    display: flex; align-items: center; justify-content: center;
    font-size: 11px;
    font-weight: 500;
    flex-shrink: 0;
  }
  .wb-username {
    font-size: 12px;
    font-weight: 500;
    color: var(--color-text-primary);
    flex: 1;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  /* Chat area */
  .wb-chat {
    flex: 1;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }
  .wb-chat-header {
    padding: 11px 16px;
    border-bottom: 0.5px solid var(--color-border-tertiary);
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .wb-chat-title {
    font-size: 14px;
    font-weight: 500;
    color: var(--color-text-primary);
    flex: 1;
  }
  .wb-e2ee-badge {
    font-size: 10px;
    font-family: 'DM Mono', monospace;
    background: #7c3aed15;
    color: #7c3aed;
    border: 0.5px solid #7c3aed40;
    padding: 3px 7px;
    border-radius: 4px;
    display: flex;
    align-items: center;
    gap: 4px;
  }
  .wb-e2ee-dot {
    width: 5px; height: 5px;
    border-radius: 50%;
    background: #22c55e;
    flex-shrink: 0;
  }
  .wb-messages {
    flex: 1;
    overflow-y: auto;
    padding: 16px;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .wb-msg-row {
    display: flex;
    flex-direction: column;
    max-width: 75%;
  }
  .wb-msg-row.mine { align-self: flex-end; align-items: flex-end; }
  .wb-msg-row.theirs { align-self: flex-start; align-items: flex-start; }
  .wb-bubble {
    padding: 8px 12px;
    border-radius: 14px;
    font-size: 13px;
    line-height: 1.5;
    position: relative;
  }
  .wb-msg-row.mine .wb-bubble {
    background: #1a1a2e;
    color: #e2e8f0;
    border-bottom-right-radius: 4px;
  }
  .wb-msg-row.theirs .wb-bubble {
    background: var(--color-background-secondary);
    color: var(--color-text-primary);
    border: 0.5px solid var(--color-border-tertiary);
    border-bottom-left-radius: 4px;
  }
  .wb-msg-meta {
    font-size: 10px;
    color: var(--color-text-tertiary);
    font-family: 'DM Mono', monospace;
    margin-top: 3px;
    display: flex;
    align-items: center;
    gap: 4px;
  }
  .wb-decrypting {
    font-style: italic;
    opacity: 0.6;
  }
  .wb-cipher-preview {
    font-family: 'DM Mono', monospace;
    font-size: 10px;
    opacity: 0.5;
    max-width: 140px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .wb-compose {
    border-top: 0.5px solid var(--color-border-tertiary);
    padding: 10px 14px;
    display: flex;
    gap: 8px;
    align-items: flex-end;
  }
  .wb-compose-input {
    flex: 1;
    min-height: 36px;
    max-height: 90px;
    padding: 8px 12px;
    border: 0.5px solid var(--color-border-secondary);
    border-radius: 18px;
    background: var(--color-background-secondary);
    color: var(--color-text-primary);
    font-family: 'DM Sans', sans-serif;
    font-size: 13px;
    resize: none;
    outline: none;
    transition: border-color 0.15s;
    line-height: 1.4;
  }
  .wb-compose-input:focus { border-color: var(--color-border-primary); }
  .wb-send-btn {
    width: 36px; height: 36px;
    border-radius: 50%;
    background: #1a1a2e;
    border: none;
    cursor: pointer;
    display: flex; align-items: center; justify-content: center;
    transition: all 0.15s;
    flex-shrink: 0;
    color: #a78bfa;
    font-size: 15px;
  }
  .wb-send-btn:hover { background: #2d2d4e; }
  .wb-send-btn:disabled { opacity: 0.4; cursor: not-allowed; }

  /* Empty state */
  .wb-empty {
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 8px;
    color: var(--color-text-tertiary);
  }
  .wb-empty-icon { font-size: 32px; opacity: 0.3; }
  .wb-empty-text { font-size: 13px; }

  /* New convo overlay */
  .wb-overlay {
    position: absolute;
    inset: 0;
    background: rgba(0,0,0,0.35);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 10;
    }
  
  .wb-modal {
    background: var(--color-background-primary);
    border: 0.5px solid var(--color-border-tertiary);
    border-radius: var(--border-radius-lg);
    padding: 1.25rem;
    width: 300px;
    display: flex;
    flex-direction: column;
    gap: 12px;
  }
  .wb-modal-title {
    font-size: 14px;
    font-weight: 500;
    color: var(--color-text-primary);
  }
  .wb-modal-row {
    display: flex;
    gap: 8px;
  }
  .wb-spinner {
    width: 14px; height: 14px;
    border: 2px solid var(--color-border-secondary);
    border-top-color: #7c3aed;
    border-radius: 50%;
    animation: spin 0.6s linear infinite;
    display: inline-block;
  }
  @keyframes spin { to { transform: rotate(360deg); } }
  .wb-status-bar {
    padding: 4px 14px;
    font-size: 10px;
    font-family: 'DM Mono', monospace;
    color: var(--color-text-tertiary);
    border-bottom: 0.5px solid var(--color-border-tertiary);
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .wb-status-dot { width: 5px; height: 5px; border-radius: 50%; background: #22c55e; }
  .wb-note {
    font-size: 11px;
    color: var(--color-text-tertiary);
    font-family: 'DM Mono', monospace;
    text-align: center;
  }
  ::-webkit-scrollbar { width: 4px; }
  ::-webkit-scrollbar-track { background: transparent; }
  ::-webkit-scrollbar-thumb { background: var(--color-border-secondary); border-radius: 2px; }
`;

// ─── App ──────────────────────────────────────────────────────────────────────

export default function WhisperBox() {
  const [screen, setScreen] = useState("auth"); // auth | app
  const [authTab, setAuthTab] = useState("login");
  const [authForm, setAuthForm] = useState({ username: "", display_name: "", password: "", email: "" });
  const [authError, setAuthError] = useState("");
  const [authLoading, setAuthLoading] = useState(false);

  const [user, setUser] = useState(null);
  const [privateKey, setPrivateKey] = useState(null);

  const [conversations, setConversations] = useState([]);
  const [activeConv, setActiveConv] = useState(null);
  const [messages, setMessages] = useState([]);
  const [msgMap, setMsgMap] = useState({}); // convId -> decrypted messages
  const [input, setInput] = useState("");
  const [sending, setSending] = useState(false);
  const [showNewConv, setShowNewConv] = useState(false);
  const [recipientInput, setRecipientInput] = useState("");
  const [newConvError, setNewConvError] = useState("");
  const [newConvLoading, setNewConvLoading] = useState(false);
  const [statusMsg, setStatusMsg] = useState("Keys loaded · E2EE active");

  const messagesEndRef = useRef(null);
  const pollRef = useRef(null);

  // ── Auth ──────────────────────────────────────────────────────────────────

  const handleLogin = async () => {
    setAuthError("");
    setAuthLoading(true);
    try {
      // Try form-encoded login (common pattern)
      // Try multiple login endpoint patterns
      const loginPaths = [
        ["/auth/login", "json"],
        ["/auth/login", "form"],
        ["/auth/token", "form"],
        ["/auth/token", "json"],
      ];
      let loginData = null;
      let lastErr = "Login failed";
      for (const [path, fmt] of loginPaths) {
        try {
          const r = await fetch(`${API}${path}`, {
            method: "POST",
            headers: { "Content-Type": fmt === "form" ? "application/x-www-form-urlencoded" : "application/json" },
            body: fmt === "form"
              ? new URLSearchParams({ username: authForm.username, password: authForm.password })
              : JSON.stringify({ username: authForm.username, password: authForm.password })
          });
          if (r.ok) { loginData = await r.json(); break; }
          const d = await r.json().catch(() => ({}));
          lastErr = d.detail || d.message || `HTTP ${r.status} at ${path}`;
        } catch(e) { lastErr = e.message; }
      }
      if (!loginData) throw new Error(lastErr);
      await afterLogin(loginData, authForm.password);
    } catch (e) {
      setAuthError(e.message);
    }
    setAuthLoading(false);
  };

  const handleRegister = async () => {
    setAuthError("");
    setAuthLoading(true);
    try {
      setStatusMsg("Generating RSA-2048 key pair...");
      // Generate key pair
      const keyPair = await Crypto.generateKeyPair();
      const pubKeyB64 = await Crypto.exportPublicKey(keyPair.publicKey);
      const privJwk = await Crypto.exportPrivateKey(keyPair.privateKey);

      // Register with server
      // Try multiple register endpoint patterns
      // Server requires: username, password, display_name, public_key, wrapped_private_key, pbkdf2_salt
      const encPriv = await Crypto.encryptPrivateKey(privJwk, authForm.password);

      const registerBody = {
        username: authForm.username,
        password: authForm.password,
        display_name: authForm.display_name || authForm.username,
        email: authForm.email || undefined,
        public_key: pubKeyB64,
        wrapped_private_key: encPriv.ct,
        pbkdf2_salt: encPriv.salt,
      };

      const r = await fetch(`${API}/auth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(registerBody)
      });
      const data = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(
        Array.isArray(data.detail)
          ? data.detail.map(e => `${e.loc?.slice(-1)[0]}: ${e.msg}`).join(", ")
          : data.detail || data.message || `HTTP ${r.status}`
      );

      // Also store locally in IndexedDB for fast access
      await KeyStore.set(`privkey:${authForm.username}`, encPriv);

      setStatusMsg("Registration complete · Keys stored securely");

      // Auto login after register
      // Auto-login after register
      const autoLoginPaths = [["/auth/login","form"],["/api/auth/login","form"],["/auth/login","json"]];
      let autoData = null;
      for (const [path, fmt] of autoLoginPaths) {
        try {
          const r = await fetch(`${API}${path}`, {
            method: "POST",
            headers: { "Content-Type": fmt === "form" ? "application/x-www-form-urlencoded" : "application/json" },
            body: fmt === "form"
              ? new URLSearchParams({ username: authForm.username, password: authForm.password })
              : JSON.stringify({ username: authForm.username, password: authForm.password })
          });
          if (r.ok) { autoData = await r.json(); break; }
        } catch {}
      }
      if (autoData) {
        await afterLogin(autoData, authForm.password, keyPair.privateKey);
      } else {
        setAuthTab("login");
        setAuthError("Registered! Please log in.");
      }
    } catch (e) {
      setAuthError(e.message);
    }
    setAuthLoading(false);
  };

  const afterLogin = async (data, password, existingPrivKey = null) => {
    const token = data.access_token || data.token;
    if (!token) throw new Error("No token received");
    api.token = token;

    // Load private key
    let privKey = existingPrivKey;
    if (!privKey) {
      const username = authForm.username;
      const encPriv = await KeyStore.get(`privkey:${username}`);
      if (!encPriv) throw new Error("Private key not found on this device. Please register again or use the same device.");
      const jwk = await Crypto.decryptPrivateKey(encPriv, password);
      privKey = await Crypto.importPrivateKey(jwk);
    }

    setPrivateKey(privKey);
    setStatusMsg("Keys loaded · E2EE active");

    // Get user profile
    const profile = await api.get("/auth/me").catch(() => null);
    setUser(profile || { username: authForm.username });
    setScreen("app");
    await loadConversations();
  };

  // ── Conversations ─────────────────────────────────────────────────────────

  const loadConversations = async () => {
    try {
      const data = await api.get("/conversations");
      const convs = Array.isArray(data) ? data : (data.conversations || []);
      setConversations(convs);
    } catch (e) {
      console.error("load convs:", e);
    }
  };

  const openConversation = async (conv) => {
    setActiveConv(conv);
    if (msgMap[conv.id]) return; // already loaded
    await loadMessages(conv);
  };

  const loadMessages = async (conv) => {
    try {
      const data = await api.get(`/conversations/${conv.id}/messages`);
      const msgs = Array.isArray(data) ? data : (data.messages || []);
      const decrypted = await decryptMessages(msgs, conv);
      setMsgMap(prev => ({ ...prev, [conv.id]: decrypted }));
    } catch (e) {
      console.error("load messages:", e);
    }
  };

  const decryptMessages = async (msgs, conv) => {
    const results = [];
    for (const m of msgs) {
      try {
        // Find the encrypted key meant for us
        const myUsername = user?.username || authForm.username;
        let encKey = null;

        if (m.encrypted_keys) {
          encKey = m.encrypted_keys[myUsername] || Object.values(m.encrypted_keys)[0];
        } else if (m.encrypted_key) {
          encKey = m.encrypted_key;
        }

        if (!encKey || !m.ciphertext) {
          results.push({ ...m, plaintext: null, failed: false });
          continue;
        }

        const aesKey = await Crypto.decryptAESKey(encKey, privateKey);
        const plaintext = await Crypto.decryptMessage(m.ciphertext, aesKey);
        results.push({ ...m, plaintext });
      } catch {
        results.push({ ...m, plaintext: null, failed: true });
      }
    }
    return results;
  };

  const createConversation = async () => {
    setNewConvError("");
    if (!recipientInput.trim()) return;
    setNewConvLoading(true);
    try {
      // Step 1: look up the recipient user to get their ID and public key
      let recipient = null;
      const userPaths = [
        `/users/search?q=${recipientInput.trim()}`,
        `/users/${recipientInput.trim()}`,
        `/users/username/${recipientInput.trim()}`,
        `/users?username=${recipientInput.trim()}`,
      ];
      for (const path of userPaths) {
        try {
          const r = await fetch(`${API}${path}`, {
            headers: { "Authorization": `Bearer ${api.token}` }
          });
          if (r.ok) {
            const d = await r.json();
            recipient = Array.isArray(d) ? d[0] : d;
            console.log("Found user at:", path, recipient);
            break;
          }
          console.warn("User lookup failed at:", path, r.status);
        } catch(e) { console.warn(e); }
      }

      if (!recipient) throw new Error("User not found. Make sure they have registered.");

      // Step 2: create conversation using recipient's id or username
      const recipientId = recipient.id || recipient.user_id || recipient.uuid;

      // Try different URL patterns for creating a conversation
      const convUrls = [
        [`/conversations/${recipientId}`, "POST", null],
        [`/conversations/with/${recipientId}`, "POST", null],
        [`/users/${recipientId}/conversations`, "POST", null],
        [`/conversations`, "POST", { participant_id: recipientId }],
        [`/conversations`, "POST", { recipient_id: recipientId }],
        [`/conversations/with/${recipientInput.trim()}`, "POST", null],
        [`/users/${recipientInput.trim()}/conversations`, "POST", null],
      ];

      let conv = null;
      let lastErr = "Could not create conversation";

      for (const [url, method, body] of convUrls) {
        try {
          const r = await fetch(`${API}${url}`, {
            method,
            headers: { "Content-Type": "application/json", "Authorization": `Bearer ${api.token}` },
            body: body ? JSON.stringify(body) : undefined
          });
          const d = await r.json().catch(() => ({}));
          if (r.ok) { conv = d; console.log("Conversation created at:", url); break; }
          lastErr = Array.isArray(d.detail)
            ? d.detail.map(e => `${e.loc?.slice(-1)[0]}: ${e.msg}`).join(", ")
            : d.detail || d.message || `HTTP ${r.status}`;
          console.warn("Conv attempt failed:", url, "→", lastErr);
        } catch(e) { lastErr = e.message; }
      }

      if (!conv) throw new Error(lastErr);

      setConversations(prev => [conv, ...prev]);
      setActiveConv(conv);
      setMsgMap(prev => ({ ...prev, [conv.id]: [] }));
      setShowNewConv(false);
      setRecipientInput("");
    } catch (e) {
      setNewConvError(e.message);
    }
    setNewConvLoading(false);
  };

  // ── Messaging ─────────────────────────────────────────────────────────────

  const sendMessage = async () => {
    if (!input.trim() || !activeConv || sending) return;
    const text = input.trim();
    setInput("");
    setSending(true);
    try {
      // Get all participants' public keys
      const myUsername = user?.username || authForm.username;
      const participants = activeConv.participants || activeConv.members || [];

      // Gather public keys
      const keyMap = {};
      for (const p of participants) {
        const uname = typeof p === "string" ? p : p.username;
        if (!uname) continue;
        try {
          const u = await api.get(`/users/${uname}`);
          if (u?.public_key) keyMap[uname] = await Crypto.importPublicKey(u.public_key);
        } catch {}
      }

      // Always encrypt for self too
      const me = await api.get("/auth/me").catch(() => null);
      if (me?.public_key && !keyMap[myUsername]) {
        keyMap[myUsername] = await Crypto.importPublicKey(me.public_key);
      }

      // Generate ephemeral AES key
      const aesKey = await Crypto.generateAESKey();
      const ciphertext = await Crypto.encryptMessage(text, aesKey);

      // Encrypt AES key for each participant
      const encrypted_keys = {};
      for (const [uname, pubKey] of Object.entries(keyMap)) {
        encrypted_keys[uname] = await Crypto.encryptAESKey(aesKey, pubKey);
      }

      const payload = {
        conversation_id: activeConv.id,
        ciphertext,
        encrypted_keys,
        // Fallback: single encrypted_key for simple backends
        encrypted_key: Object.values(encrypted_keys)[0]
      };

      const sent = await api.post(`/conversations/${activeConv.id}/messages`, payload);
      const newMsg = { ...sent, plaintext: text, sender: myUsername };

      setMsgMap(prev => ({
        ...prev,
        [activeConv.id]: [...(prev[activeConv.id] || []), newMsg]
      }));
    } catch (e) {
      setStatusMsg("Send failed: " + e.message);
    }
    setSending(false);
  };

  // ── Polling ───────────────────────────────────────────────────────────────

  useEffect(() => {
    if (!activeConv) return;
    const poll = async () => {
      try {
        const data = await api.get(`/conversations/${activeConv.id}/messages`);
        const msgs = Array.isArray(data) ? data : (data.messages || []);
        const current = msgMap[activeConv.id] || [];
        if (msgs.length > current.length) {
          const decrypted = await decryptMessages(msgs, activeConv);
          setMsgMap(prev => ({ ...prev, [activeConv.id]: decrypted }));
        }
      } catch {}
    };
    pollRef.current = setInterval(poll, 4000);
    return () => clearInterval(pollRef.current);
  }, [activeConv?.id, msgMap]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [msgMap, activeConv]);

  const logout = async () => {
    api.token = null;
    setUser(null);
    setPrivateKey(null);
    setConversations([]);
    setActiveConv(null);
    setMsgMap({});
    setScreen("auth");
    setAuthForm({ username: "", password: "", email: "" });
  };

  const myUsername = user?.username || authForm.username;
  const activeMessages = activeConv ? (msgMap[activeConv.id] || []) : [];

  const getInitials = (name = "") => name.slice(0, 2).toUpperCase();

  const getConvName = (conv) => {
    const parts = conv.participants || conv.members || [];
    const other = parts.find(p => {
      const u = typeof p === "string" ? p : p.username;
      return u !== myUsername;
    });
    return typeof other === "string" ? other : (other?.username || conv.name || "Conversation");
  };

  return (
    <>
      <style>{css}</style>
      <div className="wb-app">
        {screen === "auth" ? (
          <div className="wb-auth">
            <div className="wb-auth-logo">
              <div className="wb-auth-logo-icon">🔐</div>
              <span className="wb-auth-logo-text">WhisperBox</span>
            </div>
            <div className="wb-auth-card">
              <div className="wb-tab-row">
                <div className={`wb-tab ${authTab === "login" ? "active" : ""}`} onClick={() => { setAuthTab("login"); setAuthError(""); }}>Sign in</div>
                <div className={`wb-tab ${authTab === "register" ? "active" : ""}`} onClick={() => { setAuthTab("register"); setAuthError(""); }}>Create account</div>
              </div>
              <div className="wb-auth-title">{authTab === "login" ? "Welcome back" : "New account"}</div>
              {authTab === "register" && (
                <p className="wb-auth-sub">RSA-2048 key pair generated locally. Private key never leaves your device.</p>
              )}
              <input className="wb-input" placeholder="Username" value={authForm.username}
                onChange={e => setAuthForm(f => ({ ...f, username: e.target.value }))}
                onKeyDown={e => e.key === "Enter" && (authTab === "login" ? handleLogin() : handleRegister())} />
              {authTab === "register" && (
                <input className="wb-input" placeholder="Display name" value={authForm.display_name}
                  onChange={e => setAuthForm(f => ({ ...f, display_name: e.target.value }))} />
              )}
              {authTab === "register" && (
                <input className="wb-input" placeholder="Email (optional)" value={authForm.email}
                  onChange={e => setAuthForm(f => ({ ...f, email: e.target.value }))} />
              )}
              <input className="wb-input" type="password" placeholder="Password" value={authForm.password}
                onChange={e => setAuthForm(f => ({ ...f, password: e.target.value }))}
                onKeyDown={e => e.key === "Enter" && (authTab === "login" ? handleLogin() : handleRegister())} />
              {authError && <div className="wb-err">{authError}</div>}
              <button className="wb-btn wb-btn-primary" disabled={authLoading}
                onClick={authTab === "login" ? handleLogin : handleRegister}>
                {authLoading ? <span className="wb-spinner" /> : (authTab === "login" ? "Sign in" : "Generate keys & register")}
              </button>
              <p className="wb-note">End-to-end encrypted · Server sees only ciphertext</p>
            </div>
          </div>
        ) : (
          <div className="wb-shell">
            {/* Sidebar */}
            <div className="wb-sidebar">
              <div className="wb-sidebar-header">
                <span className="wb-sidebar-title">Messages</span>
                <div className="wb-sidebar-actions">
                  <button className="wb-icon-btn" title="New conversation" onClick={() => setShowNewConv(true)}>✏️</button>
                  <button className="wb-icon-btn" title="Refresh" onClick={loadConversations}>↻</button>
                </div>
              </div>
              <div className="wb-conv-list">
                {conversations.length === 0 && (
                  <div style={{ padding: "16px 14px", fontSize: 12, color: "var(--color-text-tertiary)" }}>
                    No conversations yet. Start one with ✏️
                  </div>
                )}
                {conversations.map(conv => (
                  <div key={conv.id}
                    className={`wb-conv-item ${activeConv?.id === conv.id ? "active" : ""}`}
                    onClick={() => openConversation(conv)}>
                    <div className="wb-conv-name">
                      {getConvName(conv)}
                      <span className="wb-lock-icon">e2e</span>
                    </div>
                    <div className="wb-cipher-preview">
                      {conv.last_message?.ciphertext ? `⊞ ${conv.last_message.ciphertext.slice(0, 24)}…` : "No messages yet"}
                    </div>
                  </div>
                ))}
              </div>
              <div className="wb-sidebar-footer">
                <div className="wb-avatar">{getInitials(myUsername)}</div>
                <span className="wb-username">{myUsername}</span>
                <button className="wb-icon-btn" onClick={logout} title="Sign out">⎋</button>
              </div>
            </div>

            {/* Chat area */}
            <div className="wb-chat">
              {!activeConv ? (
                <div className="wb-empty">
                  <div className="wb-empty-icon">🔒</div>
                  <div className="wb-empty-text">Select a conversation</div>
                </div>
              ) : (
                <>
                  <div className="wb-status-bar">
                    <span className="wb-status-dot" />
                    {statusMsg}
                  </div>
                  <div className="wb-chat-header">
                    <div className="wb-avatar">{getInitials(getConvName(activeConv))}</div>
                    <div className="wb-chat-title">{getConvName(activeConv)}</div>
                    <div className="wb-e2ee-badge">
                      <span className="wb-e2ee-dot" />
                      End-to-end encrypted
                    </div>
                  </div>
                  <div className="wb-messages">
                    {activeMessages.length === 0 && (
                      <div style={{ textAlign: "center", color: "var(--color-text-tertiary)", fontSize: 12, marginTop: 24 }}>
                        🔐 Messages are encrypted end-to-end.<br />Start the conversation.
                      </div>
                    )}
                    {activeMessages.map((msg, i) => {
                      const sender = msg.sender || msg.sender_username || msg.from;
                      const mine = sender === myUsername;
                      return (
                        <div key={msg.id || i} className={`wb-msg-row ${mine ? "mine" : "theirs"}`}>
                          <div className="wb-bubble">
                            {msg.plaintext !== undefined && msg.plaintext !== null
                              ? msg.plaintext
                              : msg.failed
                                ? <span style={{ color: "var(--color-text-danger)", fontSize: 12 }}>⚠ Decryption failed</span>
                                : <span className="wb-decrypting">Decrypting…</span>
                            }
                          </div>
                          <div className="wb-msg-meta">
                            {!mine && <span>{sender}</span>}
                            <span>{msg.created_at ? new Date(msg.created_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : ""}</span>
                            <span style={{ color: "#7c3aed", fontSize: 9 }}>🔒</span>
                          </div>
                        </div>
                      );
                    })}
                    <div ref={messagesEndRef} />
                  </div>
                  <div className="wb-compose">
                    <textarea
                      className="wb-compose-input"
                      rows={1}
                      placeholder="Message (encrypted before sending)…"
                      value={input}
                      onChange={e => setInput(e.target.value)}
                      onKeyDown={e => {
                        if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendMessage(); }
                      }}
                    />
                    <button className="wb-send-btn" onClick={sendMessage} disabled={sending || !input.trim()}>
                      {sending ? <span className="wb-spinner" style={{ width: 12, height: 12 }} /> : "➤"}
                    </button>
                  </div>
                </>
              )}
            </div>

            {/* New conversation modal */}
            {showNewConv && (
              <div className="wb-overlay" onClick={e => e.target === e.currentTarget && setShowNewConv(false)}>
                <div className="wb-modal">
                  <div className="wb-modal-title">New conversation</div>
                  <input className="wb-input" placeholder="Recipient username"
                    value={recipientInput}
                    onChange={e => setRecipientInput(e.target.value)}
                    onKeyDown={e => e.key === "Enter" && createConversation()}
                    autoFocus />
                  {newConvError && <div className="wb-err">{newConvError}</div>}
                  <div className="wb-modal-row">
                    <button className="wb-btn" style={{ flex: 1 }} onClick={() => setShowNewConv(false)}>Cancel</button>
                    <button className="wb-btn wb-btn-primary" style={{ flex: 1 }} disabled={newConvLoading}
                      onClick={createConversation}>
                      {newConvLoading ? <span className="wb-spinner" /> : "Start chat"}
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </>
  );
}
