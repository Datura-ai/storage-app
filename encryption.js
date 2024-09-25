async function derive_key(pubkey, password) {
    const enc = new TextEncoder();
    const enc_pubkey = enc.encode(pubkey); // Convert to ArrayBuffer
    const enc_password = enc.encode(password); // Convert to ArrayBuffer
    const material = await crypto.subtle.importKey(  // Derive key using PBKDF2 with 100,000 iterations
        'raw', enc_pubkey, { name: 'PBKDF2' }, false, ['deriveKey']);
    return crypto.subtle.deriveKey(
        {name: 'PBKDF2', salt: enc_password, iterations: 100000, hash: 'SHA-256'},
        material, {name: 'AES-GCM', length: 256}, false, ['encrypt', 'decrypt']);
}

async function encrypt(key, plaintext) {
    const enc = new TextEncoder();
    const plaintextBuffer = enc.encode(plaintext); // Convert to ArrayBuffer
    const iv = window.crypto.getRandomValues(new Uint8Array(12)); // Generate a random 12-byte IV (standard for GCM)
    const encryptedBuffer = await crypto.subtle.encrypt(
        {name: "AES-GCM", iv: iv}, key, plaintextBuffer); // Encrypt using AES-GCM
    // Combine IV + Encrypted data + Tag (Tag is included in the encryptedBuffer automatically)
    const encryptedData = new Uint8Array(encryptedBuffer);
    const result = new Uint8Array(iv.length + encryptedData.length);
    result.set(iv);
    result.set(encryptedData, iv.length);
    return result;
}

async function decrypt(key, encrypted) {
    const iv = encrypted.slice(0, 12); // Extract IV (first 12 bytes) and encrypted message
    const ciphertext = encrypted.slice(12);
    const decryptedBuffer = await crypto.subtle.decrypt(
        {name: "AES-GCM", iv: iv}, key, ciphertext); // Decrypt using AES-GCM
    const dec = new TextDecoder();
    return dec.decode(decryptedBuffer); // Convert ArrayBuffer to string
}

async function test() {
    const key = await derive_key('my_key', 'my_pass');
    const plaintext = "Hello, World!";
    const encrypted = await encrypt(key, plaintext);
    const decrypted = await decrypt(key, encrypted);
    console.log(`Encrypted: ${encrypted}`);
    console.log(`Decrypted: ${decrypted}`);
}

test();
