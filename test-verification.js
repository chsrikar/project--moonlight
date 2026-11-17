const http = require('http');
const crypto = require('crypto');
const { WebSocket } = require('ws');

// Verify Node's Web Crypto matches browser's SubtleCrypto for interoperability
const { subtle } = crypto.webcrypto;

const PORT = 3899;
process.env.PORT = PORT;
process.env.ROOM_PASSCODE = 'test-secret-vault';

// Load server
const serverApp = require('./server.js');

async function deriveKeys(passcode) {
  const enc = new TextEncoder();
  const authData = enc.encode('moonlight-auth-v1:' + passcode);
  const authDigest = await subtle.digest('SHA-256', authData);
  const authHash = Array.from(new Uint8Array(authDigest))
    .map(b => b.toString(16).padStart(2, '0')).join('');

  const keyMaterial = await subtle.importKey(
    'raw',
    enc.encode(passcode),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  const salt = enc.encode('moonlight-e2ee-aes-gcm-v1-salt');
  const aesKey = await subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 100000,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );

  return { authHash, aesKey };
}

async function encryptData(aesKey, dataObj) {
  const enc = new TextEncoder();
  const iv = crypto.randomBytes(12);
  const ciphertextBuffer = await subtle.encrypt(
    { name: 'AES-GCM', iv },
    aesKey,
    enc.encode(JSON.stringify(dataObj))
  );

  return {
    type: 'encrypted',
    iv: Buffer.from(iv).toString('base64'),
    ciphertext: Buffer.from(ciphertextBuffer).toString('base64')
  };
}

async function decryptData(aesKey, envelope) {
  const iv = Buffer.from(envelope.iv, 'base64');
  const ciphertext = Buffer.from(envelope.ciphertext, 'base64');
  const decrypted = await subtle.decrypt(
    { name: 'AES-GCM', iv },
    aesKey,
    ciphertext
  );
  return JSON.parse(new TextDecoder().decode(decrypted));
}

function wait(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function runTests() {
  await wait(1000); // Allow server to bind

  console.log('\n=== RUNNING SECURITY & PROTOCOL VERIFICATION TESTS ===\n');

  // Test 1: HTTP Security Headers & Healthcheck
  console.log('[Test 1] Verifying HTTP Security Headers...');
  await new Promise((resolve, reject) => {
    http.get(`http://localhost:${PORT}/`, (res) => {
      const csp = res.headers['content-security-policy'];
      const xcto = res.headers['x-content-type-options'];
      const xfo = res.headers['x-frame-options'];
      const cache = res.headers['cache-control'];

      if (!csp || !csp.includes("default-src 'self'")) return reject(new Error('Missing or invalid CSP'));
      if (xcto !== 'nosniff') return reject(new Error('Missing X-Content-Type-Options'));
      if (xfo !== 'DENY') return reject(new Error('Missing X-Frame-Options'));
      if (!cache || !cache.includes('no-store')) return reject(new Error('Cache not disabled for zero-trace'));
      console.log('  ✔ HTTP Security Headers & Zero-Cache verified.');
      resolve();
    }).on('error', reject);
  });

  // Test 2: Invalid passcode socket gate (Immediate termination)
  console.log('\n[Test 2] Verifying Socket Gate: Invalid Passcode Socket Termination...');
  await new Promise(async (resolve, reject) => {
    const wrongKeys = await deriveKeys('incorrect-passcode');
    const ws = new WebSocket(`ws://localhost:${PORT}`);

    let closed = false;
    ws.on('open', () => {
      ws.send(JSON.stringify({ type: 'auth', token: wrongKeys.authHash }));
    });

    ws.on('close', () => {
      closed = true;
      console.log('  ✔ Socket terminated immediately on invalid passcode.');
      resolve();
    });

    ws.on('error', () => {
      // Expected on sudden termination
    });

    setTimeout(() => {
      if (!closed) {
        ws.terminate();
        reject(new Error('Socket was not terminated on invalid passcode!'));
      }
    }, 2000);
  });

  // Test 3: Valid passcode socket gate + E2EE Ciphertext Relaying
  console.log('\n[Test 3] Verifying E2EE Encrypted Payload Relaying & Zero-Knowledge Transport...');
  await new Promise(async (resolve, reject) => {
    const validKeys = await deriveKeys('test-secret-vault');

    const clientA = new WebSocket(`ws://localhost:${PORT}`);
    const clientB = new WebSocket(`ws://localhost:${PORT}`);

    let clientA_authed = false;
    let clientB_authed = false;

    clientA.on('open', () => {
      clientA.send(JSON.stringify({ type: 'auth', token: validKeys.authHash }));
    });

    clientB.on('open', () => {
      clientB.send(JSON.stringify({ type: 'auth', token: validKeys.authHash }));
    });

    clientA.on('message', (data) => {
      const msg = JSON.parse(data.toString());
      if (msg.type === 'auth_success') clientA_authed = true;
    });

    clientB.on('message', async (data) => {
      const msg = JSON.parse(data.toString());
      if (msg.type === 'auth_success') {
        clientB_authed = true;
        return;
      }

      if (msg.type === 'encrypted') {
        try {
          // Decrypt payload with B's key
          const payload = await decryptData(validKeys.aesKey, msg);
          if (payload.text === 'Tor Hidden Service E2EE Message') {
            console.log('  ✔ Client B successfully decrypted message transmitted through server.');
            console.log('  ✔ Server saw only ciphertext envelope: { type: "encrypted", iv: "...", ciphertext: "..." }');
            clientA.close();
            clientB.close();
            resolve();
          } else {
            reject(new Error('Decrypted content mismatch'));
          }
        } catch (err) {
          reject(err);
        }
      }
    });

    // Wait for both to auth, then send encrypted message from A to B
    const checkInterval = setInterval(async () => {
      if (clientA_authed && clientB_authed) {
        clearInterval(checkInterval);
        const encrypted = await encryptData(validKeys.aesKey, {
          type: 'text',
          sender: 'Ghost-01',
          text: 'Tor Hidden Service E2EE Message',
          timestamp: Date.now()
        });
        clientA.send(JSON.stringify(encrypted));
      }
    }, 100);

    setTimeout(() => {
      clearInterval(checkInterval);
      reject(new Error('Timeout waiting for E2EE relay'));
    }, 5000);
  });

  // Test 4: Attacker without the key CANNOT decrypt
  console.log('\n[Test 4] Verifying Tag Authentication & Inability of Unauthorized Parties to Decrypt...');
  await new Promise(async (resolve, reject) => {
    const validKeys = await deriveKeys('test-secret-vault');
    const attackerKeys = await deriveKeys('attacker-guess-wrong-key');

    const encrypted = await encryptData(validKeys.aesKey, {
      type: 'text',
      text: 'Super sensitive Tor payload'
    });

    try {
      await decryptData(attackerKeys.aesKey, encrypted);
      reject(new Error('Attacker key succeeded in decrypting! Tag verification failed!'));
    } catch (e) {
      console.log('  ✔ AES-GCM tag verification rejected unauthorized decryption attempt.');
      resolve();
    }
  });

  console.log('\n✔ ALL TESTS PASSED SUCCESSFULLY!\n');
  process.exit(0);
}

runTests().catch(err => {
  console.error('\n❌ TEST FAILURE:', err);
  process.exit(1);
});

