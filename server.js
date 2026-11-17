/**
 * MOONLIGHT // ZERO-TRACE EPHEMERAL COMMUNICATION BACKEND
 * Phase 2: Tor Hardened, Zero-Knowledge E2EE Relay Server
 * 
 * Strict Security Guarantees:
 * 1. Zero-Log & In-Memory: No database, no disk writes, no logging of IP addresses or messages.
 * 2. Zero-Knowledge Relay: The server NEVER receives the raw passcode or the E2EE AES key.
 *    It routes opaque encrypted ciphertext blobs and cannot inspect contents.
 * 3. Tor & Cross-Network Resilient: Heartbeat tuned for WAN/Tor latency (45-60s intervals).
 * 4. Passcode-Gated Sockets: Unauthenticated sockets are closed with code 4401.
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { WebSocketServer, WebSocket } = require('ws');

// Configuration
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';
const ROOM_PASSCODE = process.env.ROOM_PASSCODE || 'moonlight-alpha';

// Pre-compute expected SHA-256 auth hash for constant-time comparison
// Domain-separated salt ensures auth hash cannot be used to deduce the E2EE key
const EXPECTED_AUTH_HASH = crypto
  .createHash('sha256')
  .update(`moonlight-auth-v1:${ROOM_PASSCODE}`)
  .digest('hex');

// MIME types for static assets (Zero external dependencies)
const MIME_TYPES = {
  '.html': 'text/html; charset=UTF-8',
  '.js': 'application/javascript; charset=UTF-8',
  '.css': 'text/css; charset=UTF-8',
  '.json': 'application/json',
  '.svg': 'image/svg+xml'
};

// HTTP Server for serving the single-page client and health checks
const server = http.createServer((req, res) => {
  // Security Headers applied to every response
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; media-src 'self' data: blob:; connect-src 'self' ws: wss:; font-src 'self' data:; object-src 'none'; base-uri 'none';"
  );
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');

  // Health check endpoint for Render keep-alive
  if (req.url === '/healthz' || req.url === '/status') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok', epoch: Date.now() }));
    return;
  }

  // Normalize requested path
  let safePath = req.url.split('?')[0];
  if (safePath === '/' || safePath === '') {
    safePath = '/index.html';
  }

  const filePath = path.join(__dirname, 'public', safePath);

  // Path traversal protection
  if (!filePath.startsWith(path.join(__dirname, 'public'))) {
    res.writeHead(403, { 'Content-Type': 'text/plain' });
    res.end('Access Denied');
    return;
  }

  fs.stat(filePath, (err, stats) => {
    if (err || !stats.isFile()) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not Found');
      return;
    }

    const ext = path.extname(filePath).toLowerCase();
    const contentType = MIME_TYPES[ext] || 'application/octet-stream';

    res.writeHead(200, { 'Content-Type': contentType });
    const stream = fs.createReadStream(filePath);
    stream.pipe(res);
  });
});

// WebSocket Server (50MB maxPayload for high-res encrypted images & audio notes)
const wss = new WebSocketServer({
  server,
  maxPayload: 50 * 1024 * 1024
});

// In-Memory Active Client Set (Zero database, volatile RAM only)
const authenticatedClients = new Set();

/**
 * Broadcast message to all authenticated clients except the sender
 */
function broadcast(senderWs, payloadString) {
  for (const client of authenticatedClients) {
    if (client !== senderWs && client.readyState === WebSocket.OPEN) {
      try {
        client.send(payloadString);
      } catch (err) {
        // Drop failed sends silently (zero-log)
      }
    }
  }
}

/**
 * Broadcast active peer count to all authenticated clients
 */
function broadcastPeerCount() {
  const countMsg = JSON.stringify({
    type: 'peer_count',
    count: authenticatedClients.size
  });
  for (const client of authenticatedClients) {
    if (client.readyState === WebSocket.OPEN) {
      try {
        client.send(countMsg);
      } catch (err) {
        // Ignore
      }
    }
  }
}

// WebSocket Connection Handling
wss.on('connection', (ws) => {
  ws.isAuthenticated = false;
  ws.missedPings = 0;

  // Strict Passcode Gate: Socket MUST authenticate within 10 seconds or be closed
  const authTimeout = setTimeout(() => {
    if (!ws.isAuthenticated) {
      try {
        ws.send(JSON.stringify({ type: 'auth_error', message: 'Authentication timeout' }));
      } catch (_) {}
      ws.close(4408, 'Auth Timeout');
      setTimeout(() => ws.terminate(), 500);
    }
  }, 10000);

  ws.on('pong', () => {
    ws.missedPings = 0;
  });

  ws.on('message', (rawData) => {
    ws.missedPings = 0; // Any incoming data indicates circuit activity

    let message;
    try {
      message = JSON.parse(rawData.toString());
    } catch (e) {
      if (!ws.isAuthenticated) {
        ws.close(4400, 'Bad Request');
        setTimeout(() => ws.terminate(), 500);
      }
      return;
    }

    // 1. Authentication Handshake
    if (!ws.isAuthenticated) {
      if (message.type === 'auth' && typeof message.token === 'string') {
        const token = message.token;
        let isMatch = false;

        if (token.length === EXPECTED_AUTH_HASH.length) {
          try {
            isMatch = crypto.timingSafeEqual(
              Buffer.from(token, 'hex'),
              Buffer.from(EXPECTED_AUTH_HASH, 'hex')
            );
          } catch (_) {
            isMatch = false;
          }
        }

        if (isMatch) {
          clearTimeout(authTimeout);
          ws.isAuthenticated = true;
          authenticatedClients.add(ws);

          // Acknowledge successful auth
          ws.send(JSON.stringify({
            type: 'auth_success',
            peerCount: authenticatedClients.size
          }));

          broadcastPeerCount();
          return;
        }
      }

      // Invalid passcode: Send auth_error and close with 4401 Unauthorized
      clearTimeout(authTimeout);
      try {
        ws.send(JSON.stringify({ type: 'auth_error', message: 'Invalid room passcode' }));
      } catch (_) {}
      ws.close(4401, 'Unauthorized');
      setTimeout(() => {
        if (ws.readyState !== WebSocket.CLOSED) {
          ws.terminate();
        }
      }, 500);
      return;
    }

    // 2. Authenticated Relay Routing
    // The server ONLY handles opaque encrypted ciphertext blobs and system signals
    if (message.type === 'encrypted') {
      // Verify minimal envelope integrity: must contain iv and ciphertext
      if (typeof message.iv === 'string' && typeof message.ciphertext === 'string') {
        // Relay unreadable ciphertext payload directly to peers
        broadcast(ws, JSON.stringify({
          type: 'encrypted',
          iv: message.iv,
          ciphertext: message.ciphertext
        }));
      }
    }
  });

  ws.on('close', () => {
    clearTimeout(authTimeout);
    authenticatedClients.delete(ws);
    broadcastPeerCount();
  });

  ws.on('error', () => {
    clearTimeout(authTimeout);
    authenticatedClients.delete(ws);
    ws.terminate();
    broadcastPeerCount();
  });
});

/**
 * Tor & WAN Tolerant Heartbeat Mechanism
 * Tuned for multi-hop internet latency spikes (Render reverse proxies + Tor circuits).
 * - Interval: 50 seconds (keeps reverse-proxy TCP connections open)
 * - Missed Ping Threshold: 2 consecutive missed intervals (~100s grace period)
 */
const HEARTBEAT_INTERVAL_MS = 50000;
const MAX_MISSED_PINGS = 2;

const heartbeatTimer = setInterval(() => {
  wss.clients.forEach((ws) => {
    if (ws.missedPings >= MAX_MISSED_PINGS) {
      authenticatedClients.delete(ws);
      return ws.terminate();
    }

    ws.missedPings = (ws.missedPings || 0) + 1;
    if (ws.readyState === WebSocket.OPEN) {
      try {
        ws.ping();
      } catch (_) {}
    }
  });
}, HEARTBEAT_INTERVAL_MS);

// Cleanup on server termination
server.on('close', () => {
  clearInterval(heartbeatTimer);
});

// Start Server on all interfaces (0.0.0.0) for local network, container, and reverse proxy access
server.listen(PORT, HOST, () => {
  process.stdout.write(`[MOONLIGHT] Node.js Zero-Trace Server active on http://${HOST}:${PORT}\n`);
  process.stdout.write(`[MOONLIGHT] WAN/Tor-Tolerant Heartbeat: ${HEARTBEAT_INTERVAL_MS}ms | Payload limit: 50MB\n`);
});
