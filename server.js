/**
 * MOONLIGHT // ZERO-TRACE EPHEMERAL COMMUNICATION BACKEND
 * Phase 2+: Ghost-Pruning, Target-Addressed E2EE Signaling & Peer Tracking
 * 
 * Strict Security Guarantees:
 * 1. Zero-Log & In-Memory: No database, no disk writes, no logging of IP addresses or messages.
 * 2. Zero-Knowledge Relay: The server NEVER receives the raw passcode or the E2EE AES key.
 *    It routes opaque encrypted ciphertext blobs and cannot inspect contents.
 * 3. Ghost Pruning: Stale sockets from browser reloads/network shifts are immediately pruned.
 * 4. Target Addressability: WebRTC signaling can be addressed 1-to-1 so calls never collide.
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
const EXPECTED_AUTH_HASH = crypto
  .createHash('sha256')
  .update(`moonlight-auth-v1:${ROOM_PASSCODE}`)
  .digest('hex');

// MIME types for static assets
const MIME_TYPES = {
  '.html': 'text/html; charset=UTF-8',
  '.js': 'application/javascript; charset=UTF-8',
  '.css': 'text/css; charset=UTF-8',
  '.json': 'application/json',
  '.svg': 'image/svg+xml'
};

// HTTP Server for serving the single-page client and health checks
const server = http.createServer((req, res) => {
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

  let safePath = req.url.split('?')[0];
  if (safePath === '/' || safePath === '') {
    safePath = '/index.html';
  }

  const filePath = path.join(__dirname, 'public', safePath);

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

// In-Memory Active Clients Map: clientId -> { id, ws, alias, sessionId }
const clients = new Map();

/**
 * Get sanitized peer list for broadcasting
 */
function getPeerList() {
  const list = [];
  for (const client of clients.values()) {
    list.push({ id: client.id, alias: client.alias });
  }
  return list;
}

/**
 * Broadcast message to all authenticated clients except the sender
 */
function broadcastExcept(senderWs, payloadString) {
  for (const client of clients.values()) {
    if (client.ws !== senderWs && client.ws.readyState === WebSocket.OPEN) {
      try {
        client.ws.send(payloadString);
      } catch (_) {}
    }
  }
}

/**
 * Broadcast peer roster and count updates
 */
function broadcastPeerRoster() {
  const peerList = getPeerList();
  const updateMsg = JSON.stringify({
    type: 'peer_roster',
    count: peerList.length,
    peers: peerList
  });

  for (const client of clients.values()) {
    if (client.ws.readyState === WebSocket.OPEN) {
      try {
        client.ws.send(updateMsg);
      } catch (_) {}
    }
  }
}

// WebSocket Connection Handling
wss.on('connection', (ws) => {
  ws.isAuthenticated = false;
  ws.clientId = null;
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
    ws.missedPings = 0;

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

    // 1. Authentication Handshake with Session Deduplication
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

          const clientId = 'peer_' + crypto.randomBytes(6).toString('hex');
          const clientAlias = (typeof message.alias === 'string' && message.alias.trim())
            ? message.alias.trim().slice(0, 24)
            : 'Anon-' + clientId.slice(5, 9);
          const sessionId = typeof message.sessionId === 'string' ? message.sessionId : null;

          // Ghost Pruning: If same browser tab refreshed with same sessionId or alias, prune the old stale socket immediately
          if (sessionId || clientAlias) {
            for (const [existingId, existingClient] of clients.entries()) {
              if (
                (sessionId && existingClient.sessionId === sessionId) ||
                (clientAlias && existingClient.alias === clientAlias)
              ) {
                try {
                  existingClient.ws.terminate();
                } catch (_) {}
                clients.delete(existingId);
              }
            }
          }

          ws.clientId = clientId;
          clients.set(clientId, {
            id: clientId,
            ws: ws,
            alias: clientAlias,
            sessionId: sessionId
          });

          // Send welcome packet with their assigned ID and current peer roster
          ws.send(JSON.stringify({
            type: 'auth_success',
            myId: clientId,
            myAlias: clientAlias,
            peerCount: clients.size,
            peers: getPeerList()
          }));

          // Announce peer entry to others
          broadcastExcept(ws, JSON.stringify({
            type: 'peer_joined',
            peer: { id: clientId, alias: clientAlias }
          }));

          broadcastPeerRoster();
          return;
        }
      }

      // Invalid passcode: Close with 4401 Unauthorized
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
    if (message.type === 'encrypted') {
      if (typeof message.iv === 'string' && typeof message.ciphertext === 'string') {
        // Targeted 1-to-1 message (WebRTC offer, answer, candidate)
        if (message.targetId && typeof message.targetId === 'string') {
          const targetClient = clients.get(message.targetId);
          if (targetClient && targetClient.ws.readyState === WebSocket.OPEN) {
            try {
              targetClient.ws.send(JSON.stringify({
                type: 'encrypted',
                fromId: ws.clientId,
                targetId: message.targetId,
                iv: message.iv,
                ciphertext: message.ciphertext
              }));
            } catch (_) {}
          }
        } else {
          // Room Broadcast (Text, Images, Audio notes)
          broadcastExcept(ws, JSON.stringify({
            type: 'encrypted',
            fromId: ws.clientId,
            iv: message.iv,
            ciphertext: message.ciphertext
          }));
        }
      }
    }
  });

  function handleDisconnect() {
    clearTimeout(authTimeout);
    if (ws.clientId && clients.has(ws.clientId)) {
      const client = clients.get(ws.clientId);
      clients.delete(ws.clientId);

      // Announce exit to others
      broadcastExcept(ws, JSON.stringify({
        type: 'peer_left',
        peerId: client.id,
        alias: client.alias
      }));

      broadcastPeerRoster();
    }
  }

  ws.on('close', handleDisconnect);
  ws.on('error', () => {
    handleDisconnect();
    ws.terminate();
  });
});

/**
 * Fast Ghost-Socket Cleanup Heartbeat
 * Runs every 25 seconds; terminates dead TCP sockets after 1 missed ping
 */
const HEARTBEAT_INTERVAL_MS = 25000;

const heartbeatTimer = setInterval(() => {
  for (const [id, client] of clients.entries()) {
    if (client.ws.missedPings >= 1) {
      try {
        client.ws.terminate();
      } catch (_) {}
      clients.delete(id);
      broadcastPeerRoster();
      continue;
    }

    client.ws.missedPings = (client.ws.missedPings || 0) + 1;
    if (client.ws.readyState === WebSocket.OPEN) {
      try {
        client.ws.ping();
      } catch (_) {}
    }
  }
}, HEARTBEAT_INTERVAL_MS);

server.on('close', () => {
  clearInterval(heartbeatTimer);
});

// Start Server on all interfaces (0.0.0.0)
server.listen(PORT, HOST, () => {
  process.stdout.write(`[MOONLIGHT] Zero-Trace Server active on http://${HOST}:${PORT}\n`);
  process.stdout.write(`[MOONLIGHT] Active Ghost Pruning: ${HEARTBEAT_INTERVAL_MS}ms | Payload limit: 50MB\n`);
});
