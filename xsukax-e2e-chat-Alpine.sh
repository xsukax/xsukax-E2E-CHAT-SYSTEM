#!/bin/sh
# xsukax E2E Chat System - Alpine Linux Installation Script
set -e

[ "$(id -u)" -ne 0 ] && { echo "Run as root: sudo $0"; exit 1; }

printf "Domain (e.g., chat.example.com): "
read DOMAIN

# Install dependencies
apk update && apk add --no-cache python3 py3-pip nginx iptables ip6tables
pip3 install --break-system-packages websockets

# Create directories first
mkdir -p /opt/chat/app
mkdir -p /opt/chat/static

# E2E encrypted server
cat > /opt/chat/app/server.py << 'EOF'
#!/usr/bin/env python3
import asyncio, websockets, json, logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('chat')

class E2EServer:
    def __init__(self):
        self.users = {}
        
    async def handle(self, ws):
        user_id = None
        try:
            async for msg in ws:
                data = json.loads(msg)
                
                if data['type'] == 'register':
                    user_id = data['id'][:8].upper()
                    self.users[user_id] = {'ws': ws, 'key': data.get('key')}
                    await ws.send(json.dumps({'type': 'registered', 'id': user_id}))
                    logger.info(f"User {user_id} connected")
                    
                elif data['type'] == 'request':
                    target = data['target'][:8].upper()
                    requester = data['from'][:8].upper()
                    if target in self.users:
                        # Forward request to target
                        await self.users[target]['ws'].send(json.dumps({
                            'type': 'incoming_request',
                            'from': requester
                        }))
                    else:
                        await ws.send(json.dumps({
                            'type': 'user_offline',
                            'user': target
                        }))
                        
                elif data['type'] == 'accept':
                    target = data['target'][:8].upper()
                    accepter = data['from'][:8].upper()
                    if target in self.users:
                        # Exchange keys between both users
                        if accepter in self.users and self.users[accepter]['key']:
                            # Send accepter's key to requester
                            await self.users[target]['ws'].send(json.dumps({
                                'type': 'accepted',
                                'user': accepter,
                                'key': self.users[accepter]['key']
                            }))
                            # Send requester's key to accepter
                            if self.users[target]['key']:
                                await ws.send(json.dumps({
                                    'type': 'key',
                                    'user': target,
                                    'key': self.users[target]['key']
                                }))
                                
                elif data['type'] == 'deny':
                    target = data['target'][:8].upper()
                    denier = data['from'][:8].upper()
                    if target in self.users:
                        await self.users[target]['ws'].send(json.dumps({
                            'type': 'denied',
                            'from': denier
                        }))
                        
                elif data['type'] in ['msg', 'file']:
                    target = data['to'][:8].upper()
                    if target in self.users:
                        await self.users[target]['ws'].send(json.dumps({
                            'type': data['type'],
                            'from': data['from'],
                            'data': data['data'],
                            'name': data.get('name'),
                            'size': data.get('size')
                        }))
                        
        except websockets.exceptions.ConnectionClosed:
            pass
        finally:
            if user_id and user_id in self.users:
                del self.users[user_id]
                logger.info(f"User {user_id} disconnected")

async def main():
    server = E2EServer()
    async with websockets.serve(server.handle, '0.0.0.0', 8765, max_size=5*1024*1024):
        logger.info("xsukax E2E Chat Server running on :8765")
        await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(main())
EOF

# HTML with responsive design
cat > /opt/chat/static/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<title>xsukax E2E Chat System</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; -webkit-tap-highlight-color: transparent; }
body { font-family: 'Courier New', monospace; background: #000; color: #0f0; padding: 10px; max-width: 800px; margin: 0 auto; height: 100vh; display: flex; flex-direction: column; }
h1 { font-size: 16px; margin-bottom: 10px; }
.box { border: 1px solid #0f0; padding: 10px; margin-bottom: 10px; }
input, button { background: #000; color: #0f0; border: 1px solid #0f0; padding: 8px; width: 100%; margin: 5px 0; font-family: inherit; font-size: 14px; -webkit-appearance: none; border-radius: 0; }
button { cursor: pointer; touch-action: manipulation; }
button:hover, button:active { background: #0f0; color: #000; }
#messages { flex: 1; overflow-y: auto; border: 1px solid #0f0; padding: 10px; margin: 10px 0; min-height: 200px; }
.msg { margin: 5px 0; word-wrap: break-word; word-break: break-word; }
.sent { color: #0ff; }
.received { color: #ff0; }
.system { color: #666; font-style: italic; }
.file-msg { background: #111; padding: 5px; border-radius: 3px; }
.file-msg a { color: #f0f; text-decoration: none; }
#status { color: #f0f; }
#myId { cursor: pointer; text-decoration: underline; }
.input-row { display: flex; gap: 5px; align-items: stretch; }
.input-row input { flex: 1; }
.input-row button { width: auto; padding: 8px 15px; white-space: nowrap; }
#fileBtn { padding: 8px 12px; }
.progress { height: 2px; background: #0f0; transition: width 0.3s; margin-top: 5px; }
.modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.8); z-index: 1000; }
.modal-content { position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); background: #000; border: 2px solid #0f0; padding: 20px; max-width: 400px; width: 90%; }
.modal-buttons { display: flex; gap: 10px; margin-top: 15px; }
.modal-buttons button { flex: 1; }
@media (max-width: 600px) {
  body { padding: 5px; }
  h1 { font-size: 14px; }
  .box { padding: 8px; margin-bottom: 8px; }
  input, button { padding: 10px; font-size: 16px; }
  .input-row { flex-direction: column; }
  .input-row button { width: 100%; }
  #messages { min-height: 150px; }
}
</style>
</head>
<body>
<h1>🔒 xsukax E2E CHAT SYSTEM</h1>
<div class="box">
  <div>ID: <span id="myId" title="Click to copy">--------</span></div>
  <div>Status: <span id="status">Disconnected</span></div>
</div>
<div class="box">
  <input id="targetId" placeholder="Enter target ID (8 chars)" maxlength="8" style="text-transform:uppercase">
  <button onclick="connect()">Connect to Peer</button>
</div>
<div id="messages"></div>
<div class="box">
  <div class="input-row">
    <input id="msgInput" placeholder="Type message..." disabled>
    <button onclick="sendMsg()" disabled id="sendBtn">Send</button>
  </div>
  <div class="input-row">
    <input type="file" id="fileInput" disabled style="display:none">
    <button onclick="document.getElementById('fileInput').click()" disabled id="fileBtn">📎 File</button>
  </div>
  <div class="progress" id="progress" style="width:0%"></div>
</div>

<!-- Custom modal for connection requests -->
<div id="requestModal" class="modal">
  <div class="modal-content">
    <div id="requestText">Connection request</div>
    <div class="modal-buttons">
      <button onclick="handleRequest(true)" style="background:#0f0;color:#000;">Accept</button>
      <button onclick="handleRequest(false)">Deny</button>
    </div>
  </div>
</div>

<script>
let ws, myId, myKeys, peerKey, peerId, pendingRequest;

myId = localStorage.getItem('chatId') || Array(8).fill().map(() => 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'[Math.floor(Math.random() * 36)]).join('');
localStorage.setItem('chatId', myId);
document.getElementById('myId').textContent = myId;

document.getElementById('myId').onclick = async () => {
  try {
    await navigator.clipboard.writeText(myId);
    document.getElementById('myId').textContent = 'Copied!';
    setTimeout(() => { document.getElementById('myId').textContent = myId; }, 1000);
  } catch {
    const t = document.createElement('textarea');
    t.value = myId;
    document.body.appendChild(t);
    t.select();
    document.execCommand('copy');
    document.body.removeChild(t);
    document.getElementById('myId').textContent = 'Copied!';
    setTimeout(() => { document.getElementById('myId').textContent = myId; }, 1000);
  }
};

document.getElementById('msgInput').onkeypress = (e) => { if(e.key === 'Enter') sendMsg(); };
document.getElementById('fileInput').onchange = () => { if(document.getElementById('fileInput').files[0]) sendFile(); };

function showRequestModal(fromUser) {
  pendingRequest = fromUser;
  document.getElementById('requestText').textContent = `User ${fromUser} wants to chat with you. Accept?`;
  document.getElementById('requestModal').style.display = 'block';
  // Auto-focus on Accept button
  setTimeout(() => {
    document.querySelector('#requestModal button').focus();
  }, 100);
}

function handleRequest(accept) {
  document.getElementById('requestModal').style.display = 'none';
  if (pendingRequest) {
    if (accept) {
      ws.send(JSON.stringify({ type: 'accept', from: myId, target: pendingRequest }));
      addMsg('System', `Accepted chat with ${pendingRequest}`, 'system');
    } else {
      ws.send(JSON.stringify({ type: 'deny', from: myId, target: pendingRequest }));
      addMsg('System', `Denied chat with ${pendingRequest}`, 'system');
    }
    pendingRequest = null;
  }
}

async function generateKeys() {
  myKeys = await crypto.subtle.generateKey(
    { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true, ['encrypt', 'decrypt']
  );
  return await crypto.subtle.exportKey('jwk', myKeys.publicKey);
}

async function rsaEncrypt(data, pubKey) {
  const key = await crypto.subtle.importKey('jwk', pubKey, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
  const encrypted = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, key, data);
  return btoa(String.fromCharCode(...new Uint8Array(encrypted)));
}

async function rsaDecrypt(data) {
  const encrypted = Uint8Array.from(atob(data), c => c.charCodeAt(0));
  return await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, myKeys.privateKey, encrypted);
}

async function generateAESKey() {
  return await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}

async function aesEncrypt(data, key) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
  const combined = new Uint8Array(iv.length + encrypted.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(encrypted), iv.length);
  return combined;
}

async function aesDecrypt(combined, key) {
  const iv = combined.slice(0, 12);
  const data = combined.slice(12);
  return await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
}

async function initWS() {
  const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
  ws = new WebSocket(`${protocol}//${location.host}/ws`);
  
  ws.onopen = async () => {
    document.getElementById('status').textContent = 'Connected';
    const pubKey = await generateKeys();
    ws.send(JSON.stringify({ type: 'register', id: myId, key: pubKey }));
  };
  
  ws.onmessage = async (e) => {
    const data = JSON.parse(e.data);
    
    if (data.type === 'registered') {
      addMsg('System', `Connected as ${data.id}`, 'system');
    } else if (data.type === 'incoming_request') {
      showRequestModal(data.from);
    } else if (data.type === 'accepted') {
      peerKey = data.key;
      peerId = data.user;
      document.getElementById('msgInput').disabled = false;
      document.getElementById('sendBtn').disabled = false;
      document.getElementById('fileInput').disabled = false;
      document.getElementById('fileBtn').disabled = false;
      addMsg('System', `✅ ${peerId} accepted! E2E established`, 'system');
    } else if (data.type === 'key') {
      peerKey = data.key;
      peerId = data.user;
      document.getElementById('msgInput').disabled = false;
      document.getElementById('sendBtn').disabled = false;
      document.getElementById('fileInput').disabled = false;
      document.getElementById('fileBtn').disabled = false;
      addMsg('System', `🔐 E2E with ${peerId}`, 'system');
    } else if (data.type === 'denied') {
      addMsg('System', `❌ ${data.from} denied your request`, 'system');
    } else if (data.type === 'user_offline') {
      addMsg('System', `⚠️ ${data.user} is offline`, 'system');
    } else if (data.type === 'msg') {
      try {
        const decrypted = await rsaDecrypt(data.data);
        addMsg(data.from, new TextDecoder().decode(decrypted), 'received');
      } catch {
        addMsg('System', 'Decrypt failed', 'system');
      }
    } else if (data.type === 'file') {
      await receiveFile(data);
    }
  };
  
  ws.onclose = () => {
    document.getElementById('status').textContent = 'Disconnected';
    setTimeout(initWS, 3000);
  };
}

function connect() {
  peerId = document.getElementById('targetId').value.toUpperCase();
  if (peerId.length !== 8) return alert('ID must be 8 characters');
  if (peerId === myId) return alert('Cannot connect to yourself');
  ws.send(JSON.stringify({ type: 'request', from: myId, target: peerId }));
  addMsg('System', `📤 Request sent to ${peerId}...`, 'system');
}

async function sendMsg() {
  const input = document.getElementById('msgInput');
  const msg = input.value.trim();
  if (!msg || !peerKey) return;
  
  const encrypted = await rsaEncrypt(new TextEncoder().encode(msg), peerKey);
  ws.send(JSON.stringify({ type: 'msg', from: myId, to: peerId, data: encrypted }));
  addMsg('You', msg, 'sent');
  input.value = '';
}

async function sendFile() {
  const file = document.getElementById('fileInput').files[0];
  if (!file || !peerKey) return;
  
  if (file.size > 1024 * 1024) {
    alert('File too large! Max 1MB');
    return;
  }
  
  try {
    const progress = document.getElementById('progress');
    progress.style.width = '40%';
    
    const buffer = await file.arrayBuffer();
    const aesKey = await generateAESKey();
    const encryptedFile = await aesEncrypt(new Uint8Array(buffer), aesKey);
    progress.style.width = '70%';
    
    const rawKey = await crypto.subtle.exportKey('raw', aesKey);
    const encryptedKey = await rsaEncrypt(new Uint8Array(rawKey), peerKey);
    
    ws.send(JSON.stringify({
      type: 'file',
      from: myId,
      to: peerId,
      data: {
        key: encryptedKey,
        file: btoa(String.fromCharCode.apply(null, new Uint8Array(encryptedFile)))
      },
      name: file.name,
      size: file.size
    }));
    
    progress.style.width = '100%';
    addMsg('You', `📎 ${file.name} (${(file.size/1024).toFixed(1)}KB)`, 'sent file-msg');
    setTimeout(() => { progress.style.width = '0%'; }, 1000);
    document.getElementById('fileInput').value = '';
  } catch (err) {
    alert('Send failed');
    document.getElementById('progress').style.width = '0%';
  }
}

async function receiveFile(data) {
  try {
    const encryptedKey = await rsaDecrypt(data.data.key);
    const aesKey = await crypto.subtle.importKey('raw', encryptedKey, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
    const encryptedFile = Uint8Array.from(atob(data.data.file), c => c.charCodeAt(0));
    const decryptedFile = await aesDecrypt(encryptedFile, aesKey);
    
    const blob = new Blob([decryptedFile]);
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = data.name;
    a.textContent = `💾 ${data.name}`;
    
    const fileMsg = document.createElement('div');
    fileMsg.className = 'msg received file-msg';
    fileMsg.innerHTML = `[${new Date().toLocaleTimeString()}] ${data.from}: `;
    fileMsg.appendChild(a);
    document.getElementById('messages').appendChild(fileMsg);
    
    a.click();
  } catch {
    addMsg('System', '❌ File decrypt failed', 'system');
  }
}

function addMsg(from, text, cls) {
  const div = document.createElement('div');
  div.className = `msg ${cls}`;
  div.textContent = `[${new Date().toLocaleTimeString()}] ${from}: ${text}`;
  const container = document.getElementById('messages');
  container.appendChild(div);
  container.scrollTop = container.scrollHeight;
}

initWS();
</script>
</body>
</html>
EOF

# Nginx config
cat > /etc/nginx/http.d/chat.conf << EOF
server {
    listen 80;
    server_name $DOMAIN;
    root /opt/chat/static;
    client_max_body_size 5M;
    
    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Referrer-Policy "strict-origin-when-cross-origin";
    
    location / {
        try_files \$uri /index.html;
    }
    
    location /ws {
        proxy_pass http://127.0.0.1:8765;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
}
EOF

# OpenRC service script
cat > /etc/init.d/chat << 'EOF'
#!/sbin/openrc-run

name="xsukax E2E Chat"
description="End-to-End Encrypted Chat Server"

command="/usr/bin/python3"
command_args="/opt/chat/app/server.py"
command_user="nobody"
command_background="yes"
pidfile="/run/chat.pid"
directory="/opt/chat/app"

depend() {
    need net
    after nginx
}

start_pre() {
    checkpath --directory --owner "$command_user" --mode 0755 /run
}
EOF

chmod +x /opt/chat/app/server.py /etc/init.d/chat

# Configure firewall with iptables
# Flush existing rules
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

# Set default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT

# Allow established connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow SSH (port 22)
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Allow HTTP (port 80)
iptables -A INPUT -p tcp --dport 80 -j ACCEPT

# Allow HTTPS (port 443) - for future SSL setup
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Save iptables rules
/etc/init.d/iptables save

# Configure services
rc-update add iptables boot
rc-update add nginx default
rc-update add chat default

# Remove default nginx config if exists
rm -f /etc/nginx/http.d/default.conf

# Start services
service nginx restart
service chat start

echo "
✅ xsukax E2E Chat System Installed on Alpine Linux
🌐 Access: http://$DOMAIN
🔒 Features: RSA-2048 + AES-256-GCM encryption
📱 Mobile responsive interface
🛡️  Firewall configured (SSH, HTTP, HTTPS only)

Services Status:
$(service nginx status)
$(service chat status)
"