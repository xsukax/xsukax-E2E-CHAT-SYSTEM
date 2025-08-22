#!/bin/bash
# xsukax E2E Chat System with Admin Panel
set -e

[[ $EUID -ne 0 ]] && { echo "Run as root: sudo $0"; exit 1; }

read -p "Domain (e.g., chat.example.com): " DOMAIN
read -p "Admin password (default: xsukax_admin): " ADMIN_PASS
ADMIN_PASS=${ADMIN_PASS:-xsukax_admin}

apt update && apt install -y python3 python3-pip nginx ufw
pip3 install websockets --break-system-packages

mkdir -p /opt/chat/{app,static,logs}
mkdir -p /var/log/xsukax

# Generate admin password hash
ADMIN_HASH=$(python3 -c "import hashlib; print(hashlib.sha256('$ADMIN_PASS'.encode()).hexdigest())")

# Create server configuration
cat > /opt/chat/config.json << EOF
{
  "admin_password_hash": "$ADMIN_HASH",
  "security": {
    "require_https": false,
    "rate_limit": 30,
    "max_users": 1000,
    "blocked_ids": []
  },
  "privacy": {
    "log_connections": true,
    "log_retention_days": 7
  },
  "maintenance": {
    "enabled": false,
    "message": "Server under maintenance"
  }
}
EOF

# E2E encrypted server with admin panel
cat > /opt/chat/app/server.py << 'EOF'
#!/usr/bin/env python3
import asyncio, websockets, json, logging, time, hashlib, os, sys
from datetime import datetime
import traceback

# Setup logging with debug for IP troubleshooting
logging.basicConfig(
    level=logging.DEBUG,  # Enable debug to troubleshoot IP detection
    format='%(asctime)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/xsukax/chat.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('xsukax')

class AdminServer:
    def __init__(self):
        self.config = self.load_config()
        self.stats = {
            'start_time': time.time(),
            'messages_total': 0,
            'messages_hour': {},
            'connections_total': 0
        }
        self.admin_sessions = set()
    
    def load_config(self):
        try:
            with open('/opt/chat/config.json', 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            return {}
    
    def save_config(self):
        try:
            with open('/opt/chat/config.json', 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save config: {e}")
    
    def verify_admin(self, password):
        expected_hash = self.config.get('admin_password_hash', '')
        if not expected_hash:
            return False
        return hashlib.sha256(password.encode()).hexdigest() == expected_hash
    
    def get_stats(self):
        uptime = int(time.time() - self.stats['start_time'])
        hours = uptime // 3600
        minutes = (uptime % 3600) // 60
        
        return {
            'uptime': f"{hours}h {minutes}m",
            'active_users': len(chat_server.users),
            'messages_total': self.stats['messages_total'],
            'messages_hour': self.stats.get('messages_hour', {}),
            'connections_total': self.stats['connections_total'],
            'memory_mb': self.get_memory_usage()
        }
    
    def get_memory_usage(self):
        try:
            import resource
            return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
        except:
            return 0

class E2EServer:
    def __init__(self, admin):
        self.users = {}
        self.admin = admin
        self.rate_limits = {}
        self.ping_tasks = {}
    
    def check_rate_limit(self, user_id):
        # Get rate limit from config
        rate_limit = self.admin.config.get('security', {}).get('rate_limit', 30)
        
        # If rate limit is 0, unlimited
        if rate_limit <= 0:
            return True
        
        now = time.time()
        if user_id not in self.rate_limits:
            self.rate_limits[user_id] = []
        
        # Clean old entries (older than 1 minute)
        self.rate_limits[user_id] = [t for t in self.rate_limits[user_id] if now - t < 60]
        
        # Check if limit exceeded
        if len(self.rate_limits[user_id]) >= rate_limit:
            logger.info(f"Rate limit exceeded for user {user_id}: {len(self.rate_limits[user_id])}/{rate_limit}")
            return False
        
        # Add current timestamp
        self.rate_limits[user_id].append(now)
        return True
    
    def is_blocked(self, user_id):
        security = self.admin.config.get('security', {})
        blocked_ids = security.get('blocked_ids', [])
        return user_id in blocked_ids
    
    def get_real_ip(self, ws):
        """Extract real IP for logging purposes only"""
        # Try different ways to access headers
        headers = None
        
        # Method 1: request_headers (most common)
        if hasattr(ws, 'request_headers'):
            headers = ws.request_headers
            logger.debug(f"Found request_headers: {dict(headers) if headers else 'None'}")
        
        # Method 2: headers attribute
        elif hasattr(ws, 'headers'):
            headers = ws.headers
            logger.debug(f"Found headers: {dict(headers) if headers else 'None'}")
        
        # Method 3: legacy access
        elif hasattr(ws, '_connection') and hasattr(ws._connection, 'request_headers'):
            headers = ws._connection.request_headers
            logger.debug(f"Found _connection headers: {dict(headers) if headers else 'None'}")
        
        if headers:
            # Check X-Forwarded-For header (case insensitive)
            for header_name in ['X-Forwarded-For', 'x-forwarded-for', 'X-FORWARDED-FOR']:
                forwarded_for = headers.get(header_name)
                if forwarded_for:
                    ip = forwarded_for.split(',')[0].strip()
                    logger.debug(f"Found {header_name}: {forwarded_for} -> {ip}")
                    if self.is_valid_ip(ip) and ip != '127.0.0.1':
                        return ip
            
            # Check X-Real-IP header (case insensitive)
            for header_name in ['X-Real-IP', 'x-real-ip', 'X-REAL-IP']:
                real_ip = headers.get(header_name)
                if real_ip:
                    logger.debug(f"Found {header_name}: {real_ip}")
                    if self.is_valid_ip(real_ip) and real_ip != '127.0.0.1':
                        return real_ip
            
            # Check Cf-Connecting-IP (CloudFlare)
            cf_ip = headers.get('Cf-Connecting-IP') or headers.get('cf-connecting-ip')
            if cf_ip and self.is_valid_ip(cf_ip):
                logger.debug(f"Found CloudFlare IP: {cf_ip}")
                return cf_ip
            
            # Check True-Client-IP (CloudFlare Enterprise)
            true_ip = headers.get('True-Client-IP') or headers.get('true-client-ip')
            if true_ip and self.is_valid_ip(true_ip):
                logger.debug(f"Found True-Client-IP: {true_ip}")
                return true_ip
        
        # Fallback to remote address (but don't use 127.0.0.1)
        try:
            if hasattr(ws, 'remote_address') and ws.remote_address:
                ip = ws.remote_address[0]
                logger.debug(f"Remote address: {ip}")
                if ip != '127.0.0.1' and self.is_valid_ip(ip):
                    return ip
        except:
            pass
        
        # Last resort - try environment variables
        import os
        env_ip = os.environ.get('HTTP_X_FORWARDED_FOR') or os.environ.get('REMOTE_ADDR')
        if env_ip:
            ip = env_ip.split(',')[0].strip()
            if self.is_valid_ip(ip) and ip != '127.0.0.1':
                logger.debug(f"Found IP in environment: {ip}")
                return ip
        
        logger.debug("Could not determine real IP, using 'unknown'")
        return 'unknown'
    
    def is_valid_ip(self, ip):
        """Basic IP validation"""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            for part in parts:
                if not (0 <= int(part) <= 255):
                    return False
            return True
        except:
            return False
    
    async def notify_peer_disconnect(self, user_id):
        """Notify peers that this user disconnected"""
        disconnect_tasks = []
        for uid, udata in list(self.users.items()):
            if uid != user_id and 'ws' in udata:
                try:
                    task = asyncio.create_task(
                        udata['ws'].send(json.dumps({
                            'type': 'peer_disconnected',
                            'user': user_id
                        }))
                    )
                    disconnect_tasks.append(task)
                except Exception as e:
                    logger.debug(f"Error notifying {uid} about {user_id} disconnect: {e}")
        
        # Wait for all notifications to complete
        if disconnect_tasks:
            await asyncio.gather(*disconnect_tasks, return_exceptions=True)
    
    async def ping_client(self, ws, user_id):
        """Send periodic pings to keep connection alive"""
        try:
            while user_id in self.users and not ws.closed:
                await asyncio.sleep(25)  # Ping every 25 seconds
                if user_id in self.users and not ws.closed:
                    try:
                        await ws.send(json.dumps({'type': 'ping'}))
                    except Exception:
                        break
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.debug(f"Ping task error for {user_id}: {e}")
    
    async def handle_websocket(self, websocket, path):
        """Fixed WebSocket handler with proper signature"""
        user_id = None
        ws_id = id(websocket)
        
        # Get IP for logging purposes
        ip = self.get_real_ip(websocket)
        
        logger.info(f"New WebSocket connection from {ip}")
        
        # Filter admin password from logs
        class PasswordFilter(logging.Filter):
            def filter(self, record):
                if hasattr(record, 'getMessage'):
                    msg = record.getMessage()
                    if 'admin_auth' in msg or 'password' in msg.lower():
                        return False
                return True
        
        logger.addFilter(PasswordFilter())
        
        try:
            async for message in websocket:
                try:
                    data = json.loads(message)
                except json.JSONDecodeError:
                    logger.warning(f"Invalid JSON received")
                    continue
                
                # Handle ping response
                if data.get('type') == 'pong':
                    continue
                
                # Admin authentication - don't log password
                if data.get('type') == 'admin_auth':
                    password = data.get('password', '')
                    if self.admin.verify_admin(password):
                        self.admin.admin_sessions.add(ws_id)
                        await websocket.send(json.dumps({'type': 'auth_success'}))
                        logger.info(f"Admin authenticated")
                    else:
                        await websocket.send(json.dumps({'type': 'auth_failed'}))
                        logger.warning(f"Failed admin login attempt")
                    continue
                
                # Admin commands
                if data.get('type') in ['get_stats', 'get_config', 'update_config', 'restart', 'drop_all', 'get_logs', 'download_logs']:
                    if ws_id not in self.admin.admin_sessions:
                        await websocket.send(json.dumps({'type': 'error', 'message': 'Not authenticated'}))
                        continue
                    
                    await self.handle_admin_command(websocket, data)
                    continue
                
                # Regular chat messages
                if data.get('type') == 'register':
                    user_id = await self.handle_user_register(websocket, data, ip)
                    
                elif data.get('type') == 'request':
                    await self.handle_chat_request(websocket, data)
                    
                elif data.get('type') == 'accept':
                    await self.handle_chat_accept(websocket, data)
                    
                elif data.get('type') == 'deny':
                    await self.handle_chat_deny(websocket, data)
                    
                elif data.get('type') in ['msg', 'file']:
                    await self.handle_message(websocket, data)
                    
        except websockets.exceptions.ConnectionClosed:
            logger.debug(f"Connection closed normally")
        except Exception as e:
            logger.error(f"Handler error: {e}")
            logger.error(traceback.format_exc())
        finally:
            # Cleanup
            if user_id and user_id in self.users:
                # Cancel ping task
                if user_id in self.ping_tasks:
                    self.ping_tasks[user_id].cancel()
                    del self.ping_tasks[user_id]
                
                # Notify peers about disconnect
                try:
                    await self.notify_peer_disconnect(user_id)
                except Exception as e:
                    logger.debug(f"Error notifying disconnect for {user_id}: {e}")
                
                del self.users[user_id]
                logger.info(f"User {user_id} disconnected")
            
            # Remove from admin sessions
            if ws_id in self.admin.admin_sessions:
                self.admin.admin_sessions.remove(ws_id)
    
    async def handle_admin_command(self, websocket, data):
        """Handle admin panel commands"""
        try:
            if data['type'] == 'get_stats':
                stats = self.admin.get_stats()
                stats['users'] = [
                    {
                        'id': uid,
                        'connected': int(time.time() - udata.get('connected_at', 0))
                    }
                    for uid, udata in self.users.items()
                ]
                await websocket.send(json.dumps({'type': 'stats', 'data': stats}))
                
            elif data['type'] == 'get_config':
                await websocket.send(json.dumps({'type': 'config', 'data': self.admin.config}))
                
            elif data['type'] == 'update_config':
                config_update = data.get('config', {})
                for key, value in config_update.items():
                    if key in self.admin.config:
                        self.admin.config[key].update(value)
                    else:
                        self.admin.config[key] = value
                self.admin.save_config()
                await websocket.send(json.dumps({'type': 'config_updated'}))
                
            elif data['type'] == 'restart':
                await websocket.send(json.dumps({'type': 'restarting'}))
                asyncio.create_task(self.restart_server())
                
            elif data['type'] == 'drop_all':
                close_tasks = []
                for user_data in list(self.users.values()):
                    if 'ws' in user_data:
                        try:
                            close_tasks.append(asyncio.create_task(user_data['ws'].close()))
                        except:
                            pass
                if close_tasks:
                    await asyncio.gather(*close_tasks, return_exceptions=True)
                self.users.clear()
                await websocket.send(json.dumps({'type': 'all_dropped'}))
                
            elif data['type'] == 'get_logs':
                try:
                    with open('/var/log/xsukax/chat.log', 'r') as f:
                        logs = f.read()
                        last_100 = '\n'.join(logs.split('\n')[-100:])
                        await websocket.send(json.dumps({'type': 'logs', 'data': last_100}))
                except Exception as e:
                    await websocket.send(json.dumps({'type': 'logs', 'data': f'Error reading logs: {e}'}))
            
            elif data['type'] == 'download_logs':
                try:
                    with open('/var/log/xsukax/chat.log', 'r') as f:
                        full_logs = f.read()
                        await websocket.send(json.dumps({'type': 'download_data', 'data': full_logs}))
                except Exception as e:
                    await websocket.send(json.dumps({'type': 'error', 'message': f'Download failed: {e}'}))
                    
        except Exception as e:
            logger.error(f"Admin command error: {e}")
            await websocket.send(json.dumps({'type': 'error', 'message': 'Command failed'}))
    
    async def restart_server(self):
        """Restart the server service"""
        await asyncio.sleep(1)  # Give time to send response
        os.system('systemctl restart chat')
    
    async def handle_user_register(self, websocket, data, ip):
        """Handle user registration"""
        # Check maintenance
        maintenance = self.admin.config.get('maintenance', {})
        if maintenance.get('enabled', False):
            await websocket.send(json.dumps({
                'type': 'error',
                'message': maintenance.get('message', 'Maintenance mode')
            }))
            await websocket.close()
            return None
        
        # Check max users
        max_users = self.admin.config.get('security', {}).get('max_users', 1000)
        if len(self.users) >= max_users:
            await websocket.send(json.dumps({'type': 'error', 'message': 'Server full'}))
            await websocket.close()
            return None
        
        user_id = str(data.get('id', ''))[:8].upper()
        if not user_id or len(user_id) < 8:
            await websocket.send(json.dumps({'type': 'error', 'message': 'Invalid ID'}))
            return None
        
        # Check if blocked
        if self.is_blocked(user_id):
            await websocket.send(json.dumps({'type': 'error', 'message': 'Access denied'}))
            await websocket.close()
            return None
        
        # Remove old connection if exists
        if user_id in self.users:
            old_data = self.users[user_id]
            if 'ws' in old_data and old_data['ws'] != websocket:
                try:
                    await old_data['ws'].close()
                except:
                    pass
            # Cancel old ping task
            if user_id in self.ping_tasks:
                self.ping_tasks[user_id].cancel()
        
        # Register new user
        self.users[user_id] = {
            'ws': websocket,
            'key': data.get('key'),
            'connected_at': time.time()
        }
        
        # Start ping task
        self.ping_tasks[user_id] = asyncio.create_task(self.ping_client(websocket, user_id))
        
        await websocket.send(json.dumps({'type': 'registered', 'id': user_id}))
        
        # Log connection with IP
        logger.info(f"User {user_id} connected from {ip}")
        
        self.admin.stats['connections_total'] += 1
        return user_id
    
    async def handle_chat_request(self, websocket, data):
        """Handle chat connection request"""
        requester = str(data.get('from', ''))[:8].upper()
        target = str(data.get('target', ''))[:8].upper()
        
        if not self.check_rate_limit(requester):
            await websocket.send(json.dumps({
                'type': 'error', 
                'message': 'Rate limit exceeded. Please wait before sending more requests.'
            }))
            return
        
        if target in self.users:
            try:
                await self.users[target]['ws'].send(json.dumps({
                    'type': 'incoming_request',
                    'from': requester
                }))
            except Exception as e:
                logger.debug(f"Error sending request to {target}: {e}")
                await websocket.send(json.dumps({'type': 'user_offline', 'user': target}))
        else:
            await websocket.send(json.dumps({'type': 'user_offline', 'user': target}))
    
    async def handle_chat_accept(self, websocket, data):
        """Handle chat accept"""
        accepter = str(data.get('from', ''))[:8].upper()
        target = str(data.get('target', ''))[:8].upper()
        
        if not self.check_rate_limit(accepter):
            await websocket.send(json.dumps({
                'type': 'error',
                'message': 'Rate limit exceeded. Please wait before accepting.'
            }))
            return
        
        if target in self.users:
            accepter_key = self.users.get(accepter, {}).get('key')
            target_key = self.users.get(target, {}).get('key')
            
            if accepter_key:
                try:
                    await self.users[target]['ws'].send(json.dumps({
                        'type': 'accepted',
                        'user': accepter,
                        'key': accepter_key
                    }))
                except Exception as e:
                    logger.debug(f"Error sending accept to {target}: {e}")
            
            if target_key:
                try:
                    await websocket.send(json.dumps({
                        'type': 'key',
                        'user': target,
                        'key': target_key
                    }))
                except Exception as e:
                    logger.debug(f"Error sending key to {accepter}: {e}")
    
    async def handle_chat_deny(self, websocket, data):
        """Handle chat deny"""
        denier = str(data.get('from', ''))[:8].upper()
        target = str(data.get('target', ''))[:8].upper()
        
        if not self.check_rate_limit(denier):
            await websocket.send(json.dumps({
                'type': 'error',
                'message': 'Rate limit exceeded. Please wait before denying.'
            }))
            return
        
        if target in self.users:
            try:
                await self.users[target]['ws'].send(json.dumps({
                    'type': 'denied',
                    'from': denier
                }))
            except Exception as e:
                logger.debug(f"Error sending deny to {target}: {e}")
    
    async def handle_message(self, websocket, data):
        """Handle chat messages and files"""
        sender = str(data.get('from', ''))[:8].upper()
        target = str(data.get('to', ''))[:8].upper()
        
        if not self.check_rate_limit(sender):
            # Send rate limit error to sender
            await websocket.send(json.dumps({
                'type': 'error',
                'message': 'Rate limit exceeded. Please slow down your messages.'
            }))
            return
        
        # Log the encrypted message to file
        logger.info(f"MSG {data['type']}: {sender} -> {target} | {str(data.get('data'))}")
        
        if target in self.users:
            try:
                message = {
                    'type': data['type'],
                    'from': sender,
                    'data': data.get('data')
                }
                
                # Add file metadata if it's a file
                if data['type'] == 'file':
                    message['name'] = data.get('name')
                    message['size'] = data.get('size')
                
                await self.users[target]['ws'].send(json.dumps(message))
            except Exception as e:
                logger.debug(f"Error sending message from {sender} to {target}: {e}")
        else:
            # Notify sender that target is offline
            await websocket.send(json.dumps({
                'type': 'user_offline',
                'user': target
            }))
        
        # Update stats
        self.admin.stats['messages_total'] += 1
        hour_key = datetime.now().strftime('%H')
        if hour_key not in self.admin.stats['messages_hour']:
            self.admin.stats['messages_hour'][hour_key] = 0
        self.admin.stats['messages_hour'][hour_key] += 1

# Initialize servers
admin_server = AdminServer()
chat_server = E2EServer(admin_server)

# Handler that works with older websockets versions (single parameter)
async def websocket_handler(websocket):
    """WebSocket handler compatible with older websockets library versions"""
    try:
        # Get path from websocket object if available
        path = getattr(websocket, 'path', '/ws')
        logger.info(f"New WebSocket connection from {getattr(websocket, 'remote_address', 'unknown')} to {path}")
        
        await chat_server.handle_websocket(websocket, path)
    except Exception as e:
        logger.error(f"Handler wrapper error: {e}")
        logger.error(traceback.format_exc())

async def main():
    try:
        logger.info(f"Starting server with websockets version: {websockets.__version__}")
        
        # Start server - older versions use different syntax
        try:
            # Try newer version syntax first
            server = await websockets.serve(
                websocket_handler,
                '0.0.0.0', 
                8765, 
                max_size=5*1024*1024,
                ping_interval=30,
                ping_timeout=15,
                close_timeout=10
            )
            logger.info("xsukax E2E Chat Server with Admin Panel running on :8765")
            await server.wait_closed()
            
        except TypeError as e:
            # Fallback for very old versions
            logger.warning(f"Trying legacy websockets API: {e}")
            start_server = websockets.serve(websocket_handler, '0.0.0.0', 8765)
            server = await start_server
            logger.info("xsukax E2E Chat Server with Admin Panel running on :8765 (legacy mode)")
            await server.wait_closed()
        
    except Exception as e:
        logger.error(f"Server startup failed: {e}")
        logger.error(traceback.format_exc())

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Server crashed: {e}")
        logger.error(traceback.format_exc())
EOF

# Create chat HTML with UTF-8 encoding fixes
cat > /opt/chat/static/index.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
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
button:disabled { opacity: 0.5; cursor: not-allowed; }
button:disabled:hover { background: #000; color: #0f0; }
#messages { flex: 1; overflow-y: auto; border: 1px solid #0f0; padding: 10px; margin: 10px 0; min-height: 200px; }
.msg { margin: 5px 0; word-wrap: break-word; word-break: break-word; }
.sent { color: #0ff; }
.received { color: #ff0; }
.system { color: #666; font-style: italic; }
.file-msg { background: #111; padding: 5px; border-radius: 3px; }
.file-msg a { color: #f0f; text-decoration: none; }
#status { color: #f0f; }
#myId { cursor: pointer; text-decoration: underline; }
.id-controls { display: flex; gap: 10px; align-items: center; }
.input-row { display: flex; gap: 5px; align-items: stretch; }
.input-row input { flex: 1; }
.input-row button { width: auto; padding: 8px 15px; white-space: nowrap; }
#fileBtn { padding: 8px 12px; }
.progress { height: 2px; background: #0f0; transition: width 0.3s; margin-top: 5px; }
.modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.9); z-index: 1000; align-items: center; justify-content: center; }
.modal-content { background: #000; border: 2px solid #0f0; padding: 20px; max-width: 90%; width: 350px; text-align: center; }
.modal-content h3 { color: #0f0; margin-bottom: 15px; font-size: 16px; }
.modal-content p { color: #0f0; margin-bottom: 20px; font-size: 14px; }
.modal-buttons { display: flex; gap: 10px; }
.modal-buttons button { flex: 1; padding: 10px; font-size: 14px; font-weight: bold; }
.accept-btn { background: #0f0; color: #000; border: 2px solid #0f0; }
.accept-btn:hover { background: #0a0; border-color: #0a0; }
.deny-btn { background: #000; color: #f00; border: 2px solid #f00; }
.deny-btn:hover { background: #f00; color: #000; }
.admin-link { position: absolute; top: 10px; right: 10px; color: #666; text-decoration: none; font-size: 10px; }
#newIdBtn { padding: 5px 10px; font-size: 12px; width: auto; }
@media (max-width: 600px) {
  body { padding: 5px; }
  h1 { font-size: 14px; }
  .box { padding: 8px; margin-bottom: 8px; }
  input, button { padding: 10px; font-size: 16px; }
  .input-row { flex-direction: column; }
  .input-row button { width: 100%; }
  #messages { min-height: 150px; }
  .modal-content { width: 90%; padding: 15px; }
}
</style>
</head>
<body>
<a href="/admin" class="admin-link">[admin]</a>
<h1>🔐 xsukax E2E CHAT SYSTEM</h1>
<div class="box">
  <div class="id-controls">
    <div>ID: <span id="myId" title="Click to copy">--------</span></div>
    <button id="newIdBtn" onclick="requestNewId()">🔄 New ID</button>
  </div>
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

<div id="requestModal" class="modal">
  <div class="modal-content">
    <h3>📨 CHAT REQUEST</h3>
    <p>User <span id="requesterID" style="color:#ff0; font-weight:bold;">--------</span> wants to chat with you</p>
    <div class="modal-buttons">
      <button class="accept-btn" onclick="acceptRequest()">✅ ACCEPT</button>
      <button class="deny-btn" onclick="denyRequest()">❌ DENY</button>
    </div>
  </div>
</div>

<div id="newIdModal" class="modal">
  <div class="modal-content">
    <h3>🔄 GENERATE NEW ID</h3>
    <p>Generate new ID? You will lose all current connections.</p>
    <div class="modal-buttons">
      <button class="accept-btn" onclick="confirmNewId()">✅ GENERATE</button>
      <button class="deny-btn" onclick="hideModal('newIdModal')">❌ CANCEL</button>
    </div>
  </div>
</div>

<script>
let ws, myId, myKeys, peerKey, peerId, pendingRequester;
let reconnectAttempts = 0;
let intentionalDisconnect = false;
let pingInterval;
let connectionTimeout;

// Initialize ID
myId = localStorage.getItem('chatId') || generateId();
localStorage.setItem('chatId', myId);
document.getElementById('myId').textContent = myId;

function generateId() {
  return Array(8).fill().map(() => 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'[Math.floor(Math.random() * 36)]).join('');
}

function requestNewId() {
  showModal('newIdModal');
}

function confirmNewId() {
  hideModal('newIdModal');
  
  intentionalDisconnect = true;
  if (ws) ws.close();
  
  // Generate new ID
  myId = generateId();
  localStorage.setItem('chatId', myId);
  document.getElementById('myId').textContent = myId;
  
  // Clear peer connection
  peerKey = null;
  peerId = null;
  enableChat(); // Reset chat state
  disableChat(); // Then disable it
  
  // Clear messages
  document.getElementById('messages').innerHTML = '';
  addMsg('System', `New ID generated: ${myId}`, 'system');
  
  // Reconnect with new ID
  setTimeout(() => {
    intentionalDisconnect = false;
    initWS();
  }, 500);
}

function enableChat() {
  document.getElementById('msgInput').disabled = false;
  document.getElementById('sendBtn').disabled = false;
  document.getElementById('fileInput').disabled = false;
  document.getElementById('fileBtn').disabled = false;
}

function disableChat() {
  document.getElementById('msgInput').disabled = true;
  document.getElementById('sendBtn').disabled = true;
  document.getElementById('fileInput').disabled = true;
  document.getElementById('fileBtn').disabled = true;
}

function showModal(id) {
  document.getElementById(id).style.display = 'flex';
}

function hideModal(id) {
  document.getElementById(id).style.display = 'none';
}

document.getElementById('myId').onclick = async () => {
  try {
    await navigator.clipboard.writeText(myId);
    document.getElementById('myId').textContent = 'Copied!';
    setTimeout(() => { document.getElementById('myId').textContent = myId; }, 1000);
  } catch {
    // Fallback for older browsers
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

document.getElementById('msgInput').onkeypress = (e) => { 
  if(e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    sendMsg();
  }
};

document.getElementById('fileInput').onchange = () => { 
  if(document.getElementById('fileInput').files[0]) sendFile(); 
};

function showRequestModal(from) {
  pendingRequester = from;
  document.getElementById('requesterID').textContent = from;
  document.getElementById('requestModal').style.display = 'flex';
  addMsg('System', `📨 Request from ${from}`, 'system');
}

function acceptRequest() {
  document.getElementById('requestModal').style.display = 'none';
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({ type: 'accept', from: myId, target: pendingRequester }));
    addMsg('System', `✅ Accepted chat with ${pendingRequester}`, 'system');
  }
  pendingRequester = null;
}

function denyRequest() {
  document.getElementById('requestModal').style.display = 'none';
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({ type: 'deny', from: myId, target: pendingRequester }));
    addMsg('System', `❌ Denied chat with ${pendingRequester}`, 'system');
  }
  pendingRequester = null;
}

function requestNewId() {
  document.getElementById('newIdModal').style.display = 'flex';
}

function confirmNewId() {
  document.getElementById('newIdModal').style.display = 'none';
  
  intentionalDisconnect = true;
  if (ws) ws.close();
  
  // Generate new ID
  myId = generateId();
  localStorage.setItem('chatId', myId);
  document.getElementById('myId').textContent = myId;
  
  // Clear peer connection
  peerKey = null;
  peerId = null;
  disableChat();
  
  // Clear messages
  document.getElementById('messages').innerHTML = '';
  addMsg('System', `New ID generated: ${myId}`, 'system');
  
  // Reconnect with new ID
  setTimeout(() => {
    intentionalDisconnect = false;
    initWS();
  }, 500);
}

function hideModal(id) {
  document.getElementById(id).style.display = 'none';
}

function enableChat() {
  document.getElementById('msgInput').disabled = false;
  document.getElementById('sendBtn').disabled = false;
  document.getElementById('fileInput').disabled = false;
  document.getElementById('fileBtn').disabled = false;
}

function disableChat() {
  document.getElementById('msgInput').disabled = true;
  document.getElementById('sendBtn').disabled = true;
  document.getElementById('fileInput').disabled = true;
  document.getElementById('fileBtn').disabled = true;
}

async function generateKeys() {
  try {
    myKeys = await crypto.subtle.generateKey(
      { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
      true, ['encrypt', 'decrypt']
    );
    return await crypto.subtle.exportKey('jwk', myKeys.publicKey);
  } catch (error) {
    console.error('Key generation failed:', error);
    addMsg('System', '❌ Crypto not supported in this browser', 'system');
    return null;
  }
}

async function rsaEncrypt(data, pubKey) {
  try {
    const key = await crypto.subtle.importKey('jwk', pubKey, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
    const encrypted = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, key, data);
    return btoa(String.fromCharCode(...new Uint8Array(encrypted)));
  } catch (error) {
    console.error('Encryption failed:', error);
    throw error;
  }
}

async function rsaDecrypt(data) {
  try {
    const encrypted = Uint8Array.from(atob(data), c => c.charCodeAt(0));
    return await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, myKeys.privateKey, encrypted);
  } catch (error) {
    console.error('Decryption failed:', error);
    throw error;
  }
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
  if (intentionalDisconnect) return;
  
  const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${protocol}//${location.host}/ws`;
  
  try {
    ws = new WebSocket(wsUrl);
    
    // Connection timeout
    connectionTimeout = setTimeout(() => {
      if (ws.readyState === WebSocket.CONNECTING) {
        ws.close();
        addMsg('System', '⚠️ Connection timeout', 'system');
      }
    }, 10000);
    
    ws.onopen = async () => {
      clearTimeout(connectionTimeout);
      document.getElementById('status').textContent = 'Connected';
      reconnectAttempts = 0;
      
      const pubKey = await generateKeys();
      if (!pubKey) {
        addMsg('System', '❌ Cannot generate encryption keys', 'system');
        return;
      }
      
      ws.send(JSON.stringify({ 
        type: 'register', 
        id: myId, 
        key: pubKey 
      }));
      
      // Setup client-side ping
      if (pingInterval) clearInterval(pingInterval);
      pingInterval = setInterval(() => {
        if (ws && ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: 'pong' }));
        }
      }, 20000); // Respond to pings every 20 seconds
    };
    
    ws.onmessage = async (e) => {
      try {
        const data = JSON.parse(e.data);
        await handleMessage(data);
      } catch (error) {
        console.error('Message handling error:', error);
      }
    };
    
    ws.onclose = (event) => {
      clearTimeout(connectionTimeout);
      document.getElementById('status').textContent = 'Disconnected';
      
      if (pingInterval) {
        clearInterval(pingInterval);
        pingInterval = null;
      }
      
      if (!intentionalDisconnect) {
        if (peerId) {
          document.getElementById('msgInput').disabled = true;
          document.getElementById('sendBtn').disabled = true;
          document.getElementById('fileInput').disabled = true;
          document.getElementById('fileBtn').disabled = true;
          addMsg('System', '⚠️ Connection lost. Reconnecting...', 'system');
        }
        
        // Reconnect with exponential backoff
        reconnectAttempts++;
        const delay = Math.min(1000 * Math.pow(2, reconnectAttempts - 1), 30000);
        setTimeout(initWS, delay);
      }
    };
    
    ws.onerror = (error) => {
      console.error('WebSocket error:', error);
      clearTimeout(connectionTimeout);
    };
    
  } catch (error) {
    console.error('WebSocket creation failed:', error);
    addMsg('System', '❌ Connection failed', 'system');
  }
}

async function handleMessage(data) {
  if (data.type === 'ping') {
    ws.send(JSON.stringify({ type: 'pong' }));
  } else if (data.type === 'registered') {
    addMsg('System', `Connected as ${data.id}`, 'system');
  } else if (data.type === 'incoming_request') {
    showRequestModal(data.from);
  } else if (data.type === 'accepted') {
    peerKey = data.key;
    peerId = data.user;
    enableChat();
    addMsg('System', `✅ ${peerId} accepted! E2E established`, 'system');
  } else if (data.type === 'key') {
    peerKey = data.key;
    peerId = data.user;
    enableChat();
    addMsg('System', `🔐 E2E with ${peerId}`, 'system');
  } else if (data.type === 'denied') {
    addMsg('System', `❌ ${data.from} denied your request`, 'system');
  } else if (data.type === 'user_offline') {
    addMsg('System', `⚠️ ${data.user} is offline`, 'system');
  } else if (data.type === 'peer_disconnected') {
    if (data.user === peerId) {
      peerKey = null;
      disableChat();
      addMsg('System', `⚠️ ${data.user} disconnected`, 'system');
    }
  } else if (data.type === 'error') {
    addMsg('System', `❌ ${data.message}`, 'system');
    
    // Visual feedback for rate limiting
    if (data.message.includes('Rate limit')) {
      document.getElementById('sendBtn').style.background = '#f00';
      document.getElementById('sendBtn').textContent = 'RATE LIMITED';
      setTimeout(() => {
        document.getElementById('sendBtn').style.background = '';
        document.getElementById('sendBtn').textContent = 'Send';
      }, 3000);
    }
  } else if (data.type === 'msg') {
    try {
      const decrypted = await rsaDecrypt(data.data);
      addMsg(data.from, new TextDecoder().decode(decrypted), 'received');
    } catch {
      addMsg('System', `⚠️ Cannot decrypt message from ${data.from}. Try reconnecting.`, 'system');
    }
  } else if (data.type === 'file') {
    await receiveFile(data);
  }
}

function enableChat() {
  document.getElementById('msgInput').disabled = false;
  document.getElementById('sendBtn').disabled = false;
  document.getElementById('fileInput').disabled = false;
  document.getElementById('fileBtn').disabled = false;
}

function disableChat() {
  document.getElementById('msgInput').disabled = true;
  document.getElementById('sendBtn').disabled = true;
  document.getElementById('fileInput').disabled = true;
  document.getElementById('fileBtn').disabled = true;
}

function connect() {
  const targetInput = document.getElementById('targetId');
  peerId = targetInput.value.toUpperCase().trim();
  
  if (peerId.length !== 8) {
    addMsg('System', '❌ ID must be exactly 8 characters', 'system');
    return;
  }
  
  if (peerId === myId) {
    addMsg('System', '❌ Cannot connect to yourself', 'system');
    return;
  }
  
  if (!ws || ws.readyState !== WebSocket.OPEN) {
    addMsg('System', '❌ Not connected to server', 'system');
    return;
  }
  
  ws.send(JSON.stringify({ type: 'request', from: myId, target: peerId }));
  addMsg('System', `📤 Request sent to ${peerId}...`, 'system');
  targetInput.value = '';
}

async function sendMsg() {
  const input = document.getElementById('msgInput');
  const msg = input.value.trim();
  
  if (!msg || !peerKey || !ws || ws.readyState !== WebSocket.OPEN) return;
  
  try {
    const encrypted = await rsaEncrypt(new TextEncoder().encode(msg), peerKey);
    ws.send(JSON.stringify({ type: 'msg', from: myId, to: peerId, data: encrypted }));
    addMsg('You', msg, 'sent');
    input.value = '';
  } catch (error) {
    addMsg('System', '❌ Failed to send message', 'system');
  }
}

async function sendFile() {
  const fileInput = document.getElementById('fileInput');
  const file = fileInput.files[0];
  
  if (!file || !peerKey || !ws || ws.readyState !== WebSocket.OPEN) return;
  
  if (file.size > 1024 * 1024) {
    addMsg('System', '❌ File too large! Max 1MB', 'system');
    return;
  }
  
  try {
    const progress = document.getElementById('progress');
    progress.style.width = '20%';
    
    const buffer = await file.arrayBuffer();
    progress.style.width = '40%';
    
    const aesKey = await generateAESKey();
    const encryptedFile = await aesEncrypt(new Uint8Array(buffer), aesKey);
    progress.style.width = '70%';
    
    const rawKey = await crypto.subtle.exportKey('raw', aesKey);
    const encryptedKey = await rsaEncrypt(new Uint8Array(rawKey), peerKey);
    progress.style.width = '90%';
    
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
    fileInput.value = '';
  } catch (error) {
    console.error('File send error:', error);
    addMsg('System', '❌ File send failed', 'system');
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
    
    const fileMsg = document.createElement('div');
    fileMsg.className = 'msg received file-msg';
    fileMsg.innerHTML = `[${new Date().toLocaleTimeString()}] ${data.from}: `;
    
    const a = document.createElement('a');
    a.href = url;
    a.download = data.name;
    a.textContent = `💾 ${data.name} (${(data.size/1024).toFixed(1)}KB)`;
    a.style.color = '#f0f';
    a.style.textDecoration = 'none';
    
    fileMsg.appendChild(a);
    document.getElementById('messages').appendChild(fileMsg);
    document.getElementById('messages').scrollTop = document.getElementById('messages').scrollHeight;
    
  } catch (error) {
    console.error('File receive error:', error);
    addMsg('System', `❌ Cannot decrypt file from ${data.from}`, 'system');
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

// Initialize on page load
window.addEventListener('beforeunload', () => {
  intentionalDisconnect = true;
  if (ws) ws.close();
});

// Start connection
initWS();
</script>
</body>
</html>
EOF

# Create admin panel HTML with enhanced features
cat > /opt/chat/static/admin.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>xsukax Admin Panel</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: 'Courier New', monospace; background: #000; color: #0f0; padding: 10px; max-width: 1200px; margin: 0 auto; }
h1 { font-size: 20px; margin-bottom: 20px; border-bottom: 1px solid #0f0; padding-bottom: 10px; }
.login-form { max-width: 400px; margin: 100px auto; border: 1px solid #0f0; padding: 30px; }
.panel { display: none; }
.panel.active { display: block; }
.section { border: 1px solid #0f0; padding: 15px; margin-bottom: 15px; }
.section h2 { font-size: 14px; margin-bottom: 10px; color: #ff0; }
input, select, button, textarea { background: #000; color: #0f0; border: 1px solid #0f0; padding: 8px; margin: 5px 0; font-family: inherit; width: 100%; }
textarea { resize: vertical; }
button { cursor: pointer; }
button:hover { background: #0f0; color: #000; }
.stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; }
.stat-box { border: 1px solid #333; padding: 10px; }
.stat-label { font-size: 10px; color: #666; }
.stat-value { font-size: 18px; color: #0ff; }
table { width: 100%; border-collapse: collapse; }
th, td { border: 1px solid #333; padding: 5px; text-align: left; font-size: 12px; }
th { background: #111; color: #ff0; }
.danger { background: #300; border-color: #f00; color: #f00; }
.danger:hover { background: #f00; color: #000; }
.success { color: #0f0; }
.error { color: #f00; }
.warning { color: #ff0; }
#logs { background: #111; padding: 10px; height: 300px; overflow-y: auto; font-size: 11px; white-space: pre-wrap; font-family: monospace; }
#messageLogs { background: #111; padding: 10px; height: 200px; overflow-y: auto; font-size: 10px; white-space: pre-wrap; font-family: monospace; }
.switch { display: inline-block; margin: 5px 0; }
.switch input { margin-right: 5px; width: auto; }
.nav { margin-bottom: 20px; }
.nav button { margin-right: 10px; width: auto; }
.save-status { display: inline-block; margin-left: 10px; font-size: 12px; }
.log-controls { 
  margin: 10px 0; 
  display: flex; 
  flex-wrap: wrap; 
  gap: 8px; 
  align-items: center; 
  background: #111;
  padding: 10px;
  border: 1px solid #333;
  border-radius: 3px;
}
.log-controls button { 
  width: auto !important; 
  margin: 0 !important; 
  padding: 8px 12px; 
  font-size: 12px; 
  white-space: nowrap; 
  min-width: 80px;
  display: inline-block;
  border: 1px solid #0f0;
  background: #000;
  color: #0f0;
  cursor: pointer;
}
.log-controls button:hover {
  background: #0f0;
  color: #000;
}
.download-btn { background: #300 !important; border-color: #f80 !important; color: #f80 !important; }
.download-btn:hover { background: #f80 !important; color: #000 !important; }
.clear-btn { background: #300 !important; border-color: #f00 !important; color: #f00 !important; }
.clear-btn:hover { background: #f00 !important; color: #000 !important; }

/* Modal styles */
.modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.8); z-index: 1000; align-items: center; justify-content: center; }
.modal-content { background: #000; border: 2px solid #0f0; padding: 20px; max-width: 90%; width: 400px; text-align: center; }
.modal-content h3 { color: #0f0; margin-bottom: 15px; }
.modal-content p { margin-bottom: 20px; }
.modal-buttons { display: flex; gap: 10px; }
.modal-buttons button { flex: 1; }

@media (max-width: 600px) {
  .stats { grid-template-columns: 1fr; }
  table { font-size: 10px; }
  .nav button { display: block; width: 100%; margin-bottom: 5px; }
}
</style>
</head>
<body>
<h1>🔧 XSUKAX ADMIN PANEL</h1>

<div id="loginPanel" class="login-form panel active">
  <h2>Admin Login</h2>
  <input type="password" id="adminPassword" placeholder="Enter admin password" onkeypress="if(event.key=='Enter')login()">
  <button onclick="login()">LOGIN</button>
  <div id="loginError" class="error"></div>
</div>

<div id="adminPanel" class="panel">
  <div class="nav">
    <button onclick="showTab('dashboard')">📊 Dashboard</button>
    <button onclick="showTab('security')">🔒 Security</button>
    <button onclick="showTab('privacy')">🕵️ Privacy</button>
    <button onclick="showTab('maintenance')">🔧 Maintenance</button>
    <button onclick="logout()" style="float:right">Logout</button>
  </div>

  <div id="dashboard" class="tab-content">
    <div class="section">
      <h2>📊 SERVER STATISTICS</h2>
      <div class="stats">
        <div class="stat-box">
          <div class="stat-label">UPTIME</div>
          <div class="stat-value" id="uptime">0h 0m</div>
        </div>
        <div class="stat-box">
          <div class="stat-label">ACTIVE USERS</div>
          <div class="stat-value" id="activeUsers">0</div>
        </div>
        <div class="stat-box">
          <div class="stat-label">MESSAGES TOTAL</div>
          <div class="stat-value" id="messagesTotal">0</div>
        </div>
        <div class="stat-box">
          <div class="stat-label">MEMORY USAGE</div>
          <div class="stat-value" id="memoryUsage">0 MB</div>
        </div>
      </div>
    </div>

    <div class="section">
      <h2>👥 CONNECTED USERS</h2>
      <table id="usersTable">
        <thead>
          <tr>
            <th>USER ID</th>
            <th>CONNECTED</th>
          </tr>
        </thead>
        <tbody id="usersList"></tbody>
      </table>
    </div>

    <div class="section">
      <h2>📈 HOURLY ACTIVITY</h2>
      <pre id="hourlyChart"></pre>
    </div>
  </div>

  <div id="security" class="tab-content" style="display:none">
    <div class="section">
      <h2>🔒 SECURITY SETTINGS</h2>
      <div class="switch">
        <label><input type="checkbox" id="requireHttps"> Require HTTPS</label>
      </div>
      <div>
        Rate Limit: <input type="number" id="rateLimit" value="30" style="width:60px"> messages/minute
      </div>
      <div>
        Max Users: <input type="number" id="maxUsers" value="1000" style="width:80px">
      </div>
      <div>
        <h3 style="margin-top:10px">Blocked IDs (one per line):</h3>
        <textarea id="blockedIds" rows="3"></textarea>
      </div>
      <button onclick="saveSecuritySettings()">💾 SAVE SECURITY SETTINGS</button>
      <span id="securityStatus" class="save-status"></span>
    </div>
  </div>

  <div id="privacy" class="tab-content" style="display:none">
    <div class="section">
      <h2>🕵️ PRIVACY SETTINGS</h2>
      <div class="switch">
        <label><input type="checkbox" id="logConnections"> Log connection events</label>
      </div>
      <div>
        Log Retention: <input type="number" id="logRetention" value="7" style="width:60px"> days
      </div>
      <button onclick="savePrivacySettings()">💾 SAVE PRIVACY SETTINGS</button>
      <span id="privacyStatus" class="save-status"></span>
    </div>
  </div>

  <div id="maintenance" class="tab-content" style="display:none">
    <div class="section">
      <h2>🔧 MAINTENANCE</h2>
      <div class="switch">
        <label><input type="checkbox" id="maintenanceMode"> Enable Maintenance Mode</label>
      </div>
      <div>
        Message: <input type="text" id="maintenanceMsg" value="Server under maintenance">
      </div>
      <div style="margin-top:15px">
        <button onclick="saveMaintenanceSettings()">💾 SAVE SETTINGS</button>
        <span id="maintenanceStatus" class="save-status"></span>
        <br><br>
        <button onclick="showModal('dropAllModal')">❌ DROP ALL CONNECTIONS</button>
        <button onclick="showModal('restartModal')">🔄 RESTART SERVER</button>
      </div>
    </div>
  </div>

  <!-- LOGS SECTION - Always Visible -->
  <div class="section">
    <h2>📋 SYSTEM LOGS</h2>
    <div id="systemLogsContent" style="background: #111; padding: 10px; height: 400px; overflow-y: auto; font-size: 11px; white-space: pre-wrap; font-family: monospace; border: 1px solid #333;"></div>
    <div class="log-controls">
      <button onclick="refreshLogs()" title="Refresh system logs">🔄 REFRESH</button>
      <button onclick="downloadLogs()" class="download-btn" title="Download complete log file">💾 DOWNLOAD LOGS</button>
      <button onclick="toggleAutoRefresh()" id="autoRefreshBtn" title="Toggle automatic refresh">▶️ AUTO REFRESH</button>
    </div>
  </div>
</div>

<!-- Modals -->
<div id="dropAllModal" class="modal">
  <div class="modal-content">
    <h3>⚠️ CONFIRM ACTION</h3>
    <p>Drop ALL active connections?</p>
    <div class="modal-buttons">
      <button onclick="dropAllConnections(); hideModal('dropAllModal')">✅ YES</button>
      <button onclick="hideModal('dropAllModal')">❌ CANCEL</button>
    </div>
  </div>
</div>

<div id="restartModal" class="modal">
  <div class="modal-content">
    <h3>⚠️ CONFIRM RESTART</h3>
    <p>Restart server? This will disconnect all users.</p>
    <div class="modal-buttons">
      <button onclick="restartServer(); hideModal('restartModal')">✅ RESTART</button>
      <button onclick="hideModal('restartModal')">❌ CANCEL</button>
    </div>
  </div>
</div>

<script>
let ws, authenticated = false;
let autoRefreshLogs = false;
let autoRefreshInterval;

// Define log functions first
function refreshLogs() {
  if (authenticated && ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({ type: 'get_logs' }));
  }
}

function downloadLogs() {
  if (authenticated && ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({ type: 'download_logs' }));
  }
}

function updateSessionTimer() {
  const sessionTime = getCookie('admin_session_time');
  if (sessionTime && authenticated) {
    const currentTime = new Date().getTime();
    const loginTime = parseInt(sessionTime);
    const twoHours = 2 * 60 * 60 * 1000;
    const remainingTime = twoHours - (currentTime - loginTime);
    
    if (remainingTime > 0) {
      const minutes = Math.floor(remainingTime / (60 * 1000));
      const hours = Math.floor(minutes / 60);
      const mins = minutes % 60;
      document.getElementById('sessionTimer').textContent = `Session: ${hours}h ${mins}m`;
    } else {
      // Session expired
      logout();
    }
  }
}

// Initialize admin panel
window.addEventListener('DOMContentLoaded', () => {
  checkAutoLogin(); // Check for existing admin session
  
  // Update session timer every minute
  setInterval(updateSessionTimer, 60000);
});

function refreshMessageLogs() {
  if (authenticated && ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({ type: 'get_message_logs' }));
  }
}

function clearMessageLogs() {
  document.getElementById('messageLogs').innerHTML = '<div style="color:#666; font-style:italic; padding:10px;">Message logs cleared</div>';
}

function toggleAutoRefresh() {
  autoRefreshLogs = !autoRefreshLogs;
  const btn = document.getElementById('autoRefreshBtn');
  if (autoRefreshLogs) {
    btn.textContent = '⏸️ STOP AUTO';
    btn.style.background = '#300';
    btn.style.color = '#f80';
    autoRefreshInterval = setInterval(() => {
      refreshLogs();
      refreshMessageLogs();
    }, 3000);
  } else {
    btn.textContent = '▶️ AUTO REFRESH';
    btn.style.background = '';
    btn.style.color = '';
    if (autoRefreshInterval) clearInterval(autoRefreshInterval);
  }
}

function downloadFile(filename, content) {
  const blob = new Blob([content], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.style.display = 'none';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function showModal(id) {
  document.getElementById(id).style.display = 'flex';
}

function hideModal(id) {
  document.getElementById(id).style.display = 'none';
}

function login() {
  const password = document.getElementById('adminPassword').value;
  if (!password) return;
  
  const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
  ws = new WebSocket(`${protocol}//${location.host}/ws`);
  
  ws.onopen = () => {
    ws.send(JSON.stringify({ type: 'admin_auth', password: password }));
  };
  
  ws.onmessage = (e) => {
    const data = JSON.parse(e.data);
    handleAdminMessage(data);
  };
  
  ws.onerror = () => {
    document.getElementById('loginError').textContent = 'Connection failed';
  };
  
  ws.onclose = () => {
    if (authenticated) {
      // Silently reconnect instead of showing alert
      setTimeout(() => {
        if (authenticated) location.reload();
      }, 2000);
    }
  };
}

function handleAdminMessage(data) {
  if (data.type === 'auth_success') {
    authenticated = true;
    document.getElementById('loginPanel').classList.remove('active');
    document.getElementById('adminPanel').classList.add('active');
    loadStats();
    loadConfig();
    refreshLogs(); // Load logs immediately since they're always visible
    setInterval(loadStats, 5000);
    if (autoRefreshLogs) {
      setInterval(refreshLogs, 3000);
    }
  } else if (data.type === 'auth_failed') {
    document.getElementById('loginError').textContent = 'Invalid password';
    document.getElementById('adminPassword').value = '';
  } else if (data.type === 'stats') {
    updateStats(data.data);
  } else if (data.type === 'config') {
    updateConfig(data.data);
  } else if (data.type === 'config_updated') {
    showSaveStatus('✅ Settings saved', 'success');
  } else if (data.type === 'logs') {
    document.getElementById('systemLogsContent').textContent = data.data;
    document.getElementById('systemLogsContent').scrollTop = document.getElementById('systemLogsContent').scrollHeight;
  } else if (data.type === 'download_data') {
    downloadFile('xsukax_chat_logs.txt', data.data);
  } else if (data.type === 'all_dropped') {
    setTimeout(loadStats, 500);
  }
}

function updateMessageLogs(logs) {
  const container = document.getElementById('messageLogs');
  container.innerHTML = '';
  logs.forEach(log => {
    container.innerHTML += `[${log.timestamp}] ${log.type.toUpperCase()}: ${log.from} → ${log.to}\n${log.data}\n\n`;
  });
  container.scrollTop = container.scrollHeight;
}

function clearMessageLogs() {
  document.getElementById('messageLogs').innerHTML = '';
}

function downloadFile(filename, content) {
  const blob = new Blob([content], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function toggleAutoRefresh() {
  autoRefreshLogs = !autoRefreshLogs;
  const btn = document.getElementById('autoRefreshBtn');
  if (autoRefreshLogs) {
    btn.textContent = '⏸️ STOP AUTO';
    autoRefreshInterval = setInterval(() => {
      refreshLogs();
      refreshMessageLogs();
    }, 3000);
  } else {
    btn.textContent = '▶️ AUTO REFRESH';
    if (autoRefreshInterval) clearInterval(autoRefreshInterval);
  }
}

function showSaveStatus(message, type) {
  // Show status message for settings saves
  const statusDiv = document.createElement('div');
  statusDiv.textContent = message;
  statusDiv.className = type;
  statusDiv.style.cssText = 'position: fixed; top: 20px; right: 20px; background: #000; border: 1px solid #0f0; padding: 10px; z-index: 1001;';
  
  if (type === 'success') {
    statusDiv.style.color = '#0f0';
    statusDiv.style.borderColor = '#0f0';
  } else if (type === 'error') {
    statusDiv.style.color = '#f00';
    statusDiv.style.borderColor = '#f00';
  }
  
  document.body.appendChild(statusDiv);
  setTimeout(() => {
    if (statusDiv.parentNode) {
      statusDiv.parentNode.removeChild(statusDiv);
    }
  }, 3000);
}

function logout() {
  if (ws) ws.close();
  location.reload();
}

function showTab(tab) {
  document.querySelectorAll('.tab-content').forEach(t => t.style.display = 'none');
  document.getElementById(tab).style.display = 'block';
}

function loadStats() {
  if (authenticated && ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({ type: 'get_stats' }));
  }
}

function loadConfig() {
  if (authenticated && ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({ type: 'get_config' }));
  }
}

function updateStats(stats) {
  document.getElementById('uptime').textContent = stats.uptime || '0h 0m';
  document.getElementById('activeUsers').textContent = stats.active_users || 0;
  document.getElementById('messagesTotal').textContent = stats.messages_total || 0;
  document.getElementById('memoryUsage').textContent = Math.round(stats.memory_mb || 0) + ' MB';
  
  const tbody = document.getElementById('usersList');
  tbody.innerHTML = '';
  if (stats.users && stats.users.length > 0) {
    stats.users.forEach(user => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${user.id}</td>
        <td>${Math.floor(user.connected/60)}m ago</td>
      `;
      tbody.appendChild(tr);
    });
  } else {
    tbody.innerHTML = '<tr><td colspan="2">No users connected</td></tr>';
  }
  
  // Update text-based hourly chart (old style)
  const chart = document.getElementById('hourlyChart');
  chart.textContent = '';
  for (let h = 0; h < 24; h++) {
    const hour = h.toString().padStart(2, '0');
    const count = (stats.messages_hour && stats.messages_hour[hour]) || 0;
    const bar = '█'.repeat(Math.min(Math.floor(count/2), 50));
    chart.textContent += `${hour}:00 ${bar} ${count}\n`;
  }
}

function updateConfig(config) {
  const security = config.security || {};
  const privacy = config.privacy || {};
  const maintenance = config.maintenance || {};
  
  document.getElementById('requireHttps').checked = security.require_https || false;
  document.getElementById('rateLimit').value = security.rate_limit || 30;
  document.getElementById('maxUsers').value = security.max_users || 1000;
  document.getElementById('blockedIds').value = (security.blocked_ids || []).join('\n');
  
  document.getElementById('logConnections').checked = privacy.log_connections !== false;
  document.getElementById('logRetention').value = privacy.log_retention_days || 7;
  
  document.getElementById('maintenanceMode').checked = maintenance.enabled || false;
  document.getElementById('maintenanceMsg').value = maintenance.message || 'Server under maintenance';
}

function saveSecuritySettings() {
  const config = {
    security: {
      require_https: document.getElementById('requireHttps').checked,
      rate_limit: parseInt(document.getElementById('rateLimit').value) || 30,
      max_users: parseInt(document.getElementById('maxUsers').value) || 1000,
      blocked_ids: document.getElementById('blockedIds').value.split('\n').filter(x => x.trim())
    }
  };
  ws.send(JSON.stringify({ type: 'update_config', config: config }));
}

function savePrivacySettings() {
  const config = {
    privacy: {
      log_connections: document.getElementById('logConnections').checked,
      log_retention_days: parseInt(document.getElementById('logRetention').value) || 7
    }
  };
  ws.send(JSON.stringify({ type: 'update_config', config: config }));
}

function saveMaintenanceSettings() {
  const config = {
    maintenance: {
      enabled: document.getElementById('maintenanceMode').checked,
      message: document.getElementById('maintenanceMsg').value || 'Server under maintenance'
    }
  };
  ws.send(JSON.stringify({ type: 'update_config', config: config }));
}

function dropAllConnections() {
  ws.send(JSON.stringify({ type: 'drop_all' }));
}

function restartServer() {
  ws.send(JSON.stringify({ type: 'restart' }));
}

function kickUser(userId) {
  showModal('kickModal');
  // Add kick confirmation modal if needed
  ws.send(JSON.stringify({ type: 'kick_user', user_id: userId }));
}

function saveMaintenanceSettings() {
  const config = {
    maintenance: {
      enabled: document.getElementById('maintenanceMode').checked,
      message: document.getElementById('maintenanceMsg').value || 'Server under maintenance'
    }
  };
  ws.send(JSON.stringify({ type: 'update_config', config: config }));
}

function refreshLogs() {
  if (authenticated && ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({ type: 'get_logs' }));
  }
}

function refreshMessageLogs() {
  if (authenticated && ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({ type: 'get_message_logs' }));
  }
}

function downloadLogs() {
  if (authenticated && ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({ type: 'download_logs' }));
  }
}
</script>
</body>
</html>
EOF

# Nginx config with better IP passing
cat > /etc/nginx/sites-available/chat << EOF
server {
    listen 80;
    server_name $DOMAIN;
    root /opt/chat/static;
    client_max_body_size 5M;
    
    # Real IP detection from various sources
    set_real_ip_from 0.0.0.0/0;
    real_ip_header X-Forwarded-For;
    real_ip_recursive on;
    
    location / {
        try_files \$uri /index.html;
    }
    
    location /admin {
        try_files /admin.html /admin.html;
    }
    
    location /ws {
        proxy_pass http://127.0.0.1:8765;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        
        # Pass the real client IP
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$remote_addr;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        # Additional headers for CloudFlare compatibility
        proxy_set_header CF-Connecting-IP \$remote_addr;
        proxy_set_header True-Client-IP \$remote_addr;
        
        # WebSocket settings
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_buffering off;
        proxy_cache off;
    }
}
EOF

# Systemd service with better configuration
cat > /etc/systemd/system/chat.service << EOF
[Unit]
Description=xsukax E2E Chat with Admin Panel
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/chat/app
ExecStart=/usr/bin/python3 server.py
Restart=always
RestartSec=10
StartLimitInterval=60
StartLimitBurst=3

# Security settings
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/opt/chat /var/log/xsukax
PrivateTmp=true

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
EOF

# Set proper permissions
chmod +x /opt/chat/app/server.py
chown -R root:root /opt/chat
chmod -R 755 /opt/chat
chmod 644 /opt/chat/config.json

# Configure firewall
ufw --force disable 2>/dev/null || true
ufw --force reset >/dev/null 2>&1
ufw default deny incoming >/dev/null 2>&1
ufw default allow outgoing >/dev/null 2>&1
ufw allow 22/tcp >/dev/null 2>&1
ufw allow 80/tcp >/dev/null 2>&1
ufw allow 443/tcp >/dev/null 2>&1
ufw --force enable >/dev/null 2>&1

# Install and start services
rm -f /etc/nginx/sites-enabled/default
ln -sf /etc/nginx/sites-available/chat /etc/nginx/sites-enabled/
systemctl daemon-reload
systemctl enable chat nginx

# Test nginx configuration
nginx -t
if [ $? -ne 0 ]; then
    echo "❌ Nginx configuration error!"
    exit 1
fi

systemctl restart nginx
systemctl restart chat

# Wait for services to start
sleep 3

# Check service status
if ! systemctl is-active --quiet chat; then
    echo "❌ Chat service failed to start!"
    journalctl -u chat --no-pager -n 20
    exit 1
fi

if ! systemctl is-active --quiet nginx; then
    echo "❌ Nginx service failed to start!"
    systemctl status nginx
    exit 1
fi

echo "
==========================
✅ xsukax E2E Chat System
==========================
Chat: http://$DOMAIN
Admin: http://$DOMAIN/admin

Default Admin Password: $ADMIN_PASS

🚀 SERVICE STATUS:
Chat Service: $(systemctl is-active chat)
Nginx Service: $(systemctl is-active nginx)

===============================================
"