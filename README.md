# xsukax E2E Chat System
---

## Important Note: Use HTTPS for more security Using one of the following options:
- Cloudflared Tunnels.
- Certbot.

![](https://raw.githubusercontent.com/xsukax/xsukax-E2E-CHAT-SYSTEM/refs/heads/main/screenshot.png)

A secure, end-to-end encrypted chat system with file sharing capabilities. No registration required - just generate an 8-character ID and start chatting securely.

## 📁 Repository Files

### 1. `xsukax-e2e-chat-Alpine.sh`
**For Alpine Linux servers**
- Uses `apk` package manager
- OpenRC service management
- iptables firewall configuration
- Lightweight installation for minimal servers

### 2. `xsukax-e2e-chat-Debian.sh`
**For Debian/Ubuntu servers**
- Uses `apt` package manager  
- systemd service management
- UFW firewall configuration
- Standard installation for most Linux servers

### 3. `xsukax-e2e-chat-Debian-AdminCP.sh`
**For Debian/Ubuntu with Admin Panel**
- Everything from the standard Debian version
- **Plus**: Admin control panel at `/admin`
- **Plus**: Real-time user monitoring
- **Plus**: Message logging and analytics
- **Plus**: Security controls and user management

## 🤔 Why 3 Separate Files?

1. **Different Linux Systems**: Alpine and Debian use different package managers and service systems
2. **Feature Choice**: Basic users get simple installation, admins get full control panel
3. **Easier Maintenance**: Separate files are easier to update and troubleshoot
4. **Clean Installation**: Users only install what they need

## 🔒 Security Features

- **RSA-OAEP 2048-bit encryption** for key exchange
- **AES-256-GCM encryption** for messages and files
- **Client-side key generation** - server never sees private keys
- **Zero message storage** - all messages are immediately forwarded, never saved
- **Perfect Forward Secrecy** - new keys for each chat session
- **Rate limiting** to prevent spam and abuse
- **User blocking** capabilities (admin version)
- **Secure file sharing** up to 1MB with full encryption

## 🕵️ Privacy Features

- **No registration required** - anonymous 8-character IDs
- **No personal data collection** - only connection logs for monitoring
- **Peer-to-peer design** - server only routes encrypted data
- **Self-hosted** - you control your own server and data
- **Open source** - transparent security you can verify
- **Optional logging** - admin can disable connection logs
- **Maintenance mode** - stop new connections when needed

## 🚀 Quick Start

1. **Choose your script** based on your Linux distribution and needs
2. **Run as root**: `sudo bash script-name.sh`
3. **Enter your domain** when prompted
4. **Set admin password** (for admin version)
5. **Access your chat** at `http://yourdomain.com`
6. **Admin panel** at `http://yourdomain.com/admin` (admin version only)

## 💡 Use Cases

- **Private conversations** between friends or family
- **Business communications** requiring end-to-end encryption
- **Temporary secure chats** without leaving digital traces
- **File sharing** with encryption for sensitive documents
- **Team communications** with admin oversight (admin version)

## 📊 Admin Panel Features (AdminCP version only)

- Real-time user monitoring
- Message traffic analytics
- Security configuration
- User blocking and rate limiting
- System logs and diagnostics
- Server maintenance controls
- Download complete logs

---

**⚠️ Important**: This is a self-hosted solution. You are responsible for server security, SSL certificates, and keeping the system updated.
