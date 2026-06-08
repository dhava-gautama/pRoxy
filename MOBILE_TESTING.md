# 📱 Mobile Device Testing Guide

This guide covers pRoxy's advanced features specifically designed for **real-world mobile device testing** without requiring root or jailbreak access.

## 🎯 The Mobile Testing Challenge

Traditional proxy tools struggle with mobile devices because:
- ❌ **Many apps bypass proxy settings** (banking, social media, games)
- ❌ **Certificate pinning** prevents traffic analysis
- ❌ **Root/jailbreak** is not practical in real-world testing
- ❌ **Complex setup** discourages regular testing
- ❌ **Limited protocol support** misses custom app protocols

## ✅ pRoxy's Mobile-First Solution

pRoxy solves these challenges with **multiple proxy modes** designed for different mobile testing scenarios:

---

## 🔒 WireGuard VPN Mode (Recommended)

**Best for: Comprehensive mobile app testing without root**

### Why WireGuard is Perfect for Mobile

```javascript
// Instead of per-app proxy configuration...
// WireGuard captures ALL device traffic as VPN
```

**✅ Advantages:**
- **Works on ANY device** - no root/jailbreak needed
- **Captures ALL traffic** - even apps that ignore proxy settings
- **Bypasses proxy detection** - apps see normal VPN, not proxy
- **Remote testing** - works over internet for distributed teams
- **Protocol agnostic** - captures HTTP, WebSocket, custom protocols

**📱 Mobile Setup:**
1. Install WireGuard app from store (free)
2. Scan QR code from pRoxy dashboard
3. Enable VPN connection
4. ALL device traffic flows through pRoxy

```bash
# Start WireGuard server in pRoxy
curl -X POST http://localhost:8081/api/wireguard/start

# Create mobile client
curl -X POST "http://localhost:8081/api/wireguard/clients?name=iPhone-Test&device_type=ios"

# Get QR code for easy mobile setup
curl http://localhost:8081/api/wireguard/clients/client_123/config?format=qr
```

### Real-World Success Stories

**Banking Apps:**
- Traditional proxy: ❌ "Network Error"
- WireGuard VPN: ✅ Full traffic capture including custom auth protocols

**Mobile Games:**  
- Traditional proxy: ❌ Misses game-specific TCP connections
- WireGuard VPN: ✅ Captures all game traffic, leaderboards, purchases

**Social Media:**
- Traditional proxy: ❌ Apps detect and block proxy
- WireGuard VPN: ✅ Seamless capture of media uploads, chat protocols

---

## 🔄 Reverse Proxy Mode

**Best for: API testing without client configuration**

### How Reverse Proxy Works

```javascript
// Traditional: App → Proxy → Server
// Problem: App must be configured to use proxy

// Reverse Proxy: App → pRoxy (acting as server) → Real Server  
// Solution: App connects directly to pRoxy, no config needed!
```

**Perfect Use Cases:**
- **API Security Testing** - Full control over responses
- **Mock API Development** - Return custom responses
- **Performance Testing** - Simulate slow/fast/error responses
- **A/B Testing** - Different responses for same requests

**🚀 Setup Example:**
```bash
# Start reverse proxy for API testing
curl -X POST "http://localhost:8081/api/proxy/modes/reverse" \
  -d "target_url=https://api.realserver.com&listen_port=8443"

# Now point mobile app to: your-proxy-ip:8443
# App thinks it's talking to real server, but pRoxy has full control!
```

**📱 Mobile Implementation:**
1. Start reverse proxy mode in pRoxy
2. Change app's server URL to point to pRoxy IP
3. App connects directly (no proxy config needed)
4. Full request/response manipulation available

---

## 📋 Regular Proxy Mode (Enhanced for Mobile)

**Best for: Development and browser testing**

### Enhanced Mobile Setup

pRoxy provides **smart device detection** and **customized setup instructions**:

```bash
# Get device-specific recommendations
curl "http://localhost:8081/api/proxy/modes/best-for-device?device_type=android&rooted=false&use_case=testing"

# Response includes:
{
  "recommendation": {
    "primary": "wireguard",
    "fallback": "regular", 
    "reason": "WireGuard captures ALL traffic including apps that bypass proxy settings"
  },
  "setup_guides": {
    "regular": "/api/proxy/setup-guide/regular",
    "wireguard": "/api/proxy/setup-guide/wireguard"
  }
}
```

### One-Click Certificate Installation

**QR Code Certificate Setup:**
```bash
# Generate QR code for certificate installation
curl http://localhost:8081/api/proxy/certificates/android

# Mobile users scan QR → automatic certificate installation
```

**Platform-Specific Certificates:**
- **Android**: Auto-formatted for easy installation
- **iOS**: Configuration profile with trust settings
- **Desktop**: Standard PEM/P12 formats

---

## 🔧 Content Injection (Silent Security Testing)

**Replace `evil.com/script.js` content with `safe.com/script.js` transparently**

### How It Works

```javascript
// Client requests: https://malicious-api.com/tracker.js
// pRoxy fetches content from: https://safe-api.com/clean-tracker.js
// Client receives safe content but sees original URL!
```

**Security Testing Applications:**
- **Replace malicious scripts** with safe versions
- **Inject custom payloads** for penetration testing
- **A/B testing** with different script versions
- **Development** - use local files instead of CDN

**⚡ Quick Setup:**
```bash
curl -X POST http://localhost:8081/api/replay/content-injection \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Security Test Rule",
    "match_pattern": "evil-app.com/*.js",
    "source_url": "safe-cdn.com/clean-scripts.js",
    "preserve_headers": true
  }'
```

---

## 📊 Smart Device Recommendations

pRoxy provides **intelligent recommendations** based on your testing scenario:

### Device + Use Case Matrix

| Device | Root Status | Use Case | Recommended Mode | Why |
|--------|-------------|----------|------------------|-----|
| Android | Non-rooted | Testing | **WireGuard VPN** | Captures all traffic, bypasses proxy detection |
| Android | Rooted | Testing | Transparent Mode | System-level capture with root access |
| iOS | Non-jailbroken | Testing | **WireGuard VPN** | iOS apps heavily ignore proxy settings |
| Any | Any | API Testing | **Reverse Proxy** | Zero client configuration needed |
| Any | Any | Development | Regular Proxy | Easy setup with certificate automation |

### Dynamic Recommendations API

```bash
# Get personalized recommendations
curl "http://localhost:8081/api/proxy/modes/best-for-device" \
  -G -d "device_type=ios" -d "rooted=false" -d "use_case=security_analysis"

# Returns optimized setup for your exact scenario
```

---

## 🎯 Real-World Testing Scenarios

### Scenario 1: Banking App Penetration Testing

**Challenge**: Banking app detects and blocks traditional proxies

**Solution**: WireGuard VPN Mode
```bash
# 1. Setup WireGuard VPN
curl -X POST http://localhost:8081/api/wireguard/start

# 2. Create mobile client  
curl -X POST "http://localhost:8081/api/wireguard/clients?name=Banking-Test&device_type=android"

# 3. Phone connects via VPN - captures all banking traffic
# 4. App sees normal VPN, not proxy - no detection
# 5. Full SSL/TLS analysis with certificate control
```

**Result**: ✅ Complete banking app traffic analysis without detection

### Scenario 2: API Security Assessment

**Challenge**: Need to test API responses without modifying mobile app

**Solution**: Reverse Proxy Mode
```bash
# 1. Start reverse proxy targeting real API
curl -X POST "http://localhost:8081/api/proxy/modes/reverse" \
  -d "target_url=https://api.bank.com&listen_port=8443"

# 2. Point app to pRoxy instead of real API
# App config: api.bank.com → your-proxy-server:8443

# 3. Full control over API responses for security testing
```

**Result**: ✅ Complete API manipulation without app modification

### Scenario 3: Mobile Game Traffic Analysis

**Challenge**: Game uses custom protocols, bypasses HTTP proxy

**Solution**: WireGuard VPN + Content Processing
```bash
# 1. Capture ALL game traffic via VPN
# 2. Process binary protocols with content analyzers
# 3. Extract game API endpoints and authentication
```

**Result**: ✅ Complete game protocol reverse engineering

### Scenario 4: Development Workflow

**Challenge**: Test mobile app against local development API

**Solution**: Regular Proxy + Content Injection
```bash
# 1. Setup regular proxy with QR certificate installation
# 2. Use content injection to redirect API calls:
#    prod-api.com → localhost:3000
```

**Result**: ✅ Seamless development testing on mobile devices

---

## 🚀 Getting Started

### Quick Start for Non-Rooted Mobile Testing

1. **Choose Your Mode** (recommended: WireGuard VPN)
   ```bash
   curl -X POST http://localhost:8081/api/wireguard/start
   ```

2. **Create Mobile Client**
   ```bash  
   curl -X POST "http://localhost:8081/api/wireguard/clients?name=MyPhone&device_type=android"
   ```

3. **Get QR Code Setup**
   - Open pRoxy dashboard
   - Navigate to "📱 Mobile" tab
   - Scan QR code with WireGuard app

4. **Start Testing!**
   - Enable VPN on mobile device
   - ALL traffic flows through pRoxy
   - View real-time analysis in dashboard

### Test Your Setup

```bash
python test_mobile_features.py
```

This comprehensive test validates:
- ✅ Proxy mode recommendations
- ✅ WireGuard VPN configuration  
- ✅ Reverse proxy functionality
- ✅ Content injection rules
- ✅ Mobile setup guides
- ✅ Certificate management

---

## 📈 Advanced Features

### Traffic Replay for Mobile
Record real mobile traffic, then replay for:
- **Load testing** with actual mobile patterns
- **Regression testing** with baseline mobile flows  
- **Performance analysis** of mobile-specific optimizations

### HAR Export for Mobile Analysis
Export mobile traffic in HAR format for:
- **Browser dev tools** analysis
- **Performance monitoring** integration
- **Team collaboration** on mobile findings

### TCP Proxying for Custom Protocols
Handle non-HTTP mobile traffic:
- **Game protocols** (TCP/UDP custom protocols)
- **IoT communication** (MQTT, CoAP)
- **Streaming protocols** (RTMP, WebRTC)

---

## 🎉 Why pRoxy Excels at Mobile Testing

1. **Real-World Focus**: Designed for non-rooted devices and production scenarios
2. **Multiple Modes**: Choose the right approach for your specific testing needs
3. **Smart Recommendations**: AI-powered guidance for optimal setup
4. **Zero Configuration**: WireGuard VPN and Reverse Proxy eliminate complex setup
5. **Complete Coverage**: Capture traffic that other tools miss
6. **Security First**: Built-in content injection and threat detection
7. **Developer Friendly**: Rich APIs and automation support

**Traditional tools force you to adapt to their limitations.**
**pRoxy adapts to real-world mobile testing requirements.**

Ready to revolutionize your mobile testing? Start with the 📱 Mobile tab in your pRoxy dashboard!