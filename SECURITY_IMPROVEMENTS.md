# Security & Quality Improvements

This document outlines the recent security and quality improvements made to pRoxy.

## 🔒 Security Improvements

### 1. Authentication Added
- **Dashboard authentication** using API key
- Key automatically generated on first run
- Stored securely in `~/.pRoxy/auth.key` (600 permissions)
- Access via URL parameter: `http://localhost:8081/?key=YOUR_KEY`
- Access via API header: `Authorization: Bearer YOUR_KEY`
- Disable with: `export PROXY_DISABLE_AUTH=true`

### 2. Input Validation
- **Regex pattern validation** - prevents ReDoS attacks
- **URL validation** - ensures valid schemes and hostnames
- **Path traversal prevention** - blocks `../` attacks in Map Local rules
- **File size limits** - prevents memory exhaustion
- **IP address validation** - validates DNS mappings
- **HTTP method validation** - only allows standard methods

### 3. Error Handling Improvements
- **Specific exception handling** - replaced bare `except Exception:`
- **Detailed error messages** - better debugging information
- **Resource limits** - prevents abuse of fuzzing/stress testing

## ✅ Quality Improvements

### 1. Testing Framework
- **pytest configuration** - `pytest.ini` for test settings
- **Model validation tests** - comprehensive test suite for all input validation
- **Run tests**: `python -m pytest tests/`

### 2. Dependency Management
- **Pinned versions** - all dependencies locked to specific versions
- **Missing dependencies added** - `cryptography` package included
- **Security updates** - updated to latest stable versions

### 3. API Documentation
- **OpenAPI/Swagger** - available at `/docs` endpoint
- **Interactive API docs** - test endpoints directly from browser
- **Model schemas** - auto-generated from Pydantic models

## 🚀 Quick Start with Security

1. **Install dependencies**:
   ```bash
   python -m pip install -r requirements.txt
   ```

2. **Run with authentication**:
   ```bash
   python main.py
   ```
   The console will show your auth key. Example:
   ```
   [pRoxy.auth] Generated new auth key: abc123def456
   [pRoxy.auth] Add ?key=abc123def456 to your dashboard URL
   ```

3. **Access dashboard**:
   ```
   http://localhost:8081/?key=abc123def456
   ```

4. **API documentation**:
   ```
   http://localhost:8081/docs?key=abc123def456
   ```

5. **Run tests**:
   ```bash
   python -m pytest tests/ -v
   ```

## 🔧 Configuration

### Authentication
- **Enable auth** (default): Normal operation
- **Disable auth**: `export PROXY_DISABLE_AUTH=true`
- **Reset key**: Delete `~/.pRoxy/auth.key` and restart
- **View current key**: `cat ~/.pRoxy/auth.key`

### Example Configuration
See `config.example.json` for a complete configuration template with security best practices.

## 🛡️ Security Best Practices

1. **Network Security**:
   - Bind to localhost only in production
   - Use firewall to restrict access
   - Use HTTPS proxy for sensitive traffic

2. **Authentication**:
   - Keep your auth key secret
   - Rotate keys regularly
   - Use separate keys for different environments

3. **Input Validation**:
   - Test regex patterns before deployment
   - Use relative paths for Map Local rules
   - Validate all URLs in replay/tamper requests

4. **Resource Limits**:
   - Monitor fuzzing iterations
   - Set reasonable stress test limits
   - Monitor flow storage usage

## 🐛 Known Limitations

1. **Single-user authentication** - no role-based access control
2. **In-memory storage** - flows lost on restart
3. **No request rate limiting** - can still be DoS'd via legitimate requests
4. **No audit logging** - no persistent record of actions

## 📝 Next Steps

Priority improvements for production readiness:

1. **Multi-user authentication** - RBAC with proper sessions
2. **Persistent storage** - SQLite/PostgreSQL for flows
3. **Rate limiting** - protect against abuse
4. **Audit logging** - track all user actions
5. **Container deployment** - Docker + docker-compose
6. **TLS termination** - HTTPS for the dashboard

## 📊 Test Coverage

Run tests with coverage:
```bash
python -m pytest tests/ --cov=. --cov-report=html
```

Current test coverage focuses on:
- ✅ Input validation (models)
- ✅ Security constraints
- ❌ Integration tests (TODO)
- ❌ Performance tests (TODO)
- ❌ End-to-end tests (TODO)