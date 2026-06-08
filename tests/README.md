# pRoxy Testing Infrastructure

Comprehensive testing framework for pRoxy security testing and pentesting tool.

## 🧪 Test Organization

```
tests/
├── api/                 # API endpoint tests
│   ├── test_settings.py    # Settings API tests
│   ├── test_replay.py      # Replay/fuzzing tests
│   └── test_intercept.py   # Intercept functionality tests
├── rules/              # Rule validation tests
│   └── test_rule_validation.py  # All rule types validation
├── security/           # Security-focused tests
│   └── test_security.py       # Comprehensive security testing
├── proxy/              # Core proxy functionality
│   └── test_proxy_core.py     # ProxyState and core features
├── fixtures/           # Test data and utilities
├── conftest.py         # Shared pytest fixtures
└── README.md           # This file
```

## 🚀 Quick Start

### Setup
```bash
# Install test dependencies
make install-dev

# Or manually:
pip install pytest pytest-asyncio pytest-cov pytest-mock pytest-xdist
```

### Running Tests
```bash
# All tests
make test

# Fast tests only (skip slow integration tests)
make test-fast

# With coverage report
make test-coverage

# Security tests only
make test-security

# Specific test types
make test-api
make test-rules  
make test-proxy

# Parallel execution
make test-parallel
```

### Using Test Runner Directly
```bash
# Basic usage
python run_tests.py --type all

# With options
python run_tests.py --type security --verbose --coverage
python run_tests.py --markers "not slow" --parallel 4
```

## 📋 Test Categories

### 🔌 API Tests (`tests/api/`)
- **Settings API**: CRUD operations, validation, security
- **Replay API**: Request replay, fuzzing, sequences  
- **Intercept API**: Traffic interception and modification

**Key Features Tested:**
- Request/response validation
- Authentication handling (disabled in test mode)
- Concurrent operations
- Error handling
- Input sanitization

### 🛡️ Security Tests (`tests/security/`)
Comprehensive security testing for pentesting tool safety:

- **Input Validation**: XSS, SQLi, Command Injection protection
- **Path Traversal**: File access protection  
- **ReDoS Protection**: Regex DoS prevention
- **SSRF Protection**: Server-side request forgery prevention
- **Rate Limiting**: DoS protection
- **Header Injection**: HTTP header security
- **Error Handling**: Information disclosure prevention

### 📐 Rule Validation Tests (`tests/rules/`)
Validation for all proxy rule types:

- **Header Rules**: Name validation, injection protection
- **Replace Rules**: Regex validation, ReDoS protection
- **Breakpoint Rules**: Pattern validation
- **Mock Rules**: Status code, JSON validation
- **Map Rules**: URL/path validation, path traversal protection  
- **Highlight Rules**: Color format, match type validation

### ⚙️ Proxy Core Tests (`tests/proxy/`)
Core proxy functionality:

- **ProxyState Management**: Singleton, thread safety
- **Flow Storage**: Traffic recording, search, filtering
- **Settings Management**: Rule application, persistence
- **Intercept Queue**: Request/response interception
- **Sequence Management**: Multi-step request chains

## 🧩 Test Fixtures

### Shared Fixtures (`conftest.py`)

```python
# HTTP clients
test_client          # Sync FastAPI test client
async_client         # Async HTTP client

# Mock objects  
mock_proxy_state     # Mocked ProxyState for isolation

# Test data
sample_settings      # Complete proxy settings
sample_flow          # HTTP flow record
sample_rules         # All rule types
malicious_inputs     # Security test payloads

# Utilities
auth_headers         # Auth headers (empty in test mode)
temp_config_dir      # Temporary directory
```

### Security Test Data

```python
malicious_inputs = {
    "xss_payloads": ["<script>alert('XSS')</script>", ...],
    "sql_injection": ["'; DROP TABLE users; --", ...],
    "path_traversal": ["../../../etc/passwd", ...],
    "command_injection": ["; ls -la", ...],
    "regex_dos": ["(a+)+$", ...],
    "large_payloads": ["A" * 1000000, ...]
}
```

## 🏷️ Test Markers

Use pytest markers to run specific test categories:

```bash
# Security tests only
pytest -m security

# API tests only  
pytest -m api

# Skip slow tests
pytest -m "not slow"

# Integration tests
pytest -m integration

# Rule validation tests
pytest -m rules
```

## 📊 Coverage Reporting

```bash
# Generate coverage report
make test-coverage

# View HTML report
open htmlcov/index.html

# Coverage targets:
# - Overall: 70%+
# - Security modules: 80%+
# - API endpoints: 90%+
```

## 🔧 Test Configuration

### pytest.ini
```ini
[tool:pytest]
testpaths = tests
addopts = --strict-markers --cov=api --cov=state --cov-fail-under=70
markers = 
    security: Security-focused tests
    slow: Tests that take longer to run
    integration: Integration tests
```

### Environment Variables
```bash
PROXY_DISABLE_AUTH=true    # Disable auth for testing
TESTING=true               # Enable test mode
DEBUG=1                    # Enable debug logging
```

## 🚦 CI/CD Integration

### GitHub Actions (`.github/workflows/test.yml`)
- Multi-version Python testing (3.9-3.12)
- Security scanning (Bandit, Safety)  
- Code quality checks (Black, flake8, mypy)
- Integration testing with live server
- Coverage reporting

### Local CI Commands
```bash
# Run CI test suite
make ci-test

# Security scan only
make ci-security
```

## 🎯 Writing New Tests

### Test Structure
```python
@pytest.mark.api
class TestNewFeature:
    """Test new feature functionality."""
    
    def test_basic_functionality(self, test_client):
        """Test basic feature works."""
        response = test_client.get("/api/new-feature")
        assert response.status_code == 200
    
    @pytest.mark.security
    def test_security_aspects(self, malicious_inputs):
        """Test security implications."""
        for payload in malicious_inputs["xss_payloads"]:
            # Test XSS protection
            pass
```

### Best Practices
1. **Use descriptive test names** - `test_header_rule_xss_protection`
2. **Test edge cases** - empty inputs, large payloads, concurrent access
3. **Include security tests** - always consider security implications
4. **Mock external dependencies** - use `mock_proxy_state` fixture
5. **Test both success and failure** - positive and negative cases
6. **Use appropriate markers** - `@pytest.mark.security`, etc.

## 🔍 Debugging Tests

```bash
# Run with detailed output
pytest -v -s tests/api/test_settings.py::TestSettingsAPI::test_get_settings

# Drop into debugger on failure
pytest --pdb

# Show local variables on failure  
pytest --tb=long

# Run single test
pytest tests/security/test_security.py::TestInputValidationSecurity::test_api_xss_protection
```

## 📈 Performance Testing

### Load Testing
```python
def test_concurrent_requests(self, test_client):
    """Test handling concurrent API requests."""
    import threading
    results = []
    
    def make_request():
        response = test_client.get("/api/settings")
        results.append(response.status_code)
    
    threads = [threading.Thread(target=make_request) for _ in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
        
    assert all(status == 200 for status in results)
```

## 🛠️ Troubleshooting

### Common Issues

1. **Import Errors**
   ```bash
   # Ensure project root in PYTHONPATH
   export PYTHONPATH=/mnt/hdd/rocket/pRoxy:$PYTHONPATH
   ```

2. **Authentication Errors** 
   ```bash
   # Ensure auth is disabled for testing
   export PROXY_DISABLE_AUTH=true
   ```

3. **Port Conflicts**
   ```bash
   # Kill existing processes
   pkill -f "python main.py"
   ```

4. **Database/State Issues**
   ```bash
   # Use fresh ProxyState for each test
   @patch('state.shared.ProxyState._instance', None)
   ```

## 🎯 For Pentesting Use Case

This testing framework is specifically designed for a security testing tool:

- **Security-first approach** - Every feature has security tests
- **Attack simulation** - Malicious payload testing throughout  
- **Edge case coverage** - Handles malformed input gracefully
- **Performance validation** - Ensures tool remains responsive under load
- **Integration testing** - Validates complete request/response cycles

The test suite serves as both validation and documentation of security considerations for each component.