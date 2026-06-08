# CLAUDE.md - pRoxy Project Guidelines

Behavioral principles for high-quality, secure coding assistance on the pRoxy MITM proxy project.

**Project Context:** pRoxy is a man-in-the-middle proxy tool built with mitmproxy 12.2.2, FastAPI, and WebSocket real-time traffic streaming. Authentication is disabled for local lab environments.

**Core tradeoff:** These guidelines prioritize security, clarity, and surgical precision over speed or cleverness.

---

## 1. Think Before Coding

**Never assume silently. Surface uncertainty and security implications.**

Before writing any code:
- Explicitly state your key assumptions about proxy behavior, security model, or client expectations.
- If the request could introduce security vulnerabilities (XSS, injection, path traversal), discuss mitigations first.
- If a request involves network traffic manipulation, explain the potential impact on clients.
- If anything is unclear about proxy rules, intercept logic, or traffic handling - **stop and ask**.

**pRoxy-specific considerations:**
- "Assuming this rule applies to [request/response] phase..."
- "This could affect [client certificates/SSL handshake/upstream routing]. Intended behavior?"
- "For security, should we validate/sanitize this input against [specific attack vector]?"

---

## 2. Simplicity First

**Write the minimum secure code that fully solves the problem. No speculation.**

- Implement **exactly** what was asked - nothing more.
- Avoid over-engineering proxy rules, complex regex patterns, or premature optimization.
- Do not add configurability unless explicitly requested.
- Skip defensive error handling for impossible network scenarios.
- Prefer straightforward proxy logic over clever traffic manipulation.

**pRoxy-specific guidelines:**
- Use existing Pydantic models for validation instead of custom parsers
- Leverage mitmproxy's built-in capabilities rather than reimplementing
- Follow the established API route patterns (`/api/{feature}`)
- Match existing WebSocket message formats for consistency

**Self-check question:**
> "Would a security-conscious engineer approve this proxy modification?"

---

## 3. Surgical Precision

**Change only what is necessary. Maintain proxy stability.**

When modifying existing code:
- Touch the smallest possible surface area - proxy stability is critical.
- Never refactor unrelated proxy rules, traffic handlers, or WebSocket logic.
- Match existing patterns: FastAPI async/await, Pydantic models, state management.
- Do not modify authentication logic, SSL handling, or core mitmproxy integration unless explicitly requested.

**pRoxy-specific cleanup rules:**
- Remove imports/variables **that your changes made unused**
- Never remove existing proxy rules, mock responses, or traffic filters
- If you spot security issues elsewhere, mention them separately - do not fix them silently
- Preserve existing API response formats to avoid breaking frontend clients

**Test for surgical changes:**
Every modified line must be traceable to the user's request AND maintain proxy functionality.

---

## 4. Goal-Driven Execution

**Define clear success criteria and verify proxy behavior.**

Turn vague requests into concrete, verifiable proxy goals:

Examples:
- "Add rule validation" → "Add Pydantic validators + test invalid regex patterns are rejected"
- "Fix intercept" → "Write test that reproduces intercept failure, then make it pass"
- "Improve performance" → "Maintain current proxy behavior while reducing response latency"

**pRoxy-specific execution plan:**
1. **Understand impact**: How does this change affect traffic flow/rule processing/client behavior?
2. **Security check**: Does this introduce vulnerabilities or bypass existing protections?
3. **Test proxy behavior**: Verify rules work, traffic flows correctly, WebSocket updates properly
4. **Validate frontend**: Ensure API changes don't break the web interface

---

## 5. Security-First Mindset

**Always consider security implications of proxy modifications.**

**Input Validation:**
- All user-provided patterns, URLs, headers must be validated
- Use Pydantic validators to prevent injection attacks
- Sanitize file paths to prevent directory traversal
- Validate regex patterns to prevent ReDoS attacks

**Network Security:**
- Never disable SSL verification without explicit user request
- Preserve existing certificate validation logic
- Be cautious with upstream proxy modifications
- Validate all network-bound data (headers, bodies, URLs)

**Access Control:**
- Even with AUTH_DISABLED=True, validate all input parameters
- Log security-relevant actions (rule changes, intercept modifications)
- Don't expose internal proxy state unnecessarily

---

## 6. pRoxy Architecture Patterns

**Follow established project conventions:**

**API Structure:**
```python
# Use FastAPI with Pydantic models
router = APIRouter(prefix="/api/{feature}")

class RequestModel(BaseModel):
    # Use validators for security
    @model_validator(mode='after')
    def validate_input(self) -> 'RequestModel':
        # Validation logic here
        return self
```

**State Management:**
```python
# Use ProxyState singleton
from state.shared import ProxyState
state = ProxyState()
```

**Frontend Integration:**
```javascript
// Use authFetch for API calls (even with auth disabled)
const response = await authFetch('/api/endpoint', { method: 'POST' });
```

**Error Handling:**
```python
# Use HTTPException with appropriate status codes
raise HTTPException(400, "Descriptive error message")
```

---

## 7. Common pRoxy Patterns

**Rule Management:**
- All rules should have `enabled` boolean flag
- Use consistent naming: `{feature}_rules` arrays in settings
- Implement CRUD operations: list, create, update, delete, toggle
- Add validation for regex patterns, URLs, file paths
- **Enterprise Features:** Templates, collections, import/export, organization
- **Security Testing Templates:** Pre-configured rule sets for common attack patterns
- **Rule Collections:** Group related rules for project-specific configurations
- **Import/Export:** JSON/YAML support with validation and backup functionality

**Traffic Handling:**
- Store flows in ProxyState with consistent FlowRecord format
- Use WebSocket for real-time traffic updates
- Implement proper request/response phase handling
- Preserve original traffic data integrity

**Frontend Updates:**
- Use consistent CSS classes for UI components
- Follow existing form patterns with validation
- Implement loading states and error handling
- Use Toast notifications for user feedback

---

## 8. Testing Approach

**When adding new features:**
1. **Unit tests** for validation logic and rule processing
2. **Integration tests** for API endpoints
3. **Proxy tests** for traffic handling and rule application
4. **Security tests** for input validation and attack prevention

**Testing commands:**
```bash
# Run tests
source .venv/bin/activate
pytest tests/

# Test specific functionality
pytest tests/test_rules.py::test_header_rule_validation
```

---

## 9. Deployment Considerations

**Local Lab Setup:**
- Authentication disabled by default (AUTH_DISABLED=True)
- Use virtual environment for dependencies
- Auto-detect available ports (8080→8082→8083→8084...)
- Provide clear certificate installation instructions for mobile devices

**Security for Production:**
- Re-enable authentication system
- Add rate limiting and connection limits  
- Implement proper logging and monitoring
- Use HTTPS for dashboard access

---

**Remember:** pRoxy handles sensitive network traffic. Every change should be made with security, stability, and user safety in mind.