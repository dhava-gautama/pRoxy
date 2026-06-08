"""
Enhanced rule management system for pRoxy.
Provides rule collections, templates, import/export, and organization features.
Perfect for security testing workflows and team collaboration.
"""
from __future__ import annotations

import json
import time
from typing import Dict, List, Optional, Any
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from fastapi.responses import Response
from pydantic import BaseModel, Field

from api.auth import get_current_user, AUTH_DISABLED
from state.shared import ProxyState

router = APIRouter(
    prefix="/api/rules",
    tags=["rules"],
    dependencies=[Depends(get_current_user)] if not AUTH_DISABLED else []
)
state = ProxyState()


RULE_LIST_FIELDS = (
    "header_rules", "replace_rules", "breakpoint_rules",
    "mock_rules", "map_rules", "highlight_rules",
)


def _settings_dict() -> Dict[str, Any]:
    """Return current proxy settings as a plain dict.

    ``state.get_settings()`` returns a ``ProxySettings`` Pydantic model in the
    running app, but tests may patch it to return a dict directly. Normalise to a
    dict so the rule-management logic can manipulate it uniformly.
    """
    settings = state.get_settings()
    if hasattr(settings, "model_dump"):
        return settings.model_dump()
    return dict(settings)


def _rules_only() -> Dict[str, List[Dict]]:
    """Return only the rule-type list fields from current settings.

    ``RuleCollection.rules`` is typed ``Dict[str, List[Dict]]``, so scalar
    settings (flags, sizes, etc.) must be excluded.
    """
    settings = _settings_dict()
    return {
        field: settings.get(field, [])
        for field in RULE_LIST_FIELDS
        if isinstance(settings.get(field), list)
    }


class RuleCollection(BaseModel):
    """A collection of related rules for organization."""
    # id/created_at/updated_at are assigned server-side; clients need not supply them.
    id: str = ""
    name: str
    description: str
    tags: List[str] = []
    rules: Dict[str, List[Dict]] = Field(default_factory=dict)  # rule_type -> rules
    created_at: float = 0
    updated_at: float = 0
    author: Optional[str] = None
    version: str = "1.0"


class RuleTemplate(BaseModel):
    """Pre-defined rule template for common security testing scenarios."""
    id: str
    name: str
    description: str
    category: str  # "pentest", "bypass", "analysis", etc.
    difficulty: str  # "beginner", "intermediate", "advanced"
    tags: List[str] = []
    rules: Dict[str, List[Dict]] = Field(default_factory=dict)
    use_cases: List[str] = []
    requirements: List[str] = []
    author: str = "pRoxy"


# ── Pre-defined Security Testing Templates ────────────────────────────

RULE_TEMPLATES = [
    RuleTemplate(
        id="sql_injection_testing",
        name="SQL Injection Testing Suite",
        description="Comprehensive rule set for SQL injection testing with automated payloads",
        category="pentest",
        difficulty="intermediate",
        tags=["sql", "injection", "database", "webapp"],
        use_cases=[
            "Web application penetration testing",
            "Database security assessment",
            "Input validation testing"
        ],
        requirements=[
            "Target application with database backend",
            "Valid authentication session if required"
        ],
        rules={
            "replace_rules": [
                {
                    "pattern": "username=([^&]*)",
                    "replacement": "username=$1' OR '1'='1",
                    "phase": "request",
                    "is_regex": True,
                    "enabled": True
                },
                {
                    "pattern": "password=([^&]*)",
                    "replacement": "password=$1' UNION SELECT null,version(),null--",
                    "phase": "request",
                    "is_regex": True,
                    "enabled": False
                }
            ],
            "header_rules": [
                {
                    "name": "X-SQL-Injection-Test",
                    "value": "' OR 1=1--",
                    "phase": "request",
                    "action": "set",
                    "enabled": False
                }
            ]
        }
    ),

    RuleTemplate(
        id="xss_testing",
        name="Cross-Site Scripting (XSS) Test Suite",
        description="Automated XSS payload injection for comprehensive testing",
        category="pentest",
        difficulty="beginner",
        tags=["xss", "javascript", "client-side", "webapp"],
        use_cases=[
            "Web application security testing",
            "Input sanitization validation",
            "Client-side security assessment"
        ],
        requirements=[
            "Web application with user input fields",
            "Access to application forms or parameters"
        ],
        rules={
            "replace_rules": [
                {
                    "pattern": "search=([^&]*)",
                    "replacement": "search=<script>alert('XSS')</script>",
                    "phase": "request",
                    "is_regex": True,
                    "enabled": True
                },
                {
                    "pattern": "comment=([^&]*)",
                    "replacement": "comment=<img src=x onerror=alert('XSS')>",
                    "phase": "request",
                    "is_regex": True,
                    "enabled": False
                }
            ],
            "header_rules": [
                {
                    "name": "X-XSS-Test",
                    "value": "<script>alert('Header-XSS')</script>",
                    "phase": "request",
                    "action": "set",
                    "enabled": False
                }
            ]
        }
    ),

    RuleTemplate(
        id="bypass_waf",
        name="Web Application Firewall (WAF) Bypass",
        description="Advanced techniques to bypass common WAF protections",
        category="bypass",
        difficulty="advanced",
        tags=["waf", "bypass", "encoding", "evasion"],
        use_cases=[
            "WAF evasion testing",
            "Security control validation",
            "Advanced penetration testing"
        ],
        requirements=[
            "Target protected by WAF",
            "Knowledge of WAF vendor/type preferred"
        ],
        rules={
            "header_rules": [
                {
                    "name": "X-Forwarded-For",
                    "value": "127.0.0.1",
                    "phase": "request",
                    "action": "set",
                    "enabled": True
                },
                {
                    "name": "X-Real-IP",
                    "value": "10.0.0.1",
                    "phase": "request",
                    "action": "set",
                    "enabled": True
                },
                {
                    "name": "User-Agent",
                    "value": "Mozilla/5.0 (compatible; Googlebot/2.1)",
                    "phase": "request",
                    "action": "set",
                    "enabled": False
                }
            ],
            "replace_rules": [
                {
                    "pattern": "SELECT",
                    "replacement": "SeLeCt",
                    "phase": "request",
                    "is_regex": False,
                    "enabled": True
                },
                {
                    "pattern": "UNION",
                    "replacement": "UnIoN",
                    "phase": "request",
                    "is_regex": False,
                    "enabled": True
                }
            ]
        }
    ),

    RuleTemplate(
        id="api_testing",
        name="REST API Security Testing",
        description="Comprehensive API security testing with common attack vectors",
        category="pentest",
        difficulty="intermediate",
        tags=["api", "rest", "json", "authorization"],
        use_cases=[
            "API penetration testing",
            "Authorization bypass testing",
            "API endpoint discovery"
        ],
        requirements=[
            "Target REST API",
            "Basic API documentation or endpoints"
        ],
        rules={
            "header_rules": [
                {
                    "name": "Authorization",
                    "value": "",
                    "phase": "request",
                    "action": "remove",
                    "enabled": False
                },
                {
                    "name": "X-HTTP-Method-Override",
                    "value": "DELETE",
                    "phase": "request",
                    "action": "set",
                    "enabled": False
                }
            ],
            "replace_rules": [
                {
                    "pattern": '"role":\\s*"user"',
                    "replacement": '"role": "admin"',
                    "phase": "request",
                    "is_regex": True,
                    "enabled": False
                },
                {
                    "pattern": '"user_id":\\s*(\\d+)',
                    "replacement": '"user_id": 1',
                    "phase": "request",
                    "is_regex": True,
                    "enabled": False
                }
            ]
        }
    ),

    RuleTemplate(
        id="mobile_ssl_bypass",
        name="Mobile SSL Pinning Bypass",
        description="Complete SSL certificate pinning bypass for mobile applications",
        category="bypass",
        difficulty="advanced",
        tags=["ssl", "mobile", "pinning", "certificate"],
        use_cases=[
            "Mobile application security testing",
            "SSL pinning bypass",
            "Certificate validation testing"
        ],
        requirements=[
            "Mobile application with SSL pinning",
            "Rooted/jailbroken device preferred",
            "Frida framework for advanced bypasses"
        ],
        rules={
            "header_rules": [
                {
                    "name": "Strict-Transport-Security",
                    "value": "",
                    "phase": "response",
                    "action": "remove",
                    "enabled": True
                },
                {
                    "name": "Public-Key-Pins",
                    "value": "",
                    "phase": "response",
                    "action": "remove",
                    "enabled": True
                },
                {
                    "name": "Expect-CT",
                    "value": "",
                    "phase": "response",
                    "action": "remove",
                    "enabled": True
                }
            ]
        }
    ),

    RuleTemplate(
        id="content_discovery",
        name="Content Discovery & Enumeration",
        description="Automated content discovery with intelligent request manipulation",
        category="analysis",
        difficulty="beginner",
        tags=["discovery", "enumeration", "recon", "content"],
        use_cases=[
            "Web application reconnaissance",
            "Hidden content discovery",
            "Directory traversal testing"
        ],
        requirements=[
            "Target web application",
            "Basic access to the application"
        ],
        rules={
            "highlight_rules": [
                {
                    "match_type": "status",
                    "pattern": "200",
                    "color": "#16a34a",
                    "enabled": True
                },
                {
                    "match_type": "status",
                    "pattern": "403",
                    "color": "#dc2626",
                    "enabled": True
                },
                {
                    "match_type": "path",
                    "pattern": "admin|config|backup",
                    "color": "#ea580c",
                    "enabled": True
                }
            ]
        }
    )
]


# ── Rule Collections Management ─────────────────────────────────────────

@router.get("/collections")
def get_rule_collections():
    """Get all saved rule collections."""
    # In production, this would load from database
    # For now, return example collections
    collections = [
        RuleCollection(
            id="pentest_web_2024",
            name="Web Pentesting 2024",
            description="Standard web application penetration testing rules",
            tags=["pentest", "web", "2024"],
            rules={
                "header_rules": [
                    {"name": "X-Forwarded-For", "value": "127.0.0.1", "phase": "request", "action": "set", "enabled": True}
                ],
                "replace_rules": [
                    {"pattern": "admin", "replacement": "user", "phase": "request", "is_regex": False, "enabled": False}
                ]
            },
            created_at=time.time() - 86400,
            updated_at=time.time(),
            author="security_team",
            version="1.2"
        )
    ]

    return {
        "collections": collections,
        "total": len(collections)
    }


@router.post("/collections")
def create_rule_collection(collection: RuleCollection):
    """Create a new rule collection."""
    collection.id = f"collection_{int(time.time() * 1000)}"
    collection.created_at = time.time()
    collection.updated_at = time.time()

    # In production, save to database
    return {
        "message": "Rule collection created successfully",
        "collection_id": collection.id,
        "collection": collection
    }


@router.get("/collections/{collection_id}")
def get_rule_collection(collection_id: str):
    """Get a specific rule collection."""
    # In production, load from database
    # For now, return mock data
    collection = RuleCollection(
        id=collection_id,
        name="Example Collection",
        description="Example rule collection",
        tags=["example"],
        rules=_rules_only(),  # Use current settings as example
        created_at=time.time() - 3600,
        updated_at=time.time(),
        version="1.0"
    )

    return collection


@router.put("/collections/{collection_id}")
def update_rule_collection(collection_id: str, collection: RuleCollection):
    """Update an existing rule collection."""
    collection.id = collection_id
    collection.updated_at = time.time()

    # In production, update in database
    return {
        "message": "Rule collection updated successfully",
        "collection": collection
    }


@router.delete("/collections/{collection_id}")
def delete_rule_collection(collection_id: str):
    """Delete a rule collection."""
    # In production, delete from database
    return {"message": f"Rule collection {collection_id} deleted successfully"}


@router.post("/collections/{collection_id}/apply")
def apply_rule_collection(collection_id: str, options: Dict = None):
    """Apply a rule collection to current proxy settings."""
    # In production, load collection from database
    # For now, just update current settings

    if options is None:
        options = {"merge": True, "backup_current": True}

    # If backup_current is enabled, save current settings
    if options.get("backup_current", False):
        backup = RuleCollection(
            id=f"backup_{int(time.time() * 1000)}",
            name=f"Backup {time.strftime('%Y-%m-%d %H:%M')}",
            description="Automatic backup before applying collection",
            tags=["backup", "auto"],
            rules=_rules_only(),
            created_at=time.time(),
            updated_at=time.time(),
            author="system"
        )
        # Save backup (in production)

    # Apply collection rules
    # For demo, just return success
    return {
        "message": f"Rule collection {collection_id} applied successfully",
        "backup_created": options.get("backup_current", False),
        "merge_mode": options.get("merge", True)
    }


# ── Rule Templates ─────────────────────────────────────────────────────

@router.get("/templates")
def get_rule_templates(
    category: Optional[str] = None,
    difficulty: Optional[str] = None,
    tags: Optional[str] = None
):
    """Get available rule templates with optional filtering."""
    templates = RULE_TEMPLATES

    # Apply filters
    if category:
        templates = [t for t in templates if t.category == category]

    if difficulty:
        templates = [t for t in templates if t.difficulty == difficulty]

    if tags:
        tag_list = [t.strip() for t in tags.split(',')]
        templates = [t for t in templates if any(tag in t.tags for tag in tag_list)]

    # Group by category for easier browsing
    by_category = {}
    for template in templates:
        if template.category not in by_category:
            by_category[template.category] = []
        by_category[template.category].append(template)

    return {
        "templates": templates,
        "by_category": by_category,
        "total": len(templates),
        "categories": list(set(t.category for t in RULE_TEMPLATES)),
        "difficulties": ["beginner", "intermediate", "advanced"],
        "all_tags": list(set(tag for t in RULE_TEMPLATES for tag in t.tags))
    }


@router.get("/templates/{template_id}")
def get_rule_template(template_id: str):
    """Get detailed information about a specific template."""
    template = next((t for t in RULE_TEMPLATES if t.id == template_id), None)

    if not template:
        raise HTTPException(404, f"Template {template_id} not found")

    return template


@router.post("/templates/{template_id}/apply")
def apply_rule_template(template_id: str, options: Dict = None):
    """Apply a rule template to current proxy settings."""
    template = next((t for t in RULE_TEMPLATES if t.id == template_id), None)

    if not template:
        raise HTTPException(404, f"Template {template_id} not found")

    if options is None:
        options = {"merge": True, "backup_current": True}

    # Backup current settings if requested
    current_settings = _settings_dict()

    if options.get("backup_current", False):
        backup = {
            "timestamp": time.time(),
            "settings": current_settings,
            "template_applied": template_id
        }
        # Save backup (in production)

    # Apply template rules
    updated_settings = current_settings.copy()

    if options.get("merge", True):
        # Merge template rules with existing rules
        for rule_type, rules in template.rules.items():
            if rule_type in updated_settings:
                if isinstance(updated_settings[rule_type], list):
                    updated_settings[rule_type].extend(rules)
                else:
                    updated_settings[rule_type] = rules
            else:
                updated_settings[rule_type] = rules
    else:
        # Replace existing rules with template rules
        updated_settings.update(template.rules)

    # Update proxy settings
    state.update_settings(updated_settings)

    return {
        "message": f"Template '{template.name}' applied successfully",
        "template": template,
        "backup_created": options.get("backup_current", False),
        "merge_mode": options.get("merge", True),
        "rules_added": sum(len(rules) for rules in template.rules.values())
    }


# ── Import/Export ──────────────────────────────────────────────────────

@router.get("/export")
def export_rules(
    format: str = "json",
    include_settings: bool = True,
    include_metadata: bool = True
):
    """Export current rules in various formats."""
    current_settings = _settings_dict()

    export_data = {
        "rules": current_settings,
        "metadata": {
            "exported_at": time.time(),
            "proxy_version": "pRoxy 1.0.0",
            "export_format": format,
            "includes_settings": include_settings
        } if include_metadata else {}
    }

    if format == "json":
        content = json.dumps(export_data, indent=2)
        media_type = "application/json"
        filename = f"proxy_rules_{int(time.time())}.json"
    elif format == "yaml":
        try:
            import yaml
            content = yaml.dump(export_data, default_flow_style=False)
            media_type = "application/x-yaml"
            filename = f"proxy_rules_{int(time.time())}.yaml"
        except ImportError:
            raise HTTPException(400, "YAML support not available")
    else:
        raise HTTPException(400, f"Unsupported export format: {format}")

    return Response(
        content=content,
        media_type=media_type,
        headers={
            "Content-Disposition": f"attachment; filename={filename}"
        }
    )


@router.post("/import")
async def import_rules(
    file: UploadFile = File(...),
    merge: bool = True,
    backup_current: bool = True,
    validate_only: bool = False
):
    """Import rules from uploaded file."""
    try:
        content = await file.read()

        if file.filename.endswith('.json'):
            import_data = json.loads(content)
        elif file.filename.endswith(('.yaml', '.yml')):
            try:
                import yaml
                import_data = yaml.safe_load(content)
            except ImportError:
                raise HTTPException(400, "YAML support not available")
        else:
            raise HTTPException(400, "Unsupported file format. Use JSON or YAML.")

        # Validate import data structure
        if "rules" not in import_data:
            raise HTTPException(400, "Invalid import file: missing 'rules' section")

        imported_rules = import_data["rules"]

        # Validate rule structure
        valid_rule_types = [
            "header_rules", "replace_rules", "breakpoint_rules",
            "mock_rules", "map_rules", "highlight_rules", "scope_patterns"
        ]

        validation_errors = []
        for rule_type, rules in imported_rules.items():
            if rule_type not in valid_rule_types and not rule_type.endswith(('_strip', '_bypass', '_enabled')):
                validation_errors.append(f"Unknown rule type: {rule_type}")

        if validation_errors:
            return {
                "valid": False,
                "errors": validation_errors,
                "preview": imported_rules
            }

        if validate_only:
            return {
                "valid": True,
                "preview": imported_rules,
                "rule_counts": {
                    rule_type: len(rules) if isinstance(rules, list) else 1
                    for rule_type, rules in imported_rules.items()
                }
            }

        # Backup current settings if requested
        if backup_current:
            backup_data = {
                "timestamp": time.time(),
                "settings": _settings_dict(),
                "import_file": file.filename
            }
            # Save backup (in production)

        # Apply imported rules
        current_settings = _settings_dict()

        if merge:
            # Merge with existing rules
            updated_settings = current_settings.copy()
            for rule_type, rules in imported_rules.items():
                if rule_type in updated_settings:
                    if isinstance(updated_settings[rule_type], list) and isinstance(rules, list):
                        updated_settings[rule_type].extend(rules)
                    else:
                        updated_settings[rule_type] = rules
                else:
                    updated_settings[rule_type] = rules
        else:
            # Replace existing rules
            updated_settings = imported_rules

        # Update proxy settings
        state.update_settings(updated_settings)

        return {
            "message": "Rules imported successfully",
            "imported_from": file.filename,
            "backup_created": backup_current,
            "merge_mode": merge,
            "rule_counts": {
                rule_type: len(rules) if isinstance(rules, list) else 1
                for rule_type, rules in imported_rules.items()
            },
            "metadata": import_data.get("metadata", {})
        }

    except json.JSONDecodeError as e:
        raise HTTPException(400, f"Invalid JSON format: {e}")
    except HTTPException:
        # Preserve client-error responses (e.g. missing 'rules' section) raised above.
        raise
    except Exception as e:
        raise HTTPException(500, f"Import failed: {e}")


# ── Rule Organization ─────────────────────────────────────────────────

class OrganizeRequest(BaseModel):
    action: str  # "reorder", "group", "cleanup"
    target_type: str  # rule type to organize
    options: Dict = Field(default_factory=dict)


@router.post("/organize")
def organize_rules(request: OrganizeRequest):
    """Organize rules with various actions."""
    action = request.action
    target_type = request.target_type
    options = request.options or {}

    current_settings = _settings_dict()

    if target_type not in current_settings:
        raise HTTPException(404, f"Rule type {target_type} not found")

    rules = current_settings[target_type]

    if not isinstance(rules, list):
        raise HTTPException(400, f"Cannot organize non-list rule type: {target_type}")

    if action == "reorder":
        # Reorder rules by priority or criteria
        if options.get("by") == "enabled":
            rules.sort(key=lambda r: (not r.get("enabled", True), r.get("name", "")))
        elif options.get("by") == "name":
            rules.sort(key=lambda r: r.get("name", "").lower())
        elif options.get("by") == "type":
            rules.sort(key=lambda r: r.get("phase", ""))
        else:
            # Custom order specified
            order = options.get("order", [])
            if len(order) == len(rules):
                rules = [rules[i] for i in order]

    elif action == "cleanup":
        # Remove disabled or invalid rules
        original_count = len(rules)
        if options.get("remove_disabled", False):
            rules = [r for r in rules if r.get("enabled", True)]
        if options.get("remove_empty", False):
            rules = [r for r in rules if r.get("pattern") or r.get("name")]
        cleaned_count = original_count - len(rules)

    elif action == "group":
        # Group similar rules together
        # For now, just sort by phase/type
        rules.sort(key=lambda r: (r.get("phase", ""), r.get("action", ""), r.get("name", "")))

    else:
        raise HTTPException(400, f"Unsupported organization action: {action}")

    # Update settings
    updated_settings = current_settings.copy()
    updated_settings[target_type] = rules
    state.update_settings(updated_settings)

    result = {
        "message": f"Rules organized using action: {action}",
        "rule_type": target_type,
        "total_rules": len(rules)
    }

    if action == "cleanup":
        result["rules_removed"] = cleaned_count

    return result


@router.get("/statistics")
def get_rule_statistics():
    """Get comprehensive statistics about current rules."""
    current_settings = _settings_dict()

    stats = {
        "total_rules": 0,
        "by_type": {},
        "enabled_rules": 0,
        "disabled_rules": 0,
        "rule_complexity": {},
        "common_patterns": [],
        "settings_flags": {}
    }

    # Count rules by type
    rule_types = ["header_rules", "replace_rules", "breakpoint_rules", "mock_rules", "map_rules", "highlight_rules"]

    for rule_type in rule_types:
        rules = current_settings.get(rule_type, [])
        if isinstance(rules, list):
            count = len(rules)
            enabled = sum(1 for r in rules if r.get("enabled", True))
            disabled = count - enabled

            stats["by_type"][rule_type] = {
                "total": count,
                "enabled": enabled,
                "disabled": disabled
            }

            stats["total_rules"] += count
            stats["enabled_rules"] += enabled
            stats["disabled_rules"] += disabled

    # Scope patterns
    scope_patterns = current_settings.get("scope_patterns", [])
    stats["scope_patterns"] = len(scope_patterns)

    # Settings flags
    flag_keys = ["hsts_strip", "hpkp_strip", "csp_strip", "cors_bypass", "force_ssl",
                 "intercept_enabled", "intercept_responses"]
    for key in flag_keys:
        stats["settings_flags"][key] = current_settings.get(key, False)

    # Complexity analysis
    stats["rule_complexity"] = {
        "has_regex_rules": any(
            rule.get("is_regex", False)
            for rule_type in ["replace_rules", "map_rules", "mock_rules"]
            for rule in current_settings.get(rule_type, [])
        ),
        "has_conditional_rules": len(current_settings.get("breakpoint_rules", [])) > 0,
        "has_mock_responses": len(current_settings.get("mock_rules", [])) > 0,
        "uses_header_manipulation": len(current_settings.get("header_rules", [])) > 0
    }

    return stats