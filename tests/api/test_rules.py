"""
Tests for enhanced rule management system.
Covers templates, collections, import/export, and organization features.
"""
from __future__ import annotations

import json
import pytest
from unittest.mock import Mock, patch
from fastapi.testclient import TestClient
from io import BytesIO


def test_get_rule_templates(test_client: TestClient):
    """Test retrieving rule templates."""
    response = test_client.get("/api/rules/templates")
    assert response.status_code == 200

    data = response.json()
    assert "templates" in data
    assert "by_category" in data
    assert "categories" in data
    assert "difficulties" in data
    assert len(data["templates"]) > 0

    # Verify template structure
    template = data["templates"][0]
    assert "id" in template
    assert "name" in template
    assert "description" in template
    assert "category" in template
    assert "difficulty" in template
    assert "rules" in template


def test_get_rule_templates_filtered(test_client: TestClient):
    """Test retrieving rule templates with filters."""
    # Test category filter
    response = test_client.get("/api/rules/templates?category=pentest")
    assert response.status_code == 200
    data = response.json()
    for template in data["templates"]:
        assert template["category"] == "pentest"

    # Test difficulty filter
    response = test_client.get("/api/rules/templates?difficulty=beginner")
    assert response.status_code == 200
    data = response.json()
    for template in data["templates"]:
        assert template["difficulty"] == "beginner"

    # Test tags filter
    response = test_client.get("/api/rules/templates?tags=sql")
    assert response.status_code == 200
    data = response.json()
    for template in data["templates"]:
        assert any("sql" in tag for tag in template["tags"])


def test_get_specific_rule_template(test_client: TestClient):
    """Test retrieving a specific rule template."""
    response = test_client.get("/api/rules/templates/sql_injection_testing")
    assert response.status_code == 200

    template = response.json()
    assert template["id"] == "sql_injection_testing"
    assert template["name"] == "SQL Injection Testing Suite"
    assert "rules" in template
    assert "replace_rules" in template["rules"]


def test_get_nonexistent_rule_template(test_client: TestClient):
    """Test retrieving a non-existent rule template."""
    response = test_client.get("/api/rules/templates/nonexistent")
    assert response.status_code == 404


def test_apply_rule_template(test_client: TestClient, mock_proxy_state):
    """Test applying a rule template."""
    # Mock current settings
    mock_proxy_state.get_settings.return_value = {
        "header_rules": [],
        "replace_rules": []
    }
    mock_proxy_state.update_settings.return_value = {"success": True}

    response = test_client.post("/api/rules/templates/sql_injection_testing/apply", json={
        "merge": True,
        "backup_current": True
    })
    assert response.status_code == 200

    data = response.json()
    assert "message" in data
    assert "template" in data
    assert "rules_added" in data
    assert data["merge_mode"] is True
    assert data["backup_created"] is True

    # Verify state was updated
    mock_proxy_state.update_settings.assert_called_once()


def test_apply_nonexistent_template(test_client: TestClient):
    """Test applying a non-existent template."""
    response = test_client.post("/api/rules/templates/nonexistent/apply")
    assert response.status_code == 404


def test_get_rule_collections(test_client: TestClient):
    """Test retrieving rule collections."""
    response = test_client.get("/api/rules/collections")
    assert response.status_code == 200

    data = response.json()
    assert "collections" in data
    assert "total" in data
    assert isinstance(data["collections"], list)


def test_create_rule_collection(test_client: TestClient):
    """Test creating a new rule collection."""
    collection_data = {
        "name": "Test Collection",
        "description": "Test collection for unit tests",
        "tags": ["test", "unit"],
        "rules": {
            "header_rules": [
                {"name": "X-Test", "value": "test", "phase": "request", "action": "set", "enabled": True}
            ]
        },
        "author": "test_user",
        "version": "1.0"
    }

    response = test_client.post("/api/rules/collections", json=collection_data)
    assert response.status_code == 200

    data = response.json()
    assert "message" in data
    assert "collection_id" in data
    assert "collection" in data
    assert data["collection"]["name"] == "Test Collection"


def test_get_specific_rule_collection(test_client: TestClient, mock_proxy_state):
    """Test retrieving a specific rule collection."""
    # Mock current settings for the example collection
    mock_proxy_state.get_settings.return_value = {"header_rules": []}

    response = test_client.get("/api/rules/collections/test_collection")
    assert response.status_code == 200

    collection = response.json()
    assert "id" in collection
    assert "name" in collection
    assert "rules" in collection


def test_update_rule_collection(test_client: TestClient):
    """Test updating a rule collection."""
    collection_data = {
        "name": "Updated Collection",
        "description": "Updated description",
        "tags": ["updated"],
        "rules": {},
        "version": "1.1"
    }

    response = test_client.put("/api/rules/collections/test_collection", json=collection_data)
    assert response.status_code == 200

    data = response.json()
    assert "message" in data
    assert data["collection"]["name"] == "Updated Collection"


def test_delete_rule_collection(test_client: TestClient):
    """Test deleting a rule collection."""
    response = test_client.delete("/api/rules/collections/test_collection")
    assert response.status_code == 200

    data = response.json()
    assert "message" in data


def test_apply_rule_collection(test_client: TestClient):
    """Test applying a rule collection."""
    response = test_client.post("/api/rules/collections/test_collection/apply", json={
        "merge": True,
        "backup_current": True
    })
    assert response.status_code == 200

    data = response.json()
    assert "message" in data
    assert "backup_created" in data
    assert "merge_mode" in data


def test_export_rules_json(test_client: TestClient, mock_proxy_state):
    """Test exporting rules in JSON format."""
    # Mock current settings
    mock_proxy_state.get_settings.return_value = {
        "header_rules": [
            {"name": "X-Test", "value": "test", "phase": "request", "action": "set", "enabled": True}
        ],
        "replace_rules": []
    }

    response = test_client.get("/api/rules/export?format=json")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"
    assert "attachment" in response.headers["content-disposition"]

    # Verify JSON structure
    data = response.json()
    assert "rules" in data
    assert "metadata" in data
    assert data["metadata"]["export_format"] == "json"


def test_export_rules_unsupported_format(test_client: TestClient):
    """Test exporting rules in unsupported format."""
    response = test_client.get("/api/rules/export?format=xml")
    assert response.status_code == 400


def test_import_rules_json(test_client: TestClient, mock_proxy_state):
    """Test importing rules from JSON file."""
    # Mock current settings
    mock_proxy_state.get_settings.return_value = {"header_rules": []}
    mock_proxy_state.update_settings.return_value = {"success": True}

    # Create test import data
    import_data = {
        "rules": {
            "header_rules": [
                {"name": "X-Imported", "value": "imported", "phase": "request", "action": "set", "enabled": True}
            ]
        },
        "metadata": {
            "exported_at": 1234567890,
            "proxy_version": "pRoxy 1.0.0"
        }
    }

    # Create file-like object
    file_content = json.dumps(import_data).encode()
    files = {"file": ("rules.json", BytesIO(file_content), "application/json")}

    response = test_client.post("/api/rules/import", files=files, data={
        "merge": "true",
        "backup_current": "true"
    })
    assert response.status_code == 200

    data = response.json()
    assert "message" in data
    assert "rule_counts" in data
    assert data["imported_from"] == "rules.json"
    assert data["merge_mode"] is True

    # Verify state was updated
    mock_proxy_state.update_settings.assert_called_once()


def test_import_rules_invalid_json(test_client: TestClient):
    """Test importing rules from invalid JSON file."""
    file_content = b"invalid json content"
    files = {"file": ("invalid.json", BytesIO(file_content), "application/json")}

    response = test_client.post("/api/rules/import", files=files)
    assert response.status_code == 400


def test_import_rules_missing_rules_section(test_client: TestClient):
    """Test importing file without rules section."""
    import_data = {"metadata": {"version": "1.0"}}
    file_content = json.dumps(import_data).encode()
    files = {"file": ("incomplete.json", BytesIO(file_content), "application/json")}

    response = test_client.post("/api/rules/import", files=files)
    assert response.status_code == 400


def test_import_rules_validate_only(test_client: TestClient):
    """Test importing rules with validation only."""
    import_data = {
        "rules": {
            "header_rules": [
                {"name": "X-Valid", "value": "valid", "phase": "request", "action": "set", "enabled": True}
            ]
        }
    }

    file_content = json.dumps(import_data).encode()
    files = {"file": ("test.json", BytesIO(file_content), "application/json")}

    response = test_client.post("/api/rules/import?validate_only=true", files=files)
    assert response.status_code == 200

    data = response.json()
    assert "valid" in data
    assert "preview" in data
    assert "rule_counts" in data
    assert data["valid"] is True


def test_organize_rules_reorder(test_client: TestClient, mock_proxy_state):
    """Test organizing rules by reordering."""
    # Mock current settings with rules to reorder
    mock_proxy_state.get_settings.return_value = {
        "header_rules": [
            {"name": "B-Header", "enabled": False},
            {"name": "A-Header", "enabled": True}
        ]
    }
    mock_proxy_state.update_settings.return_value = {"success": True}

    response = test_client.post("/api/rules/organize", json={
        "action": "reorder",
        "target_type": "header_rules",
        "options": {"by": "name"}
    })
    assert response.status_code == 200

    data = response.json()
    assert "message" in data
    assert data["rule_type"] == "header_rules"

    # Verify state was updated
    mock_proxy_state.update_settings.assert_called_once()


def test_organize_rules_cleanup(test_client: TestClient, mock_proxy_state):
    """Test organizing rules by cleanup."""
    # Mock current settings with disabled rules
    mock_proxy_state.get_settings.return_value = {
        "header_rules": [
            {"name": "Enabled", "enabled": True},
            {"name": "Disabled", "enabled": False}
        ]
    }
    mock_proxy_state.update_settings.return_value = {"success": True}

    response = test_client.post("/api/rules/organize", json={
        "action": "cleanup",
        "target_type": "header_rules",
        "options": {"remove_disabled": True}
    })
    assert response.status_code == 200

    data = response.json()
    assert "rules_removed" in data


def test_organize_rules_invalid_action(test_client: TestClient):
    """Test organizing rules with invalid action."""
    response = test_client.post("/api/rules/organize", json={
        "action": "invalid_action",
        "target_type": "header_rules"
    })
    assert response.status_code == 400


def test_organize_rules_nonexistent_type(test_client: TestClient, mock_proxy_state):
    """Test organizing non-existent rule type."""
    mock_proxy_state.get_settings.return_value = {}

    response = test_client.post("/api/rules/organize", json={
        "action": "reorder",
        "target_type": "nonexistent_rules"
    })
    assert response.status_code == 404


def test_get_rule_statistics(test_client: TestClient, mock_proxy_state):
    """Test retrieving rule statistics."""
    # Mock current settings with various rule types
    mock_proxy_state.get_settings.return_value = {
        "header_rules": [
            {"name": "Header1", "enabled": True},
            {"name": "Header2", "enabled": False}
        ],
        "replace_rules": [
            {"pattern": "test", "replacement": "TEST", "enabled": True}
        ],
        "hsts_strip": True,
        "cors_bypass": False,
        "scope_patterns": ["*.example.com", "*.test.com"]
    }

    response = test_client.get("/api/rules/statistics")
    assert response.status_code == 200

    data = response.json()
    assert "total_rules" in data
    assert "by_type" in data
    assert "enabled_rules" in data
    assert "disabled_rules" in data
    assert "rule_complexity" in data
    assert "settings_flags" in data
    assert "scope_patterns" in data

    # Verify statistics accuracy
    assert data["total_rules"] == 3  # 2 header + 1 replace
    assert data["enabled_rules"] == 2  # 1 header + 1 replace
    assert data["disabled_rules"] == 1  # 1 header
    assert data["scope_patterns"] == 2


def test_rule_template_security_validation(test_client: TestClient):
    """Test that rule templates are structurally sound.

    Offensive security-testing templates (categories "pentest"/"bypass")
    intentionally carry attack payloads such as XSS/SQLi strings — that is the
    whole point of the template. Only non-offensive templates are expected to be
    free of such payloads. Structural validation applies to every template.
    """
    response = test_client.get("/api/rules/templates")
    assert response.status_code == 200

    data = response.json()

    offensive_categories = {"pentest", "bypass"}

    for template in data["templates"]:
        # Verify no dangerous patterns in rule content — but only for
        # non-offensive templates. Offensive templates ship attack payloads on
        # purpose.
        if template["category"] not in offensive_categories:
            rules_content = json.dumps(template["rules"])

            # Check for potential script injection attempts
            dangerous_patterns = [
                "<script>", "javascript:", "eval(", "document.write",
                "window.location", "process.env", "require(", "import("
            ]

            for pattern in dangerous_patterns:
                assert pattern not in rules_content.lower(), f"Dangerous pattern '{pattern}' found in template {template['id']}"

        # Verify template structure is valid
        assert isinstance(template["rules"], dict)
        for rule_type, rules in template["rules"].items():
            if isinstance(rules, list):
                for rule in rules:
                    assert isinstance(rule, dict)
                    if "enabled" in rule:
                        assert isinstance(rule["enabled"], bool)


def test_import_security_validation(test_client: TestClient):
    """Test security validation during rule import."""
    # Test with potentially malicious content
    malicious_import = {
        "rules": {
            "header_rules": [
                {
                    "name": "X-XSS-Test",
                    "value": "<script>alert('xss')</script>",
                    "phase": "request",
                    "action": "set",
                    "enabled": True
                }
            ]
        }
    }

    file_content = json.dumps(malicious_import).encode()
    files = {"file": ("malicious.json", BytesIO(file_content), "application/json")}

    # Should still import (content filtering happens at proxy level)
    response = test_client.post("/api/rules/import?validate_only=true", files=files)
    assert response.status_code == 200

    data = response.json()
    assert data["valid"] is True  # Structure is valid, content filtering is proxy responsibility


@pytest.mark.asyncio
async def test_large_rule_import_handling(test_client: TestClient):
    """Test handling of large rule imports."""
    # Create a large rule set
    large_rules = {
        "rules": {
            "header_rules": [
                {"name": f"X-Header-{i}", "value": f"value{i}", "phase": "request", "action": "set", "enabled": True}
                for i in range(1000)  # 1000 header rules
            ]
        }
    }

    file_content = json.dumps(large_rules).encode()
    files = {"file": ("large_rules.json", BytesIO(file_content), "application/json")}

    response = test_client.post("/api/rules/import?validate_only=true", files=files)
    assert response.status_code == 200

    data = response.json()
    assert data["valid"] is True
    assert data["rule_counts"]["header_rules"] == 1000


def test_rule_template_use_case_documentation(test_client: TestClient):
    """Test that rule templates have proper documentation."""
    response = test_client.get("/api/rules/templates")
    assert response.status_code == 200

    data = response.json()

    for template in data["templates"]:
        # Verify required documentation fields
        assert len(template["description"]) > 20, f"Template {template['id']} needs better description"
        assert len(template["use_cases"]) > 0, f"Template {template['id']} missing use cases"

        if template["difficulty"] == "advanced":
            assert len(template["requirements"]) > 0, f"Advanced template {template['id']} should have requirements"

        # Verify tags are meaningful
        assert len(template["tags"]) > 0, f"Template {template['id']} needs tags for searchability"