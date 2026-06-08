"""
Simple test to verify pytest is working.
"""
import pytest


def test_basic_functionality():
    """Test that basic pytest functionality works."""
    assert 1 + 1 == 2


def test_environment_setup():
    """Test that environment variables are set."""
    import os
    assert os.environ.get("PROXY_DISABLE_AUTH") == "true"
    assert os.environ.get("TESTING") == "true"


@pytest.mark.api
def test_marker_functionality():
    """Test that pytest markers work."""
    assert True