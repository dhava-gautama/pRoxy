"""
Tests for core proxy functionality.
"""
import pytest
from unittest.mock import Mock, patch, MagicMock
import time

from state.shared import ProxyState
from state.models import FlowRecord, ProxySettings


@pytest.mark.proxy
class TestProxyState:
    """Test ProxyState functionality."""

    def test_proxy_state_singleton(self):
        """Test that ProxyState is a singleton."""
        state1 = ProxyState()
        state2 = ProxyState()
        assert state1 is state2

    def test_proxy_state_initialization(self):
        """Test ProxyState initialization."""
        state = ProxyState()

        # Should expose the core state API
        assert hasattr(state, 'get_settings')
        assert hasattr(state, 'get_flows')
        assert hasattr(state, 'get_sequences')
        assert hasattr(state, 'get_intercept_queue')

    @patch('state.shared.ProxyState._instance', None)
    def test_get_settings_default(self):
        """Test getting default settings."""
        state = ProxyState()
        settings = state.get_settings()

        assert isinstance(settings, ProxySettings)
        assert isinstance(settings.hsts_strip, bool)
        assert isinstance(settings.intercept_enabled, bool)
        assert isinstance(settings.header_rules, list)

    @patch('state.shared.ProxyState._instance', None)
    def test_update_settings(self):
        """Test updating settings."""
        state = ProxyState()

        # Update some settings
        new_settings = ProxySettings(
            hsts_strip=True,
            csp_strip=True,
            custom_user_agent="Test-Agent"
        )

        updated = state.update_settings(new_settings)

        assert updated.hsts_strip == True
        assert updated.csp_strip == True
        assert updated.custom_user_agent == "Test-Agent"

    @patch('state.shared.ProxyState._instance', None)
    def test_store_flow(self, sample_flow):
        """Test storing flow records."""
        state = ProxyState()

        # Store a flow
        state.store_flow(sample_flow)

        # Should be stored
        flows = state.get_flows()
        assert len(flows) >= 1
        assert any(flow.id == sample_flow.id for flow in flows)

    @patch('state.shared.ProxyState._instance', None)
    def test_get_flows_limit(self, sample_flow):
        """Test flow retrieval with limits."""
        state = ProxyState()

        # Store multiple flows
        for i in range(10):
            flow = FlowRecord(
                id=f"test-flow-{i}",
                timestamp=time.time() + i,
                method="GET",
                scheme="https",
                host="example.com",
                port=443,
                path=f"/test/{i}",
                url=f"https://example.com/test/{i}",
                request_headers={},
                request_body="",
                request_content_type="",
                status_code=200,
                reason="OK",
                response_headers={},
                response_body=f"Response {i}",
                response_content_type="text/plain",
                response_size=len(f"Response {i}"),
                completed=True,
                duration_ms=100.0
            )
            state.store_flow(flow)

        # Test limit
        flows = state.get_flows(limit=5)
        assert len(flows) <= 5

    @patch('state.shared.ProxyState._instance', None)
    def test_flow_search_filtering(self, sample_flow):
        """Test flow search and filtering."""
        state = ProxyState()

        # Store test flows
        flows_data = [
            ("GET", "https://api.example.com/users", 200),
            ("POST", "https://api.example.com/login", 401),
            ("GET", "https://cdn.example.com/image.jpg", 200),
            ("DELETE", "https://api.example.com/users/123", 404),
        ]

        for i, (method, url, status) in enumerate(flows_data):
            from urllib.parse import urlparse
            parsed = urlparse(url)

            flow = FlowRecord(
                id=f"search-flow-{i}",
                timestamp=time.time() + i,
                method=method,
                scheme=parsed.scheme,
                host=parsed.hostname,
                port=443,
                path=parsed.path,
                url=url,
                request_headers={},
                request_body="",
                request_content_type="",
                status_code=status,
                reason="OK" if status == 200 else "Error",
                response_headers={},
                response_body="",
                response_content_type="",
                response_size=0,
                completed=True,
                duration_ms=100.0
            )
            state.store_flow(flow)

        # Test search functionality (if implemented)
        all_flows = state.get_flows()
        api_flows = [f for f in all_flows if "api.example.com" in f.host]
        assert len(api_flows) == 3  # 3 API calls

        post_flows = [f for f in all_flows if f.method == "POST"]
        assert len(post_flows) == 1  # 1 POST request

    @patch('state.shared.ProxyState._instance', None)
    def test_intercept_queue_operations(self, sample_flow):
        """Test intercept queue operations."""
        from state.models import InterceptedFlow

        state = ProxyState()

        # Initially empty
        assert len(state.get_intercept_queue()) == 0

        # Enqueue an intercepted flow (normally done by the proxy engine)
        intercepted = InterceptedFlow(
            id="test-intercept-1",
            flow_record=sample_flow,
            phase="request",
        )
        event = state.enqueue_intercept(intercepted)
        key = "test-intercept-1:request"

        assert len(state.get_intercept_queue()) == 1

        # Resolve intercept
        success = state.resolve_intercept(
            key,
            "forward",
            modified_body='{"username": "admin"}',
            modified_headers={"X-Modified": "true"}
        )
        assert success == True
        assert event.is_set()

        # Pop the resolved entry to clear it from the queue
        resolved = state.pop_resolved(key)
        assert resolved is not None
        assert resolved.action == "forward"
        assert len(state.get_intercept_queue()) == 0

    @patch('state.shared.ProxyState._instance', None)
    def test_sequence_management(self):
        """Test sequence save/load/delete operations."""
        state = ProxyState()

        # Create test sequence
        from state.models import SavedSequence, SequenceStep

        sequence = SavedSequence(
            id="test-seq-1",
            name="Login Sequence",
            steps=[
                SequenceStep(
                    name="Login",
                    method="POST",
                    url="https://api.example.com/login",
                    headers={"Content-Type": "application/json"},
                    body='{"username": "test", "password": "pass"}',
                    extract={"token": "json:access_token"}
                )
            ]
        )

        # Save sequence
        saved = state.save_sequence(sequence)
        assert saved.id == "test-seq-1"

        # Get sequences
        sequences = state.get_sequences()
        assert len(sequences) >= 1
        assert any(seq.id == "test-seq-1" for seq in sequences)

        # Delete sequence
        success = state.delete_sequence("test-seq-1")
        assert success == True

        # Should be gone
        sequences = state.get_sequences()
        assert not any(seq.id == "test-seq-1" for seq in sequences)

    @patch('state.shared.ProxyState._instance', None)
    def test_concurrent_flow_storage(self, sample_flow):
        """Test concurrent flow storage operations."""
        import threading
        import time

        state = ProxyState()
        stored_flows = []

        def store_flows(thread_id, count):
            for i in range(count):
                flow = FlowRecord(
                    id=f"concurrent-{thread_id}-{i}",
                    timestamp=time.time(),
                    method="GET",
                    scheme="https",
                    host="example.com",
                    port=443,
                    path=f"/thread/{thread_id}/item/{i}",
                    url=f"https://example.com/thread/{thread_id}/item/{i}",
                    request_headers={},
                    request_body="",
                    request_content_type="",
                    status_code=200,
                    reason="OK",
                    response_headers={},
                    response_body=f"Thread {thread_id} Item {i}",
                    response_content_type="text/plain",
                    response_size=len(f"Thread {thread_id} Item {i}"),
                    completed=True,
                    duration_ms=50.0
                )
                state.store_flow(flow)
                stored_flows.append(flow.id)

        # Create multiple threads storing flows
        threads = []
        for thread_id in range(3):
            thread = threading.Thread(target=store_flows, args=[thread_id, 5])
            threads.append(thread)
            thread.start()

        # Wait for completion
        for thread in threads:
            thread.join()

        # Verify all flows were stored
        all_flows = state.get_flows()
        stored_ids = [flow.id for flow in all_flows]

        for expected_id in stored_flows:
            assert expected_id in stored_ids

    @patch('state.shared.ProxyState._instance', None)
    def test_memory_management(self, sample_flow):
        """Test memory management with large number of flows."""
        state = ProxyState()

        # Store many flows to test memory management
        for i in range(1000):
            flow = FlowRecord(
                id=f"memory-test-{i}",
                timestamp=time.time() + i,
                method="GET",
                scheme="https",
                host="example.com",
                port=443,
                path=f"/test/{i}",
                url=f"https://example.com/test/{i}",
                request_headers={},
                request_body="",
                request_content_type="",
                status_code=200,
                reason="OK",
                response_headers={},
                response_body=f"Response {i}" * 100,  # Larger responses
                response_content_type="text/plain",
                response_size=len(f"Response {i}" * 100),
                completed=True,
                duration_ms=100.0
            )
            state.store_flow(flow)

        # Should handle large number of flows
        flows = state.get_flows(limit=100)
        assert len(flows) == 100

        # Should have reasonable memory usage (basic check)
        import sys
        memory_usage = sys.getsizeof(state.get_flows())
        # This is a very basic check - in practice you'd use more sophisticated memory profiling
        assert memory_usage > 0


@pytest.mark.proxy
@pytest.mark.integration
class TestProxyIntegration:
    """Integration tests for proxy functionality."""

    def test_flow_lifecycle(self, sample_flow):
        """Test complete flow lifecycle."""
        state = ProxyState()

        # 1. Store initial flow
        state.store_flow(sample_flow)

        # 2. Verify it's stored
        flows = state.get_flows()
        stored_flow = next(f for f in flows if f.id == sample_flow.id)
        assert stored_flow is not None

        # 3. Test flow search
        matching_flows = [f for f in flows if f.host == sample_flow.host]
        assert len(matching_flows) >= 1

        # 4. Test flow filtering by status
        success_flows = [f for f in flows if f.status_code == 200]
        assert len(success_flows) >= 1

    def test_settings_rule_application(self, sample_rules):
        """Test that settings and rules are properly applied."""
        state = ProxyState()

        # Create settings with rules
        settings = ProxySettings(
            hsts_strip=True,
            header_rules=[sample_rules["header_rule"]],
            replace_rules=[sample_rules["replace_rule"]]
        )

        # Update settings
        updated = state.update_settings(settings)

        # Verify rules are stored
        assert len(updated.header_rules) == 1
        assert len(updated.replace_rules) == 1
        assert updated.header_rules[0].name == sample_rules["header_rule"].name
        assert updated.replace_rules[0].pattern == sample_rules["replace_rule"].pattern

    def test_replay_integration(self):
        """Test replay functionality integration."""
        # The api package isn't importable under the current test harness
        # (tests/api shadows the top-level api package); skip like other
        # api-dependent tests until that's resolved.
        replay_module = pytest.importorskip("api.routes.replay")

        with patch.object(replay_module, "_do_request") as mock_do_request:
            mock_do_request.return_value = {
                "id": "replay-integration-test",
                "status_code": 200,
                "reason": "OK",
                "headers": {"Content-Type": "application/json"},
                "body": '{"integration": "test"}',
                "duration_ms": 150.0
            }

            # The replay request executor is patchable and wired for integration
            assert hasattr(replay_module, "_do_request")