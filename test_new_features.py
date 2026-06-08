#!/usr/bin/env python3
"""
Test script for new advanced mitmproxy features:
1. Traffic Replay System
2. HAR Export
3. TCP Proxying (demonstration)
4. Advanced Content Processing
5. Content Injection Rules
"""

import asyncio
import json
import time
import httpx
from pathlib import Path

# API base URL
API_BASE = "http://localhost:8081"

async def test_new_features():
    """Test all the new advanced mitmproxy features."""
    print("🚀 Testing new pRoxy advanced features...")

    async with httpx.AsyncClient() as client:

        # Test 1: Create Content Injection Rule
        print("\n1️⃣ Testing Content Injection...")
        content_rule = {
            "name": "Test Content Injection",
            "match_pattern": "example.com/test.js",
            "source_url": "httpbin.org/json",
            "is_regex": False,
            "preserve_headers": True,
            "custom_headers": {"X-Injected": "true"},
            "timeout": 30
        }

        try:
            response = await client.post(f"{API_BASE}/api/replay/content-injection", json=content_rule)
            if response.status_code == 200:
                rule = response.json()
                print(f"✅ Content injection rule created: {rule['id']}")

                # Test toggle
                toggle_resp = await client.post(f"{API_BASE}/api/replay/content-injection/{rule['id']}/toggle")
                if toggle_resp.status_code == 200:
                    print("✅ Content injection rule toggled")
            else:
                print(f"❌ Failed to create content injection rule: {response.status_code}")
        except Exception as e:
            print(f"❌ Error testing content injection: {e}")

        # Test 2: Create Traffic Replay Session
        print("\n2️⃣ Testing Traffic Replay...")
        try:
            # Create session
            response = await client.post(f"{API_BASE}/api/replay/sessions",
                                       data={"name": "Test Session", "description": "Testing replay system"})
            if response.status_code == 200:
                session = response.json()
                print(f"✅ Replay session created: {session['id']}")

                # List sessions
                list_resp = await client.get(f"{API_BASE}/api/replay/sessions")
                if list_resp.status_code == 200:
                    sessions = list_resp.json()
                    print(f"✅ Found {len(sessions)} replay sessions")
            else:
                print(f"❌ Failed to create replay session: {response.status_code}")
        except Exception as e:
            print(f"❌ Error testing traffic replay: {e}")

        # Test 3: HAR Export
        print("\n3️⃣ Testing HAR Export...")
        try:
            response = await client.post(f"{API_BASE}/api/replay/export-har")
            if response.status_code == 200:
                har_data = response.json()
                print(f"✅ HAR export successful, version: {har_data['log']['version']}")
                print(f"   Entries: {len(har_data['log']['entries'])}")

                # Save HAR file
                har_file = Path("test_export.har")
                har_file.write_text(json.dumps(har_data, indent=2))
                print(f"✅ HAR saved to {har_file}")
            else:
                print(f"❌ Failed to export HAR: {response.status_code}")
        except Exception as e:
            print(f"❌ Error testing HAR export: {e}")

        # Test 4: Content Processing
        print("\n4️⃣ Testing Content Processing...")
        try:
            # Test content analysis
            test_content = '{"test": "data", "nested": {"key": "value"}}'
            analysis_data = {
                "content": test_content,
                "content_type": "application/json"
            }

            response = await client.post(f"{API_BASE}/api/content/analyze", json=analysis_data)
            if response.status_code == 200:
                analysis = response.json()
                print(f"✅ Content analysis successful:")
                print(f"   Size: {analysis['size']} bytes")
                print(f"   Detected formats: {analysis['detected_formats']}")
                print(f"   Encoding: {analysis['encoding']}")
            else:
                print(f"❌ Failed to analyze content: {response.status_code}")

            # Test content transformation
            transform_data = {
                "content": test_content,
                "content_type": "application/json",
                "processors": ["beautify_json"]
            }

            response = await client.post(f"{API_BASE}/api/content/transform", json=transform_data)
            if response.status_code == 200:
                result = response.json()
                print(f"✅ Content transformation successful")
                print(f"   Applied processors: {result['applied_processors']}")
            else:
                print(f"❌ Failed to transform content: {response.status_code}")

        except Exception as e:
            print(f"❌ Error testing content processing: {e}")

        # Test 5: TCP Proxy Rules
        print("\n5️⃣ Testing TCP Proxy...")
        try:
            tcp_rule = {
                "name": "Test TCP Proxy",
                "protocol": "tcp",
                "listen_port": 9999,
                "target_host": "httpbin.org",
                "target_port": 80,
                "description": "Test TCP proxy rule",
                "log_traffic": True,
                "max_connections": 10,
                "timeout": 60
            }

            response = await client.post(f"{API_BASE}/api/tcp/rules", json=tcp_rule)
            if response.status_code == 200:
                rule = response.json()
                print(f"✅ TCP proxy rule created: {rule['id']}")
                print(f"   Listen port: {rule['listen_port']} -> {rule['target_host']}:{rule['target_port']}")

                # Get stats
                stats_resp = await client.get(f"{API_BASE}/api/tcp/stats")
                if stats_resp.status_code == 200:
                    stats = stats_resp.json()
                    print(f"✅ TCP proxy stats: {stats['active_rules']} active rules")
            else:
                print(f"❌ Failed to create TCP proxy rule: {response.status_code}")
        except Exception as e:
            print(f"❌ Error testing TCP proxy: {e}")

        # Test 6: Server Replay Rules
        print("\n6️⃣ Testing Server Replay...")
        try:
            server_rule = {
                "name": "Test Server Replay",
                "enabled": True,
                "match_method": True,
                "match_host": True,
                "match_path": True,
                "match_query": False,
                "match_headers": [],
                "flows": [],  # Would contain actual flow IDs
                "fallback_action": "passthrough"
            }

            response = await client.post(f"{API_BASE}/api/replay/server-rules", json=server_rule)
            if response.status_code == 200:
                rule = response.json()
                print(f"✅ Server replay rule created: {rule['id']}")

                # List all server rules
                list_resp = await client.get(f"{API_BASE}/api/replay/server-rules")
                if list_resp.status_code == 200:
                    rules = list_resp.json()
                    print(f"✅ Found {len(rules)} server replay rules")
            else:
                print(f"❌ Failed to create server replay rule: {response.status_code}")
        except Exception as e:
            print(f"❌ Error testing server replay: {e}")

    print(f"\n🎉 New features test completed!")
    print(f"\n📊 Summary of new capabilities:")
    print(f"   • Traffic Replay System - Record and replay HTTP traffic")
    print(f"   • Content Injection - Replace xx.com/file.js with content from yy.com/file.js")
    print(f"   • HAR Export - Export traffic for browser dev tools")
    print(f"   • TCP Proxying - Proxy non-HTTP protocols (SSH, SMTP, etc.)")
    print(f"   • Advanced Content Processing - JSON beautification, security scanning")
    print(f"   • Server Replay - Return cached responses")
    print(f"\n🌟 mitmproxy's power fully unleashed in pRoxy!")

if __name__ == "__main__":
    asyncio.run(test_new_features())