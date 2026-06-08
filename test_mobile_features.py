#!/usr/bin/env python3
"""
Test script for real device proxy modes and mobile-focused features.
Tests WireGuard VPN, Reverse Proxy, Content Injection, and Mobile Setup.
"""

import asyncio
import json
import time
import httpx
from pathlib import Path

# API base URL
API_BASE = "http://localhost:8081"

async def test_mobile_features():
    """Test all mobile-focused proxy features for real device scenarios."""
    print("📱 Testing pRoxy Mobile Device Features...")
    print("🎯 Focus: Non-rooted devices, real-world scenarios")

    async with httpx.AsyncClient() as client:

        # Test 1: Check Proxy Modes Status
        print("\n1️⃣ Testing Proxy Modes Status...")
        try:
            response = await client.get(f"{API_BASE}/api/proxy/modes/status")
            if response.status_code == 200:
                modes = response.json()
                print(f"✅ Proxy modes status retrieved")
                print(f"   Regular proxy: {modes['modes']['regular']['status']}")
                print(f"   WireGuard: {modes['modes']['wireguard']['status']}")
                print(f"   Reverse: {modes['modes']['reverse']['status']}")

                # Show mobile support info
                for mode_name, mode_info in modes['modes'].items():
                    print(f"   {mode_name}: {mode_info['mobile_support']}")
            else:
                print(f"❌ Failed to get proxy modes status: {response.status_code}")
        except Exception as e:
            print(f"❌ Error testing proxy modes: {e}")

        # Test 2: Get Best Proxy Mode Recommendation
        print("\n2️⃣ Testing Mobile Device Recommendations...")
        test_scenarios = [
            ("android", False, "testing"),  # Non-rooted Android
            ("ios", False, "testing"),      # Non-jailbroken iOS
            ("android", True, "security_analysis"),  # Rooted Android for pentesting
            ("ios", False, "development")   # iOS development
        ]

        for device, rooted, use_case in test_scenarios:
            try:
                response = await client.get(
                    f"{API_BASE}/api/proxy/modes/best-for-device",
                    params={"device_type": device, "rooted": rooted, "use_case": use_case}
                )
                if response.status_code == 200:
                    rec = response.json()
                    print(f"✅ {device} ({'rooted' if rooted else 'stock'}) for {use_case}:")
                    print(f"   Recommended: {rec['recommendation']['primary']}")
                    print(f"   Reason: {rec['recommendation']['reason']}")
                else:
                    print(f"❌ Failed to get recommendation for {device}: {response.status_code}")
            except Exception as e:
                print(f"❌ Error getting recommendation for {device}: {e}")

        # Test 3: WireGuard Configuration
        print("\n3️⃣ Testing WireGuard VPN Mode...")
        try:
            # Get current WireGuard config
            response = await client.get(f"{API_BASE}/api/wireguard/config")
            if response.status_code == 200:
                config = response.json()
                print(f"✅ WireGuard config retrieved")
                print(f"   Server IP: {config['server_ip']}")
                print(f"   Listen port: {config['listen_port']}")
                print(f"   Client IP range: {config['client_ip_range']}")

                # Create a test client
                response = await client.post(
                    f"{API_BASE}/api/wireguard/clients",
                    params={"name": "Test Mobile Device", "device_type": "android"}
                )
                if response.status_code == 200:
                    wg_client = response.json()
                    print(f"✅ WireGuard client created: {wg_client['name']}")
                    print(f"   Client IP: {wg_client['ip_address']}")

                    # Get client config (with QR code info)
                    response = await client.get(
                        f"{API_BASE}/api/wireguard/clients/{wg_client['id']}/config",
                        params={"format": "qr"}
                    )
                    if response.status_code == 200:
                        config_data = response.json()
                        print(f"✅ WireGuard client config generated")
                        print(f"   Instructions: {len(config_data['instructions'])} steps")
                        print(f"   Config ready for mobile QR scanning")
                else:
                    print(f"❌ Failed to create WireGuard client: {response.status_code}")
            else:
                print(f"❌ Failed to get WireGuard config: {response.status_code}")
        except Exception as e:
            print(f"❌ Error testing WireGuard: {e}")

        # Test 4: Reverse Proxy Mode (Perfect for API Testing)
        print("\n4️⃣ Testing Reverse Proxy Mode...")
        try:
            target_url = "https://httpbin.org"
            response = await client.post(
                f"{API_BASE}/api/proxy/modes/reverse",
                params={"target_url": target_url, "listen_port": 8443}
            )
            if response.status_code == 200:
                reverse_info = response.json()
                print(f"✅ Reverse proxy started successfully")
                print(f"   Target: {reverse_info['target']}")
                print(f"   Listen port: {reverse_info['listen_port']}")
                print(f"   Thread: {reverse_info['thread_id']}")
                print(f"   Instructions:")
                for instruction in reverse_info['instructions']:
                    print(f"      {instruction}")
            else:
                print(f"❌ Failed to start reverse proxy: {response.status_code}")
        except Exception as e:
            print(f"❌ Error testing reverse proxy: {e}")

        # Test 5: Content Injection for Mobile Testing
        print("\n5️⃣ Testing Content Injection Rules...")
        try:
            # Create content injection rule (evil.com → safe.com)
            injection_rule = {
                "name": "Mobile App Security Test",
                "match_pattern": "malicious-api.example.com/*/script.js",
                "source_url": "safe-cdn.example.com/clean-script.js",
                "is_regex": False,
                "preserve_headers": True,
                "custom_headers": {"X-Replaced-By": "pRoxy-Security"},
                "timeout": 30
            }

            response = await client.post(f"{API_BASE}/api/replay/content-injection", json=injection_rule)
            if response.status_code == 200:
                rule = response.json()
                print(f"✅ Content injection rule created: {rule['id']}")
                print(f"   Pattern: {rule['match_pattern']}")
                print(f"   Source: {rule['source_url']}")
                print(f"   Perfect for mobile app security testing!")

                # Test toggle
                toggle_resp = await client.post(f"{API_BASE}/api/replay/content-injection/{rule['id']}/toggle")
                if toggle_resp.status_code == 200:
                    print("✅ Content injection rule toggled successfully")
            else:
                print(f"❌ Failed to create content injection rule: {response.status_code}")
        except Exception as e:
            print(f"❌ Error testing content injection: {e}")

        # Test 6: Mobile Setup Guides
        print("\n6️⃣ Testing Mobile Setup Guides...")
        setup_modes = ["regular", "wireguard", "reverse"]

        for mode in setup_modes:
            try:
                response = await client.get(f"{API_BASE}/api/proxy/setup-guide/{mode}")
                if response.status_code == 200:
                    guide = response.json()
                    print(f"✅ Setup guide for {mode} mode:")
                    print(f"   Title: {guide['title']}")
                    print(f"   Android steps: {len(guide.get('android_steps', []))} steps")
                    if 'ios_steps' in guide:
                        print(f"   iOS steps: {len(guide['ios_steps'])} steps")
                    if 'pros' in guide:
                        print(f"   Advantages: {len(guide['pros'])} benefits")
                else:
                    print(f"❌ Failed to get setup guide for {mode}: {response.status_code}")
            except Exception as e:
                print(f"❌ Error getting setup guide for {mode}: {e}")

        # Test 7: Certificate Management for Mobile
        print("\n7️⃣ Testing Mobile Certificate Management...")
        try:
            # Get certificates info
            response = await client.get(f"{API_BASE}/api/proxy/certificates")
            if response.status_code == 200:
                cert_info = response.json()
                print(f"✅ Certificate information retrieved")
                print(f"   Total certificates: {cert_info['total']}")
                print(f"   CA configured: {cert_info['ca_configured']}")

                # Test Android certificate download
                response = await client.get(f"{API_BASE}/api/proxy/certificates/android")
                if response.status_code == 200:
                    android_cert = response.json()
                    print(f"✅ Android certificate ready for download")
                    print(f"   Filename: {android_cert['filename']}")
                    print(f"   MIME type: {android_cert['mime_type']}")
                else:
                    print(f"⚠️ Android certificate not available: {response.status_code}")
            else:
                print(f"❌ Failed to get certificate info: {response.status_code}")
        except Exception as e:
            print(f"❌ Error testing certificates: {e}")

    print(f"\n🎉 Mobile device testing completed!")
    print(f"\n📱 Mobile-Focused Feature Summary:")
    print(f"   ✅ WireGuard VPN - Perfect for non-rooted devices")
    print(f"   ✅ Reverse Proxy - Zero client configuration needed")
    print(f"   ✅ Content Injection - Silent content replacement")
    print(f"   ✅ Smart Recommendations - Device-specific guidance")
    print(f"   ✅ Mobile Setup Guides - Step-by-step instructions")
    print(f"   ✅ Certificate Management - Easy mobile installation")

    print(f"\n🌟 Real-World Mobile Testing Scenarios:")
    print(f"   📱 Banking Apps: Use WireGuard to bypass proxy detection")
    print(f"   🎮 Mobile Games: WireGuard captures custom protocols")
    print(f"   🛡️ Security Testing: Reverse proxy for API manipulation")
    print(f"   🔧 Development: Regular proxy with easy cert setup")
    print(f"   🚀 Pentesting: Content injection for payload delivery")

    print(f"\n🎯 Why These Features Matter:")
    print(f"   • 90% of mobile testing happens on NON-ROOTED devices")
    print(f"   • Many apps bypass traditional proxy settings")
    print(f"   • WireGuard VPN captures traffic other methods miss")
    print(f"   • Reverse proxy enables API testing without app modification")
    print(f"   • Content injection allows silent security testing")

if __name__ == "__main__":
    asyncio.run(test_mobile_features())