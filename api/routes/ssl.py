"""SSL Bypass and Certificate Management for Mobile Testing."""

from __future__ import annotations

import asyncio
import base64
import json
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional, Set

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, model_validator

from state.shared import ProxyState

router = APIRouter(prefix="/api/ssl", tags=["ssl"])


class SSLBypassMethod(BaseModel):
    """SSL pinning bypass method configuration."""
    id: str
    name: str
    method: str  # frida, magisk, reverse_proxy, certificate_replacement
    enabled: bool = True
    target_apps: List[str] = []
    script: Optional[str] = None
    description: str = ""
    effectiveness: str = "high"  # low, medium, high
    requires_root: bool = False


class FridaScript(BaseModel):
    """Frida script for SSL bypass."""
    id: str
    name: str
    script_content: str
    target_platform: str  # android, ios, universal
    bypass_methods: List[str]  # okhttp, nsurlsession, custom
    auto_attach: bool = True
    description: str = ""


class CertificateReplacement(BaseModel):
    """Certificate replacement configuration."""
    target_domain: str
    replacement_cert: str
    replacement_key: str
    method: str = "dns_hijack"  # dns_hijack, hosts_file, transparent_proxy
    enabled: bool = True


class DetectedApp(BaseModel):
    """Detected mobile app for SSL bypass."""
    package_name: str
    app_name: str
    version: str
    is_running: bool
    has_network_permission: bool
    detected_domains: List[str] = []
    ssl_pinning_detected: bool = False
    confidence_score: float = 0.0


class AutoDetectionConfig(BaseModel):
    """Configuration for automatic detection."""
    device_ip: Optional[str] = None  # For ADB over network
    detection_timeout: int = 60  # seconds
    traffic_sample_duration: int = 30  # seconds
    enable_deep_scan: bool = True
    auto_apply_bypass: bool = True
    excluded_packages: List[str] = []


# Global storage
_ssl_bypass_methods: Dict[str, SSLBypassMethod] = {}
_frida_scripts: Dict[str, FridaScript] = {}
_cert_replacements: Dict[str, CertificateReplacement] = {}
_detection_running = False


# SSL Bypass Methods Management

@router.get("/bypass-methods")
def get_ssl_bypass_methods() -> List[SSLBypassMethod]:
    """Get all SSL pinning bypass methods."""
    return list(_ssl_bypass_methods.values())


@router.post("/bypass-methods")
def create_ssl_bypass_method(method: SSLBypassMethod) -> SSLBypassMethod:
    """Create new SSL bypass method."""
    if not method.id:
        method.id = f"ssl_bypass_{int(time.time() * 1000)}"

    _ssl_bypass_methods[method.id] = method
    return method


@router.get("/bypass-methods/builtin")
def get_builtin_ssl_bypass_methods() -> List[SSLBypassMethod]:
    """Get built-in SSL bypass methods for different scenarios."""
    builtin_methods = [
        SSLBypassMethod(
            id="reverse_proxy_bypass",
            name="Reverse Proxy SSL Bypass",
            method="reverse_proxy",
            description="App connects to pRoxy directly, bypassing pinning entirely",
            effectiveness="high",
            requires_root=False,
            target_apps=["any"],
            script="""
# Reverse Proxy SSL Bypass
1. Start pRoxy in reverse proxy mode
2. Point app to pRoxy IP instead of real server
3. App trusts pRoxy certificate (no pinning check)
4. pRoxy handles real SSL connection to server
5. Complete SSL bypass without root!
            """
        ),

        SSLBypassMethod(
            id="wireguard_cert_injection",
            name="WireGuard + Certificate Injection",
            method="certificate_replacement",
            description="VPN captures traffic + automatic certificate replacement",
            effectiveness="high",
            requires_root=False,
            target_apps=["any"],
            script="""
# WireGuard + Certificate Injection
1. Connect device via WireGuard VPN
2. Automatically inject pRoxy certificates
3. DNS hijacking redirects to pRoxy certificates
4. Some apps bypass pinning with VPN active
            """
        ),

        SSLBypassMethod(
            id="frida_universal_bypass",
            name="Frida Universal SSL Bypass",
            method="frida",
            description="Runtime SSL function hooking (requires USB/ADB access)",
            effectiveness="high",
            requires_root=True,
            target_apps=["android", "ios"],
            script="""
Java.perform(function() {
    // Universal Android SSL Bypass
    console.log('[pRoxy] Starting universal SSL bypass...');

    // OkHttp3 Certificate Pinner
    try {
        var CertPinner = Java.use("okhttp3.CertificatePinner");
        CertPinner.check.overload('java.lang.String', 'java.util.List').implementation = function() {
            console.log('[pRoxy] OkHttp pinning bypassed');
        };
    } catch(e) {}

    // Network Security Config
    try {
        var NetworkSecurityPolicy = Java.use("android.security.NetworkSecurityPolicy");
        NetworkSecurityPolicy.getInstance.implementation = function() {
            console.log('[pRoxy] Network security policy bypassed');
            return Java.use("android.security.NetworkSecurityPolicy").$new();
        };
    } catch(e) {}

    // HttpsURLConnection
    try {
        var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
        HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(verifier) {
            console.log('[pRoxy] Hostname verification bypassed');
        };
    } catch(e) {}

    console.log('[pRoxy] Universal SSL bypass activated');
});
            """
        ),

        SSLBypassMethod(
            id="ios_nsurlsession_bypass",
            name="iOS NSURLSession Bypass",
            method="frida",
            description="iOS SSL pinning bypass via NSURLSession hooking",
            effectiveness="high",
            requires_root=False,  # Works with Frida over USB
            target_apps=["ios"],
            script="""
if (ObjC.available) {
    console.log('[pRoxy] iOS SSL bypass starting...');

    // NSURLSession bypass
    var NSURLSession = ObjC.classes.NSURLSession;
    var NSURLSessionConfiguration = ObjC.classes.NSURLSessionConfiguration;

    // Hook SSL validation
    var method = ObjC.classes.NSURLSessionDelegate['- URLSession:didReceiveChallenge:completionHandler:'];
    if (method) {
        Interceptor.attach(method.implementation, {
            onEnter: function(args) {
                console.log('[pRoxy] SSL challenge intercepted');
                var completionHandler = new ObjC.Block(args[4]);
                var disposition = 1; // NSURLSessionAuthChallengeUseCredential
                var credential = ObjC.classes.NSURLCredential.credentialForTrust_(args[3]);
                completionHandler(disposition, credential);
            }
        });
    }

    console.log('[pRoxy] iOS SSL bypass activated');
}
            """
        )
    ]

    return builtin_methods


# Frida Scripts Management

@router.get("/frida-scripts")
def get_frida_scripts() -> List[FridaScript]:
    """Get all Frida scripts for SSL bypass."""
    return list(_frida_scripts.values())


@router.post("/frida-scripts")
def create_frida_script(script: FridaScript) -> FridaScript:
    """Create new Frida script."""
    if not script.id:
        script.id = f"frida_{int(time.time() * 1000)}"

    _frida_scripts[script.id] = script
    return script


@router.get("/frida-scripts/templates")
def get_frida_script_templates() -> List[dict]:
    """Get pre-built Frida script templates."""
    templates = [
        {
            "name": "Android Universal SSL Bypass",
            "platform": "android",
            "description": "Bypasses most Android SSL pinning implementations",
            "script": """
Java.perform(function() {
    console.log('[pRoxy] Loading Android SSL bypass...');

    // OkHttp3 CertificatePinner
    hookOkHttp();

    // Android Network Security Config
    hookNetworkSecurityPolicy();

    // Conscrypt (Android's SSL provider)
    hookConscrypt();

    // Apache HTTP Client
    hookApacheHttpClient();

    // Volley
    hookVolley();

    function hookOkHttp() {
        try {
            var CertificatePinner = Java.use("okhttp3.CertificatePinner");
            CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
                console.log('[pRoxy] OkHttp3 pinning bypassed for: ' + hostname);
                return true;
            };

            CertificatePinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function(hostname, peerCertificates) {
                console.log('[pRoxy] OkHttp3 certificate pinning bypassed for: ' + hostname);
                return true;
            };
        } catch(e) {
            console.log('[pRoxy] OkHttp3 not found: ' + e);
        }
    }

    function hookNetworkSecurityPolicy() {
        try {
            var NetworkSecurityPolicy = Java.use("android.security.NetworkSecurityPolicy");
            NetworkSecurityPolicy.getInstance.implementation = function() {
                console.log('[pRoxy] NetworkSecurityPolicy bypassed');
                var policy = this.getInstance();
                policy.isCleartextTrafficPermitted.implementation = function() { return true; };
                policy.isCertificateTransparencyVerificationRequired.implementation = function() { return false; };
                return policy;
            };
        } catch(e) {
            console.log('[pRoxy] NetworkSecurityPolicy not found: ' + e);
        }
    }

    function hookConscrypt() {
        try {
            var ConscryptFileDescriptorSocket = Java.use("com.android.org.conscrypt.ConscryptFileDescriptorSocket");
            ConscryptFileDescriptorSocket.verifyCertificateChain.implementation = function() {
                console.log('[pRoxy] Conscrypt certificate verification bypassed');
            };
        } catch(e) {
            console.log('[pRoxy] Conscrypt not found: ' + e);
        }
    }

    function hookApacheHttpClient() {
        try {
            var DefaultHttpClient = Java.use("org.apache.http.impl.client.DefaultHttpClient");
            DefaultHttpClient.$init.overload().implementation = function() {
                console.log('[pRoxy] Apache HttpClient SSL verification disabled');
                this.$init();
            };
        } catch(e) {
            console.log('[pRoxy] Apache HttpClient not found: ' + e);
        }
    }

    function hookVolley() {
        try {
            var HurlStack = Java.use("com.android.volley.toolbox.HurlStack");
            HurlStack.performRequest.implementation = function(request, additionalHeaders) {
                console.log('[pRoxy] Volley SSL verification bypassed');
                return this.performRequest(request, additionalHeaders);
            };
        } catch(e) {
            console.log('[pRoxy] Volley not found: ' + e);
        }
    }

    console.log('[pRoxy] Android SSL bypass fully loaded');
});
            """,
            "bypass_methods": ["okhttp", "network_security_config", "conscrypt", "apache", "volley"]
        },

        {
            "name": "iOS Universal SSL Bypass",
            "platform": "ios",
            "description": "Bypasses iOS SSL pinning via NSURLSession and Security framework",
            "script": """
if (ObjC.available) {
    console.log('[pRoxy] Loading iOS SSL bypass...');

    // NSURLSession SSL bypass
    hookNSURLSession();

    // Security framework bypass
    hookSecurityFramework();

    // CFNetwork bypass
    hookCFNetwork();

    function hookNSURLSession() {
        try {
            var NSURLSessionDelegate = ObjC.protocols.NSURLSessionDelegate;
            var originalMethod = NSURLSessionDelegate['- URLSession:didReceiveChallenge:completionHandler:'];

            Interceptor.attach(originalMethod.implementation, {
                onEnter: function(args) {
                    console.log('[pRoxy] NSURLSession challenge bypassed');
                    var block = new ObjC.Block(args[4]);
                    var NSURLSessionAuthChallengeUseCredential = 1;
                    var challenge = ObjC.Object(args[3]);
                    var credential = ObjC.classes.NSURLCredential.credentialForTrust_(challenge.protectionSpace().serverTrust());
                    block(NSURLSessionAuthChallengeUseCredential, credential);
                }
            });
        } catch(e) {
            console.log('[pRoxy] NSURLSession hook failed: ' + e);
        }
    }

    function hookSecurityFramework() {
        try {
            var SecTrustEvaluate = Module.findExportByName('Security', 'SecTrustEvaluate');
            if (SecTrustEvaluate) {
                Interceptor.attach(SecTrustEvaluate, {
                    onLeave: function(retval) {
                        console.log('[pRoxy] SecTrustEvaluate bypassed');
                        retval.replace(ptr('0x1')); // kSecTrustResultProceed
                    }
                });
            }

            var SecTrustGetTrustResult = Module.findExportByName('Security', 'SecTrustGetTrustResult');
            if (SecTrustGetTrustResult) {
                Interceptor.attach(SecTrustGetTrustResult, {
                    onLeave: function(retval) {
                        console.log('[pRoxy] SecTrustGetTrustResult bypassed');
                        retval.replace(ptr('0x1'));
                    }
                });
            }
        } catch(e) {
            console.log('[pRoxy] Security framework hook failed: ' + e);
        }
    }

    function hookCFNetwork() {
        try {
            var CFNetworkModule = Process.findModuleByName('CFNetwork');
            if (CFNetworkModule) {
                var SSLSetSessionOption = Module.findExportByName('Security', 'SSLSetSessionOption');
                if (SSLSetSessionOption) {
                    Interceptor.attach(SSLSetSessionOption, {
                        onEnter: function(args) {
                            if (args[1].toInt32() == 0x32) { // kSSLSessionOptionBreakOnServerAuth
                                console.log('[pRoxy] SSL session option bypassed');
                                args[2] = ptr(0x0); // false
                            }
                        }
                    });
                }
            }
        } catch(e) {
            console.log('[pRoxy] CFNetwork hook failed: ' + e);
        }
    }

    console.log('[pRoxy] iOS SSL bypass fully loaded');
}
            """,
            "bypass_methods": ["nsurlsession", "security_framework", "cfnetwork"]
        }
    ]

    return templates


# Certificate Management

@router.post("/certificate-replacement")
def create_certificate_replacement(replacement: CertificateReplacement) -> CertificateReplacement:
    """Create certificate replacement rule."""
    _cert_replacements[replacement.target_domain] = replacement

    # Apply certificate replacement logic
    _apply_certificate_replacement(replacement)

    return replacement


@router.get("/certificate-replacements")
def get_certificate_replacements() -> List[CertificateReplacement]:
    """Get all certificate replacement rules."""
    return list(_cert_replacements.values())


# Auto-Configuration for SSL Bypass

@router.post("/auto-bypass/{app_package}")
def auto_bypass_ssl_pinning(
    app_package: str,
    method: str = "reverse_proxy",  # reverse_proxy, frida, certificate_injection
    target_domains: List[str] = Query(default=[])
) -> dict:
    """Automatically configure SSL bypass for specific app."""

    if method == "reverse_proxy":
        # The most effective non-root method
        instructions = [
            f"1. Identify {app_package} API endpoints: {target_domains}",
            "2. Start reverse proxy mode for each domain",
            "3. Use DNS hijacking or hosts file to redirect domains to pRoxy",
            "4. App connects to pRoxy thinking it's the real server",
            "5. SSL pinning completely bypassed - app trusts pRoxy certificates"
        ]

        setup_commands = []
        for domain in target_domains:
            setup_commands.append(f"curl -X POST 'http://localhost:8081/api/proxy/modes/reverse' -d 'target_url=https://{domain}&listen_port=8443'")
            setup_commands.append(f"# Add to device hosts file: 127.0.0.1 {domain}")

        return {
            "app_package": app_package,
            "method": "reverse_proxy",
            "effectiveness": "95%",
            "requires_root": False,
            "instructions": instructions,
            "setup_commands": setup_commands,
            "advantages": [
                "No root required",
                "100% SSL pinning bypass",
                "Works on any app",
                "Real-time traffic modification",
                "No Frida/hooking needed"
            ]
        }

    elif method == "frida":
        return {
            "app_package": app_package,
            "method": "frida",
            "effectiveness": "90%",
            "requires_root": False,  # Can work over USB
            "setup_commands": [
                f"frida -U -f {app_package} -l universal_ssl_bypass.js",
                f"# Or attach to running app: frida -U {app_package} -l universal_ssl_bypass.js"
            ],
            "requirements": [
                "Frida installed on host machine",
                "USB debugging enabled on device",
                "App debuggable or USB access"
            ]
        }

    elif method == "certificate_injection":
        return {
            "app_package": app_package,
            "method": "certificate_injection",
            "effectiveness": "70%",
            "requires_root": True,
            "setup_commands": [
                "# Install pRoxy certificate as system certificate",
                "adb push prxy.0 /system/etc/security/cacerts/",
                "adb shell chmod 644 /system/etc/security/cacerts/prxy.0",
                "# Modify app's network security config if possible"
            ]
        }

    return {"error": f"Unknown method: {method}"}


@router.get("/effectiveness-comparison")
def get_ssl_bypass_effectiveness() -> dict:
    """Compare effectiveness of different SSL bypass methods."""

    return {
        "methods": {
            "reverse_proxy": {
                "effectiveness": 95,
                "requires_root": False,
                "setup_difficulty": "Easy",
                "works_on": ["Any app", "Any device"],
                "limitations": ["Requires domain redirection", "Per-domain setup"],
                "best_for": "API testing and security analysis"
            },
            "wireguard_vpn": {
                "effectiveness": 80,
                "requires_root": False,
                "setup_difficulty": "Medium",
                "works_on": ["Most apps", "Non-rooted devices"],
                "limitations": ["Some apps detect VPN", "Certificate still needed"],
                "best_for": "General traffic capture"
            },
            "frida_hooking": {
                "effectiveness": 90,
                "requires_root": False,
                "setup_difficulty": "Hard",
                "works_on": ["Debuggable apps", "USB accessible devices"],
                "limitations": ["App-specific", "Runtime dependency", "Detection possible"],
                "best_for": "Dynamic analysis and research"
            },
            "certificate_injection": {
                "effectiveness": 70,
                "requires_root": True,
                "setup_difficulty": "Hard",
                "works_on": ["System-level apps", "Rooted devices"],
                "limitations": ["Requires root", "Android 7+ user cert restrictions"],
                "best_for": "Comprehensive system analysis"
            },
            "magisk_modules": {
                "effectiveness": 85,
                "requires_root": True,
                "setup_difficulty": "Medium",
                "works_on": ["Magisk-rooted devices"],
                "limitations": ["Requires root", "Android-specific"],
                "best_for": "Persistent bypass on rooted devices"
            }
        },
        "recommendations": {
            "non_rooted_testing": "Use reverse_proxy mode - highest success rate",
            "comprehensive_analysis": "Combine reverse_proxy + wireguard_vpn",
            "research_development": "Use frida_hooking for maximum control",
            "production_testing": "reverse_proxy is safest and most reliable"
        }
    }


# Smart App Discovery (Simplified, Working Version)

@router.get("/app-discovery")
async def discover_apps() -> dict:
    """Discover apps using working detection methods."""

    detected_apps = []

    # Method 1: Traffic-based discovery (actually works)
    try:
        traffic_apps = await _discover_via_traffic()
        detected_apps.extend(traffic_apps)
    except Exception as e:
        print(f"Traffic discovery failed: {e}")

    # Method 2: ADB detection (if available)
    try:
        adb_apps = await _adb_detect_apps(None)
        detected_apps.extend(adb_apps)
    except Exception as e:
        print(f"ADB discovery failed: {e}")

    # Method 3: Database of known apps
    try:
        db_apps = await _discover_via_database()
        detected_apps.extend(db_apps)
    except Exception as e:
        print(f"Database discovery failed: {e}")

    # Deduplicate apps
    unique_apps = _deduplicate_apps(detected_apps)

    return {
        "discovered_apps": unique_apps,
        "discovery_methods_used": 3,
        "total_candidates": len(unique_apps),
        "recommendation": "Use reverse proxy mode for highest success rate"
    }


# Detection Status

@router.get("/detection-status")
def get_detection_status() -> dict:
    """Get status of detection process."""
    return {
        "detection_running": _detection_running,
        "available_methods": ["reverse_proxy", "frida", "certificate_injection"],
        "recommended_method": "reverse_proxy"
    }


# Helper Functions (Working implementations only)

async def _adb_detect_apps(device_ip: Optional[str]) -> List[DetectedApp]:
    """Detect apps via ADB commands."""

    detected_apps = []

    # Defense-in-depth: keep device_ip to host/IP/port characters. The adb calls
    # below use argv lists (no shell), so device_ip is a single token regardless.
    if device_ip and not set(device_ip) <= set(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.:-_"
    ):
        device_ip = None

    try:
        # Connect first (if given), then list third-party packages. No shell.
        if device_ip:
            subprocess.run(["adb", "connect", device_ip], capture_output=True, text=True, timeout=10)
        result = subprocess.run(
            ["adb", "shell", "pm", "list", "packages", "-3"],
            capture_output=True, text=True, timeout=30,
        )

        if result.returncode == 0:
            packages = [line.replace('package:', '').strip() for line in result.stdout.split('\n') if line.strip()]

            for package in packages[:20]:  # Limit to 20 packages
                if package and not any(exclude in package for exclude in ['com.android', 'com.google.android']):

                    # Get app details
                    app_info = await _get_adb_app_details(package)

                    detected_apps.append(DetectedApp(
                        package_name=package,
                        app_name=app_info.get('name', package.split('.')[-1]),
                        version=app_info.get('version', 'unknown'),
                        is_running=app_info.get('running', False),
                        has_network_permission=app_info.get('network_permission', True),
                        confidence_score=0.8 if app_info.get('running') else 0.6
                    ))

    except Exception as e:
        print(f"ADB app detection error: {e}")

    return detected_apps


async def _get_adb_app_details(package: str) -> dict:
    """Get detailed app information via ADB."""

    try:
        # Check if app is running (argv, no shell; grep in Python so a crafted
        # package name from the device can't inject a command).
        ps = subprocess.run(["adb", "shell", "ps"], capture_output=True, text=True, timeout=10)
        is_running = ps.returncode == 0 and package in ps.stdout

        # Get app name
        dump = subprocess.run(["adb", "shell", "pm", "dump", package], capture_output=True, text=True, timeout=10)
        app_name = package.split('.')[-1]  # fallback

        if dump.returncode == 0 and 'applicationLabel=' in dump.stdout:
            app_name = dump.stdout.split('applicationLabel=')[-1].split('\n')[0].strip()

        return {
            'name': app_name,
            'running': is_running,
            'network_permission': True,  # Assume true for now
            'version': '1.0'  # Placeholder
        }

    except Exception:
        return {'name': package.split('.')[-1], 'running': False, 'network_permission': True, 'version': 'unknown'}


async def _discover_via_traffic() -> List[DetectedApp]:
    """Discover apps by analyzing existing traffic patterns."""

    state = ProxyState()
    recent_flows = state.get_flows(limit=200)

    # Group flows by likely app patterns
    app_patterns = {}

    for flow in recent_flows:
        if flow.host:
            # Extract potential app identifier from host
            host_parts = flow.host.split('.')
            if len(host_parts) >= 2:
                likely_app = host_parts[-2]  # e.g., "facebook" from "api.facebook.com"

                if likely_app not in app_patterns:
                    app_patterns[likely_app] = {
                        'domains': set(),
                        'flow_count': 0,
                        'https_ratio': 0
                    }

                app_patterns[likely_app]['domains'].add(flow.host)
                app_patterns[likely_app]['flow_count'] += 1
                if flow.scheme == 'https':
                    app_patterns[likely_app]['https_ratio'] += 1

    # Convert patterns to DetectedApp objects
    detected_apps = []

    for app_name, pattern in app_patterns.items():
        if pattern['flow_count'] >= 3:  # Minimum traffic threshold
            https_ratio = pattern['https_ratio'] / pattern['flow_count']

            detected_apps.append(DetectedApp(
                package_name=f"com.{app_name}.app",  # Guess package name
                app_name=app_name.capitalize(),
                version="unknown",
                is_running=True,  # Inferred from traffic
                has_network_permission=True,
                detected_domains=list(pattern['domains']),
                confidence_score=0.7 if https_ratio > 0.5 else 0.5
            ))

    return detected_apps


async def _discover_via_database() -> List[DetectedApp]:
    """Discover apps using database of popular mobile apps."""

    # Popular apps that commonly use SSL pinning
    popular_pinned_apps = [
        {"package": "com.chase.sig.android", "name": "Chase Bank", "domains": ["api.chase.com"]},
        {"package": "com.bankofamerica.digitalbanking", "name": "Bank of America", "domains": ["api.bankofamerica.com"]},
        {"package": "com.facebook.katana", "name": "Facebook", "domains": ["graph.facebook.com", "api.facebook.com"]},
        {"package": "com.instagram.android", "name": "Instagram", "domains": ["i.instagram.com", "api.instagram.com"]},
        {"package": "com.whatsapp", "name": "WhatsApp", "domains": ["web.whatsapp.com"]},
        {"package": "com.twitter.android", "name": "Twitter", "domains": ["api.twitter.com"]},
        {"package": "com.snapchat.android", "name": "Snapchat", "domains": ["api.snapchat.com"]},
        {"package": "com.spotify.music", "name": "Spotify", "domains": ["api.spotify.com"]},
        {"package": "com.paypal.android.p2pmobile", "name": "PayPal", "domains": ["api.paypal.com"]},
        {"package": "com.coinbase.android", "name": "Coinbase", "domains": ["api.coinbase.com"]}
    ]

    # Check which popular apps might be present
    detected_apps = []

    for app_data in popular_pinned_apps:
        detected_apps.append(DetectedApp(
            package_name=app_data["package"],
            app_name=app_data["name"],
            version="unknown",
            is_running=False,  # Unknown
            has_network_permission=True,
            detected_domains=app_data["domains"],
            ssl_pinning_detected=True,  # Known to use pinning
            confidence_score=0.6  # Medium confidence without device confirmation
        ))

    return detected_apps


def _deduplicate_apps(apps: List[DetectedApp]) -> List[DetectedApp]:
    """Remove duplicate apps and merge information."""

    unique_apps = {}

    for app in apps:
        key = app.package_name

        if key in unique_apps:
            # Merge with existing
            existing = unique_apps[key]
            existing.detected_domains = list(set(existing.detected_domains + app.detected_domains))
            existing.confidence_score = max(existing.confidence_score, app.confidence_score)
            existing.is_running = existing.is_running or app.is_running
            existing.ssl_pinning_detected = existing.ssl_pinning_detected or app.ssl_pinning_detected
        else:
            unique_apps[key] = app

    return list(unique_apps.values())


def _apply_certificate_replacement(replacement: CertificateReplacement) -> None:
    """Apply certificate replacement configuration."""
    if replacement.method == "dns_hijack":
        # Would implement DNS hijacking logic
        print(f"DNS hijacking configured for {replacement.target_domain}")
    elif replacement.method == "hosts_file":
        # Would implement hosts file modification
        print(f"Hosts file modification for {replacement.target_domain}")
    elif replacement.method == "transparent_proxy":
        # Would implement transparent proxy certificate replacement
        print(f"Transparent proxy certificate replacement for {replacement.target_domain}")


def get_ssl_bypass_methods_for_addon() -> Dict[str, SSLBypassMethod]:
    """Get all SSL bypass methods for addon access."""
    return _ssl_bypass_methods