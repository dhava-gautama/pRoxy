from __future__ import annotations

from fastapi import APIRouter, HTTPException

from pydantic import BaseModel, ValidationError

from state.shared import ProxyState

router = APIRouter(prefix="/api/settings", tags=["settings"])
state = ProxyState()


# ── SSL pinning bypass helper presets ──────────────────────────────────────
#
# Each preset bundles the header-stripping toggles that make a MITM session
# usable against an app, plus a ready-to-paste Frida script implementing a
# well-known certificate-pinning bypass for that platform. The header toggles
# map 1:1 onto ProxySettings fields and are applied via state.update_settings.
#
# The Frida scripts use only real, documented runtime APIs:
#   - Android: javax.net.ssl.X509TrustManager (custom SSLContext TrustManager),
#     okhttp3.CertificatePinner.check, and WebViewClient.onReceivedSslError.
#   - iOS: Security.framework SecTrustEvaluate / SecTrustEvaluateWithError, and
#     AFNetworking's AFSecurityPolicy.setSSLPinningMode:.
#   - Flutter: the BoringSSL ssl_verify_cert_chain / ssl_set_custom_verify
#     code path inside libflutter, patched by forcing the verify callback's
#     result to "ok" (the classic Flutter pinning bypass).

_ANDROID_FRIDA = r"""// Android SSL pinning bypass: TrustManager + OkHttp + WebView
// Run with: frida -U -f <pkg> -l android.js --no-pause
Java.perform(function () {
    // 1) Custom X509TrustManager that accepts every certificate
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    var TrustManager = Java.registerClass({
        name: 'org.proxy.TrustAllManager',
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function (chain, authType) {},
            checkServerTrusted: function (chain, authType) {},
            getAcceptedIssuers: function () { return []; }
        }
    });
    var trustManagers = [TrustManager.$new()];
    var initOverload = SSLContext.init.overload(
        '[Ljavax.net.ssl.KeyManager;',
        '[Ljavax.net.ssl.TrustManager;',
        'java.security.SecureRandom');
    initOverload.implementation = function (km, tm, sr) {
        console.log('[+] SSLContext.init() hooked -> injecting trust-all manager');
        initOverload.call(this, km, trustManagers, sr);
    };

    // 2) OkHttp3 CertificatePinner.check — neutralise pin verification
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List')
            .implementation = function (hostname, peerCertificates) {
                console.log('[+] OkHttp CertificatePinner.check() bypassed: ' + hostname);
                return;
            };
    } catch (e) {
        console.log('[-] OkHttp CertificatePinner not present: ' + e);
    }

    // 3) WebViewClient.onReceivedSslError — proceed past SSL errors
    try {
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.onReceivedSslError.implementation = function (view, handler, error) {
            console.log('[+] WebViewClient.onReceivedSslError() bypassed');
            handler.proceed();
        };
    } catch (e) {
        console.log('[-] WebViewClient hook failed: ' + e);
    }
});
"""

_IOS_FRIDA = r"""// iOS SSL pinning bypass: SecTrust + AFNetworking
// Run with: frida -U -f <bundle-id> -l ios.js --no-pause
if (ObjC.available) {
    // 1) Security.framework SecTrustEvaluate — force kSecTrustResultProceed
    try {
        var SecTrustEvaluate = Module.findExportByName('Security', 'SecTrustEvaluate');
        if (SecTrustEvaluate) {
            Interceptor.replace(SecTrustEvaluate, new NativeCallback(function (trust, result) {
                // kSecTrustResultProceed = 1
                Memory.writeU32(result, 1);
                console.log('[+] SecTrustEvaluate() -> kSecTrustResultProceed');
                return 0; // errSecSuccess
            }, 'int', ['pointer', 'pointer']));
        }
    } catch (e) {
        console.log('[-] SecTrustEvaluate hook failed: ' + e);
    }

    // 2) Modern SecTrustEvaluateWithError — return true, clear error
    try {
        var SecTrustEvaluateWithError = Module.findExportByName('Security', 'SecTrustEvaluateWithError');
        if (SecTrustEvaluateWithError) {
            Interceptor.replace(SecTrustEvaluateWithError, new NativeCallback(function (trust, error) {
                if (!error.isNull()) { Memory.writePointer(error, NULL); }
                console.log('[+] SecTrustEvaluateWithError() -> true');
                return 1; // true
            }, 'bool', ['pointer', 'pointer']));
        }
    } catch (e) {
        console.log('[-] SecTrustEvaluateWithError hook failed: ' + e);
    }

    // 3) AFNetworking AFSecurityPolicy — disable pinning mode
    try {
        var AFSecurityPolicy = ObjC.classes.AFSecurityPolicy;
        if (AFSecurityPolicy) {
            Interceptor.attach(AFSecurityPolicy['- setSSLPinningMode:'].implementation, {
                onEnter: function (args) {
                    // AFSSLPinningModeNone = 0
                    args[2] = ptr('0x0');
                    console.log('[+] AFSecurityPolicy.setSSLPinningMode: -> None');
                }
            });
            Interceptor.attach(AFSecurityPolicy['- setAllowInvalidCertificates:'].implementation, {
                onEnter: function (args) {
                    args[2] = ptr('0x1'); // YES
                    console.log('[+] AFSecurityPolicy.setAllowInvalidCertificates: -> YES');
                }
            });
        }
    } catch (e) {
        console.log('[-] AFNetworking hooks failed: ' + e);
    }
} else {
    console.log('[-] Objective-C runtime is not available');
}
"""

_FLUTTER_FRIDA = r"""// Flutter / Dart SSL pinning bypass via BoringSSL ssl_verify
// Flutter ignores the system proxy & trust store and pins inside libflutter's
// statically-linked BoringSSL. We scan libflutter.so for the
// ssl_crypto_x509_session_verify_cert_chain pattern and force it to return 1.
// Run with: frida -U -f <pkg> -l flutter.js --no-pause
function hookFlutterSSLVerify() {
    var m = Process.findModuleByName('libflutter.so');
    if (!m) {
        console.log('[-] libflutter.so not loaded yet, retrying...');
        return false;
    }
    // ssl_verify_cert_chain prologue pattern (arm64). Adjust per Flutter build.
    var pattern = 'FF 03 03 D1 FD 7B 04 A9 F4 4F 05 A9 ?? ?? ?? 94 ?? ?? ?? 94';
    var matches = Memory.scanSync(m.base, m.size, pattern);
    if (matches.length === 0) {
        console.log('[-] ssl_verify pattern not found in this libflutter build');
        return false;
    }
    matches.forEach(function (hit) {
        Interceptor.attach(hit.address, {
            onLeave: function (retval) {
                // ssl_verify_result: 1 == ssl_verify_ok
                retval.replace(0x1);
                console.log('[+] Flutter ssl_verify_cert_chain forced to ssl_verify_ok');
            }
        });
    });
    console.log('[+] Hooked ' + matches.length + ' Flutter ssl_verify site(s)');
    return true;
}

if (!hookFlutterSSLVerify()) {
    // libflutter may load after process start; watch for it.
    var dlopen = Module.findExportByName(null, 'android_dlopen_ext') ||
                 Module.findExportByName(null, 'dlopen');
    if (dlopen) {
        Interceptor.attach(dlopen, {
            onEnter: function (args) { this.path = args[0].readCString(); },
            onLeave: function () {
                if (this.path && this.path.indexOf('libflutter.so') !== -1) {
                    hookFlutterSSLVerify();
                }
            }
        });
    }
}
"""

SSL_PROFILES: list[dict] = [
    {
        "name": "Android (Full Bypass)",
        "description": (
            "Strips transport-security headers and provides a Frida script that "
            "bypasses TrustManager, OkHttp CertificatePinner, and WebView SSL "
            "pinning."
        ),
        "settings": {
            "hsts_strip": True,
            "hpkp_strip": True,
            "csp_strip": True,
            "cors_bypass": True,
        },
        "frida_script": _ANDROID_FRIDA,
    },
    {
        "name": "iOS (Full Bypass)",
        "description": (
            "Strips transport-security headers and provides a Frida script that "
            "bypasses SecTrustEvaluate / SecTrustEvaluateWithError and "
            "AFNetworking certificate pinning."
        ),
        "settings": {
            "hsts_strip": True,
            "hpkp_strip": True,
            "csp_strip": True,
            "cors_bypass": True,
        },
        "frida_script": _IOS_FRIDA,
    },
    {
        "name": "Flutter/Dart Bypass",
        "description": (
            "Strips transport-security headers and provides a Frida script that "
            "patches libflutter's BoringSSL ssl_verify code path so pinned "
            "Flutter apps accept the proxy CA."
        ),
        "settings": {
            "hsts_strip": True,
            "hpkp_strip": True,
            "csp_strip": True,
            "cors_bypass": True,
        },
        "frida_script": _FLUTTER_FRIDA,
    },
    {
        "name": "Generic (Headers Only)",
        "description": (
            "Header-only relaxation (HSTS/HPKP/CSP strip + CORS bypass) with no "
            "Frida script. Use for web apps or clients without certificate "
            "pinning."
        ),
        "settings": {
            "hsts_strip": True,
            "hpkp_strip": True,
            "csp_strip": True,
            "cors_bypass": True,
        },
        "frida_script": "",
    },
]


class ApplySSLProfileRequest(BaseModel):
    index: int


@router.get("")
def get_settings():
    return state.get_settings()


@router.post("")
def update_settings(body: dict):
    # Settings are validated by the ProxySettings pydantic model (rule regex,
    # path traversal, ReDoS, etc.). Surface invalid input as 422 instead of a
    # 500 from the unhandled ValidationError.
    try:
        return state.update_settings(body)
    except ValidationError as e:
        raise HTTPException(422, "Invalid settings") from e


@router.get("/ssl-profiles")
def list_ssl_profiles():
    """Return the SSL pinning bypass helper presets the Tools tab renders."""
    return SSL_PROFILES


@router.post("/ssl-profiles/apply")
def apply_ssl_profile(body: ApplySSLProfileRequest):
    """Apply the header toggles of the selected SSL bypass profile."""
    if body.index < 0 or body.index >= len(SSL_PROFILES):
        raise HTTPException(
            404,
            f"SSL profile index {body.index} out of range "
            f"(0..{len(SSL_PROFILES) - 1})",
        )
    profile = SSL_PROFILES[body.index]
    return state.update_settings(profile["settings"])
