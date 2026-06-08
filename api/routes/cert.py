from __future__ import annotations

from fastapi import APIRouter, HTTPException

from api.auth import create_auth_dependencies
from fastapi.responses import FileResponse

from proxy.ca import get_ca_cert_path, get_android_cert_path, get_ca_info, regenerate_ca

router = APIRouter(tags=["cert"], dependencies=create_auth_dependencies())


@router.get("/ca.pem")
def download_pem():
    path = get_ca_cert_path("pem")
    if path is None:
        raise HTTPException(404, "CA certificate not generated yet. Start the proxy first.")
    return FileResponse(path, media_type="application/x-pem-file", filename="mitmproxy-ca-cert.pem")


@router.get("/ca.crt")
def download_crt():
    path = get_ca_cert_path("crt")
    if path is None:
        raise HTTPException(404, "CA certificate not generated yet. Start the proxy first.")
    return FileResponse(path, media_type="application/x-x509-ca-cert", filename="mitmproxy-ca-cert.crt")


@router.get("/api/cert/info")
def cert_info():
    """Return CA certificate fingerprint, subject, and validity dates."""
    info = get_ca_info()
    if info is None:
        raise HTTPException(404, "CA certificate not generated yet. Start the proxy first.")
    return info


@router.post("/api/cert/regenerate")
def cert_regenerate():
    """Delete existing CA files and generate a fresh CA certificate."""
    ok = regenerate_ca()
    if not ok:
        raise HTTPException(500, "Failed to regenerate CA certificate.")
    info = get_ca_info()
    return {"success": True, "cert": info}


@router.get("/ca.android")
def download_android():
    """Download CA cert in Android system format (<hash>.0)."""
    result = get_android_cert_path()
    if result is None:
        raise HTTPException(404, "CA certificate not generated yet or openssl not available.")
    path, filename = result
    return FileResponse(path, media_type="application/x-pem-file", filename=filename)