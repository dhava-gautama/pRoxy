"""Advanced content processing and transformation."""

from __future__ import annotations

import base64
import gzip
import json
import re
import time
import zlib
from typing import Any, Dict, List, Optional, Union

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, model_validator

from state.shared import ProxyState

router = APIRouter(prefix="/api/content", tags=["content-processing"])


class ContentProcessor(BaseModel):
    """Content processing rule."""
    id: str
    name: str
    enabled: bool = True
    match_content_type: str = ""  # Regex pattern for content-type
    match_url_pattern: str = ""   # Regex pattern for URL
    processors: List[str] = []    # List of processor types
    config: Dict[str, Any] = {}
    priority: int = 0             # Higher priority runs first
    description: str = ""

    @model_validator(mode='after')
    def validate_processor(self) -> 'ContentProcessor':
        if not self.name.strip():
            raise ValueError("Processor name cannot be empty")
        valid_processors = [
            "decode_gzip", "decode_brotli", "decode_deflate",
            "parse_json", "parse_xml", "parse_html",
            "extract_urls", "extract_emails", "extract_ips",
            "beautify_json", "beautify_xml", "beautify_html",
            "minify_json", "minify_html", "minify_css",
            "convert_encoding", "detect_encoding",
            "extract_forms", "extract_links", "extract_scripts",
            "sanitize_html", "strip_comments", "decode_base64"
        ]
        for processor in self.processors:
            if processor not in valid_processors:
                raise ValueError(f"Invalid processor: {processor}")
        return self


class ContentAnalysis(BaseModel):
    """Result of content analysis."""
    content_type: str
    encoding: str
    size: int
    is_compressed: bool
    compression_type: Optional[str]
    detected_formats: List[str]
    extracted_data: Dict[str, Any]
    security_issues: List[str]
    performance_hints: List[str]


class ContentTransformation(BaseModel):
    """Content transformation request."""
    content: str
    content_type: str = "text/plain"
    processors: List[str]
    config: Dict[str, Any] = {}


class ContentAnalysisRequest(BaseModel):
    """Content analysis request."""
    content: str
    content_type: str = "text/plain"


# Global storage
_content_processors: Dict[str, ContentProcessor] = {}
_processing_stats: Dict[str, int] = {}


@router.get("/processors")
def list_content_processors() -> List[ContentProcessor]:
    """List all content processors."""
    return sorted(_content_processors.values(), key=lambda x: x.priority, reverse=True)


@router.post("/processors")
def create_content_processor(processor: ContentProcessor) -> ContentProcessor:
    """Create content processor."""
    processor_id = f"proc_{int(time.time() * 1000)}"
    processor.id = processor_id
    _content_processors[processor_id] = processor

    # Update proxy addon
    state = ProxyState()
    if getattr(state, 'proxy_addon', None) is not None:
        state.proxy_addon.update_content_processors(_content_processors)

    return processor


@router.put("/processors/{processor_id}")
def update_content_processor(processor_id: str, processor: ContentProcessor) -> ContentProcessor:
    """Update content processor."""
    if processor_id not in _content_processors:
        raise HTTPException(404, "Processor not found")

    processor.id = processor_id
    _content_processors[processor_id] = processor

    # Update proxy addon
    state = ProxyState()
    if getattr(state, 'proxy_addon', None) is not None:
        state.proxy_addon.update_content_processors(_content_processors)

    return processor


@router.delete("/processors/{processor_id}")
def delete_content_processor(processor_id: str) -> dict:
    """Delete content processor."""
    if processor_id not in _content_processors:
        raise HTTPException(404, "Processor not found")

    del _content_processors[processor_id]

    # Update proxy addon
    state = ProxyState()
    if getattr(state, 'proxy_addon', None) is not None:
        state.proxy_addon.update_content_processors(_content_processors)

    return {"message": "Processor deleted"}


@router.post("/processors/{processor_id}/toggle")
def toggle_content_processor(processor_id: str) -> ContentProcessor:
    """Toggle content processor enabled state."""
    if processor_id not in _content_processors:
        raise HTTPException(404, "Processor not found")

    processor = _content_processors[processor_id]
    processor.enabled = not processor.enabled

    # Update proxy addon
    state = ProxyState()
    if getattr(state, 'proxy_addon', None) is not None:
        state.proxy_addon.update_content_processors(_content_processors)

    return processor


@router.post("/analyze")
def analyze_content(request: ContentAnalysisRequest) -> ContentAnalysis:
    """Analyze content and extract metadata."""
    content = request.content
    content_type = request.content_type
    try:
        analysis = ContentAnalysis(
            content_type=content_type,
            encoding=_detect_encoding(content.encode() if isinstance(content, str) else content),
            size=len(content),
            is_compressed=False,
            compression_type=None,
            detected_formats=[],
            extracted_data={},
            security_issues=[],
            performance_hints=[]
        )

        # Detect compression
        if content_type.lower().find('gzip') != -1:
            analysis.is_compressed = True
            analysis.compression_type = 'gzip'
        elif content_type.lower().find('brotli') != -1:
            analysis.is_compressed = True
            analysis.compression_type = 'brotli'

        # Detect formats
        analysis.detected_formats = _detect_formats(content, content_type)

        # Extract data based on detected formats
        if 'json' in analysis.detected_formats:
            analysis.extracted_data['json'] = _extract_json_data(content)
        if 'html' in analysis.detected_formats:
            analysis.extracted_data['html'] = _extract_html_data(content)
        if 'xml' in analysis.detected_formats:
            analysis.extracted_data['xml'] = _extract_xml_data(content)

        # Security analysis
        analysis.security_issues = _analyze_security(content, content_type)

        # Performance hints
        analysis.performance_hints = _analyze_performance(content, content_type)

        return analysis

    except Exception as e:
        raise HTTPException(500, f"Content analysis failed: {e}")


@router.post("/transform")
def transform_content(transformation: ContentTransformation) -> dict:
    """Transform content using specified processors."""
    try:
        result = transformation.content
        applied_processors = []

        for processor_name in transformation.processors:
            try:
                result = _apply_processor(result, processor_name, transformation.config)
                applied_processors.append(processor_name)
                _processing_stats[processor_name] = _processing_stats.get(processor_name, 0) + 1
            except Exception as e:
                return {
                    "success": False,
                    "error": f"Processor '{processor_name}' failed: {e}",
                    "applied_processors": applied_processors,
                    "result": result
                }

        return {
            "success": True,
            "result": result,
            "applied_processors": applied_processors,
            "original_size": len(transformation.content),
            "new_size": len(result)
        }

    except Exception as e:
        raise HTTPException(500, f"Content transformation failed: {e}")


@router.get("/stats")
def get_processing_stats() -> dict:
    """Get content processing statistics."""
    return {
        "total_processors": len(_content_processors),
        "active_processors": len([p for p in _content_processors.values() if p.enabled]),
        "processor_usage": _processing_stats,
        "available_processors": [
            "decode_gzip", "decode_brotli", "decode_deflate",
            "parse_json", "parse_xml", "parse_html",
            "extract_urls", "extract_emails", "extract_ips",
            "beautify_json", "beautify_xml", "beautify_html",
            "minify_json", "minify_html", "minify_css",
            "convert_encoding", "detect_encoding",
            "extract_forms", "extract_links", "extract_scripts",
            "sanitize_html", "strip_comments", "decode_base64"
        ]
    }


@router.get("/templates")
def get_processor_templates() -> List[dict]:
    """Get pre-defined processor templates."""
    return [
        {
            "name": "JSON Beautifier",
            "description": "Parse and beautify JSON responses",
            "processors": ["parse_json", "beautify_json"],
            "match_content_type": "application/json",
            "config": {"indent": 2}
        },
        {
            "name": "HTML Analyzer",
            "description": "Extract forms, links, and scripts from HTML",
            "processors": ["parse_html", "extract_forms", "extract_links", "extract_scripts"],
            "match_content_type": "text/html",
            "config": {}
        },
        {
            "name": "Compression Decoder",
            "description": "Decode gzip, brotli, and deflate content",
            "processors": ["decode_gzip", "decode_brotli", "decode_deflate"],
            "match_content_type": "",
            "config": {}
        },
        {
            "name": "Security Scanner",
            "description": "Extract URLs, emails, and IPs for security analysis",
            "processors": ["extract_urls", "extract_emails", "extract_ips"],
            "match_content_type": "",
            "config": {}
        },
        {
            "name": "Minifier",
            "description": "Minify HTML, CSS, and JavaScript",
            "processors": ["minify_html", "minify_css"],
            "match_content_type": "(text/html|text/css|application/javascript)",
            "config": {}
        }
    ]


# Helper functions

def _detect_encoding(content: bytes) -> str:
    """Detect content encoding."""
    try:
        import chardet
        result = chardet.detect(content)
        return result.get('encoding', 'utf-8') or 'utf-8'
    except ImportError:
        # Fallback without chardet
        try:
            content.decode('utf-8')
            return 'utf-8'
        except UnicodeDecodeError:
            return 'latin-1'


def _detect_formats(content: str, content_type: str) -> List[str]:
    """Detect content formats."""
    formats = []

    # By content type
    if 'json' in content_type.lower():
        formats.append('json')
    if 'html' in content_type.lower():
        formats.append('html')
    if 'xml' in content_type.lower():
        formats.append('xml')
    if 'css' in content_type.lower():
        formats.append('css')
    if 'javascript' in content_type.lower():
        formats.append('javascript')

    # By content analysis
    try:
        json.loads(content)
        if 'json' not in formats:
            formats.append('json')
    except Exception:
        pass

    if '<html' in content.lower() and 'html' not in formats:
        formats.append('html')
    if '<?xml' in content.lower() and 'xml' not in formats:
        formats.append('xml')

    return formats


def _extract_json_data(content: str) -> dict:
    """Extract data from JSON content."""
    try:
        data = json.loads(content)
        return {
            "keys": list(data.keys()) if isinstance(data, dict) else [],
            "type": type(data).__name__,
            "size": len(str(data)),
            "depth": _calculate_json_depth(data)
        }
    except Exception:
        return {}


def _extract_html_data(content: str) -> dict:
    """Extract data from HTML content."""
    import re

    forms = len(re.findall(r'<form[^>]*>', content, re.IGNORECASE))
    inputs = len(re.findall(r'<input[^>]*>', content, re.IGNORECASE))
    links = len(re.findall(r'<a[^>]+href[^>]*>', content, re.IGNORECASE))
    scripts = len(re.findall(r'<script[^>]*>', content, re.IGNORECASE))
    images = len(re.findall(r'<img[^>]*>', content, re.IGNORECASE))

    return {
        "forms": forms,
        "inputs": inputs,
        "links": links,
        "scripts": scripts,
        "images": images,
        "title": _extract_html_title(content)
    }


def _extract_xml_data(content: str) -> dict:
    """Extract data from XML content."""
    import re

    elements = len(re.findall(r'<[^/][^>]*>', content))
    namespaces = len(set(re.findall(r'xmlns:?(\w*)', content)))

    return {
        "elements": elements,
        "namespaces": namespaces,
        "root_element": _extract_xml_root(content)
    }


def _analyze_security(content: str, content_type: str) -> List[str]:
    """Analyze content for security issues."""
    issues = []

    # XSS patterns
    xss_patterns = [
        r'<script[^>]*>.*?</script>',
        r'javascript:',
        r'on\w+\s*=',
        r'eval\s*\(',
        r'document\.cookie',
        r'document\.write'
    ]

    for pattern in xss_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            issues.append(f"Potential XSS: {pattern}")

    # SQL injection patterns
    sql_patterns = [
        r"'\s*or\s+'1'\s*=\s*'1",
        r'union\s+select',
        r'drop\s+table',
        r'insert\s+into'
    ]

    for pattern in sql_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            issues.append(f"Potential SQL injection: {pattern}")

    # Sensitive data patterns
    if re.search(r'password\s*[:=]', content, re.IGNORECASE):
        issues.append("Potential password exposure")
    if re.search(r'api[_-]?key\s*[:=]', content, re.IGNORECASE):
        issues.append("Potential API key exposure")

    return issues[:10]  # Limit to 10 issues


def _analyze_performance(content: str, content_type: str) -> List[str]:
    """Analyze content for performance improvements."""
    hints = []

    size = len(content)
    if size > 1024 * 1024:  # > 1MB
        hints.append("Large content size - consider compression")

    if 'json' in content_type.lower():
        try:
            data = json.loads(content)
            if isinstance(data, dict) and len(data) > 100:
                hints.append("Large JSON object - consider pagination")
        except Exception:
            pass

    if 'html' in content_type.lower():
        if content.count('<script') > 10:
            hints.append("Many script tags - consider bundling")
        if content.count('<link') > 20:
            hints.append("Many CSS links - consider bundling")

    # Compression opportunity
    if size > 1024 and not any(h in content_type.lower() for h in ['gzip', 'brotli', 'deflate']):
        hints.append("Content could benefit from compression")

    return hints[:5]  # Limit to 5 hints


_MAX_DECOMPRESS_BYTES = 25 * 1024 * 1024  # cap gunzip output to thwart gzip-bomb DoS


def _gunzip_bounded(raw: bytes, limit: int = _MAX_DECOMPRESS_BYTES) -> bytes:
    """Decompress gzip data, aborting if the output would exceed `limit` bytes."""
    d = zlib.decompressobj(16 + zlib.MAX_WBITS)  # 16 => expect a gzip header
    out = bytearray()
    data = raw
    while True:
        chunk = d.decompress(data, limit + 1 - len(out))
        out += chunk
        if len(out) > limit:
            raise ValueError("gzip output exceeds size limit")
        data = d.unconsumed_tail
        if not chunk and not data:
            return bytes(out)


def _apply_processor(content: str, processor: str, config: dict) -> str:
    """Apply a single processor to content."""
    if processor == "decode_gzip":
        try:
            return _gunzip_bounded(base64.b64decode(content)).decode('utf-8')
        except Exception:
            return content

    elif processor == "decode_base64":
        try:
            return base64.b64decode(content).decode('utf-8')
        except Exception:
            return content

    elif processor == "beautify_json":
        try:
            data = json.loads(content)
            indent = config.get('indent', 2)
            return json.dumps(data, indent=indent, ensure_ascii=False)
        except Exception:
            return content

    elif processor == "minify_json":
        try:
            data = json.loads(content)
            return json.dumps(data, separators=(',', ':'))
        except Exception:
            return content

    elif processor == "extract_urls":
        urls = re.findall(r'https?://[^\s<>"]+', content)
        return '\n'.join(sorted(set(urls)))

    elif processor == "extract_emails":
        emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', content)
        return '\n'.join(sorted(set(emails)))

    elif processor == "extract_ips":
        ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', content)
        return '\n'.join(sorted(set(ips)))

    elif processor == "strip_comments":
        # Strip HTML/XML comments
        return re.sub(r'<!--.*?-->', '', content, flags=re.DOTALL)

    else:
        return content  # Processor not implemented


def _calculate_json_depth(data, depth=0) -> int:
    """Calculate depth of JSON structure."""
    if isinstance(data, dict):
        return max([_calculate_json_depth(v, depth + 1) for v in data.values()], default=depth)
    elif isinstance(data, list):
        return max([_calculate_json_depth(v, depth + 1) for v in data], default=depth)
    else:
        return depth


def _extract_html_title(content: str) -> str:
    """Extract title from HTML content."""
    match = re.search(r'<title[^>]*>(.*?)</title>', content, re.IGNORECASE | re.DOTALL)
    return match.group(1).strip() if match else ""


def _extract_xml_root(content: str) -> str:
    """Extract root element from XML content."""
    match = re.search(r'<([^?\s/>]+)', content)
    return match.group(1) if match else ""


def get_content_processors() -> Dict[str, ContentProcessor]:
    """Get all content processors for addon access."""
    return _content_processors