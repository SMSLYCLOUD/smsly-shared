"""
Lightweight, defense-in-depth file and media upload scanner.

Pure-Python core with lazy optional acceleration from:
- ``filetype`` (header magic-byte identification)
- ``puremagic`` (deep magic-byte / offset signatures)
- ``Pillow`` (image dimension & truncation verification)
- ``ClamAV`` (optional clamd ``zINSTREAM`` TCP or Unix socket AV scan)

All third-party imports remain lazy inside functions so pure-Python fallback
verification works identically in minimal or sandboxed runtimes.
"""
from __future__ import annotations

import asyncio
import hashlib
import io
import json
import os
import posixpath
import re
import socket
import struct
import zipfile
import zlib
from dataclasses import dataclass, field
from typing import Iterable, Optional, Sequence, Tuple


class FileScanError(ValueError):
    """Raised when an uploaded file fails security, type, or size validation."""

    def __init__(
        self,
        message: str,
        *,
        code: str = "file_scan_rejected",
        status_code: int = 400,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code


@dataclass(frozen=True)
class FileScanResult:
    """Validated metadata returned by ``scan_uploaded_file``."""

    safe_filename: str
    detected_mime: str
    declared_mime: Optional[str]
    extension: str
    size_bytes: int
    sha256: str
    clamav_status: str = "skipped"
    warnings: Tuple[str, ...] = field(default_factory=tuple)


# ---------------------------------------------------------------------------
# Mime presets
# ---------------------------------------------------------------------------

PRESET_AVATARS: frozenset[str] = frozenset({
    "image/jpeg",
    "image/png",
    "image/webp",
    "image/gif",
})

PRESET_IMAGES: frozenset[str] = PRESET_AVATARS

PRESET_KYC: frozenset[str] = frozenset({
    "image/jpeg",
    "image/png",
    "image/webp",
    "application/pdf",
})

PRESET_DOCUMENTS: frozenset[str] = frozenset({
    "application/pdf",
    "text/plain",
    "text/csv",
    "application/json",
    "application/msword",
    "application/vnd.ms-excel",
    "application/vnd.ms-powerpoint",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
})

PRESET_MEDIA_ALL: frozenset[str] = frozenset({
    *PRESET_IMAGES,
    "application/pdf",
    "text/plain",
    "text/csv",
    "video/mp4",
    "video/quicktime",
    "video/webm",
    "video/3gpp",
    "audio/mpeg",
    "audio/ogg",
    "audio/wav",
    "audio/aac",
    "audio/amr",
    "audio/mp4",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
})

PRESET_EMAIL_ATTACHMENTS: frozenset[str] = frozenset({
    *PRESET_IMAGES,
    *PRESET_DOCUMENTS,
    "application/zip",
    "audio/mpeg",
    "video/mp4",
})

# Never allow executable / active web payloads through standard upload presets
DANGEROUS_EXTENSIONS: frozenset[str] = frozenset({
    ".exe", ".dll", ".so", ".dylib", ".bat", ".cmd", ".ps1", ".psm1",
    ".vbs", ".vbe", ".js", ".jse", ".mjs", ".cjs", ".wsf", ".wsh",
    ".hta", ".scr", ".pif", ".msi", ".msp", ".com", ".cpl", ".jar",
    ".sh", ".bash", ".zsh", ".php", ".phtml", ".asp", ".aspx", ".jsp",
    ".py", ".rb", ".pl", ".cgi", ".svg", ".html", ".htm", ".xhtml",
    ".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm",
})

DANGEROUS_MIME_TYPES: frozenset[str] = frozenset({
    "application/x-dosexec",
    "application/x-msdownload",
    "application/x-executable",
    "application/x-sharedlib",
    "application/x-mach-binary",
    "application/x-sh",
    "application/x-shellscript",
    "application/javascript",
    "text/javascript",
    "text/html",
    "application/xhtml+xml",
    "image/svg+xml",
})

_EICAR_BYTES = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)

_EXECUTABLE_SIGNATURES: Tuple[Tuple[bytes, str], ...] = (
    (b"MZ", "Windows PE/DOS executable"),
    (b"\x7fELF", "Linux ELF binary"),
    (b"\xfe\xed\xfa\xce", "Mach-O 32-bit binary"),
    (b"\xfe\xed\xfa\xcf", "Mach-O 64-bit binary"),
    (b"\xcf\xfa\xed\xfe", "Mach-O 64-bit LE binary"),
    (b"\xce\xfa\xed\xfe", "Mach-O 32-bit LE binary"),
    (b"#!/", "Shell script shebang"),
    (b"#! /", "Shell script shebang"),
)

_MIME_EXTENSIONS: dict[str, frozenset[str]] = {
    "image/jpeg": frozenset({".jpg", ".jpeg", ".jpe", ".jfif"}),
    "image/png": frozenset({".png"}),
    "image/gif": frozenset({".gif"}),
    "image/webp": frozenset({".webp"}),
    "image/svg+xml": frozenset({".svg"}),
    "application/pdf": frozenset({".pdf"}),
    "text/plain": frozenset({".txt", ".log", ".md"}),
    "text/csv": frozenset({".csv", ".tsv"}),
    "application/json": frozenset({".json"}),
    "application/zip": frozenset({".zip"}),
    "application/msword": frozenset({".doc"}),
    "application/vnd.ms-excel": frozenset({".xls"}),
    "application/vnd.ms-powerpoint": frozenset({".ppt"}),
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": frozenset({".docx"}),
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": frozenset({".xlsx"}),
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": frozenset({".pptx"}),
    "video/mp4": frozenset({".mp4", ".m4v"}),
    "video/quicktime": frozenset({".mov"}),
    "video/webm": frozenset({".webm"}),
    "video/3gpp": frozenset({".3gp", ".3gpp"}),
    "audio/mpeg": frozenset({".mp3"}),
    "audio/ogg": frozenset({".ogg", ".oga", ".opus"}),
    "audio/wav": frozenset({".wav"}),
    "audio/aac": frozenset({".aac", ".m4a"}),
    "audio/amr": frozenset({".amr"}),
    "audio/mp4": frozenset({".m4a", ".mp4"}),
}

_MIME_ALIASES: dict[str, str] = {
    "image/jpg": "image/jpeg",
    "image/pjpeg": "image/jpeg",
    "audio/mp3": "audio/mpeg",
    "audio/x-wav": "audio/wav",
    "audio/wave": "audio/wav",
    "audio/x-m4a": "audio/mp4",
    "video/x-m4v": "video/mp4",
    "application/x-pdf": "application/pdf",
    "application/x-zip-compressed": "application/zip",
    "text/x-csv": "text/csv",
    "application/csv": "text/csv",
}

_PDF_ACTIVE_TOKENS = re.compile(
    rb"/(?:JS|JavaScript|Launch|EmbeddedFile|EmbeddedFiles|RichMedia|XFA|SubmitForm|ImportData|OpenAction|AA|GoToR|GoToE)\b"
)
_PDF_NAME_WITH_HEX_RE = re.compile(rb"/[A-Za-z0-9._-]*#[0-9A-Fa-f]{2}[A-Za-z0-9#._-]*")
_HTML_XSS_PATTERNS = re.compile(
    rb"(?i)(?:<\s*script\b|javascript\s*:|vbscript\s*:|data\s*:\s*text/html|xlink\s*:\s*href\b|<\s*iframe\b|<\s*object\b|<\s*embed\b|<\s*foreignobject\b|<\s*svg\b|\bon[a-z]+\s*=)"
)
_SVG_TAG_RE = re.compile(rb"(?i)<\s*svg\b")
_HTML_TAG_RE = re.compile(rb"(?i)(?:<!doctype\s+html\b|<\s*html\b|<\s*head\b|<\s*body\b|<\s*script\b)")


def _decode_pdf_name_escapes(buf: bytes) -> bytes:
    """Decode ISO 32000-1 #XX hex escapes inside PDF Name tokens before scanning."""
    if b"#" not in buf:
        return buf

    def _unescape(match: re.Match[bytes]) -> bytes:
        return re.sub(
            rb"#([0-9A-Fa-f]{2})",
            lambda hx: bytes([int(hx.group(1), 16)]),
            match.group(0),
        )

    return _PDF_NAME_WITH_HEX_RE.sub(_unescape, buf)


def _is_zlib_header(buf: bytes) -> bool:
    """Validate RFC 1950 2-byte zlib header (supports all deflate window sizes, not just 0x78)."""
    if len(buf) < 2:
        return False
    cmf, flg = buf[0], buf[1]
    return (cmf & 0x0F) == 8 and (cmf >> 4) <= 7 and (((cmf << 8) + flg) % 31) == 0


def _normalize_mime(mime: Optional[str]) -> Optional[str]:
    if not mime:
        return None
    base = mime.split(";", 1)[0].strip().lower()
    if not base:
        return None
    return _MIME_ALIASES.get(base, base)


def sanitize_upload_filename(filename: Optional[str], fallback_ext: str = "") -> str:
    """Return a path-safe ASCII/Unicode filename stripped of traversal & control chars."""
    raw = (filename or "upload").replace("\\", "/").split("/")[-1]
    raw = re.sub(r"[\x00-\x1f\x7f]+", "", raw).strip(" .")
    if not raw or raw in {".", ".."}:
        raw = "upload"
    stem, ext = posixpath.splitext(raw)
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", stem).strip("._-") or "upload"
    ext = re.sub(r"[^A-Za-z0-9.]+", "", ext.lower())
    if not ext and fallback_ext:
        ext = fallback_ext if fallback_ext.startswith(".") else f".{fallback_ext}"
    if len(stem) > 96:
        stem = stem[:96]
    return f"{stem}{ext}"


def _detect_ooxml_or_zip(data: bytes) -> str:
    """Distinguish DOCX/XLSX/PPTX from plain ZIP using central directory names (no 200-entry truncation)."""
    has_content_types = False
    ooxml_kind: Optional[str] = None
    try:
        with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
            for idx, name in enumerate(zf.namelist()):
                if idx >= 10000:
                    break
                if name == "[Content_Types].xml":
                    has_content_types = True
                elif ooxml_kind is None:
                    if name.startswith("word/"):
                        ooxml_kind = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                    elif name.startswith("xl/"):
                        ooxml_kind = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                    elif name.startswith("ppt/"):
                        ooxml_kind = "application/vnd.openxmlformats-officedocument.presentationml.presentation"
                if has_content_types and ooxml_kind is not None:
                    return ooxml_kind
    except Exception:
        return "application/zip"
    return "application/zip"


def _detect_ole2(data: bytes, declared_mime: Optional[str], ext: str) -> str:
    if ext == ".xls" or declared_mime == "application/vnd.ms-excel":
        return "application/vnd.ms-excel"
    if ext == ".ppt" or declared_mime == "application/vnd.ms-powerpoint":
        return "application/vnd.ms-powerpoint"
    return "application/msword"


def _looks_like_text(sample: bytes) -> bool:
    if not sample or b"\x00" in sample:
        return False
    try:
        decoded = sample.decode("utf-8")
    except UnicodeDecodeError:
        return False
    bad_ctrl = sum(1 for ch in decoded if ord(ch) < 32 and ch not in "\r\n\t")
    return bad_ctrl == 0


def detect_mime_type(
    data: bytes,
    *,
    filename: Optional[str] = None,
    declared_mime: Optional[str] = None,
) -> str:
    """Detect real MIME type from content bytes using filetype, puremagic, and pure-Python rules."""
    head = data[:8192]
    norm_declared = _normalize_mime(declared_mime)
    _, ext = posixpath.splitext((filename or "").lower())

    # 1. Explicit executable / dangerous binary headers first
    for sig, _ in _EXECUTABLE_SIGNATURES:
        if head.startswith(sig):
            if sig == b"MZ":
                return "application/x-dosexec"
            if sig == b"\x7fELF":
                return "application/x-executable"
            if sig.startswith(b"#!"):
                return "application/x-shellscript"
            return "application/x-mach-binary"

    # 2. High-confidence container/magic checks
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if head.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if head.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif"
    if len(head) >= 12 and head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "image/webp"
    if len(head) >= 12 and head[:4] == b"RIFF" and head[8:12] == b"WAVE":
        return "audio/wav"
    if head.lstrip()[:5].lower() == b"%pdf-":
        return "application/pdf"
    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
        return _detect_ooxml_or_zip(data)
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return _detect_ole2(data, norm_declared, ext)
    if head.startswith(b"OggS"):
        return "audio/ogg"
    if head.startswith(b"#!AMR"):
        return "audio/amr"
    # ADTS AAC: 12-bit syncword 0xFFF with layer bits == 00 ((byte1 & 0xF6) == 0xF0)
    if len(head) >= 2 and head[0] == 0xFF and (head[1] & 0xF6) == 0xF0:
        return "audio/aac"
    # MP3: ID3 tag or MPEG syncword with non-zero layer bits
    if head.startswith(b"ID3") or (
        len(head) >= 2 and head[0] == 0xFF and (head[1] & 0xE0) == 0xE0 and (head[1] & 0x06) != 0x00
    ):
        if head.startswith(b"ID3") and (ext == ".aac" or norm_declared == "audio/aac"):
            return "audio/aac"
        return "audio/mpeg"
    if len(head) >= 12 and head[4:8] == b"ftyp":
        brand = head[8:12]
        if brand in {b"qt  "}:
            return "video/quicktime"
        if brand.startswith(b"3gp"):
            return "video/3gpp"
        if brand in {b"M4A ", b"M4B "}:
            return "audio/mp4"
        return "video/mp4"
    if head.startswith(b"\x1a\x45\xdf\xa3"):
        return "video/webm"

    # 3. Optional pure-Python filetype library
    try:
        import filetype  # type: ignore

        kind = filetype.guess(head)
        if kind and kind.mime:
            detected = _normalize_mime(kind.mime)
            if detected == "application/zip":
                return _detect_ooxml_or_zip(data)
            if detected:
                return detected
    except Exception:
        pass

    # 4. Optional puremagic library
    try:
        import puremagic  # type: ignore

        matches = puremagic.magic_string(head)
        for match in matches:
            cand = _normalize_mime(getattr(match, "mime_type", None))
            if cand:
                if cand == "application/zip":
                    return _detect_ooxml_or_zip(data)
                return cand
    except Exception:
        pass

    # 5. Text / HTML / SVG / JSON / CSV inspection (scan full payload, no 512 B truncation bypass)
    if b"\x00" not in head:
        if _SVG_TAG_RE.search(data):
            return "image/svg+xml"
        if _HTML_TAG_RE.search(data):
            return "text/html"
    if _looks_like_text(head):
        if ext == ".json" or norm_declared == "application/json":
            return "application/json"
        if ext in {".csv", ".tsv"} or norm_declared == "text/csv":
            return "text/csv"
        return "text/plain"

    return "application/octet-stream"


def _inspect_zip_container(
    data: bytes,
    *,
    max_entries: int = 2000,
    max_uncompressed_bytes: int = 50 * 1024 * 1024,
    max_compression_ratio: int = 100,
    allow_macros: bool = False,
) -> None:
    try:
        zf = zipfile.ZipFile(io.BytesIO(data), "r")
    except zipfile.BadZipFile as exc:
        raise FileScanError(
            "Corrupt or malformed archive container",
            code="corrupt_archive",
            status_code=422,
        ) from exc

    with zf:
        infos = zf.infolist()
        if len(infos) > max_entries:
            raise FileScanError(
                "Archive contains too many entries",
                code="zip_bomb_entries",
                status_code=422,
            )
        total_uncompressed = 0
        for info in infos:
            name = info.filename.replace("\\", "/")
            parts = [p for p in name.split("/") if p]
            if name.startswith("/") or ".." in parts or ":" in name.split("/")[0]:
                raise FileScanError(
                    "Archive contains unsafe path traversal entry",
                    code="zip_slip",
                    status_code=422,
                )
            lower_name = name.lower()
            if not allow_macros and (
                lower_name.endswith("vbaproject.bin")
                or "/macrosheets/" in lower_name
                or "/activex/" in lower_name
            ):
                raise FileScanError(
                    "Office documents containing VBA macros or ActiveX controls are rejected",
                    code="office_macros_rejected",
                    status_code=422,
                )
            total_uncompressed += max(0, info.file_size)
            if total_uncompressed > max_uncompressed_bytes:
                raise FileScanError(
                    "Archive decompressed size exceeds security limit",
                    code="zip_bomb_size",
                    status_code=422,
                )
            if info.compress_size > 0 and (info.file_size / info.compress_size) > max_compression_ratio and info.file_size > 1024 * 1024:
                raise FileScanError(
                    "Archive exhibits suspicious compression ratio (zip bomb)",
                    code="zip_bomb_ratio",
                    status_code=422,
                )
            if not info.is_dir():
                _, member_ext = posixpath.splitext(lower_name)
                if member_ext in DANGEROUS_EXTENSIONS:
                    raise FileScanError(
                        f"Archive contains disallowed file type '{member_ext}'",
                        code="archive_dangerous_member",
                        status_code=422,
                    )
                # Inspect bounded prefix of each unencrypted member for executable magic bytes / EICAR
                if not (info.flag_bits & 0x1):
                    try:
                        with zf.open(info, "r") as member_fp:
                            member_head = member_fp.read(128)
                    except FileScanError:
                        raise
                    except Exception:
                        member_head = b""
                    if _EICAR_BYTES in member_head:
                        raise FileScanError(
                            "Archive member contains known malware signature (EICAR)",
                            code="malware_detected",
                            status_code=422,
                        )
                    for sig, sig_desc in _EXECUTABLE_SIGNATURES:
                        if member_head.startswith(sig):
                            raise FileScanError(
                                f"Archive contains executable member ({sig_desc})",
                                code="archive_executable_member",
                                status_code=422,
                            )


def _decompress_bounded(raw_stream: bytes, wbits: int, budget: int) -> bytes:
    """Decompress a deflate/zlib stream incrementally, rejecting immediately if output exceeds budget."""
    dobj = zlib.decompressobj(wbits)
    out = bytearray()
    mv = memoryview(raw_stream)
    slice_size = 65536
    for offset in range(0, len(raw_stream), slice_size):
        remaining = budget - len(out)
        if remaining <= 0:
            raise FileScanError(
                "PDF decompressed stream size exceeds security limit (PDF bomb)",
                code="pdf_bomb",
                status_code=422,
            )
        chunk = dobj.decompress(mv[offset:offset + slice_size], remaining + 1)
        out.extend(chunk)
        if len(out) > budget or dobj.unconsumed_tail:
            raise FileScanError(
                "PDF decompressed stream size exceeds security limit (PDF bomb)",
                code="pdf_bomb",
                status_code=422,
            )
        if dobj.eof:
            break
    remaining = budget - len(out)
    tail = dobj.flush(max(1, remaining + 1))
    out.extend(tail)
    if len(out) > budget:
        raise FileScanError(
            "PDF decompressed stream size exceeds security limit (PDF bomb)",
            code="pdf_bomb",
            status_code=422,
        )
    return bytes(out)


def _inspect_pdf(data: bytes) -> None:
    if _PDF_ACTIVE_TOKENS.search(data) or _PDF_ACTIVE_TOKENS.search(_decode_pdf_name_escapes(data)):
        raise FileScanError(
            "PDF contains disallowed active content (JavaScript, Launch, OpenAction, XFA, or embedded files)",
            code="pdf_active_content",
            status_code=422,
        )

    # Linear scan for stream...endstream blocks (no backtracking DOTALL regex) with bounded zlib decompression
    decompressed_budget = 8 * 1024 * 1024
    used = 0
    pos = 0
    n = len(data)
    stream_count = 0

    while pos < n:
        start_kw = data.find(b"stream", pos)
        if start_kw == -1:
            break
        # Ignore 'endstream' or identifiers ending with 'stream'
        if start_kw > 0 and (data[start_kw - 1:start_kw].isalnum() or data[start_kw - 1:start_kw] == b"_"):
            pos = start_kw + 6
            continue

        after_kw = start_kw + 6
        if data[after_kw:after_kw + 2] == b"\r\n":
            body_start = after_kw + 2
        elif data[after_kw:after_kw + 1] in (b"\n", b"\r"):
            body_start = after_kw + 1
        else:
            pos = after_kw
            continue

        end_kw = data.find(b"endstream", body_start)
        if end_kw == -1:
            break

        raw_stream = data[body_start:end_kw]
        if raw_stream.endswith(b"\r\n"):
            raw_stream = raw_stream[:-2]
        elif raw_stream.endswith((b"\n", b"\r")):
            raw_stream = raw_stream[:-1]

        dict_window = data[max(0, start_kw - 512):start_kw]
        pos = end_kw + 9
        if not raw_stream:
            continue

        stream_count += 1
        if stream_count > 1024:
            raise FileScanError(
                "PDF contains excessive stream count",
                code="pdf_bomb",
                status_code=422,
            )

        decoded_dict = _decode_pdf_name_escapes(dict_window)
        declares_flate = b"/FlateDecode" in decoded_dict or b"/Fl" in decoded_dict
        has_zlib_hdr = _is_zlib_header(raw_stream)
        if not has_zlib_hdr and not declares_flate:
            continue

        remaining = decompressed_budget - used
        if remaining <= 0:
            raise FileScanError(
                "PDF decompressed stream size exceeds security limit (PDF bomb)",
                code="pdf_bomb",
                status_code=422,
            )

        chunk: Optional[bytes] = None
        wbits_candidates = (zlib.MAX_WBITS, -zlib.MAX_WBITS) if has_zlib_hdr else (zlib.MAX_WBITS, -zlib.MAX_WBITS)
        for wb in wbits_candidates:
            try:
                chunk = _decompress_bounded(raw_stream, wb, remaining)
                break
            except FileScanError:
                raise
            except zlib.error:
                continue

        if not chunk:
            continue

        used += len(chunk)
        if _PDF_ACTIVE_TOKENS.search(chunk) or _PDF_ACTIVE_TOKENS.search(_decode_pdf_name_escapes(chunk)):
            raise FileScanError(
                "PDF compressed stream contains disallowed active content",
                code="pdf_active_content",
                status_code=422,
            )


def _inspect_ole2(data: bytes) -> None:
    # Legacy Office binary containers embed VBA streams with these markers
    if b"_VBA_PROJECT" in data or (b"VBA" in data and b"\x00P\x00r\x00o\x00j\x00e\x00c\x00t" in data):
        raise FileScanError(
            "Legacy Office document containing embedded VBA macros is rejected",
            code="ole2_macros_rejected",
            status_code=422,
        )


def _extract_image_dimensions(data: bytes, mime: str) -> Optional[Tuple[int, int]]:
    if mime == "image/png" and len(data) >= 24 and data[12:16] == b"IHDR":
        w, h = struct.unpack(">II", data[16:24])
        return int(w), int(h)
    if mime == "image/gif" and len(data) >= 10:
        w, h = struct.unpack("<HH", data[6:10])
        return int(w), int(h)
    if mime == "image/jpeg":
        i = 2
        n = len(data)
        while i + 4 < n:
            if data[i] != 0xFF:
                i += 1
                continue
            while i < n and data[i] == 0xFF:
                i += 1
            if i >= n:
                break
            marker = data[i]
            i += 1
            if marker in (0xD8, 0xD9, 0x01) or (0xD0 <= marker <= 0xD7):
                continue
            if i + 2 > n:
                break
            seg_len = struct.unpack(">H", data[i:i + 2])[0]
            if seg_len < 2:
                break
            if marker in (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF):
                if i + 7 <= n:
                    h, w = struct.unpack(">HH", data[i + 3:i + 7])
                    return int(w), int(h)
                break
            i += seg_len
    if mime == "image/webp" and len(data) >= 30 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        chunk_type = data[12:16]
        if chunk_type == b"VP8X" and len(data) >= 30:
            w = int.from_bytes(data[24:27], "little") + 1
            h = int.from_bytes(data[27:30], "little") + 1
            return w, h
        if chunk_type == b"VP8L" and len(data) >= 25 and data[20] == 0x2F:
            bits = struct.unpack("<I", data[21:25])[0]
            return (bits & 0x3FFF) + 1, ((bits >> 14) & 0x3FFF) + 1
        if chunk_type == b"VP8 " and len(data) >= 30 and data[23:26] == b"\x9d\x01\x2a":
            w, h = struct.unpack("<HH", data[26:30])
            return int(w & 0x3FFF), int(h & 0x3FFF)
    return None


def _inspect_image(data: bytes, mime: str, max_pixels: int) -> None:
    dims = _extract_image_dimensions(data, mime)
    if dims is not None:
        w, h = dims
        if w <= 0 or h <= 0 or (w * h) > max_pixels:
            raise FileScanError(
                f"Image dimensions ({w}x{h}) exceed allowed pixel limit",
                code="image_bomb",
                status_code=422,
            )

    # Optional Pillow header/structural check (kept lazy)
    try:
        from PIL import Image  # type: ignore

        with Image.open(io.BytesIO(data)) as img:
            pw, ph = img.size
            if pw <= 0 or ph <= 0 or (pw * ph) > max_pixels:
                raise FileScanError(
                    f"Image dimensions ({pw}x{ph}) exceed allowed pixel limit",
                    code="image_bomb",
                    status_code=422,
                )
    except FileScanError:
        raise
    except ImportError:
        pass
    except Exception as exc:
        raise FileScanError(
            "Corrupt or unreadable image payload",
            code="corrupt_image",
            status_code=422,
        ) from exc


def clamav_scan_bytes(
    data: bytes,
    *,
    host: Optional[str] = None,
    port: Optional[int] = None,
    socket_path: Optional[str] = None,
    timeout: float = 10.0,
    required: Optional[bool] = None,
) -> str:
    """Scan bytes using clamd's ``zINSTREAM`` protocol if configured; return status string."""
    env_host = host if host is not None else os.environ.get("UPLOAD_CLAMAV_HOST", "").strip()
    env_socket = socket_path if socket_path is not None else os.environ.get("UPLOAD_CLAMAV_SOCKET", "").strip()
    env_port = port if port is not None else int(os.environ.get("UPLOAD_CLAMAV_PORT", "3310") or "3310")
    is_required = (
        required
        if required is not None
        else os.environ.get("UPLOAD_CLAMAV_REQUIRED", "").strip().lower() in {"1", "true", "yes"}
    )

    if not env_host and not env_socket:
        if is_required:
            raise FileScanError(
                "ClamAV scanning is required but no clamd host or socket is configured",
                code="clamav_unconfigured",
                status_code=503,
            )
        return "skipped"

    sock = None
    try:
        can_use_unix = bool(
            env_socket
            and hasattr(socket, "AF_UNIX")
            and (os.name != "nt" or os.path.exists(env_socket))
        )
        if can_use_unix:
            try:
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                sock.connect(env_socket)
            except OSError:
                if sock is not None:
                    try:
                        sock.close()
                    except Exception:
                        pass
                    sock = None
                if not env_host:
                    raise
        if sock is None:
            if not env_host:
                if is_required:
                    raise FileScanError(
                        "ClamAV Unix socket is unavailable on this platform and no TCP host is configured",
                        code="clamav_unavailable",
                        status_code=503,
                    )
                return "unavailable"
            sock = socket.create_connection((env_host, env_port), timeout=timeout)

        sock.sendall(b"zINSTREAM\0")
        mv = memoryview(data)
        chunk_size = 65536
        for offset in range(0, len(data), chunk_size):
            chunk = mv[offset:offset + chunk_size]
            sock.sendall(struct.pack(">I", len(chunk)))
            sock.sendall(chunk)
        sock.sendall(struct.pack(">I", 0))

        chunks = []
        while True:
            resp = sock.recv(4096)
            if not resp:
                break
            chunks.append(resp)
            if b"\0" in resp:
                break
        verdict = b"".join(chunks).rstrip(b"\0 \r\n").decode("utf-8", errors="replace")
        if "FOUND" in verdict:
            raise FileScanError(
                f"Malware detected by ClamAV ({verdict})",
                code="malware_detected",
                status_code=422,
            )
        if verdict.endswith("OK"):
            return "clean"
        if is_required:
            raise FileScanError(
                f"Unexpected ClamAV response: {verdict}",
                code="clamav_error",
                status_code=503,
            )
        return f"error:{verdict}"
    except FileScanError:
        raise
    except Exception as exc:
        if is_required:
            raise FileScanError(
                f"ClamAV scan unavailable: {exc}",
                code="clamav_unavailable",
                status_code=503,
            ) from exc
        return "unavailable"
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


def scan_uploaded_file(
    data: bytes,
    *,
    filename: Optional[str] = None,
    declared_mime: Optional[str] = None,
    allowed_mimes: Optional[Iterable[str]] = None,
    max_bytes: Optional[int] = None,
    max_image_pixels: int = 50_000_000,
    enable_clamav: bool = True,
) -> FileScanResult:
    """
    Validate and deep-scan an uploaded file payload before persistence or forwarding.

    Raises ``FileScanError`` with an appropriate HTTP status code on any violation.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise FileScanError("Upload payload must be bytes", code="invalid_payload", status_code=400)
    raw = bytes(data)
    size_bytes = len(raw)

    if size_bytes == 0:
        raise FileScanError("Uploaded file is empty", code="empty_file", status_code=400)

    if max_bytes is not None and size_bytes > max_bytes:
        raise FileScanError(
            f"Uploaded file ({size_bytes} bytes) exceeds maximum limit ({max_bytes} bytes)",
            code="file_too_large",
            status_code=413,
        )

    if _EICAR_BYTES in raw:
        raise FileScanError(
            "Known malware signature detected (EICAR)",
            code="malware_detected",
            status_code=422,
        )

    safe_name = sanitize_upload_filename(filename)
    _, ext = posixpath.splitext(safe_name.lower())
    if ext in DANGEROUS_EXTENSIONS:
        raise FileScanError(
            f"File extension '{ext}' is blocked for security reasons",
            code="blocked_extension",
            status_code=415,
        )

    norm_declared = _normalize_mime(declared_mime)
    detected_mime = detect_mime_type(raw, filename=safe_name, declared_mime=norm_declared)

    if detected_mime in DANGEROUS_MIME_TYPES:
        raise FileScanError(
            f"Detected payload type '{detected_mime}' is blocked for security reasons",
            code="blocked_mime",
            status_code=415,
        )

    if allowed_mimes is not None:
        normalized_allowed = {_normalize_mime(m) for m in allowed_mimes if m}
        # Permit text/csv <-> text/plain equivalence only when file looks like valid CSV
        effective_allowed = set(normalized_allowed)
        if detected_mime not in effective_allowed:
            if not (detected_mime == "text/plain" and "text/csv" in effective_allowed and ext == ".csv"):
                raise FileScanError(
                    f"Unsupported or mismatched file content type '{detected_mime}'",
                    code="unsupported_media_type",
                    status_code=415,
                )
            detected_mime = "text/csv"

    # Reject misleading executable/dangerous extension mismatches when extension is present
    if ext and detected_mime in _MIME_EXTENSIONS:
        expected_exts = _MIME_EXTENSIONS[detected_mime]
        # Allow .csv uploaded as text/plain when explicitly allowed
        if ext not in expected_exts and not (detected_mime == "text/plain" and ext in {".csv", ".tsv", ".json"}):
            # Spoofed extension (e.g. PDF renamed .jpg or PNG renamed .pdf)
            raise FileScanError(
                f"File extension '{ext}' does not match detected content type '{detected_mime}'",
                code="extension_mime_mismatch",
                status_code=422,
            )

    warnings: list[str] = []
    if norm_declared and norm_declared != detected_mime and norm_declared != "application/octet-stream":
        # Check cross-type spoofing beyond benign image/jpg aliases or csv/text aliases
        if not (
            (norm_declared in {"text/csv", "application/json"} and detected_mime in {"text/plain", norm_declared})
            or (norm_declared in {"audio/mp4", "video/mp4"} and detected_mime in {"audio/mp4", "video/mp4", "audio/aac"})
        ):
            warnings.append(f"declared_mime={norm_declared};detected_mime={detected_mime}")

    # Deep structural inspection per format
    if detected_mime in {
        "application/zip",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    }:
        _inspect_zip_container(raw)
    elif detected_mime == "application/pdf":
        _inspect_pdf(raw)
    elif detected_mime in {
        "application/msword",
        "application/vnd.ms-excel",
        "application/vnd.ms-powerpoint",
    }:
        _inspect_ole2(raw)
    elif detected_mime.startswith("image/"):
        _inspect_image(raw, detected_mime, max_pixels=max_image_pixels)
    elif detected_mime in {"text/plain", "text/csv", "application/json"}:
        if detected_mime == "application/json":
            try:
                json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, ValueError) as exc:
                raise FileScanError(
                    "Uploaded JSON file is malformed",
                    code="invalid_json",
                    status_code=422,
                ) from exc
        if _HTML_XSS_PATTERNS.search(raw):
            raise FileScanError(
                "Text upload contains disallowed active script or HTML markup",
                code="script_payload_rejected",
                status_code=422,
            )

    clamav_status = clamav_scan_bytes(raw) if enable_clamav else "skipped"
    sha256_hex = hashlib.sha256(raw).hexdigest()

    if not ext and detected_mime in _MIME_EXTENSIONS:
        fallback_ext = sorted(_MIME_EXTENSIONS[detected_mime])[0]
        safe_name = sanitize_upload_filename(safe_name, fallback_ext=fallback_ext)
        _, ext = posixpath.splitext(safe_name.lower())

    return FileScanResult(
        safe_filename=safe_name,
        detected_mime=detected_mime,
        declared_mime=norm_declared,
        extension=ext,
        size_bytes=size_bytes,
        sha256=sha256_hex,
        clamav_status=clamav_status,
        warnings=tuple(warnings),
    )


async def scan_uploaded_file_async(
    data: bytes,
    *,
    filename: Optional[str] = None,
    declared_mime: Optional[str] = None,
    allowed_mimes: Optional[Iterable[str]] = None,
    max_bytes: Optional[int] = None,
    max_image_pixels: int = 50_000_000,
    enable_clamav: bool = True,
) -> FileScanResult:
    """Run ``scan_uploaded_file`` off the asyncio event loop."""
    return await asyncio.to_thread(
        scan_uploaded_file,
        data,
        filename=filename,
        declared_mime=declared_mime,
        allowed_mimes=allowed_mimes,
        max_bytes=max_bytes,
        max_image_pixels=max_image_pixels,
        enable_clamav=enable_clamav,
    )
