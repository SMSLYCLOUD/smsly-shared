"""
Unified S3-compatible object storage adapter for SMSLY / TRULAY services.

Supports AWS S3 (IAM roles/IRSA or static credentials), Cloudflare R2,
DigitalOcean Spaces, MinIO, and GCS S3-interop via canonical ``S3_*`` vars
as well as ``AWS_*``, ``MINIO_*``, and optional service-prefixed aliases.

All ``boto3`` / ``botocore`` imports are deferred inside adapter methods so
pure configuration checks never fail when boto3 is absent in lightweight tests.
"""
from __future__ import annotations

import asyncio
import os
import re
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple
from urllib.parse import quote

from smsly_core.residency import (
    DataResidencyError,
    REGION_DEFAULT,
    REGION_EU,
    REGION_US,
    get_data_region,
    is_eu_residency_strict,
    is_region_strict,
    normalize_data_region,
    region_env_suffix,
)

_REGION_CACHE_KEY_RE = re.compile(r"^[a-z][a-z0-9-]{1,31}$")


def _format_content_disposition(filename: str, *, inline: bool = False) -> str:
    """Build an injection-safe RFC 6266 / RFC 5987 Content-Disposition header value."""
    disposition = "inline" if inline else "attachment"
    cleaned = re.sub(r"[\x00-\x1f\x7f/\\]+", "", str(filename or "")).strip()
    cleaned = cleaned.replace('"', "").replace(";", "")
    if not cleaned:
        cleaned = "download"
    ascii_fallback = re.sub(r"[^A-Za-z0-9._ -]+", "_", cleaned).strip() or "download"
    encoded_utf8 = quote(cleaned, safe="")
    return f'{disposition}; filename="{ascii_fallback}"; filename*=UTF-8\'\'{encoded_utf8}'


def _env_first(*names: str, default: str = "") -> str:
    for name in names:
        if not name:
            continue
        val = os.environ.get(name)
        if val is not None and val.strip() != "":
            return val.strip()
    return default


def _parse_bool(val: str, default: bool) -> bool:
    norm = val.strip().lower()
    if norm in {"1", "true", "yes", "on"}:
        return True
    if norm in {"0", "false", "no", "off"}:
        return False
    return default


@dataclass(frozen=True)
class S3Config:
    """Resolved S3 / S3-compatible bucket configuration."""

    enabled: bool
    bucket: str = ""
    region: str = "us-east-1"
    endpoint_url: Optional[str] = None
    access_key_id: Optional[str] = None
    secret_access_key: Optional[str] = None
    session_token: Optional[str] = None
    addressing_style: str = "auto"
    signature_version: str = "s3v4"
    sse: Optional[str] = None
    kms_key_id: Optional[str] = None
    public_url: Optional[str] = None
    key_prefix: str = ""
    use_ssl: bool = True

    @classmethod
    def from_env(
        cls,
        service_prefix: Optional[str] = None,
        data_region: Optional[str] = None,
        *,
        strict_eu: Optional[bool] = None,
    ) -> "S3Config":
        """Resolve S3 config with optional ``SERVICE_`` prefix, regional overrides, and AWS/MINIO aliases.

        When ``data_region == "eu"`` (e.g. EU GDPR tenants), checks regional vars first:
        ``{PFX}S3_BUCKET_EU``, ``S3_BUCKET_EU``, ``EU_S3_BUCKET``, ``S3_REGION_EU``
        (defaulting to ``eu-central-1``), ``S3_ENDPOINT_URL_EU``, ``S3_KMS_KEY_ID_EU``, etc.
        Fails closed with ``DataResidencyError`` when ``strict_eu`` / ``EU_RESIDENCY_STRICT``
        is active and no EU bucket is configured.
        """
        pfx = f"{service_prefix.strip('_').upper()}_" if service_prefix else ""
        norm_region = normalize_data_region(data_region) if data_region is not None else REGION_DEFAULT
        strict = strict_eu if strict_eu is not None else is_eu_residency_strict()

        if norm_region != REGION_DEFAULT:
            r_tag = region_env_suffix(norm_region)  # e.g. "EU", "US", "UK", "AP_SG"
            reg_bucket = _env_first(
                f"{pfx}S3_BUCKET_{r_tag}" if pfx else "",
                f"{pfx}{r_tag}_S3_BUCKET" if pfx else "",
                f"S3_BUCKET_{r_tag}",
                f"{r_tag}_S3_BUCKET",
                f"AWS_STORAGE_BUCKET_NAME_{r_tag}",
            )
            is_strict = (
                (norm_region == REGION_EU and strict)
                or (norm_region != REGION_EU and is_region_strict(norm_region))
            )
            if not reg_bucket:
                if is_strict:
                    raise DataResidencyError(
                        f"Regional object storage bucket (S3_BUCKET_{r_tag}) is required under strict residency enforcement.",
                        data_region=norm_region,
                        store_type="s3",
                    )
            else:
                default_aws_region = "eu-central-1" if norm_region == REGION_EU else "us-east-1"
                reg_aws_region = _env_first(
                    f"{pfx}S3_REGION_{r_tag}" if pfx else "",
                    f"S3_REGION_{r_tag}",
                    f"{r_tag}_S3_REGION",
                    default=default_aws_region,
                )
                reg_use_ssl = _parse_bool(
                    _env_first(f"S3_USE_SSL_{r_tag}", "S3_USE_SSL", "AWS_S3_USE_SSL", default="true"),
                    True,
                )
                # Never inherit global/default endpoint across regional boundaries
                raw_ep = _env_first(
                    f"{pfx}S3_ENDPOINT_URL_{r_tag}" if pfx else "",
                    f"S3_ENDPOINT_URL_{r_tag}",
                    f"{r_tag}_S3_ENDPOINT_URL",
                )
                ep_url: Optional[str] = None
                if raw_ep:
                    if raw_ep.startswith(("http://", "https://")):
                        ep_url = raw_ep.rstrip("/")
                        reg_use_ssl = ep_url.startswith("https://")
                    else:
                        ep_url = f"{'https' if reg_use_ssl else 'http'}://{raw_ep.rstrip('/')}"
                reg_access_only = _env_first(
                    f"S3_ACCESS_KEY_ID_{r_tag}",
                    f"{r_tag}_S3_ACCESS_KEY_ID",
                )
                reg_access = reg_access_only or _env_first(
                    f"{pfx}S3_ACCESS_KEY_ID" if pfx else "",
                    "S3_ACCESS_KEY_ID",
                    "AWS_ACCESS_KEY_ID",
                ) or None
                reg_secret = _env_first(
                    f"S3_SECRET_ACCESS_KEY_{r_tag}",
                    f"{r_tag}_S3_SECRET_ACCESS_KEY",
                    f"{pfx}S3_SECRET_ACCESS_KEY" if pfx else "",
                    "S3_SECRET_ACCESS_KEY",
                    "AWS_SECRET_ACCESS_KEY",
                ) or None
                reg_session_token = _env_first(
                    f"S3_SESSION_TOKEN_{r_tag}",
                    f"{r_tag}_S3_SESSION_TOKEN",
                ) or (None if reg_access_only else (_env_first("S3_SESSION_TOKEN", "AWS_SESSION_TOKEN") or None))
                # Never inherit cross-region KMS key ARNs into regional buckets
                reg_kms = _env_first(
                    f"{pfx}S3_KMS_KEY_ID_{r_tag}" if pfx else "",
                    f"S3_KMS_KEY_ID_{r_tag}",
                    f"{r_tag}_S3_KMS_KEY_ID",
                ) or None
                global_sse = _env_first("S3_SSE", "AWS_S3_ENCRYPTION")
                if global_sse.lower() == "aws:kms" and not reg_kms:
                    global_sse = ""
                reg_sse = _env_first(
                    f"{pfx}S3_SSE_{r_tag}" if pfx else "",
                    f"S3_SSE_{r_tag}",
                    f"{r_tag}_S3_SSE",
                    default="aws:kms" if reg_kms else global_sse,
                ) or None
                reg_pub = _env_first(
                    f"{pfx}S3_PUBLIC_URL_{r_tag}" if pfx else "",
                    f"S3_PUBLIC_URL_{r_tag}",
                    f"{r_tag}_S3_PUBLIC_URL",
                ) or None
                if reg_pub and not reg_pub.startswith(("http://", "https://")):
                    reg_pub = f"https://{reg_pub.rstrip('/')}"
                elif reg_pub:
                    reg_pub = reg_pub.rstrip("/")
                reg_prefix = _env_first(
                    f"{pfx}S3_KEY_PREFIX_{r_tag}" if pfx else "",
                    f"S3_KEY_PREFIX_{r_tag}",
                    f"{pfx}S3_KEY_PREFIX" if pfx else "",
                    "S3_KEY_PREFIX",
                    default="",
                ).strip("/")
                default_style = "path" if ep_url else "auto"
                reg_style = _env_first(
                    f"S3_ADDRESSING_STYLE_{r_tag}",
                    "S3_ADDRESSING_STYLE",
                    "AWS_S3_ADDRESSING_STYLE",
                    default=default_style,
                ).lower()
                return cls(
                    enabled=True,
                    bucket=reg_bucket,
                    region=reg_aws_region,
                    endpoint_url=ep_url,
                    access_key_id=reg_access,
                    secret_access_key=reg_secret,
                    session_token=reg_session_token,
                    addressing_style=reg_style,
                    signature_version=_env_first("S3_SIGNATURE_VERSION", "AWS_S3_SIGNATURE_VERSION", default="s3v4"),
                    sse=reg_sse,
                    kms_key_id=reg_kms,
                    public_url=reg_pub,
                    key_prefix=reg_prefix,
                    use_ssl=reg_use_ssl,
                )

        bucket = _env_first(
            f"{pfx}S3_BUCKET" if pfx else "",
            "S3_BUCKET",
            "AWS_STORAGE_BUCKET_NAME",
            "AWS_S3_BUCKET_NAME",
            "S3_BUCKET_NAME",
            "MINIO_BUCKET",
        )
        region = _env_first(
            f"{pfx}S3_REGION" if pfx else "",
            "S3_REGION",
            "AWS_S3_REGION_NAME",
            "AWS_REGION",
            "AWS_DEFAULT_REGION",
            default="us-east-1",
        )

        use_ssl_raw = _env_first(
            f"{pfx}S3_USE_SSL" if pfx else "",
            "S3_USE_SSL",
            "AWS_S3_USE_SSL",
            "MINIO_SECURE",
            default="true",
        )
        use_ssl = _parse_bool(use_ssl_raw, True)

        raw_endpoint = _env_first(
            f"{pfx}S3_ENDPOINT_URL" if pfx else "",
            f"{pfx}S3_ENDPOINT" if pfx else "",
            "S3_ENDPOINT_URL",
            "AWS_S3_ENDPOINT_URL",
            "S3_ENDPOINT",
            "MINIO_ENDPOINT",
        )
        endpoint_url: Optional[str] = None
        if raw_endpoint:
            if raw_endpoint.startswith(("http://", "https://")):
                endpoint_url = raw_endpoint.rstrip("/")
                use_ssl = endpoint_url.startswith("https://")
            else:
                scheme = "https" if use_ssl else "http"
                endpoint_url = f"{scheme}://{raw_endpoint.rstrip('/')}"

        access_key_id = _env_first(
            f"{pfx}S3_ACCESS_KEY_ID" if pfx else "",
            f"{pfx}S3_ACCESS_KEY" if pfx else "",
            "S3_ACCESS_KEY_ID",
            "S3_ACCESS_KEY",
            "AWS_ACCESS_KEY_ID",
            "MINIO_ACCESS_KEY",
            "MINIO_ROOT_USER",
        ) or None

        secret_access_key = _env_first(
            f"{pfx}S3_SECRET_ACCESS_KEY" if pfx else "",
            f"{pfx}S3_SECRET_KEY" if pfx else "",
            "S3_SECRET_ACCESS_KEY",
            "S3_SECRET_KEY",
            "AWS_SECRET_ACCESS_KEY",
            "MINIO_SECRET_KEY",
            "MINIO_ROOT_PASSWORD",
        ) or None

        session_token = _env_first(
            "S3_SESSION_TOKEN",
            "AWS_SESSION_TOKEN",
        ) or None

        explicit_flag = _env_first(
            f"{pfx}USE_S3" if pfx else "",
            "USE_S3",
        )
        if explicit_flag:
            enabled = _parse_bool(explicit_flag, False)
        else:
            # Explicit S3_BUCKET / AWS_STORAGE_BUCKET_NAME enables S3 cleanly; otherwise disabled
            enabled = bool(
                _env_first(
                    f"{pfx}S3_BUCKET" if pfx else "",
                    "S3_BUCKET",
                    "AWS_STORAGE_BUCKET_NAME",
                    "AWS_S3_BUCKET_NAME",
                )
            )

        default_style = "path" if endpoint_url else "auto"
        addressing_style = _env_first(
            f"{pfx}S3_ADDRESSING_STYLE" if pfx else "",
            "S3_ADDRESSING_STYLE",
            "AWS_S3_ADDRESSING_STYLE",
            default=default_style,
        ).lower()

        signature_version = _env_first(
            "S3_SIGNATURE_VERSION",
            "AWS_S3_SIGNATURE_VERSION",
            default="s3v4",
        )
        sse = _env_first("S3_SSE", "AWS_S3_ENCRYPTION") or None
        kms_key_id = _env_first("S3_KMS_KEY_ID", "AWS_KMS_KEY_ID") or None
        public_url = _env_first(
            f"{pfx}S3_PUBLIC_URL" if pfx else "",
            "S3_PUBLIC_URL",
            "AWS_S3_CUSTOM_DOMAIN",
        ) or None
        if public_url and not public_url.startswith(("http://", "https://")):
            public_url = f"https://{public_url.rstrip('/')}"
        elif public_url:
            public_url = public_url.rstrip("/")

        key_prefix = _env_first(
            f"{pfx}S3_KEY_PREFIX" if pfx else "",
            "S3_KEY_PREFIX",
            default="",
        ).strip("/")

        return cls(
            enabled=enabled,
            bucket=bucket,
            region=region,
            endpoint_url=endpoint_url,
            access_key_id=access_key_id,
            secret_access_key=secret_access_key,
            session_token=session_token,
            addressing_style=addressing_style,
            signature_version=signature_version,
            sse=sse,
            kms_key_id=kms_key_id,
            public_url=public_url,
            key_prefix=key_prefix,
            use_ssl=use_ssl,
        )


class S3StorageAdapter:
    """Sync and async boto3 wrapper for S3 and S3-compatible object stores."""

    def __init__(self, config: Optional[S3Config] = None, *, service_prefix: Optional[str] = None) -> None:
        self.config = config or S3Config.from_env(service_prefix=service_prefix)
        self._client: Any = None

    @property
    def enabled(self) -> bool:
        return bool(self.config.enabled and self.config.bucket)

    def normalize_key(self, key: str) -> str:
        if not key or not isinstance(key, str):
            raise ValueError("S3 object key must be a non-empty string")
        if "\x00" in key or "\\" in key:
            raise ValueError("S3 object key contains illegal characters")
        clean = key.lstrip("/")
        if not clean:
            raise ValueError("S3 object key must not be empty")
        if any(segment == ".." for segment in clean.split("/")):
            raise ValueError(f"S3 object key must not contain path traversal segments ('..'): {key!r}")
        if self.config.key_prefix and not clean.startswith(f"{self.config.key_prefix}/"):
            return f"{self.config.key_prefix}/{clean}"
        return clean

    def _get_client(self) -> Any:
        if self._client is not None:
            return self._client
        if not self.config.bucket:
            raise RuntimeError("S3 bucket is not configured")

        import boto3  # type: ignore
        from botocore.config import Config as BotoConfig  # type: ignore

        s3_cfg: Dict[str, Any] = {}
        if self.config.addressing_style in {"path", "virtual", "auto"}:
            s3_cfg["addressing_style"] = self.config.addressing_style

        boto_cfg = BotoConfig(
            signature_version=self.config.signature_version,
            s3=s3_cfg,
            retries={"max_attempts": 3, "mode": "standard"},
        )
        kwargs: Dict[str, Any] = {
            "service_name": "s3",
            "region_name": self.config.region,
            "config": boto_cfg,
            "use_ssl": self.config.use_ssl,
        }
        if self.config.endpoint_url:
            kwargs["endpoint_url"] = self.config.endpoint_url
        if self.config.access_key_id and self.config.secret_access_key:
            kwargs["aws_access_key_id"] = self.config.access_key_id
            kwargs["aws_secret_access_key"] = self.config.secret_access_key
            if self.config.session_token:
                kwargs["aws_session_token"] = self.config.session_token

        self._client = boto3.client(**kwargs)
        return self._client

    def upload_bytes(
        self,
        key: str,
        data: bytes,
        content_type: str = "application/octet-stream",
        *,
        metadata: Optional[Dict[str, str]] = None,
        cache_control: Optional[str] = None,
        inline: bool = False,
        filename: Optional[str] = None,
    ) -> Dict[str, Any]:
        client = self._get_client()
        full_key = self.normalize_key(key)
        put_kwargs: Dict[str, Any] = {
            "Bucket": self.config.bucket,
            "Key": full_key,
            "Body": data,
            "ContentType": content_type,
        }
        if metadata:
            put_kwargs["Metadata"] = {str(k): str(v) for k, v in metadata.items()}
        if cache_control:
            put_kwargs["CacheControl"] = cache_control
        if filename:
            put_kwargs["ContentDisposition"] = _format_content_disposition(filename, inline=inline)
        if self.config.kms_key_id:
            put_kwargs["ServerSideEncryption"] = "aws:kms"
            put_kwargs["SSEKMSKeyId"] = self.config.kms_key_id
        elif self.config.sse:
            put_kwargs["ServerSideEncryption"] = self.config.sse

        resp = client.put_object(**put_kwargs)
        return {
            "bucket": self.config.bucket,
            "key": full_key,
            "etag": str(resp.get("ETag", "")).strip('"'),
            "size_bytes": len(data),
            "content_type": content_type,
            "url": self.public_object_url(full_key),
        }

    def public_object_url(self, key: str) -> Optional[str]:
        full_key = self.normalize_key(key)
        if self.config.public_url:
            return f"{self.config.public_url}/{full_key}"
        return None

    def download_bytes(self, key: str) -> Tuple[bytes, str, Dict[str, Any]]:
        client = self._get_client()
        full_key = self.normalize_key(key)
        resp = client.get_object(Bucket=self.config.bucket, Key=full_key)
        stream = resp["Body"]
        try:
            body = stream.read()
        finally:
            close_fn = getattr(stream, "close", None)
            if callable(close_fn):
                close_fn()
        content_type = resp.get("ContentType") or "application/octet-stream"
        meta = dict(resp.get("Metadata") or {})
        return body, content_type, meta

    def delete_object(self, key: str) -> bool:
        client = self._get_client()
        full_key = self.normalize_key(key)
        client.delete_object(Bucket=self.config.bucket, Key=full_key)
        return True

    def exists(self, key: str) -> bool:
        client = self._get_client()
        full_key = self.normalize_key(key)
        try:
            client.head_object(Bucket=self.config.bucket, Key=full_key)
            return True
        except Exception as exc:
            resp = getattr(exc, "response", None)
            if isinstance(resp, dict):
                status = (resp.get("ResponseMetadata") or {}).get("HTTPStatusCode")
                code = str((resp.get("Error") or {}).get("Code", ""))
                if status == 404 or code in {"404", "NoSuchKey", "NotFound"}:
                    return False
            raise

    def generate_presigned_get_url(
        self,
        key: str,
        *,
        expires_in: int = 3600,
        filename: Optional[str] = None,
        inline: bool = False,
    ) -> str:
        client = self._get_client()
        full_key = self.normalize_key(key)
        params: Dict[str, Any] = {"Bucket": self.config.bucket, "Key": full_key}
        if filename:
            params["ResponseContentDisposition"] = _format_content_disposition(filename, inline=inline)
        return str(
            client.generate_presigned_url(
                ClientMethod="get_object",
                Params=params,
                ExpiresIn=expires_in,
            )
        )

    def generate_presigned_put_url(
        self,
        key: str,
        *,
        content_type: str,
        expires_in: int = 900,
    ) -> str:
        client = self._get_client()
        full_key = self.normalize_key(key)
        return str(
            client.generate_presigned_url(
                ClientMethod="put_object",
                Params={
                    "Bucket": self.config.bucket,
                    "Key": full_key,
                    "ContentType": content_type,
                },
                ExpiresIn=expires_in,
            )
        )

    def generate_presigned_post(
        self,
        key: str,
        *,
        content_type: str,
        max_bytes: int,
        expires_in: int = 900,
    ) -> Dict[str, Any]:
        client = self._get_client()
        full_key = self.normalize_key(key)
        return dict(
            client.generate_presigned_post(
                Bucket=self.config.bucket,
                Key=full_key,
                Fields={"Content-Type": content_type},
                Conditions=[
                    {"Content-Type": content_type},
                    ["content-length-range", 1, max_bytes],
                ],
                ExpiresIn=expires_in,
            )
        )

    async def upload_bytes_async(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return await asyncio.to_thread(self.upload_bytes, *args, **kwargs)

    async def download_bytes_async(self, *args: Any, **kwargs: Any) -> Tuple[bytes, str, Dict[str, Any]]:
        return await asyncio.to_thread(self.download_bytes, *args, **kwargs)

    async def delete_object_async(self, *args: Any, **kwargs: Any) -> bool:
        return await asyncio.to_thread(self.delete_object, *args, **kwargs)

    async def generate_presigned_get_url_async(self, *args: Any, **kwargs: Any) -> str:
        return await asyncio.to_thread(self.generate_presigned_get_url, *args, **kwargs)

    async def generate_presigned_post_async(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return await asyncio.to_thread(self.generate_presigned_post, *args, **kwargs)


class RegionalS3Router:
    """Routes S3/R2/MinIO object operations to regional buckets based on ContextVar data_region."""

    def __init__(
        self,
        *,
        service_prefix: Optional[str] = None,
        configs: Optional[Dict[str, S3Config]] = None,
        strict_eu: Optional[bool] = None,
        max_cached_regions: int = 32,
    ) -> None:
        self._service_prefix = service_prefix
        self._strict_eu_override = strict_eu
        self._max_cached_regions = max(4, int(max_cached_regions))
        self._adapters: OrderedDict[str, S3StorageAdapter] = OrderedDict()
        if configs:
            for region, cfg in configs.items():
                self.register_adapter(region, S3StorageAdapter(config=cfg))

    def _has_dedicated_regional_env(self, norm_region: str) -> bool:
        if norm_region == REGION_DEFAULT:
            return True
        pfx = f"{self._service_prefix.strip('_').upper()}_" if self._service_prefix else ""
        r_tag = region_env_suffix(norm_region)
        return bool(
            _env_first(
                f"{pfx}S3_BUCKET_{r_tag}" if pfx else "",
                f"{pfx}{r_tag}_S3_BUCKET" if pfx else "",
                f"S3_BUCKET_{r_tag}",
                f"{r_tag}_S3_BUCKET",
                f"AWS_STORAGE_BUCKET_NAME_{r_tag}",
            )
        )

    def _cache_adapter(self, key: str, adapter: S3StorageAdapter) -> None:
        if key in self._adapters:
            self._adapters.move_to_end(key)
            self._adapters[key] = adapter
            return
        while len(self._adapters) >= self._max_cached_regions:
            evict_key = next((k for k in self._adapters.keys() if k != REGION_DEFAULT), None)
            if evict_key is None:
                break
            self._adapters.pop(evict_key, None)
        self._adapters[key] = adapter

    def register_adapter(self, region: str, adapter: S3StorageAdapter) -> None:
        norm = normalize_data_region(region)
        if norm != REGION_DEFAULT and not _REGION_CACHE_KEY_RE.match(norm):
            raise ValueError(f"Invalid S3 residency region key: {region!r}")
        self._cache_adapter(norm, adapter)

    def get_adapter(self, region: Optional[str] = None) -> S3StorageAdapter:
        target = normalize_data_region(region if region is not None else get_data_region())
        if target in self._adapters:
            self._adapters.move_to_end(target)
            return self._adapters[target]

        if target != REGION_DEFAULT and not _REGION_CACHE_KEY_RE.match(target):
            target = REGION_DEFAULT

        # Resolve config (enforces strict residency fail-closed before any fallback)
        cfg = S3Config.from_env(
            service_prefix=self._service_prefix,
            data_region=target,
            strict_eu=self._strict_eu_override,
        )
        # Do not cache arbitrary unconfigured region headers under separate keys (anti-memory-DoS)
        if target != REGION_DEFAULT and not self._has_dedicated_regional_env(target):
            if REGION_DEFAULT not in self._adapters:
                self._cache_adapter(REGION_DEFAULT, S3StorageAdapter(config=cfg))
            return self._adapters[REGION_DEFAULT]

        adapter = S3StorageAdapter(config=cfg)
        self._cache_adapter(target, adapter)
        return adapter

    def upload_bytes(self, key: str, data: bytes, *args: Any, data_region: Optional[str] = None, **kwargs: Any) -> Dict[str, Any]:
        result = self.get_adapter(data_region).upload_bytes(key, data, *args, **kwargs)
        result["data_region"] = normalize_data_region(data_region if data_region is not None else get_data_region())
        return result

    def download_bytes(self, key: str, *, data_region: Optional[str] = None) -> Tuple[bytes, str, Dict[str, Any]]:
        return self.get_adapter(data_region).download_bytes(key)

    def delete_object(self, key: str, *, data_region: Optional[str] = None) -> bool:
        return self.get_adapter(data_region).delete_object(key)

    def generate_presigned_get_url(self, key: str, *args: Any, data_region: Optional[str] = None, **kwargs: Any) -> str:
        return self.get_adapter(data_region).generate_presigned_get_url(key, *args, **kwargs)

    def generate_presigned_put_url(self, key: str, *args: Any, data_region: Optional[str] = None, **kwargs: Any) -> str:
        return self.get_adapter(data_region).generate_presigned_put_url(key, *args, **kwargs)

    async def upload_bytes_async(self, key: str, data: bytes, *args: Any, data_region: Optional[str] = None, **kwargs: Any) -> Dict[str, Any]:
        region = normalize_data_region(data_region if data_region is not None else get_data_region())
        return await asyncio.to_thread(self.upload_bytes, key, data, *args, data_region=region, **kwargs)

    async def download_bytes_async(self, key: str, *, data_region: Optional[str] = None) -> Tuple[bytes, str, Dict[str, Any]]:
        region = normalize_data_region(data_region if data_region is not None else get_data_region())
        return await asyncio.to_thread(self.download_bytes, key, data_region=region)

    async def delete_object_async(self, key: str, *, data_region: Optional[str] = None) -> bool:
        region = normalize_data_region(data_region if data_region is not None else get_data_region())
        return await asyncio.to_thread(self.delete_object, key, data_region=region)

