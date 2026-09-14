import logging
import httpx
from typing import Optional, Type, TypeVar, Any, Dict, Union
from pydantic import BaseModel
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type, before_sleep_log

from .exceptions import (
    InternalServiceError,
    ServiceUnavailableError,
    ServiceTimeoutError,
    AuthenticationError,
    NotFoundError,
    ValidationError
)

# Generic type for Pydantic models
T = TypeVar("T", bound=BaseModel)

logger = logging.getLogger(__name__)

class BaseInternalClient:
    """
    Resilient Async HTTP Client for Internal Microservices.
    
    Features:
    - Automatic retries on network errors and 5xx responses.
    - Connection pooling (via httpx.AsyncClient).
    - Pydantic model serialization/deserialization.
    - Standardized exception mapping.
    """

    def __init__(
        self,
        base_url: str,
        service_name: str,
        api_key: Optional[str] = None,
        timeout: float = 10.0,
        verify_ssl: Optional[bool] = None,
        mtls_enabled: bool = True,
    ):
        """
        verify_ssl semantics (internal mesh, see smsly_core.mtls.verify_for_url):
          - None (default): auto — :8443 targets get the SVID client context
            (direct mTLS), other https:// targets get the mesh context
            (system CA, no hostname check — Traefik edge termination),
            http:// targets skip verification (plain mesh).
          - True/False: explicit override (False only for dev plain HTTP).
        mtls_enabled=False forces the mesh context for https targets
        (no SVID client cert).
        """
        self.base_url = base_url.rstrip("/")
        self.service_name = service_name
        self.timeout = timeout

        self._headers = {
            "User-Agent": f"SMSLY-Internal-Client/{service_name}",
            "Accept": "application/json",
        }
        if api_key:
            self._headers["X-Internal-Secret"] = api_key

        verify: Any = verify_ssl
        if verify_ssl is None:
            try:
                from smsly_core.mtls import verify_for_url, build_tag
                verify = verify_for_url(self.base_url, prefer_mtls=mtls_enabled)
                self._ctx_tag: str = build_tag()
            except Exception as e:
                logger.warning(
                    "mesh_verify_unavailable_legacy service=%s error=%s",
                    service_name, e,
                )
                verify = self.base_url.startswith("https://")
                self._ctx_tag = ""
        else:
            self._ctx_tag = ""

        self.client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=timeout,
            headers=self._headers,
            verify=verify
        )

    async def _refresh_if_stale(self, force: bool = False) -> bool:
        """Rebuild the underlying client when the SVID rotated/expires.

        Returns True if the client was rebuilt. Never raises — refresh
        failures keep the existing client (better a stale attempt than
        no client at all; errors still surface per-request).
        """
        try:
            from smsly_core.mtls import is_stale, verify_for_url, build_tag
        except Exception:
            return False
        try:
            if not force and not is_stale(getattr(self, "_ctx_tag", None)):
                return False
            try:
                await self.client.aclose()
            except Exception:
                pass
            self.client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=self.timeout,
                headers=self._headers,
                verify=verify_for_url(self.base_url),
            )
            self._ctx_tag = build_tag()
            logger.info("mtls_client_refreshed service=%s", self.service_name)
            return True
        except Exception as e:
            logger.warning(
                "mtls_refresh_failed service=%s error=%s", self.service_name, e,
            )
            return False

    async def aclose(self):
        """Close the underlying HTTP client."""
        await self.client.aclose()

    def _map_exception(self, exc: Exception) -> Exception:
        """Map httpx exceptions to internal service exceptions."""
        if isinstance(exc, httpx.TimeoutException):
            return ServiceTimeoutError("Request timed out", service=self.service_name)
        if isinstance(exc, (httpx.ConnectError, httpx.NetworkError)):
            return ServiceUnavailableError(f"Failed to connect: {str(exc)}", service=self.service_name)
        if isinstance(exc, httpx.HTTPStatusError):
            status = exc.response.status_code
            text = exc.response.text
            if status == 401:
                return AuthenticationError("Unauthorized", service=self.service_name, status_code=status)
            if status == 403:
                return AuthenticationError("Forbidden", service=self.service_name, status_code=status)
            if status == 404:
                return NotFoundError("Resource not found", service=self.service_name, status_code=status)
            if status == 422:
                return ValidationError("Validation error", service=self.service_name, status_code=status, details=text)
            if status >= 500:
                return ServiceUnavailableError("Server error", service=self.service_name, status_code=status, details=text)
            
            return InternalServiceError(f"HTTP {status} Error", service=self.service_name, status_code=status, details=text)
        
        return InternalServiceError(f"Unexpected error: {str(exc)}", service=self.service_name)

    @retry(
        retry=retry_if_exception_type((ServiceUnavailableError, ServiceTimeoutError)),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        before_sleep=before_sleep_log(logger, logging.WARNING),
        reraise=True
    )
    async def _request(
        self, 
        method: str, 
        path: str, 
        response_model: Optional[Type[T]] = None,
        **kwargs
    ) -> Union[T, Dict[str, Any], None]:
        """Execute request with retries and error handling."""
        # Proactive SVID refresh: rotation/expiry is predictable, so rebuild
        # before the handshake fails (cheap — staleness probe is cached).
        await self._refresh_if_stale()
        try:
            response = await self.client.request(method, path, **kwargs)
            response.raise_for_status()
            
            if response.status_code == 204:
                return None
            
            if response_model:
                return response_model.model_validate(response.json())
            
            return response.json()
            
        except httpx.HTTPError as e:
            # Reactive refresh: an expiry mid-flight (rotation landed between
            # the proactive check and the handshake) gets exactly one rebuild
            # + retry; anything else maps to domain errors as before.
            try:
                from smsly_core.mtls import is_cert_expired_error
                expired = is_cert_expired_error(e)
            except Exception:
                expired = False
            if expired and await self._refresh_if_stale(force=True):
                try:
                    response = await self.client.request(method, path, **kwargs)
                    response.raise_for_status()
                    if response.status_code == 204:
                        return None
                    if response_model:
                        return response_model.model_validate(response.json())
                    return response.json()
                except httpx.HTTPError as e2:
                    raise self._map_exception(e2)
            raise self._map_exception(e)
        except Exception as e:
            logger.exception(f"Unexpected internal client error for {self.service_name}")
            raise InternalServiceError(str(e), service=self.service_name)

    async def get(self, path: str, params: Optional[Dict] = None, response_model: Optional[Type[T]] = None) -> Union[T, Dict, None]:
        return await self._request("GET", path, params=params, response_model=response_model)

    async def post(self, path: str, json: Any = None, response_model: Optional[Type[T]] = None) -> Union[T, Dict, None]:
        return await self._request("POST", path, json=json, response_model=response_model)

    async def put(self, path: str, json: Any = None, response_model: Optional[Type[T]] = None) -> Union[T, Dict, None]:
        return await self._request("PUT", path, json=json, response_model=response_model)

    async def delete(self, path: str, response_model: Optional[Type[T]] = None) -> Union[T, Dict, None]:
        return await self._request("DELETE", path, response_model=response_model)
