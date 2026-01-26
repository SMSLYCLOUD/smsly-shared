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
        verify_ssl: bool = False # Internal traffic usually trusts self-signed or is plain HTTP
    ):
        self.base_url = base_url.rstrip("/")
        self.service_name = service_name
        self.timeout = timeout
        
        headers = {
            "User-Agent": f"SMSLY-Internal-Client/{service_name}",
            "Accept": "application/json",
        }
        if api_key:
            headers["X-Internal-Secret"] = api_key

        self.client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=timeout,
            headers=headers,
            verify=verify_ssl
        )

    async def aclose(self):
        """Close the underlying HTTP client."""
        await self.client.aclose()

    def _map_exception(self, exc: Exception) -> Exception:
        """Map httpx exceptions to internal service exceptions."""
        if isinstance(exc, httpx.TimeoutException):
            return ServiceTimeoutError(f"Request timed out", service=self.service_name)
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
        try:
            response = await self.client.request(method, path, **kwargs)
            response.raise_for_status()
            
            if response.status_code == 204:
                return None
            
            if response_model:
                return response_model.model_validate(response.json())
            
            return response.json()
            
        except httpx.HTTPError as e:
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
