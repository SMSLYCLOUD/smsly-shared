"""
CORS Middleware Helper
=======================
Standardized CORS configuration for all services.
"""

import os
from typing import List, Optional
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import structlog

logger = structlog.get_logger(__name__)


def setup_cors(
    app: FastAPI,
    origins: Optional[List[str]] = None,
    env_var: str = "CORS_ORIGINS",
    allow_credentials: bool = True,
    allow_methods: Optional[List[str]] = None,
    allow_headers: Optional[List[str]] = None,
) -> None:
    """
    Configure CORS middleware with secure defaults.
    
    Args:
        app: FastAPI application instance
        origins: Explicit list of allowed origins (overrides env var)
        env_var: Environment variable name for origins (default: CORS_ORIGINS)
        allow_credentials: Allow cookies/auth headers (default: True)
        allow_methods: Allowed HTTP methods (default: standard REST methods)
        allow_headers: Allowed headers (default: common auth headers)
    
    Example:
        from smsly_core.middleware import setup_cors
        
        app = FastAPI()
        setup_cors(app)  # Uses CORS_ORIGINS env var
        
        # Or with explicit origins:
        setup_cors(app, origins=["https://app.smsly.cloud"])
    """
    # Get origins from explicit list or environment
    if origins is None:
        origins_str = os.getenv(env_var, "http://localhost:3000,http://127.0.0.1:3000")
        origins = [o.strip() for o in origins_str.split(",") if o.strip()]
    
    # Validate: no wildcards in production
    if "*" in origins:
        logger.warning(
            "CORS wildcard detected! This is insecure in production.",
            origins=origins,
        )
    
    # Default methods and headers
    if allow_methods is None:
        allow_methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
    
    if allow_headers is None:
        allow_headers = [
            "Authorization",
            "Content-Type",
            "X-Request-ID",
            "X-Smsly-Key-Id",
            "X-Smsly-Signature",
        ]
    
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=allow_credentials,
        allow_methods=allow_methods,
        allow_headers=allow_headers,
    )
    
    logger.info("CORS configured", origins_count=len(origins))
