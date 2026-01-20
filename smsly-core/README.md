# smsly-core

Shared core library for SMSLYCLOUD microservices. Provides unified implementations of common patterns:

- **Database**: AsyncSessionLocal, get_db dependency, connection pooling
- **Health**: Comprehensive health checks with component status
- **Adapters**: BaseProviderAdapter pattern with retry logic
- **Middleware**: CORS setup helper
- **Auth**: API key authentication utilities
- **Observability**: Structured logging and Prometheus metrics

## Installation

```bash
# From within another SMSLYCLOUD service
pip install -e ../shared/smsly-core
```

## Usage

```python
from smsly_core.database import get_db, create_async_engine
from smsly_core.health import create_health_router
from smsly_core.adapters import BaseProviderAdapter

# Database
app.include_router(create_health_router(engine, redis_client))

# In dependencies
async def my_endpoint(db: AsyncSession = Depends(get_db)):
    ...
```

## Development

```bash
pip install -e ".[dev]"
pytest tests/
```
