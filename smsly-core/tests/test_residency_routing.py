"""Comprehensive unit tests for EU GDPR data residency routing across DB, Redis, and S3."""
from __future__ import annotations

import os
import pytest
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
from sqlalchemy import Column, Integer, String, select
from sqlalchemy.ext.asyncio import AsyncSession

from smsly_core.residency import (
    DATA_REGION_HEADER,
    DataRegionMiddleware,
    DataResidencyError,
    REGION_DEFAULT,
    REGION_EU,
    REGION_US,
    blind_index_email,
    data_region_context,
    extract_region_from_identifier,
    get_data_region,
    is_eu_country,
    normalize_data_region,
    resolve_region_for_country,
)
from smsly_core.database import (
    Base,
    close_all_engines,
    create_async_engine,
    create_tables_all_regions,
    get_db,
    get_engine,
    get_session,
)
from smsly_core.redis_router import RegionalRedisRouter
from smsly_core.s3_storage import RegionalS3Router, S3Config


class _SampleRecord(Base):
    __tablename__ = "residency_test_records"
    id = Column(Integer, primary_key=True, autoincrement=True)
    label = Column(String(64), nullable=False)


class _FakeRedis:
    def __init__(self, name: str):
        self.name = name
        self.store: dict[str, str] = {}
        self.closed = False

    async def ping(self):
        return True

    async def set(self, k: str, v: str):
        self.store[k] = v

    async def get(self, k: str):
        return self.store.get(k)

    async def aclose(self):
        self.closed = True


def test_region_normalization_and_eu_country_classification():
    assert normalize_data_region("eu-central-1") == REGION_EU
    assert normalize_data_region("EU-WEST") == REGION_EU
    assert normalize_data_region("gdpr") == REGION_EU
    assert normalize_data_region("us-east-1") == REGION_US
    assert normalize_data_region(None) == REGION_DEFAULT

    assert is_eu_country("DE") is True
    assert is_eu_country("fr") is True
    assert is_eu_country("NO") is True
    assert is_eu_country("GB", include_uk_ch=True) is True
    assert is_eu_country("GB", include_uk_ch=False) is False
    assert is_eu_country("US") is False
    assert resolve_region_for_country("DE") == REGION_EU
    assert resolve_region_for_country("US") == REGION_DEFAULT


def test_blind_index_and_identifier_prefix_extraction():
    idx1 = blind_index_email("  Alice@Example.DE ", pepper="test-pepper")
    idx2 = blind_index_email("alice@example.de", pepper="test-pepper")
    assert idx1 == idx2
    assert idx1.startswith("email_hmac:")
    assert "alice" not in idx1

    assert extract_region_from_identifier("tlk_live_eu_abc123") == REGION_EU
    assert extract_region_from_identifier("msg_eu_01JXYZ") == REGION_EU
    assert extract_region_from_identifier("org_us_12345") == REGION_US
    assert extract_region_from_identifier("org_12345") is None


@pytest.mark.asyncio
async def test_multi_region_sqlalchemy_routing_isolates_eu_and_default_dbs(tmp_path):
    default_db = f"sqlite+aiosqlite:///{(tmp_path / 'default.db').as_posix()}"
    eu_db = f"sqlite+aiosqlite:///{(tmp_path / 'eu.db').as_posix()}"
    try:
        create_async_engine(default_db, eu_database_url=eu_db, strict_eu=True)
        await create_tables_all_regions(Base.metadata)

        with data_region_context(REGION_DEFAULT):
            async with get_session() as s:
                s.add(_SampleRecord(label="us-tenant-row"))

        with data_region_context(REGION_EU):
            async with get_session() as s:
                s.add(_SampleRecord(label="eu-gdpr-row"))

        async with get_session(region=REGION_DEFAULT) as s:
            default_rows = [r.label for r in (await s.execute(select(_SampleRecord))).scalars().all()]
        async with get_session(region=REGION_EU) as s:
            eu_rows = [r.label for r in (await s.execute(select(_SampleRecord))).scalars().all()]

        assert default_rows == ["us-tenant-row"]
        assert eu_rows == ["eu-gdpr-row"]
    finally:
        await close_all_engines()


@pytest.mark.asyncio
async def test_multi_region_db_fails_closed_when_strict_eu_and_eu_db_missing(tmp_path):
    default_db = f"sqlite+aiosqlite:///{(tmp_path / 'default_only.db').as_posix()}"
    try:
        create_async_engine(default_db, strict_eu=True)
        with data_region_context(REGION_EU):
            with pytest.raises(DataResidencyError) as exc_info:
                get_engine()
            assert exc_info.value.data_region == REGION_EU
            assert exc_info.value.store_type == "database"
    finally:
        await close_all_engines()


@pytest.mark.asyncio
async def test_regional_redis_router_isolates_and_fails_closed():
    router = RegionalRedisRouter(strict_eu=True)
    default_r = _FakeRedis("default")
    eu_r = _FakeRedis("eu")
    router.bind_client(REGION_DEFAULT, default_r)
    router.bind_client(REGION_EU, eu_r)

    async with data_region_context(REGION_EU):
        client = await router.get_client()
        await client.set("otp:user1", "999999")

    async with data_region_context(REGION_DEFAULT):
        client = await router.get_client()
        await client.set("otp:user2", "111111")

    assert eu_r.store == {"otp:user1": "999999"}
    assert default_r.store == {"otp:user2": "111111"}

    strict_missing_eu = RegionalRedisRouter(strict_eu=True)
    strict_missing_eu.bind_client(REGION_DEFAULT, default_r)
    async with data_region_context(REGION_EU):
        with pytest.raises(DataResidencyError) as exc_info:
            await strict_missing_eu.get_client()
        assert exc_info.value.store_type == "redis"

    await router.close_all()
    assert eu_r.closed is True


def test_regional_s3_config_and_router_isolation(monkeypatch):
    monkeypatch.setenv("S3_BUCKET", "trulay-us-media")
    monkeypatch.setenv("S3_REGION", "us-east-1")
    monkeypatch.setenv("S3_BUCKET_EU", "trulay-eu-gdpr-media")
    monkeypatch.setenv("S3_REGION_EU", "eu-central-1")
    monkeypatch.setenv("S3_KMS_KEY_ID_EU", "arn:aws:kms:eu-central-1:1111:key/eu-key")
    monkeypatch.setenv("EU_RESIDENCY_STRICT", "true")

    router = RegionalS3Router()
    us_cfg = router.get_adapter(REGION_DEFAULT).config
    eu_cfg = router.get_adapter(REGION_EU).config

    assert us_cfg.bucket == "trulay-us-media"
    assert us_cfg.region == "us-east-1"
    assert eu_cfg.bucket == "trulay-eu-gdpr-media"
    assert eu_cfg.region == "eu-central-1"
    assert eu_cfg.kms_key_id == "arn:aws:kms:eu-central-1:1111:key/eu-key"
    assert eu_cfg.sse == "aws:kms"

    monkeypatch.delenv("S3_BUCKET_EU")
    with pytest.raises(DataResidencyError) as exc_info:
        S3Config.from_env(data_region=REGION_EU, strict_eu=True)
    assert exc_info.value.store_type == "s3"


def test_asgi_middleware_binds_context_and_returns_503_on_strict_residency_error(tmp_path):
    app = FastAPI()
    app.add_middleware(DataRegionMiddleware)

    @app.get("/region")
    async def check_region():
        return {"region": get_data_region()}

    @app.get("/strict-eu-db")
    async def strict_eu_db():
        # Simulate strict residency error raised inside a handler
        raise DataResidencyError("EU DB missing", data_region=REGION_EU, store_type="database")

    client = TestClient(app)
    r_eu = client.get("/region", headers={DATA_REGION_HEADER: "eu-central-1"})
    assert r_eu.status_code == 200
    assert r_eu.json() == {"region": "eu"}
    assert r_eu.headers.get("x-trulay-data-region") == "eu"

    r_default = client.get("/region")
    assert r_default.status_code == 200
    assert r_default.json() == {"region": "default"}

    r_fail = client.get("/strict-eu-db", headers={DATA_REGION_HEADER: "eu"})
    assert r_fail.status_code == 503
    assert r_fail.json()["error"] == "regional_data_store_unavailable"
    assert r_fail.json()["data_region"] == "eu"


@pytest.mark.asyncio
async def test_dynamic_admin_custom_regions_route_db_redis_and_s3(tmp_path, monkeypatch):
    from smsly_core.residency import region_env_suffix

    assert normalize_data_region("uk") == "uk"
    assert normalize_data_region("AP-SG") == "ap-sg"
    assert region_env_suffix("ap-sg") == "AP_SG"
    assert region_env_suffix("default") == ""
    assert extract_region_from_identifier("org_uk_9988") == "uk"

    default_db = f"sqlite+aiosqlite:///{(tmp_path / 'def_dyn.db').as_posix()}"
    uk_db = f"sqlite+aiosqlite:///{(tmp_path / 'uk_dyn.db').as_posix()}"
    monkeypatch.setenv("DATABASE_URL_UK", uk_db)
    monkeypatch.setenv("S3_BUCKET_AP_SG", "trulay-ap-sg-media")
    monkeypatch.setenv("S3_REGION_AP_SG", "ap-southeast-1")

    try:
        create_async_engine(default_db, strict_eu=True)
        await create_tables_all_regions(Base.metadata, regions=("default", "uk"))

        with data_region_context("uk"):
            async with get_session() as s:
                s.add(_SampleRecord(label="uk-sovereign-row"))

        async with get_session(region="uk") as s:
            uk_rows = [r.label for r in (await s.execute(select(_SampleRecord))).scalars().all()]
        async with get_session(region=REGION_DEFAULT) as s:
            def_rows = [r.label for r in (await s.execute(select(_SampleRecord))).scalars().all()]

        assert uk_rows == ["uk-sovereign-row"]
        assert def_rows == []
    finally:
        await close_all_engines()

    sg_cfg = S3Config.from_env(data_region="ap-sg")
    assert sg_cfg.bucket == "trulay-ap-sg-media"
    assert sg_cfg.region == "ap-southeast-1"


@pytest.mark.asyncio
async def test_custom_strict_region_fails_closed_for_db_and_redis(tmp_path, monkeypatch):
    from smsly_core.residency import is_region_strict

    monkeypatch.setenv("DATA_RESIDENCY_STRICT_REGIONS", "ap-sg,ch")
    assert is_region_strict("ap-sg") is True
    assert is_region_strict("ch") is True
    assert is_region_strict("us") is False

    default_db = f"sqlite+aiosqlite:///{(tmp_path / 'def_strict.db').as_posix()}"
    try:
        create_async_engine(default_db)
        with data_region_context("ap-sg"):
            with pytest.raises(DataResidencyError) as db_exc:
                get_engine()
            assert db_exc.value.data_region == "ap-sg"
            assert db_exc.value.store_type == "database"
    finally:
        await close_all_engines()

    router = RegionalRedisRouter()
    router.bind_client(REGION_DEFAULT, _FakeRedis("default"))
    async with data_region_context("ap-sg"):
        with pytest.raises(DataResidencyError) as redis_exc:
            await router.get_client()
        assert redis_exc.value.data_region == "ap-sg"
        assert redis_exc.value.store_type == "redis"
