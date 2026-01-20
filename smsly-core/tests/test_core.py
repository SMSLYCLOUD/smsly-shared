"""
Unit Tests for smsly-core Library
==================================
Tests for core functionality.
"""

import pytest
from datetime import datetime, timezone, timedelta


class TestAPIKeys:
    """Tests for API key generation and validation."""
    
    def test_generate_api_key(self):
        """Should generate a valid API key."""
        from smsly_core.api_keys import generate_api_key
        
        full_key, prefix, key_hash = generate_api_key()
        
        assert full_key.startswith("sk_live_")
        assert prefix.startswith("sk_live_")
        assert len(key_hash) == 64  # SHA-256 hex
    
    def test_generate_test_key(self):
        """Should generate a test mode key."""
        from smsly_core.api_keys import generate_test_key
        
        full_key, prefix, key_hash = generate_test_key()
        
        assert full_key.startswith("sk_test_")
    
    def test_validate_api_key(self):
        """Should validate key against hash."""
        from smsly_core.api_keys import generate_api_key, validate_api_key
        
        full_key, _, key_hash = generate_api_key()
        
        assert validate_api_key(full_key, key_hash) is True
        assert validate_api_key("invalid_key", key_hash) is False
    
    def test_mask_api_key(self):
        """Should mask key for display."""
        from smsly_core.api_keys import mask_api_key
        
        masked = mask_api_key("sk_live_abcdefghij1234567890")
        
        assert "abcd" in masked
        assert "****" in masked
        assert "1234567890" not in masked


class TestMessaging:
    """Tests for message segmentation and encoding."""
    
    def test_detect_gsm7_encoding(self):
        """Should detect GSM-7 for basic ASCII."""
        from smsly_core.messaging import detect_encoding, EncodingType
        
        result = detect_encoding("Hello World!")
        assert result == EncodingType.GSM7
    
    def test_detect_ucs2_encoding(self):
        """Should detect UCS-2 for unicode."""
        from smsly_core.messaging import detect_encoding, EncodingType
        
        result = detect_encoding("Hello 你好")
        assert result == EncodingType.UCS2
    
    def test_calculate_segments_short(self):
        """Short message should be 1 segment."""
        from smsly_core.messaging import calculate_segments
        
        segments, encoding, chars = calculate_segments("Hello")
        
        assert segments == 1
    
    def test_calculate_segments_long(self):
        """Long message should be multiple segments."""
        from smsly_core.messaging import calculate_segments
        
        long_message = "A" * 200  # Over 160 char limit
        segments, encoding, chars = calculate_segments(long_message)
        
        assert segments == 2
        assert chars == 200
    
    def test_validate_e164(self):
        """Should validate E.164 format."""
        from smsly_core.messaging import validate_e164
        
        assert validate_e164("+14155551234") is True
        assert validate_e164("+1") is False
        assert validate_e164("4155551234") is False
    
    def test_normalize_phone(self):
        """Should normalize to E.164."""
        from smsly_core.messaging import normalize_phone
        
        assert normalize_phone("(415) 555-1234") == "+14155551234"
        assert normalize_phone("14155551234") == "+14155551234"


class TestOTP:
    """Tests for OTP generation and verification."""
    
    def test_generate_otp_numeric(self):
        """Should generate numeric OTP."""
        from smsly_core.otp import generate_otp
        
        otp = generate_otp(length=6)
        
        assert len(otp) == 6
        assert otp.isdigit()
    
    def test_generate_otp_alphanumeric(self):
        """Should generate alphanumeric OTP."""
        from smsly_core.otp import generate_otp
        
        otp = generate_otp(length=8, alphanumeric=True)
        
        assert len(otp) == 8
        # Should not contain confusing characters
        assert "0" not in otp
        assert "O" not in otp
        assert "1" not in otp
        assert "l" not in otp
    
    def test_hash_and_verify_otp(self):
        """Should hash and verify OTP."""
        from smsly_core.otp import generate_salt, hash_otp, verify_otp_hash
        
        otp = "123456"
        salt = generate_salt()
        otp_hash = hash_otp(otp, salt)
        
        assert verify_otp_hash("123456", salt, otp_hash) is True
        assert verify_otp_hash("654321", salt, otp_hash) is False
    
    def test_otp_generator_session(self):
        """Should create valid OTP session."""
        from smsly_core.otp import OTPGenerator, OTPConfig
        
        generator = OTPGenerator(OTPConfig(length=6, expiry_seconds=300))
        otp, session = generator.create_session("+14155551234")
        
        assert len(otp) == 6
        assert session.attempts_remaining == 3
        assert not session.is_expired
    
    def test_otp_verification_success(self):
        """Should verify correct OTP."""
        from smsly_core.otp import OTPGenerator
        
        generator = OTPGenerator()
        otp, session = generator.create_session("+14155551234")
        
        success, message = generator.verify(session, otp)
        
        assert success is True
        assert session.is_verified
    
    def test_otp_verification_wrong_code(self):
        """Should reject wrong OTP."""
        from smsly_core.otp import OTPGenerator
        
        generator = OTPGenerator()
        _, session = generator.create_session("+14155551234")
        
        success, message = generator.verify(session, "000000")
        
        assert success is False
        assert session.attempts_remaining == 2


class TestRateLimit:
    """Tests for rate limiting."""
    
    def test_in_memory_rate_limiter(self):
        """Should enforce rate limits."""
        from smsly_core.rate_limit import InMemoryRateLimiter
        
        limiter = InMemoryRateLimiter(rate=5, window=60)
        
        # First 5 should pass
        for i in range(5):
            result = limiter.check("user1")
            assert result.allowed is True
        
        # 6th should fail
        result = limiter.check("user1")
        assert result.allowed is False
    
    def test_rate_limit_separate_keys(self):
        """Different keys should have separate limits."""
        from smsly_core.rate_limit import InMemoryRateLimiter
        
        limiter = InMemoryRateLimiter(rate=2, window=60)
        
        limiter.check("user1")
        limiter.check("user1")
        
        # user1 is at limit
        assert limiter.check("user1").allowed is False
        
        # user2 should still be allowed
        assert limiter.check("user2").allowed is True


class TestAudit:
    """Tests for audit logging."""
    
    def test_compute_event_hash(self):
        """Should compute deterministic hash."""
        from smsly_core.audit import compute_event_hash
        from datetime import datetime, timezone
        
        ts = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        
        hash1 = compute_event_hash(None, ts, "test", "test.event", {"key": "value"})
        hash2 = compute_event_hash(None, ts, "test", "test.event", {"key": "value"})
        
        assert hash1 == hash2
        assert len(hash1) == 64
    
    def test_audit_logger_chain(self):
        """Should maintain hash chain."""
        from smsly_core.audit import AuditLogger, AuditEventType
        
        logger = AuditLogger("test-service")
        
        event1 = logger.log(AuditEventType.AUTH_LOGIN, action="User login")
        event2 = logger.log(AuditEventType.MESSAGE_SENT, action="SMS sent")
        
        assert event1.previous_hash is None
        assert event2.previous_hash == event1.hash
    
    def test_verify_chain_integrity(self):
        """Should verify chain integrity."""
        from smsly_core.audit import AuditLogger, AuditEventType, verify_chain_integrity
        
        logger = AuditLogger("test-service")
        
        logger.log(AuditEventType.AUTH_LOGIN, action="Login")
        logger.log(AuditEventType.MESSAGE_SENT, action="Send")
        logger.log(AuditEventType.AUTH_LOGOUT, action="Logout")
        
        events = logger.flush()
        
        is_valid, first_invalid = verify_chain_integrity(events)
        
        assert is_valid is True
        assert first_invalid is None


class TestInternalAuth:
    """Tests for HMAC signing."""
    
    def test_compute_signature(self):
        """Should compute HMAC signature."""
        from smsly_core.internal_auth import compute_signature
        
        sig = compute_signature(
            secret="my-secret",
            method="POST",
            path="/v1/messages",
            timestamp=1704067200,
            nonce="abc123",
            body_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
        
        assert len(sig) == 64  # SHA-256 hex
    
    def test_verify_signature(self):
        """Should verify valid signature."""
        from smsly_core.internal_auth import compute_signature, verify_signature
        
        secret = "my-secret"
        method = "POST"
        path = "/v1/messages"
        timestamp = 1704067200
        nonce = "abc123"
        body_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        
        sig = compute_signature(secret, method, path, timestamp, nonce, body_hash)
        
        assert verify_signature(secret, method, path, timestamp, nonce, body_hash, sig) is True
        assert verify_signature("wrong-secret", method, path, timestamp, nonce, body_hash, sig) is False
    
    def test_nonce_cache_replay_protection(self):
        """Should detect replay attacks."""
        from smsly_core.internal_auth import NonceCache
        
        cache = NonceCache(ttl_seconds=60)
        
        # First use should pass
        assert cache.check_and_store("nonce-1") is True
        
        # Replay should fail
        assert cache.check_and_store("nonce-1") is False
        
        # Different nonce should pass
        assert cache.check_and_store("nonce-2") is True


class TestRetry:
    """Tests for retry logic."""
    
    @pytest.mark.asyncio
    async def test_retry_success_first_attempt(self):
        """Should succeed without retry if first attempt works."""
        from smsly_core.retry import retry_with_backoff
        
        call_count = 0
        
        async def succeed():
            nonlocal call_count
            call_count += 1
            return "success"
        
        result = await retry_with_backoff(succeed, max_attempts=3)
        
        assert result == "success"
        assert call_count == 1
    
    @pytest.mark.asyncio
    async def test_retry_success_after_failure(self):
        """Should retry on failure and eventually succeed."""
        from smsly_core.retry import retry_with_backoff
        
        call_count = 0
        
        async def fail_then_succeed():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ValueError("Temporary failure")
            return "success"
        
        result = await retry_with_backoff(
            fail_then_succeed,
            max_attempts=5,
            base_delay=0.01,
        )
        
        assert result == "success"
        assert call_count == 3
    
    @pytest.mark.asyncio
    async def test_retry_exhausted(self):
        """Should raise after max attempts."""
        from smsly_core.retry import retry_with_backoff, RetryExhausted
        
        async def always_fail():
            raise ValueError("Always fails")
        
        with pytest.raises(RetryExhausted):
            await retry_with_backoff(
                always_fail,
                max_attempts=3,
                base_delay=0.01,
            )
    
    def test_circuit_breaker_opens(self):
        """Should open circuit after failures."""
        from smsly_core.retry import CircuitBreaker
        
        cb = CircuitBreaker(failure_threshold=3)
        
        assert cb.state == "closed"
        
        cb.record_failure()
        cb.record_failure()
        cb.record_failure()
        
        assert cb.state == "open"
