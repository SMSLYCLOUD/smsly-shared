"""
Trust Score Engine
==================
Aggregates signals from multiple providers into a unified trust score
for continuous authentication and account takeover prevention.

Components:
- TrustSignal: Individual signal from a provider
- TrustScore: Aggregated trust assessment
- TrustScoreEngine: Main computation engine
"""

import hashlib
from typing import Any, Dict, List, Literal, Optional
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum

import structlog

logger = structlog.get_logger(__name__)


class SignalType(str, Enum):
    """Types of trust signals."""
    SILENT_AUTH = "silent_auth"           # Carrier verified phone
    SIM_SWAP = "sim_swap"                 # SIM swap detection
    DEVICE_FINGERPRINT = "device"         # Known/new device
    BEHAVIORAL = "behavioral"             # Usage pattern match
    LOCATION = "location"                 # IP/geo match
    LINE_TYPE = "line_type"               # Mobile/VoIP/landline
    CARRIER = "carrier"                   # Carrier reputation


@dataclass
class TrustSignal:
    """Individual trust signal from any source."""
    source: str                           # Provider name: "truid", "vonage", etc.
    signal_type: SignalType
    score_contribution: int               # -50 to +50 points
    confidence: float                     # 0.0 to 1.0
    reason: str                           # Human-readable explanation
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    evidence: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "signal_type": self.signal_type.value,
            "score_contribution": self.score_contribution,
            "confidence": self.confidence,
            "reason": self.reason,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class TrustScore:
    """Aggregated trust score result."""
    overall_score: int                    # 0-100 (higher = more trusted)
    risk_level: Literal["trusted", "neutral", "suspicious", "blocked"]
    signals: List[TrustSignal]
    sim_swap_detected: bool
    device_change_detected: bool
    location_anomaly_detected: bool
    recommendation: Literal["allow", "step_up", "block"]
    step_up_method: Optional[str] = None  # "sms_otp", "email", "biometric"
    session_id: Optional[str] = None
    computed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "overall_score": self.overall_score,
            "risk_level": self.risk_level,
            "signals": [s.to_dict() for s in self.signals],
            "sim_swap_detected": self.sim_swap_detected,
            "device_change_detected": self.device_change_detected,
            "location_anomaly_detected": self.location_anomaly_detected,
            "recommendation": self.recommendation,
            "step_up_method": self.step_up_method,
            "session_id": self.session_id,
            "computed_at": self.computed_at.isoformat(),
        }


class TrustScoreEngine:
    """
    Computes unified trust scores from multiple signal sources.
    
    Scoring Logic (base: 50 points, range 0-100):
    
    Positive signals (add points):
    - Silent auth passed (tru.ID/IPification): +40
    - No SIM swap detected: +15
    - Known device: +15
    - Known location: +10
    - Mobile line type: +5
    - Trusted carrier: +5
    
    Negative signals (subtract points):
    - SIM swap < 24h: -50
    - SIM swap < 7 days: -30
    - SIM swap < 30 days: -15
    - New device: -15
    - VoIP/virtual number: -25
    - Location anomaly: -15
    - Behavioral anomaly: -20
    """
    
    # Score thresholds
    TRUSTED_THRESHOLD = 75
    SUSPICIOUS_THRESHOLD = 40
    BLOCKED_THRESHOLD = 20
    
    def __init__(
        self,
        phone_reputation_db=None,
        device_db=None,
        session_db=None,
    ):
        self.phone_db = phone_reputation_db
        self.device_db = device_db
        self.session_db = session_db
    
    async def compute_trust(
        self,
        phone: str,
        device_fingerprint: Optional[str] = None,
        ip_address: Optional[str] = None,
        session_id: Optional[str] = None,
        provider_results: Optional[Dict[str, Any]] = None,
    ) -> TrustScore:
        """
        Compute unified trust score from all available signals.
        
        Args:
            phone: E.164 phone number
            device_fingerprint: Device fingerprint hash
            ip_address: Client IP address
            session_id: Existing session ID (for continuous auth)
            provider_results: Pre-fetched provider results
            
        Returns:
            TrustScore with aggregated assessment
        """
        signals: List[TrustSignal] = []
        base_score = 50  # Start neutral
        
        # Normalize inputs
        phone_hash = self._hash_phone(phone)
        
        # 1. Process provider results (if provided)
        if provider_results:
            provider_signals = self._process_provider_results(provider_results)
            signals.extend(provider_signals)
        
        # 2. Check device fingerprint
        if device_fingerprint:
            device_signal = await self._check_device(phone_hash, device_fingerprint)
            if device_signal:
                signals.append(device_signal)
        
        # 3. Check location/IP
        if ip_address:
            location_signal = await self._check_location(phone_hash, ip_address)
            if location_signal:
                signals.append(location_signal)
        
        # 4. Check existing session (continuous auth)
        if session_id:
            session_signal = await self._check_session(session_id, phone_hash, device_fingerprint, ip_address)
            if session_signal:
                signals.append(session_signal)
        
        # 5. Calculate final score
        for signal in signals:
            weighted_contribution = int(signal.score_contribution * signal.confidence)
            base_score += weighted_contribution
        
        # Clamp to 0-100
        final_score = max(0, min(100, base_score))
        
        # 6. Determine risk level and recommendation
        sim_swap = any(s.signal_type == SignalType.SIM_SWAP and s.score_contribution < 0 for s in signals)
        device_change = any(s.signal_type == SignalType.DEVICE_FINGERPRINT and s.score_contribution < 0 for s in signals)
        location_anomaly = any(s.signal_type == SignalType.LOCATION and s.score_contribution < 0 for s in signals)
        
        risk_level, recommendation, step_up = self._determine_outcome(
            final_score, sim_swap, device_change, location_anomaly
        )
        
        logger.info(
            "trust_score_computed",
            phone=phone[:6] + "****",
            score=final_score,
            risk_level=risk_level,
            recommendation=recommendation,
            signal_count=len(signals),
        )
        
        return TrustScore(
            overall_score=final_score,
            risk_level=risk_level,
            signals=signals,
            sim_swap_detected=sim_swap,
            device_change_detected=device_change,
            location_anomaly_detected=location_anomaly,
            recommendation=recommendation,
            step_up_method=step_up,
            session_id=session_id,
        )
    
    def _process_provider_results(self, results: Dict[str, Any]) -> List[TrustSignal]:
        """Process provider results into trust signals."""
        signals = []
        
        # Silent auth result
        if "silent_auth" in results:
            auth = results["silent_auth"]
            if auth.get("verified"):
                signals.append(TrustSignal(
                    source=auth.get("provider", "unknown"),
                    signal_type=SignalType.SILENT_AUTH,
                    score_contribution=40,
                    confidence=1.0,
                    reason="Silent network authentication passed",
                    evidence=auth,
                ))
            elif auth.get("error"):
                pass  # Don't penalize for provider errors
            else:
                signals.append(TrustSignal(
                    source=auth.get("provider", "unknown"),
                    signal_type=SignalType.SILENT_AUTH,
                    score_contribution=-20,
                    confidence=0.8,
                    reason="Silent network authentication failed",
                    evidence=auth,
                ))
        
        # SIM swap result
        if "sim_swap" in results:
            swap = results["sim_swap"]
            if swap.get("sim_swap_detected"):
                days = swap.get("days_since_swap", 999)
                if days <= 1:
                    score = -50
                    reason = "SIM swap detected in last 24 hours"
                elif days <= 7:
                    score = -30
                    reason = "SIM swap detected in last 7 days"
                elif days <= 30:
                    score = -15
                    reason = "SIM swap detected in last 30 days"
                else:
                    score = -5
                    reason = "Old SIM swap detected"
                
                signals.append(TrustSignal(
                    source=swap.get("provider", "unknown"),
                    signal_type=SignalType.SIM_SWAP,
                    score_contribution=score,
                    confidence=0.95,
                    reason=reason,
                    evidence=swap,
                ))
            else:
                signals.append(TrustSignal(
                    source=swap.get("provider", "unknown"),
                    signal_type=SignalType.SIM_SWAP,
                    score_contribution=15,
                    confidence=0.9,
                    reason="No recent SIM swap detected",
                    evidence=swap,
                ))
        
        # Line type result
        if "line_type" in results:
            lt = results["line_type"]
            line_type = lt.get("type", "unknown")
            
            if line_type == "mobile":
                signals.append(TrustSignal(
                    source=lt.get("provider", "unknown"),
                    signal_type=SignalType.LINE_TYPE,
                    score_contribution=5,
                    confidence=0.9,
                    reason="Mobile line confirmed",
                    evidence=lt,
                ))
            elif line_type in ("voip", "virtual"):
                signals.append(TrustSignal(
                    source=lt.get("provider", "unknown"),
                    signal_type=SignalType.LINE_TYPE,
                    score_contribution=-25,
                    confidence=0.9,
                    reason="VoIP/virtual number detected",
                    evidence=lt,
                ))
            elif line_type == "landline":
                signals.append(TrustSignal(
                    source=lt.get("provider", "unknown"),
                    signal_type=SignalType.LINE_TYPE,
                    score_contribution=-5,
                    confidence=0.9,
                    reason="Landline number detected",
                    evidence=lt,
                ))
        
        return signals
    
    async def _check_device(self, phone_hash: str, fingerprint: str) -> Optional[TrustSignal]:
        """Check if device is known for this phone."""
        if not self.device_db:
            return None
        
        try:
            known = await self.device_db.is_known_device(phone_hash, fingerprint)
            
            if known:
                return TrustSignal(
                    source="device_db",
                    signal_type=SignalType.DEVICE_FINGERPRINT,
                    score_contribution=15,
                    confidence=0.85,
                    reason="Known trusted device",
                )
            else:
                return TrustSignal(
                    source="device_db",
                    signal_type=SignalType.DEVICE_FINGERPRINT,
                    score_contribution=-15,
                    confidence=0.7,
                    reason="New or unknown device",
                )
        except Exception:
            return None
    
    async def _check_location(self, phone_hash: str, ip_address: str) -> Optional[TrustSignal]:
        """Check if IP/location is consistent with history."""
        if not self.phone_db:
            return None
        
        try:
            # Get historical IPs for this phone
            history = await self.phone_db.get_ip_history(phone_hash)
            
            if not history or len(history) == 0:
                # First time - neutral, not suspicious
                return None
            
            # Extract /16 prefix for comparison (allows some NAT/mobile variation)
            current_prefix = ".".join(ip_address.split(".")[:2])
            
            known_prefixes = set()
            for record in history:
                if record.get("ip"):
                    prefix = ".".join(record["ip"].split(".")[:2])
                    known_prefixes.add(prefix)
            
            if current_prefix in known_prefixes:
                return TrustSignal(
                    source="location_db",
                    signal_type=SignalType.LOCATION,
                    score_contribution=10,
                    confidence=0.7,
                    reason="Known IP range",
                )
            else:
                return TrustSignal(
                    source="location_db",
                    signal_type=SignalType.LOCATION,
                    score_contribution=-15,
                    confidence=0.6,
                    reason="New IP range detected",
                )
        except Exception:
            return None
    
    async def _check_session(
        self,
        session_id: str,
        phone_hash: str,
        device_fingerprint: Optional[str],
        ip_address: Optional[str],
    ) -> Optional[TrustSignal]:
        """Check if current request matches existing session."""
        if not self.session_db:
            return None
        
        try:
            session = await self.session_db.get_session(session_id)
            if not session:
                return None
            
            # Check if session matches current context
            matches = 0
            total = 0
            
            if session.get("phone_hash") == phone_hash:
                matches += 1
            total += 1
            
            if device_fingerprint and session.get("device_fingerprint") == device_fingerprint:
                matches += 1
            if device_fingerprint:
                total += 1
            
            if ip_address and session.get("ip_address") == ip_address:
                matches += 0.5
            if ip_address:
                total += 0.5
            
            match_ratio = matches / total if total > 0 else 0
            
            if match_ratio >= 0.8:
                return TrustSignal(
                    source="session_db",
                    signal_type=SignalType.BEHAVIORAL,
                    score_contribution=20,
                    confidence=match_ratio,
                    reason="Session context matches",
                )
            elif match_ratio < 0.5:
                return TrustSignal(
                    source="session_db",
                    signal_type=SignalType.BEHAVIORAL,
                    score_contribution=-20,
                    confidence=1 - match_ratio,
                    reason="Session context mismatch - possible hijacking",
                )
        except Exception:
            return None
        
        return None
    
    def _determine_outcome(
        self,
        score: int,
        sim_swap: bool,
        device_change: bool,
        location_anomaly: bool,
    ) -> tuple[str, str, Optional[str]]:
        """Determine risk level, recommendation, and step-up method."""
        
        # Critical: Recent SIM swap always requires step-up
        if sim_swap:
            return "suspicious", "step_up", "sms_otp"
        
        # Score-based decisions
        if score >= self.TRUSTED_THRESHOLD:
            return "trusted", "allow", None
        elif score >= self.SUSPICIOUS_THRESHOLD:
            if device_change or location_anomaly:
                return "neutral", "step_up", "sms_otp"
            return "neutral", "allow", None
        elif score >= self.BLOCKED_THRESHOLD:
            return "suspicious", "step_up", "sms_otp"
        else:
            return "blocked", "block", None
    
    def _hash_phone(self, phone: str) -> str:
        """Hash phone number for storage."""
        return hashlib.sha256(phone.encode()).hexdigest()


# Convenience function for quick assessment
async def assess_trust(
    phone: str,
    device_fingerprint: Optional[str] = None,
    ip_address: Optional[str] = None,
    provider_results: Optional[Dict[str, Any]] = None,
) -> TrustScore:
    """Quick trust assessment without database dependencies."""
    engine = TrustScoreEngine()
    return await engine.compute_trust(
        phone=phone,
        device_fingerprint=device_fingerprint,
        ip_address=ip_address,
        provider_results=provider_results,
    )
