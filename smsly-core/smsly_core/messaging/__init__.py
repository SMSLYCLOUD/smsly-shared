"""
Message Segmentation and Encoding
==================================
Utilities for SMS message segmentation and encoding detection.
"""

# Re-export all public APIs for backwards compatibility
from .models import EncodingType, GSM7_BASIC, GSM7_EXTENDED
from .encoding import detect_encoding, count_gsm7_characters
from .segmentation import calculate_segments, split_message, estimate_cost
from .phone_utils import sanitize_sender_id, validate_e164, normalize_phone

__all__ = [
    # Models
    "EncodingType",
    "GSM7_BASIC",
    "GSM7_EXTENDED",
    # Encoding
    "detect_encoding",
    "count_gsm7_characters",
    # Segmentation
    "calculate_segments",
    "split_message",
    "estimate_cost",
    # Phone
    "sanitize_sender_id",
    "validate_e164",
    "normalize_phone",
]
