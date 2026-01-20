"""
Message Segmentation and Encoding
==================================
Utilities for SMS message segmentation and encoding detection.
"""

import re
from typing import Tuple
from enum import Enum


class EncodingType(str, Enum):
    GSM7 = "GSM-7"
    UCS2 = "UCS-2"


# GSM-7 character set (basic)
GSM7_BASIC = set(
    "@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞ ÆæßÉ !\"#¤%&'()*+,-./0123456789:;<=>?"
    "¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà"
)

# GSM-7 extended characters (count as 2)
GSM7_EXTENDED = set("€^{}\\[~]|")


def detect_encoding(text: str) -> EncodingType:
    """
    Detect the required encoding for a message.
    
    Args:
        text: Message content
        
    Returns:
        EncodingType.GSM7 or EncodingType.UCS2
    """
    for char in text:
        if char not in GSM7_BASIC and char not in GSM7_EXTENDED:
            return EncodingType.UCS2
    return EncodingType.GSM7


def count_gsm7_characters(text: str) -> int:
    """
    Count the number of GSM-7 character units (extended chars count as 2).
    
    Args:
        text: Message content
        
    Returns:
        Character count for segmentation
    """
    count = 0
    for char in text:
        if char in GSM7_EXTENDED:
            count += 2
        else:
            count += 1
    return count


def calculate_segments(text: str) -> Tuple[int, EncodingType, int]:
    """
    Calculate the number of SMS segments required.
    
    Segment limits:
    - GSM-7: 160 chars (single), 153 chars (concatenated)
    - UCS-2: 70 chars (single), 67 chars (concatenated)
    
    Args:
        text: Message content
        
    Returns:
        Tuple of (segments, encoding, char_count)
    """
    encoding = detect_encoding(text)
    
    if encoding == EncodingType.GSM7:
        char_count = count_gsm7_characters(text)
        if char_count <= 160:
            return 1, encoding, char_count
        else:
            # Concatenated: 153 chars per segment (7 bytes for UDH)
            segments = (char_count + 152) // 153
            return segments, encoding, char_count
    else:
        # UCS-2 (UTF-16)
        char_count = len(text)
        if char_count <= 70:
            return 1, encoding, char_count
        else:
            # Concatenated: 67 chars per segment
            segments = (char_count + 66) // 67
            return segments, encoding, char_count


def split_message(text: str) -> list:
    """
    Split a message into segments for sending.
    
    Note: This is for display/preview purposes.
    Actual concatenation is handled by the carrier.
    
    Args:
        text: Message content
        
    Returns:
        List of message segments
    """
    segments, encoding, _ = calculate_segments(text)
    
    if segments == 1:
        return [text]
    
    if encoding == EncodingType.GSM7:
        segment_size = 153
        chars = list(text)
        result = []
        i = 0
        while i < len(chars):
            segment = []
            segment_chars = 0
            while i < len(chars) and segment_chars < segment_size:
                char = chars[i]
                char_cost = 2 if char in GSM7_EXTENDED else 1
                if segment_chars + char_cost <= segment_size:
                    segment.append(char)
                    segment_chars += char_cost
                    i += 1
                else:
                    break
            result.append(''.join(segment))
        return result
    else:
        # UCS-2
        segment_size = 67
        return [text[i:i+segment_size] for i in range(0, len(text), segment_size)]


def estimate_cost(text: str, cost_per_segment: float = 0.01) -> float:
    """
    Estimate the cost to send a message.
    
    Args:
        text: Message content
        cost_per_segment: Cost per SMS segment
        
    Returns:
        Estimated cost
    """
    segments, _, _ = calculate_segments(text)
    return segments * cost_per_segment


def sanitize_sender_id(sender_id: str, max_length: int = 11) -> str:
    """
    Sanitize an alphanumeric sender ID.
    
    Rules:
    - Max 11 characters for alphanumeric
    - Only letters, numbers (no special chars)
    - Must start with a letter
    
    Args:
        sender_id: Raw sender ID
        max_length: Maximum length (default 11)
        
    Returns:
        Sanitized sender ID
    """
    # Remove non-alphanumeric except spaces
    clean = re.sub(r'[^a-zA-Z0-9 ]', '', sender_id)
    
    # Ensure starts with letter
    if clean and not clean[0].isalpha():
        clean = 'A' + clean
    
    # Truncate
    return clean[:max_length]


def validate_e164(phone: str) -> bool:
    """
    Validate E.164 phone number format.
    
    Args:
        phone: Phone number
        
    Returns:
        True if valid E.164 format
    """
    pattern = r'^\+[1-9]\d{1,14}$'
    return bool(re.match(pattern, phone))


def normalize_phone(phone: str, default_country: str = "1") -> str:
    """
    Normalize a phone number to E.164 format.
    
    Args:
        phone: Raw phone number
        default_country: Default country code (without +)
        
    Returns:
        E.164 formatted number
    """
    # Remove all non-digit characters
    digits = re.sub(r'\D', '', phone)
    
    # If already has country code
    if phone.startswith('+'):
        return f"+{digits}"
    
    # If 10 digits, assume US/Canada
    if len(digits) == 10:
        return f"+{default_country}{digits}"
    
    # If 11 digits starting with 1, assume US/Canada with country code
    if len(digits) == 11 and digits.startswith('1'):
        return f"+{digits}"
    
    # Otherwise, assume it's already a full number
    return f"+{digits}"
