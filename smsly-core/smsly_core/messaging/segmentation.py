"""
Message Segmentation
====================
Functions for SMS segment calculation and splitting.
"""

from typing import Tuple, List

from .models import EncodingType, GSM7_EXTENDED
from .encoding import detect_encoding, count_gsm7_characters


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
            segments = (char_count + 152) // 153
            return segments, encoding, char_count
    else:
        char_count = len(text)
        if char_count <= 70:
            return 1, encoding, char_count
        else:
            segments = (char_count + 66) // 67
            return segments, encoding, char_count


def split_message(text: str) -> List[str]:
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
