"""
Encoding Detection
==================
Functions for SMS encoding detection and character counting.
"""

from typing import Tuple

from .models import EncodingType, GSM7_BASIC, GSM7_EXTENDED


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
