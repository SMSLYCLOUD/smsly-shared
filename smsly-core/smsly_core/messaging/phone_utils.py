"""
Phone Utilities
===============
Functions for phone number validation and normalization.
"""

import re


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
