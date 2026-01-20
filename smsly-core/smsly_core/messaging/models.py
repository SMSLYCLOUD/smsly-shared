"""
Messaging Models
================
Data models for message encoding and segmentation.
"""

from enum import Enum


class EncodingType(str, Enum):
    """SMS encoding types."""
    GSM7 = "GSM-7"
    UCS2 = "UCS-2"


# GSM-7 character set (basic)
GSM7_BASIC = set(
    "@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞ ÆæßÉ !\"#¤%&'()*+,-./0123456789:;<=>?"
    "¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà"
)

# GSM-7 extended characters (count as 2)
GSM7_EXTENDED = set("€^{}\\[~]|")
