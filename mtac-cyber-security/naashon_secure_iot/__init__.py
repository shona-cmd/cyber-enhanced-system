"""
NaashonSecureIoT: A Hybrid Framework for Enhancing Cybersecurity in the Internet of Things

This package provides a multi-layered cybersecurity framework integrating AI, blockchain,
zero trust, encryption, and other techniques for IoT security at MTAC.

Author: Naashon Kuteesa
"""

__version__ = "1.0.0"
__author__ = "Naashon Kuteesa"

from .core import NaashonSecureIoT
from .config import Config

__all__ = ["NaashonSecureIoT", "Config"]
