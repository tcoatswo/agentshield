"""
AgentShield: Fast, deterministic Prompt Injection & Indirect Prompt Injection (IPI) Defense Engine.
"""

from .scanner import scan_prompt, normalize_and_deobfuscate, ScanResult
from .sanitizer import sanitize_text

__version__ = "0.1.0"
__all__ = ["scan_prompt", "normalize_and_deobfuscate", "ScanResult", "sanitize_text"]
