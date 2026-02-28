"""
PhishGuard CLI — phishing_kit.py
==================================
Phishing Kit Simulator — For security research, CTF, and awareness training only.

This module demonstrates HOW phishing kits are built so defenders can:
  • Recognise them in the wild
  • Build better detection rules
  • Understand attacker infrastructure

   DO NOT deploy generated pages against real users.
    Use only in isolated lab / CTF environments.

    Authors are not responsible for misuse.
"""

from pathlib import Path

#  CONSTANTS

LOOT_FILE   = Path("phishkit_loot.json")
LOG_FILE    = Path("phishkit_log.txt")
PAGES_DIR   = Path("phishkit_pages")
KIT_BANNER  = "[bold red]⚠  PHISHGUARD — PHISHING KIT SIMULATOR  ⚠[/bold red]"

BRAND_TEMPLATES = {
    "1": "Google",
    "2": "Microsoft / Office 365",
    "3": "PayPal",
    "4": "Facebook",
    "5": "Generic Corporate SSO",
    "6": "Bank (Generic)",
    "7": "Custom",
}