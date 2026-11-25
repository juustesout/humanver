"""
humanver — Windows Hello vingerafdruk verificatie voor Hermes.

Biedt een tool `human_verify` die de gebruiker vraagt de vingerafdrukscanner
te gebruiken om een actie te bevestigen.
"""

from __future__ import annotations

import logging
import platform
from typing import Any

from ._winbio import winbio_verify

logger = logging.getLogger(__name__)

HUMAN_VERIFY_SCHEMA = {
    "type": "object",
    "properties": {
        "prompt": {
            "type": "string",
            "description": "Wat moet de gebruiker bevestigen? Bijv: 'Verzend bericht naar X'",
        },
    },
    "required": ["prompt"],
}

def check_human_verify(**kwargs: Any) -> bool:
    """check_fn: True when this platform can run Windows Hello fingerprint verification."""
    return platform.system().lower() == "windows"


def handle_human_verify(prompt: str, **kwargs: Any) -> str:
    """Handler: prompt the user to scan their fingerprint.

    Tries WinBioVerify directly. On failure returns a clear message
    distinguishing: no sensor, no enrollment, mismatch, or system error.
    """
    try:
        logger.info("human_verify: starting fingerprint scan for: %s", prompt)
        verified = winbio_verify()
        if verified:
            return (
                f"✅ **Vingerafdruk geverifieerd!**\n\n"
                f"Bevestiging voor: _{prompt}_\n"
                f"Identiteit komt overeen."
            )
        else:
            return (
                "❌ **Vingerafdruk verificatie mislukt.**\n\n"
                "De gescande vingerafdruk komt niet overeen met de "
                "geregistreerde gebruiker."
            )
    except RuntimeError as e:
        logger.warning("human_verify failed: %s", e)
        return f"❌ **Verificatie fout:** {e.args[0] if e.args else str(e)}"


def register(ctx) -> None:
    """Register humanver tools with the plugin context."""
    ctx.register_tool(
        name="human_verify",
        toolset="humanver",
        schema=HUMAN_VERIFY_SCHEMA,
        handler=handle_human_verify,
        check_fn=check_human_verify,
        emoji="🖐️",
    )
    logger.info("humanver plugin registered")