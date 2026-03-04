"""Encoder/Decoder plugin for base64, hex, URL, and ROT13.

Implements EncoderDecoder(BasePlugin) expected by plugin system.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import urllib.parse
from typing import Any, Dict

from src.core.plugin import BasePlugin

class EncoderDecoder(BasePlugin):
    """Plugin that encodes/decodes strings in multiple formats.

    Metadata expected by the plugin system is provided as class attributes.
    """

    name = "Encoder/Decoder"
    category = "crypto"
    description = "Encode/decode data (base64, hex, URL, ROT13)"

    def __init__(self) -> None:
        self._config: Dict[str, Any] = {}
        self._result: Dict[str, Any] = {}

    def init(self, config: Dict[str, Any]) -> None:
        """Initialize plugin with provided config.

        Stores the config for potential future use. No other setup required.
        """
        self._config = dict(config or {})

    def run(self, params: Dict[str, Any]) -> None:
        """Run an encode/decode operation.

        Expected params: {
            'mode': 'encode'|'decode',
            'format': 'base64'|'hex'|'url'|'rot13',
            'data': str
        }
        The result is stored and retrievable via get_results().
        """
        mode = params.get("mode")
        fmt = params.get("format")
        data = params.get("data")

        if mode not in ("encode", "decode"):
            raise ValueError("mode must be 'encode' or 'decode'")
        if fmt not in ("base64", "hex", "url", "rot13"):
            raise ValueError("format must be one of: base64, hex, url, rot13")
        if not isinstance(data, str):
            raise ValueError("data must be a string")

        output = ""

        if fmt == "base64":
            if mode == "encode":
                output = base64.b64encode(data.encode("utf-8")).decode("ascii")
            else:
                output = base64.b64decode(data.encode("ascii")).decode("utf-8")

        elif fmt == "hex":
            if mode == "encode":
                output = binascii.hexlify(data.encode("utf-8")).decode("ascii")
            else:
                output = binascii.unhexlify(data.encode("ascii")).decode("utf-8")

        elif fmt == "url":
            if mode == "encode":
                # use safe='' to encode all characters conservatively
                output = urllib.parse.quote(data, safe="")
            else:
                output = urllib.parse.unquote(data)

        elif fmt == "rot13":
            # codecs.encode handles ROT13 for str input
            output = codecs.encode(data, "rot_13")

        self._result = {"output": output}

    def stop(self) -> None:
        """No-op cleanup hook required by BasePlugin interface."""
        return None

    def get_results(self) -> Dict[str, Any]:
        """Return the last operation result as a dict: {'output': str}."""
        return dict(self._result)
