import re
from typing import List, Dict, Any, Pattern


class FlagFinder:
    """Simple CTF flag finder utility.

    Finds common CTF flag formats in text or files and returns a list of
    match dictionaries with flag text, originating pattern, start position,
    and a short surrounding context.
    """

    PATTERNS = [
        r'flag\{[^}]+\}',
        r'CTF\{[^}]+\}',
        r'picoCTF\{[^}]+\}',
        r'HTB\{[^}]+\}',
        r'[A-Za-z0-9_]+\{[A-Fa-f0-9]{32,}\}',  # Generic hex-based token
    ]

    def __init__(self) -> None:
        # Precompile regexes with IGNORECASE for flexibility
        self._regexes: List[Pattern[str]] = [re.compile(p, re.IGNORECASE) for p in self.PATTERNS]

    def find_in_text(self, text: str) -> List[Dict[str, Any]]:
        """Find flags in the provided text.

        Returns a list of dictionaries:
        {
            "flag": str,         # matched flag string
            "pattern": str,      # original pattern that produced the match
            "position": int,     # start index in text
            "context": str       # up to 20 chars before and after match
        }
        Duplicate matches (same flag at same position) are suppressed.
        """
        results: List[Dict[str, Any]] = []
        seen = set()
        text_len = len(text)

        for pattern, regex in zip(self.PATTERNS, self._regexes):
            for m in regex.finditer(text):
                start = m.start()
                flag_text = m.group(0)
                key = (flag_text, start)
                if key in seen:
                    continue
                seen.add(key)

                ctx_start = max(0, start - 20)
                ctx_end = min(text_len, m.end() + 20)
                context = text[ctx_start:ctx_end]

                results.append({
                    "flag": flag_text,
                    "pattern": pattern,
                    "position": start,
                    "context": context,
                })

        # Sort by position for deterministic output
        results.sort(key=lambda r: r["position"])
        return results

    def find_in_bytes(self, data: bytes) -> List[Dict[str, Any]]:
        """Search flags inside raw bytes.

        We decode bytes using latin-1 to keep a 1:1 mapping of byte offsets to
        character indices which makes reported positions correspond to byte
        offsets. This keeps behavior predictable for binary files.
        """
        try:
            # Use latin-1 (direct 1:1 mapping) so positions map to byte indices
            text = data.decode("latin-1", errors="ignore")
        except Exception:
            text = data.decode("utf-8", errors="ignore")
        return self.find_in_text(text)

    def find_in_file(self, filepath: str) -> List[Dict[str, Any]]:
        """Open a file in binary mode and search for flags.

        Returns an empty list on read errors.
        """
        try:
            with open(filepath, "rb") as fh:
                data = fh.read()
            return self.find_in_bytes(data)
        except Exception:
            return []


__all__ = ["FlagFinder"]
