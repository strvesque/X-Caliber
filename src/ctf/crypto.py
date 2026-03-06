"""CTF Crypto Module for common cipher operations."""
import base64
from typing import List, Dict, Any


class CryptoSolver:
    """Solver for common CTF crypto challenges."""
    
    def caesar_decrypt(self, ciphertext: str, shift: int = None) -> List[Dict[str, Any]]:
        """
        Caesar cipher decryption. If shift is None, try all 26 shifts.
        
        Returns list of {"shift": int, "plaintext": str}
        """
        results = []
        shifts = [shift] if shift is not None else range(26)
        
        for s in shifts:
            plaintext = ""
            for char in ciphertext:
                if char.isalpha():
                    base = ord('A') if char.isupper() else ord('a')
                    plaintext += chr((ord(char) - base - s) % 26 + base)
                else:
                    plaintext += char
            results.append({"shift": s, "plaintext": plaintext})
        
        return results
    
    def rot13(self, text: str) -> str:
        """ROT13 encoding/decoding (Caesar shift of 13)."""
        result = self.caesar_decrypt(text, 13)
        return result[0]["plaintext"] if result else ""
    
    def xor_decrypt(self, data: bytes, key: bytes) -> bytes:
        """
        XOR decryption with a repeating key.
        
        Args:
            data: Encrypted data bytes
            key: Key bytes (will repeat if shorter than data)
        
        Returns:
            Decrypted bytes
        """
        if not key:
            return data
        
        result = bytearray()
        key_len = len(key)
        for i, byte in enumerate(data):
            result.append(byte ^ key[i % key_len])
        return bytes(result)
    
    def xor_bruteforce_single_byte(self, data: bytes) -> List[Dict[str, Any]]:
        """
        Bruteforce single-byte XOR key.
        
        Returns list of {"key": int, "plaintext": bytes, "score": int}
        sorted by likelihood (English text score).
        """
        results = []
        
        for key in range(256):
            plaintext = self.xor_decrypt(data, bytes([key]))
            score = self._score_english_text(plaintext)
            results.append({
                "key": key,
                "key_char": chr(key) if 32 <= key < 127 else f"\\x{key:02x}",
                "plaintext": plaintext,
                "score": score
            })
        
        # Sort by score descending (higher score = more likely English)
        results.sort(key=lambda x: x["score"], reverse=True)
        return results
    
    def base64_decode(self, encoded: str) -> bytes:
        """
        Base64 decode.
        
        Returns decoded bytes, or empty if invalid.
        """
        try:
            return base64.b64decode(encoded)
        except Exception:
            return b""
    
    def base64_encode(self, data: bytes) -> str:
        """Base64 encode."""
        return base64.b64encode(data).decode('ascii')
    
    def _score_english_text(self, data: bytes) -> int:
        """
        Score how likely data is English plaintext.
        
        Simple heuristic: count printable ASCII + common letters.
        """
        score = 0
        try:
            text = data.decode('ascii')
        except UnicodeDecodeError:
            return -1000  # Not ASCII
        
        # Count printable characters
        printable = sum(1 for c in text if 32 <= ord(c) < 127)
        score += printable
        
        # Bonus for common English letters
        common_letters = "etaoinshrdlcumwfgypbvkjxqz"
        for char in text.lower():
            if char in common_letters:
                score += 2
        
        # Bonus for spaces (word boundaries)
        score += text.count(' ') * 3
        
        # Penalty for control characters
        control = sum(1 for c in text if ord(c) < 32 and c not in '\n\r\t')
        score -= control * 10
        
        return score
