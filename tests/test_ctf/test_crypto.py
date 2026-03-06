"""Tests for CTF Crypto Module."""
import pytest
from src.ctf.crypto import CryptoSolver


class TestCaesarCipher:
    def test_caesar_decrypt_known_shift(self):
        solver = CryptoSolver()
        ciphertext = "Khoor Zruog"  # "Hello World" with shift 3
        results = solver.caesar_decrypt(ciphertext, shift=3)
        assert len(results) == 1
        assert results[0]["plaintext"] == "Hello World"
        assert results[0]["shift"] == 3
    
    def test_caesar_decrypt_all_shifts(self):
        solver = CryptoSolver()
        ciphertext = "ABC"
        results = solver.caesar_decrypt(ciphertext, shift=None)
        assert len(results) == 26
        # Shift 0 should return original
        assert results[0]["plaintext"] == "ABC"
        # Shift 1 should give ZAB
        assert results[1]["plaintext"] == "ZAB"
    
    def test_caesar_preserves_non_alpha(self):
        solver = CryptoSolver()
        ciphertext = "Abc123!@#"
        results = solver.caesar_decrypt(ciphertext, shift=1)
        assert "123!@#" in results[0]["plaintext"]
    
    def test_caesar_handles_empty_string(self):
        solver = CryptoSolver()
        results = solver.caesar_decrypt("", shift=5)
        assert results[0]["plaintext"] == ""


class TestROT13:
    def test_rot13_encode_decode(self):
        solver = CryptoSolver()
        original = "Hello World"
        encoded = solver.rot13(original)
        decoded = solver.rot13(encoded)
        assert decoded == original
    
    def test_rot13_known_example(self):
        solver = CryptoSolver()
        assert solver.rot13("Uryyb") == "Hello"


class TestXORDecryption:
    def test_xor_decrypt_single_byte(self):
        solver = CryptoSolver()
        plaintext = b"HELLO"
        key = b"X"
        encrypted = solver.xor_decrypt(plaintext, key)  # XOR to encrypt
        decrypted = solver.xor_decrypt(encrypted, key)  # XOR to decrypt
        assert decrypted == plaintext
    
    def test_xor_decrypt_repeating_key(self):
        solver = CryptoSolver()
        plaintext = b"HELLO WORLD"
        key = b"KEY"
        encrypted = solver.xor_decrypt(plaintext, key)
        decrypted = solver.xor_decrypt(encrypted, key)
        assert decrypted == plaintext
    
    def test_xor_bruteforce_finds_key(self):
        solver = CryptoSolver()
        plaintext = b"the flag is here"
        key = 42
        encrypted = bytes([b ^ key for b in plaintext])
        
        results = solver.xor_bruteforce_single_byte(encrypted)
        
        # Top result should be correct key
        assert results[0]["key"] == key
        assert results[0]["plaintext"] == plaintext
    
    def test_xor_empty_key_returns_data(self):
        solver = CryptoSolver()
        data = b"test"
        assert solver.xor_decrypt(data, b"") == data


class TestBase64:
    def test_base64_encode_decode(self):
        solver = CryptoSolver()
        original = b"Hello World"
        encoded = solver.base64_encode(original)
        decoded = solver.base64_decode(encoded)
        assert decoded == original
    
    def test_base64_known_encoding(self):
        solver = CryptoSolver()
        assert solver.base64_encode(b"Hello") == "SGVsbG8="
    
    def test_base64_known_decoding(self):
        solver = CryptoSolver()
        assert solver.base64_decode("SGVsbG8=") == b"Hello"
    
    def test_base64_invalid_returns_empty(self):
        solver = CryptoSolver()
        assert solver.base64_decode("not@valid!base64") == b""


class TestEnglishScoring:
    def test_score_recognizes_english(self):
        solver = CryptoSolver()
        english_score = solver._score_english_text(b"The quick brown fox")
        gibberish_score = solver._score_english_text(b"\x01\x02\x03\x04\x05")
        assert english_score > gibberish_score
    
    def test_score_penalizes_control_chars(self):
        solver = CryptoSolver()
        clean_score = solver._score_english_text(b"hello world")
        dirty_score = solver._score_english_text(b"hello\x00\x01world")
        assert clean_score > dirty_score
