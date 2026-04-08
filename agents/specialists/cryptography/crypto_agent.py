"""
Cryptography Specialist Agent

Specialized agent for solving cryptography-based CTF challenges.
"""

from typing import Dict, Any, List, Tuple, Optional
from agents.base_agent import BaseAgent, AgentType
import base64
import binascii
import re

from core import challenge


class CryptographyAgent(BaseAgent):
    """
    Specialist agent for cryptography challenges.
    """

    def __init__(self, agent_id: str = "crypto_agent"):
        super().__init__(agent_id, AgentType.SPECIALIST)
        self.capabilities = [
            "crypto",
            "cryptography",
            "encryption",
            "decryption",
            "hash_cracking",
            "encoding",
            "rsa",
            "aes",
            "classical_ciphers",
            "base64",
            "hex",
            "xor",
        ]

        self.common_words = {
            "the", "and", "that", "have", "for", "not", "with", "you", "this",
            "but", "his", "from", "they", "say", "her", "she", "will", "one",
            "all", "would", "there", "their", "what", "about", "which", "when",
            "make", "can", "like", "time", "just", "know", "take", "into",
            "year", "your", "good", "some", "could", "them", "see", "other",
            "than", "then", "now", "look", "only", "come", "its", "over",
            "think", "also", "back", "after", "use", "two", "how", "our",
            "work", "first", "well", "way", "even", "new", "want", "because",
            "any", "these", "give", "day", "most", "us", "he", "it", "in",
            "to", "of", "if", "had", "anything", "confidential", "cipher",
            "wrote", "word", "letters", "alphabet", "order", "made", "out",
            "hello", "world", "flag", "ctf"
        }

    def analyze_challenge(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        description = challenge.get("description", "").lower()
        hints = " ".join(challenge.get("hints", [])).lower()
        metadata = challenge.get("metadata", {})
        tags = " ".join(challenge.get("tags", [])).lower()
        cipher_text = self._extract_ciphertext(challenge)
        cipher_types = []

        if any(k in description for k in ["caesar", "shift", "rot"]):
            cipher_types.append("caesar_cipher")
        if any(k in hints for k in ["shift", "caesar", "rot"]):
            cipher_types.append("caesar_cipher")
        if metadata.get("cipher_type") == "caesar":
            cipher_types.append("caesar_cipher")

        if (
            "base64" in description
            or "base64" in tags
            or metadata.get("cipher_type") == "base64"
            or self._looks_like_base64(cipher_text)
        ):
            cipher_types.append("base64")
        if "hex" in description or metadata.get("cipher_type") == "hex":
            cipher_types.append("hex")
        if "xor" in description or metadata.get("cipher_type") == "xor":
            cipher_types.append("single_byte_xor")

        if any(k in description for k in ["rsa", "public key", "private key"]):
            cipher_types.append("rsa")
        if any(k in description for k in ["hash", "md5", "sha"]):
            cipher_types.append("hash")
        if "aes" in description:
            cipher_types.append("aes")

        cipher_types = sorted(set(cipher_types))
        confidence = 0.9 if challenge.get("category") == "crypto" else 0.1

        return {
            "agent_id": self.agent_id,
            "can_handle": challenge.get("category") == "crypto",
            "confidence": confidence,
            "detected_types": cipher_types,
            "approach": self._plan_approach(cipher_types),
        }

    def solve_challenge(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        analysis = self.analyze_challenge(challenge)

        steps: List[str] = []
        flag = None

        steps.append("Analyzed cipher/encoding type")
        steps.append("Detected types: " + ", ".join(analysis["detected_types"]))

        cipher_text = self._extract_ciphertext(challenge)
        steps.append(f"Extracted ciphertext: {cipher_text}")

        best_result: Optional[Tuple[str, str, float, str]] = None
        # (method_name, plaintext, score, detail)

        if "caesar_cipher" in analysis["detected_types"]:
            steps.append("Attempting Caesar brute force (shifts 1-25)")
            shift, plaintext, score = self._best_caesar_candidate(cipher_text)
            candidate = ("caesar", plaintext, score, f"Chosen shift: {shift}")
            best_result = self._pick_better(best_result, candidate)

        if "base64" in analysis["detected_types"] or self._looks_like_base64(cipher_text):
            steps.append("Attempting Base64 decode")
            plaintext = self._try_base64(cipher_text)
            if plaintext is not None:
                score = self._score_english(plaintext)
                candidate = ("base64", plaintext, score, "Decoded as Base64")
                best_result = self._pick_better(best_result, candidate)

        if "hex" in analysis["detected_types"] or self._looks_like_hex(cipher_text):
            steps.append("Attempting hex decode")
            plaintext = self._try_hex(cipher_text)
            if plaintext is not None:
                score = self._score_english(plaintext)
                candidate = ("hex", plaintext, score, "Decoded as hex")
                best_result = self._pick_better(best_result, candidate)

        if "single_byte_xor" in analysis["detected_types"]:
            steps.append("Attempting single-byte XOR brute force")
            key, plaintext, score = self._best_single_byte_xor(cipher_text)
            candidate = ("single_byte_xor", plaintext, score, f"Best XOR key: {key}")
            best_result = self._pick_better(best_result, candidate)

        if best_result is not None:
            method, plaintext, score, detail = best_result
            steps.append(f"Selected method: {method}")
            steps.append(detail)
            steps.append(f"Recovered plaintext: {plaintext}")
            steps.append(f"English score: {score:.2f}")
            flag = plaintext
        else:
            steps.append("No implemented solver succeeded")

        return {
            "challenge_id": challenge.get("id"),
            "agent_id": self.agent_id,
            "status": "solved" if flag else "attempted",
            "flag": flag,
            "steps": steps,
            "cipher_types": analysis["detected_types"],
        }

    def get_capabilities(self) -> List[str]:
        return self.capabilities

    def _plan_approach(self, cipher_types: List[str]) -> str:
        if not cipher_types:
            return "General cryptanalysis and cipher identification"
        return f"Focus on {', '.join(cipher_types)}"

    def _extract_ciphertext(self, challenge: Dict[str, Any]) -> str:
        description = challenge.get("description", "")

        m = re.search(r"'([^']+)'", description)
        if m:
            return m.group(1).strip()

        m = re.search(r'"([^"]+)"', description)
        if m:
            return m.group(1).strip()

        return description.strip()

    def _pick_better(
        self,
        current: Optional[Tuple[str, str, float, str]],
        candidate: Tuple[str, str, float, str],
    ) -> Tuple[str, str, float, str]:
        if current is None:
            return candidate
        return candidate if candidate[2] > current[2] else current

    def _best_caesar_candidate(self, cipher_text: str) -> Tuple[int, str, float]:
        candidates = []
        for shift in range(1, 26):
            plain = self._caesar_decrypt(cipher_text, shift)
            score = self._score_english(plain)
            candidates.append((shift, plain, score))

        candidates.sort(key=lambda x: x[2], reverse=True)
        return candidates[0]

    def _caesar_decrypt(self, text: str, shift: int) -> str:
        result = []
        for ch in text:
            if ch.isalpha():
                base = ord("A") if ch.isupper() else ord("a")
                result.append(chr((ord(ch) - base - shift) % 26 + base))
            else:
                result.append(ch)
        return "".join(result)

    def _looks_like_base64(self, text: str) -> bool:
        compact = re.sub(r"\s+", "", text)
        if len(compact) < 8 or len(compact) % 4 != 0:
            return False
        return bool(re.fullmatch(r"[A-Za-z0-9+/=]+", compact))

    def _try_base64(self, text: str) -> Optional[str]:
        try:
            compact = re.sub(r"\s+", "", text)
            decoded = base64.b64decode(compact, validate=True)
            return decoded.decode("utf-8", errors="ignore")
        except Exception:
            return None

    def _looks_like_hex(self, text: str) -> bool:
        compact = re.sub(r"\s+", "", text)
        return len(compact) >= 8 and len(compact) % 2 == 0 and bool(re.fullmatch(r"[0-9a-fA-F]+", compact))

    def _try_hex(self, text: str) -> Optional[str]:
        try:
            compact = re.sub(r"\s+", "", text)
            decoded = bytes.fromhex(compact)
            return decoded.decode("utf-8", errors="ignore")
        except Exception:
            return None

    def _best_single_byte_xor(self, cipher_text: str) -> Tuple[int, str, float]:
        raw = self._parse_cipher_bytes(cipher_text)
        if raw is None:
            return 0, "", float("-inf")

        best_key = 0
        best_plain = ""
        best_score = float("-inf")

        for key in range(256):
            plain_bytes = bytes(b ^ key for b in raw)
            plain = plain_bytes.decode("utf-8", errors="ignore")
            score = self._score_english(plain)
            if score > best_score:
                best_key = key
                best_plain = plain
                best_score = score

        return best_key, best_plain, best_score

    def _parse_cipher_bytes(self, text: str) -> Optional[bytes]:
        compact = re.sub(r"\s+", "", text)

        if self._looks_like_hex(compact):
            try:
                return bytes.fromhex(compact)
            except ValueError:
                return None

        try:
            return text.encode("utf-8")
        except Exception:
            return None

    def _score_english(self, text: str) -> float:
        lowered = text.lower()
        words = re.findall(r"[a-z]+", lowered)

        if not words:
            return float("-inf")

        score = 0.0

        common_word_hits = sum(1 for w in words if w in self.common_words)
        score += common_word_hits * 8.0

        for token in [" the ", " and ", " to ", " of ", " in ", " he ", " it ", " if "]:
            if token in f" {lowered} ":
                score += 6.0

        letters = [c for c in lowered if c.isalpha()]
        if letters:
            vowel_ratio = sum(c in "aeiou" for c in letters) / len(letters)
            if 0.25 <= vowel_ratio <= 0.45:
                score += 8.0
            else:
                score -= abs(vowel_ratio - 0.35) * 20.0

        avg_word_len = sum(len(w) for w in words) / len(words)
        if 2.5 <= avg_word_len <= 7.5:
            score += 4.0

        weird_chars = sum(not (c.isalpha() or c.isspace() or c in ".,!?;:'\"-{}_()[]") for c in text)
        score -= weird_chars * 2.5

        if re.search(r"[bcdfghjklmnpqrstvwxyz]{6,}", lowered):
            score -= 10.0

        for pattern in ["ing", "tion", "ed", "er", "th", "he", "an", "re"]:
            score += lowered.count(pattern) * 0.8

        return score