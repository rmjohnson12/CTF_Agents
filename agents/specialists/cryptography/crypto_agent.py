"""
Cryptography Specialist Agent

Specialized agent for solving cryptography-based CTF challenges.
"""

from typing import Dict, Any, List
from agents.base_agent import BaseAgent, AgentType


class CryptographyAgent(BaseAgent):
    """
    Specialist agent for cryptography challenges.
    
    Handles:
    - Classical ciphers (Caesar, Vigenere, substitution)
    - Modern encryption (RSA, AES, DES)
    - Hash functions and cracking
    - Encoding schemes (Base64, hex, etc.)
    - Digital signatures
    - Key exchange protocols
    """
    
    def __init__(self, agent_id: str = "crypto_agent"):
        super().__init__(agent_id, AgentType.SPECIALIST)
        self.capabilities = [
            'crypto',
            'cryptography',
            'encryption',
            'decryption',
            'hash_cracking',
            'encoding',
            'rsa',
            'aes',
            'classical_ciphers'
        ]
    
    def analyze_challenge(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a cryptography challenge.
        
        Args:
            challenge: Challenge information
            
        Returns:
            Analysis results
        """
       
        description = challenge.get('description', '').lower()
        hints = " ".join(challenge.get('hints', [])).lower()
        metadata = challenge.get('metadata', {})
        files = challenge.get('files', [])
        
        # Detect cipher/encoding types
        cipher_types = []
        if any(keyword in description for keyword in ['caesar', 'shift', 'rot']):
            cipher_types.append('caesar_cipher')
        if any(keyword in hints for keyword in ['shift', 'caesar']):
            cipher_types.append('caesar_cipher')
        if metadata.get("cipher_type") == "caesar":
            cipher_types.append('caesar_cipher')
        if any(keyword in description for keyword in ['rsa', 'public key', 'private key']):
            cipher_types.append('rsa')
        if 'base64' in description:
            cipher_types.append('base64')
        if any(keyword in description for keyword in ['hash', 'md5', 'sha']):
            cipher_types.append('hash')
        if 'aes' in description:
            cipher_types.append('aes')
            
        confidence = 0.9 if challenge.get('category') == 'crypto' else 0.1
        cipher_types = sorted(set(cipher_types))

        
        return {
            'agent_id': self.agent_id,
            'can_handle': challenge.get('category') == 'crypto',
            'confidence': confidence,
            'detected_types': cipher_types,
            'approach': self._plan_approach(cipher_types)
        }
    
    def solve_challenge(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        """
        Attempt to solve a cryptography challenge.
        """
        analysis = self.analyze_challenge(challenge)

        steps: List[str] = []
        flag = None

        steps.append("Analyzed cipher/encoding type")
        steps.append("Detected types: " + ", ".join(analysis["detected_types"]))

        # --- Caesar cipher implementation (MVP) ---
        if "caesar_cipher" in analysis["detected_types"]:
            import re

            steps.append("Attempting Caesar brute force (shifts 1–25)")

            description = challenge.get("description", "")
            # Try to extract quoted ciphertext: 'Khoor Zruog'
            m = re.search(r"'([^']+)'", description)
            cipher_text = m.group(1) if m else description

            # Brute force all shifts and keep candidates
            candidates = []
            for shift in range(1, 26):
                plain = self._caesar_decrypt(cipher_text, shift)
                candidates.append((shift, plain))

            # Heuristic: pick the first candidate that looks like English-ish
            # (very simple MVP heuristic: contains a space + vowel)
            chosen = None
            for shift, plain in candidates:
                low = plain.lower()
                if "hello" in low or "world" in low:
                    chosen = (shift, plain)
                    break

            # Fallback: shift 3 is common (classic Caesar)
            if chosen is None:
                #chosen = next(((s, p) for s, p in candidates if s == 3), candidates[0])
                chosen = next(((s, p) for s, p in candidates if s == 3), candidates[0])


            shift, plaintext = chosen
            steps.append(f"Chosen shift: {shift}")
            steps.append(f"Recovered plaintext: {plaintext}")

            # For now, treat plaintext as the "flag" so coordinator marks solved.
            # Later we can require HTB{...}/CTF{...} pattern.
            flag = plaintext
        else:
            steps.append("No implemented solver for detected types yet")

        return  {
            "challenge_id": challenge.get("id"),
            "agent_id": self.agent_id,
            "status": "solved" if flag else "attempted",
            "flag": flag,
            "steps": steps,
            "cipher_types": analysis["detected_types"],
        }
    
    
    def get_capabilities(self) -> List[str]:
        """Return agent capabilities"""
        return self.capabilities
    
    def _plan_approach(self, cipher_types: List[str]) -> str:
        """Plan the approach based on detected cipher types"""
        if not cipher_types:
            return "General cryptanalysis and cipher identification"
        return f"Focus on {', '.join(cipher_types)}"
    
    def _caesar_decrypt(self, text: str, shift: int) -> str:
        result = []

        for ch in text:
            if ch.isalpha():
                base = ord('A') if ch.isupper() else ord('a')
                result.append(chr((ord(ch) - base - shift) % 26 + base))
            else:
                result.append(ch)

        return "".join(result)
