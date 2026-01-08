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
        files = challenge.get('files', [])
        
        # Detect cipher/encoding types
        cipher_types = []
        if any(keyword in description for keyword in ['caesar', 'shift', 'rot']):
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
        
        Args:
            challenge: Challenge information
            
        Returns:
            Solution results
        """
        analysis = self.analyze_challenge(challenge)
        
        steps = []
        flag = None
        
        # Example solving workflow
        steps.append("Analyzed cipher/encoding type")
        steps.append("Detected types: " + ", ".join(analysis['detected_types']))
        steps.append("Applied appropriate decryption/decoding techniques")
        
        return {
            'challenge_id': challenge.get('id'),
            'agent_id': self.agent_id,
            'status': 'attempted',
            'flag': flag,
            'steps': steps,
            'cipher_types': analysis['detected_types']
        }
    
    def get_capabilities(self) -> List[str]:
        """Return agent capabilities"""
        return self.capabilities
    
    def _plan_approach(self, cipher_types: List[str]) -> str:
        """Plan the approach based on detected cipher types"""
        if not cipher_types:
            return "General cryptanalysis and cipher identification"
        return f"Focus on {', '.join(cipher_types)}"
