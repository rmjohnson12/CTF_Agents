"""
Core system components
"""

from core._version import __version__
from core.challenge import Challenge, ChallengeCategory, ChallengeDifficulty, ChallengeStatus

__all__ = [
    '__version__',
    'Challenge',
    'ChallengeCategory',
    'ChallengeDifficulty',
    'ChallengeStatus',
]
