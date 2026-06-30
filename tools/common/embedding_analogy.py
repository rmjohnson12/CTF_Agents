"""Deterministic word-embedding analogy recovery for text artifacts."""

from __future__ import annotations

import os
import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Optional


_ANALOGY_RE = re.compile(r"^Like (.*?) is to (.*?), (.*?) is to\?$", re.UNICODE)
_SUPPORTED_MODELS = {
    "glove-twitter-25",
    "glove-twitter-50",
    "glove-twitter-100",
    "glove-twitter-200",
}


@dataclass(frozen=True)
class EmbeddingAnalogyResult:
    text: str
    answers: tuple[str, ...]
    model_name: str


def parse_analogies(lines: Iterable[str]) -> Optional[list[tuple[str, str, str]]]:
    """Parse a complete ``Like A is to B, C is to?`` artifact."""
    parsed: list[tuple[str, str, str]] = []
    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue
        match = _ANALOGY_RE.fullmatch(line)
        if match is None:
            return None
        parsed.append(match.groups())
    return parsed if len(parsed) >= 2 else None


def is_embedding_analogy_file(path: str) -> bool:
    """Cheap artifact-level routing check that does not load an ML model."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return parse_analogies(handle) is not None
    except (OSError, UnicodeError):
        return False


def model_name_from_description(description: str) -> str:
    """Select a supported model named by the challenge, or the common default."""
    lowered = description.lower().replace("_", "-")
    for model_name in sorted(_SUPPORTED_MODELS):
        if model_name in lowered:
            return model_name
    return "glove-twitter-25"


def load_gensim_model(model_name: str) -> Any:
    """Load a supported Gensim model, requiring opt-in for a new download."""
    if model_name not in _SUPPORTED_MODELS:
        raise ValueError(f"Unsupported embedding model: {model_name}")

    import gensim.downloader as api

    cached_model = Path(api.BASE_DIR) / model_name
    if not cached_model.is_dir() and os.getenv("CTF_AGENTS_ALLOW_MODEL_DOWNLOAD") != "1":
        raise RuntimeError(
            f"Embedding model {model_name!r} is not cached. Set "
            "CTF_AGENTS_ALLOW_MODEL_DOWNLOAD=1 to permit Gensim to download it."
        )
    return api.load(model_name)


class EmbeddingAnalogySolver:
    """Solve analogies using raw vector offsets and ASCII-only candidates."""

    def __init__(self, model_loader: Callable[[str], Any] = load_gensim_model) -> None:
        self._model_loader = model_loader

    def solve_file(
        self,
        path: str,
        *,
        description: str = "",
    ) -> Optional[EmbeddingAnalogyResult]:
        try:
            with open(path, "r", encoding="utf-8") as handle:
                analogies = parse_analogies(handle)
        except (OSError, UnicodeError):
            return None
        if analogies is None:
            return None

        model_name = model_name_from_description(description)
        model = self._model_loader(model_name)
        answers = self._solve_analogies(model, analogies)
        return EmbeddingAnalogyResult(
            text="".join(answers),
            answers=tuple(answers),
            model_name=model_name,
        )

    @staticmethod
    def _solve_analogies(
        model: Any,
        analogies: list[tuple[str, str, str]],
    ) -> list[str]:
        import numpy as np

        missing = sorted({word for row in analogies for word in row if word not in model})
        if missing:
            preview = ", ".join(repr(word) for word in missing[:5])
            raise ValueError(f"Embedding vocabulary is missing: {preview}")

        candidate_indices = np.asarray([
            index
            for index, word in enumerate(model.index_to_key)
            if unicodedata.normalize("NFKC", word).isascii()
        ], dtype=np.int64)
        if candidate_indices.size == 0:
            raise ValueError("Embedding vocabulary contains no ASCII candidates")
        candidate_vectors = model.get_normed_vectors()[candidate_indices]

        answers: list[str] = []
        for left, right, query in analogies:
            # Modern Gensim most_similar() normalizes each input first, which
            # changes the intended answer for this family of challenges.
            target = model[right] - model[left] + model[query]
            norm = float(np.linalg.norm(target))
            if norm == 0:
                raise ValueError(f"Analogy produced a zero vector: {left}:{right}::{query}")
            scores = candidate_vectors @ (target / norm)

            for source_word in (left, right, query):
                source_index = model.key_to_index[source_word]
                position = int(np.searchsorted(candidate_indices, source_index))
                if position < candidate_indices.size and candidate_indices[position] == source_index:
                    scores[position] = -np.inf

            best_index = int(candidate_indices[int(np.argmax(scores))])
            answers.append(unicodedata.normalize("NFKC", model.index_to_key[best_index]))

        return answers
