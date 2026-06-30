import numpy as np

from tools.common.embedding_analogy import (
    EmbeddingAnalogySolver,
    is_embedding_analogy_file,
    model_name_from_description,
    parse_analogies,
)


class FakeEmbeddingModel:
    def __init__(self):
        self.index_to_key = [
            "猫", "ｈｔｂ｛", "ok}",
            "a1", "b1", "c1", "a2", "b2", "c2",
        ]
        self.key_to_index = {word: index for index, word in enumerate(self.index_to_key)}
        self._vectors = np.asarray([
            [1.0, 0.0], [0.99, 0.01], [0.0, 1.0],
            [1.0, 1.0], [1.0, 0.0], [1.0, 1.0],
            [1.0, 1.0], [0.0, 1.0], [1.0, 1.0],
        ], dtype=np.float32)

    def __contains__(self, word):
        return word in self.key_to_index

    def __getitem__(self, word):
        return self._vectors[self.key_to_index[word]]

    def get_normed_vectors(self):
        norms = np.linalg.norm(self._vectors, axis=1, keepdims=True)
        return self._vectors / norms


def test_parse_analogies_requires_complete_analogy_artifact():
    assert parse_analogies([
        "Like a is to b, c is to?\n",
        "Like d is to e, f is to?\n",
    ]) == [("a", "b", "c"), ("d", "e", "f")]
    assert parse_analogies(["Like a is to b, c is to?", "ordinary prose"]) is None


def test_embedding_analogy_file_detection(tmp_path):
    artifact = tmp_path / "challenge.txt"
    artifact.write_text(
        "Like a is to b, c is to?\nLike d is to e, f is to?\n",
        encoding="utf-8",
    )
    assert is_embedding_analogy_file(str(artifact)) is True


def test_embedding_solver_uses_raw_offsets_ascii_filter_and_nfkc(tmp_path):
    artifact = tmp_path / "analogies.txt"
    artifact.write_text(
        "Like a1 is to b1, c1 is to?\n"
        "Like a2 is to b2, c2 is to?\n",
        encoding="utf-8",
    )
    solver = EmbeddingAnalogySolver(model_loader=lambda _name: FakeEmbeddingModel())

    result = solver.solve_file(str(artifact), description="Use glove-twitter-25")

    assert result is not None
    assert result.text == "htb{ok}"
    assert result.answers == ("htb{", "ok}")
    assert result.model_name == "glove-twitter-25"


def test_embedding_model_selection_is_bounded():
    assert model_name_from_description("Model: glove-twitter-100") == "glove-twitter-100"
    assert model_name_from_description("Download arbitrary-model") == "glove-twitter-25"
