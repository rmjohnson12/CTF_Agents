import struct

from core.utils.firmware_signatures import (
    looks_like_esp32_firmware,
    category_for_file,
    category_for_files,
)
from agents.coordinator.coordinator_agent import CoordinatorAgent


def _write_synthetic_esp32(path, app_offset=0x1000):
    """Minimal but valid ESP32 flash dump: partition table magic at 0x8000 and
    one app-type entry pointing at an ESP image magic (0xE9)."""
    data = bytearray(0x9000)
    data[app_offset] = 0xE9  # ESP image magic at the referenced app offset
    entry = struct.pack("<HBBII16sI", 0x50AA, 0, 0, app_offset, 0x1000, b"factory", 0)
    data[0x8000:0x8000 + len(entry)] = entry
    path.write_bytes(bytes(data))
    return path


def test_detects_valid_esp32_dump(tmp_path):
    fw = _write_synthetic_esp32(tmp_path / "firmware.bin")
    assert looks_like_esp32_firmware(str(fw)) is True
    assert category_for_file(str(fw)) == "hardware"


def test_rejects_non_esp32_binary(tmp_path):
    blob = tmp_path / "random.bin"
    blob.write_bytes(b"\x00" * 0x9000)
    assert looks_like_esp32_firmware(str(blob)) is False
    assert category_for_file(str(blob)) is None


def test_rejects_too_small_file(tmp_path):
    small = tmp_path / "tiny.bin"
    small.write_bytes(b"\xaa\x50" * 8)
    assert looks_like_esp32_firmware(str(small)) is False


def test_rejects_magic_without_app_image(tmp_path):
    # Partition magic present but the app entry does not point at an ESP image.
    data = bytearray(0x9000)
    entry = struct.pack("<HBBII16sI", 0x50AA, 0, 0, 0x1000, 0x1000, b"factory", 0)
    data[0x8000:0x8000 + len(entry)] = entry  # data[0x1000] stays 0x00, not 0xE9
    blob = tmp_path / "noapp.bin"
    blob.write_bytes(bytes(data))
    assert looks_like_esp32_firmware(str(blob)) is False


def test_missing_file_is_safe():
    assert looks_like_esp32_firmware("/no/such/file.bin") is False
    assert category_for_files(["/no/such/file.bin", None, ""]) is None


def test_content_override_corrects_misclassified_category(tmp_path):
    fw = _write_synthetic_esp32(tmp_path / "firmware.bin")
    challenge = {"id": "c", "category": "reverse", "files": [str(fw)]}

    applied = CoordinatorAgent._apply_content_based_category(challenge)

    assert applied == "hardware"
    assert challenge["category"] == "hardware"
    assert challenge["_content_category_override"] == {"hardware": "reverse"}


def test_content_override_noop_when_already_correct(tmp_path):
    fw = _write_synthetic_esp32(tmp_path / "firmware.bin")
    challenge = {"id": "c", "category": "hardware", "files": [str(fw)]}

    assert CoordinatorAgent._apply_content_based_category(challenge) is None
    assert challenge["category"] == "hardware"


def test_content_override_noop_without_recognized_artifact(tmp_path):
    blob = tmp_path / "x.bin"
    blob.write_bytes(b"\x00" * 0x9000)
    challenge = {"id": "c", "category": "reverse", "files": [str(blob)]}

    assert CoordinatorAgent._apply_content_based_category(challenge) is None
    assert challenge["category"] == "reverse"
