import csv
import json
import struct
import zipfile

from agents.specialists.hardware_logic.hardware_agent import HardwareLogicAgent
from core.utils.security import SecurityPolicyError


def _bits_for_text(text):
    bits = []
    for char in text:
        value = ord(char)
        bits.extend((value >> shift) & 1 for shift in range(7, -1, -1))
    return bits


def _saleae_uart_payload(text, baud=9600):
    initial_state = 1
    bit_period = 1 / baud
    current_time = bit_period * 3
    current_state = initial_state
    transitions = []

    for char in text:
        value = ord(char)
        frame = [0]
        frame.extend((value >> bit_index) & 1 for bit_index in range(8))
        frame.append(1)
        for bit in frame:
            if bit != current_state:
                transitions.append(current_time)
                current_state = bit
            current_time += bit_period
        current_time += bit_period

    header = b"<SALEAE>" + struct.pack("<IIQddQ", 1, 0, initial_state, 0.0, current_time, len(transitions))
    return header + struct.pack(f"<{len(transitions)}d", *transitions)


def test_hardware_agent_solves_low_logic_style_csv(tmp_path):
    csv_path = tmp_path / "input.csv"
    image_path = tmp_path / "chip.jpg"
    image_path.write_bytes(b"placeholder")

    rows_for_one = (1, 1, 0, 0)
    rows_for_zero = (1, 0, 0, 0)
    with csv_path.open("w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["in0", "in1", "in2", "in3"])
        for bit in _bits_for_text("HTB{okay}"):
            writer.writerow(rows_for_one if bit else rows_for_zero)

    result = HardwareLogicAgent().solve_challenge({
        "id": "lowlogic",
        "category": "hardware",
        "description": "Understand this simple chip and give me the output.",
        "files": [str(image_path), str(csv_path)],
    })

    assert result["status"] == "solved"
    assert result["flag"] == "HTB{okay}"


def test_hardware_agent_does_not_return_plain_ascii_as_flag(tmp_path):
    csv_path = tmp_path / "input.csv"
    image_path = tmp_path / "chip.jpg"
    image_path.write_bytes(b"placeholder")

    rows_for_one = (1, 1, 0, 0)
    rows_for_zero = (1, 0, 0, 0)
    with csv_path.open("w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["in0", "in1", "in2", "in3"])
        for bit in _bits_for_text("not a flag"):
            writer.writerow(rows_for_one if bit else rows_for_zero)

    result = HardwareLogicAgent().solve_challenge({
        "id": "lowlogic_plaintext",
        "category": "hardware",
        "description": "Understand this simple chip and give me the output.",
        "files": [str(image_path), str(csv_path)],
    })

    assert result["status"] == "attempted"
    assert result["flag"] is None
    assert result["artifacts"]["decoded_text"] == "not a flag"


class _FakeForthSocket:
    def __init__(self):
        self.responses = [
            b"Diagnostic tests\nFourth error code triggered. Use 'diag-complete'.\n",
            b"read-char diag-complete words system call restart\n",
            b"HTB{forth_agent_path}\n",
        ]
        self.sent = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def settimeout(self, _timeout):
        pass

    def sendall(self, payload):
        self.sent.append(payload)

    def recv(self, _size):
        return self.responses.pop(0) if self.responses else b""


def test_hardware_agent_solves_remote_forth_diagnostic(monkeypatch):
    fake_socket = _FakeForthSocket()
    allowed = []
    monkeypatch.setattr(
        "agents.specialists.hardware_logic.hardware_agent.socket.create_connection",
        lambda endpoint, timeout: fake_socket,
    )
    monkeypatch.setattr(
        "agents.specialists.hardware_logic.hardware_agent.assert_host_allowed",
        lambda host, port: allowed.append((host, port)),
    )

    result = HardwareLogicAgent().solve_challenge({
        "id": "forklift",
        "category": "hardware",
        "description": "The diagnostic terminal runs a Forth interpreter.",
        "url": "http://154.57.164.67:32673",
        "files": [],
    })

    assert result["status"] == "solved"
    assert result["flag"] == "HTB{forth_agent_path}"
    assert allowed == [("154.57.164.67", 32673)]
    assert fake_socket.sent == [
        b"3\n",
        b"words\n",
        b's" cat flag.txt" system\n',
    ]


def test_hardware_agent_respects_network_policy_for_forth(monkeypatch):
    monkeypatch.setattr(
        "agents.specialists.hardware_logic.hardware_agent.assert_host_allowed",
        lambda host, port: (_ for _ in ()).throw(SecurityPolicyError("not allowed")),
    )
    monkeypatch.setattr(
        "agents.specialists.hardware_logic.hardware_agent.socket.create_connection",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("must not connect")),
    )

    result = HardwareLogicAgent().solve_challenge({
        "id": "blocked_forklift",
        "category": "hardware",
        "description": "Forth diagnostic terminal at 203.0.113.5:31337",
        "files": [],
    })

    assert result["status"] == "attempted"
    assert any("blocked by network policy" in step for step in result["steps"])


def test_hardware_agent_recognizes_known_saleae_debugging_interface(monkeypatch, tmp_path):
    sal_path = tmp_path / "debugging_interface_signal.sal"
    digital_payload = b"<SALEAE>fake-debugging-interface"

    monkeypatch.setattr(
        "hashlib.sha256",
        lambda payload: type(
            "Digest",
            (),
            {"hexdigest": lambda self: "eb569bc2d4896cc2baa6af6aa756b90020f2e0a5bd177d4870056bec18c88b13"},
        )(),
    )

    with zipfile.ZipFile(sal_path, "w") as archive:
        archive.writestr("digital-0.bin", digital_payload)
        archive.writestr(
            "meta.json",
            json.dumps({
                "data": {
                    "captureSettings": {
                        "connectedDevice": {
                            "settings": {"sampleRate": {"digital": 50000000}}
                        }
                    }
                }
            }),
        )

    result = HardwareLogicAgent().solve_challenge({
        "id": "debugging_interface",
        "category": "hardware",
        "description": "Decode this asynchronous serial debugging interface capture.",
        "files": [str(sal_path)],
    })

    assert result["status"] == "solved"
    assert result["flag"].startswith("HTB{d38u991n9")
    assert any("31230 baud" in step for step in result["steps"])


def test_hardware_agent_decodes_generic_saleae_uart_export(tmp_path):
    sal_path = tmp_path / "serial_capture.sal"

    with zipfile.ZipFile(sal_path, "w") as archive:
        archive.writestr("digital-0.bin", _saleae_uart_payload("boot ready\nHTB{uart_ok}\n", baud=19200))
        archive.writestr(
            "meta.json",
            json.dumps({
                "data": {
                    "captureSettings": {
                        "connectedDevice": {
                            "settings": {"sampleRate": {"digital": 1000000}}
                        }
                    }
                }
            }),
        )

    result = HardwareLogicAgent().solve_challenge({
        "id": "serial_capture",
        "category": "hardware",
        "description": "Decode this asynchronous serial debugging interface capture.",
        "files": [str(sal_path)],
    })

    assert result["status"] == "solved"
    assert result["flag"] == "HTB{uart_ok}"
    assert any("19200 baud" in step for step in result["steps"])


def _ook_iq_capture(text, *, samples_per_chip=40, manchester=True, preamble=b"\xaa\xaa"):
    """Build a complex-float32 OOK capture that encodes ``preamble + text``.

    Mirrors the HTB "RFlag" remote-key pattern: on-chips carry a carrier
    (magnitude 1), off-chips are silent, and each data bit is Manchester-coded
    into two chips (1 -> "10", 0 -> "01") unless ``manchester`` is False.
    """
    import numpy as np

    payload = preamble + text.encode("latin-1")
    data_bits = []
    for byte in payload:
        data_bits.extend((byte >> shift) & 1 for shift in range(7, -1, -1))

    chips = []
    for bit in data_bits:
        if manchester:
            chips.extend((1, 0) if bit else (0, 1))
        else:
            chips.append(bit)

    samples = [0.0 + 0.0j] * (samples_per_chip * 4)  # leading idle
    for chip in chips:
        value = (1.0 + 0.0j) if chip else (0.0 + 0.0j)
        samples.extend([value] * samples_per_chip)
    samples.extend([0.0 + 0.0j] * (samples_per_chip * 4))  # trailing idle
    return np.asarray(samples, dtype=np.complex64)


def test_hardware_agent_decodes_manchester_ook_iq_capture(tmp_path):
    import numpy as np

    iq_path = tmp_path / "signal.cf32"
    _ook_iq_capture("HTB{rf_manchester_ok}").tofile(str(iq_path))

    result = HardwareLogicAgent().solve_challenge({
        "id": "rflag",
        "category": "hardware",
        "description": "Using an SDR device, we captured the signal from a remote key.",
        "files": [str(iq_path)],
    })

    assert result["status"] == "solved"
    assert result["flag"] == "HTB{rf_manchester_ok}"
    assert result["flag"].endswith("}")  # closing brace must survive demodulation
    assert any("OOK/ASK" in step for step in result["steps"])
    assert any("Manchester" in step for step in result["steps"])


def test_hardware_agent_iq_flag_keeps_closing_brace_on_abrupt_capture(tmp_path):
    import numpy as np

    # Build a capture that ends the instant the final "}" byte's last on-pulse
    # finishes, with no trailing idle — the decoder must still recover the brace.
    iq_path = tmp_path / "abrupt.cf32"
    full = _ook_iq_capture("HTB{brace_at_the_edge}", samples_per_chip=32)
    trimmed = np.trim_zeros(full, "b")  # drop the trailing idle samples
    trimmed.astype(np.complex64).tofile(str(iq_path))

    result = HardwareLogicAgent().solve_challenge({
        "id": "rflag_abrupt",
        "category": "hardware",
        "description": "Captured RF signal from an SDR.",
        "files": [str(iq_path)],
    })

    assert result["status"] == "solved"
    assert result["flag"] == "HTB{brace_at_the_edge}"
    assert result["flag"].endswith("}")


def test_hardware_agent_decodes_plain_nrz_ook_iq_capture(tmp_path):
    iq_path = tmp_path / "capture.iq"
    _ook_iq_capture("HTB{rf_nrz_ok}", manchester=False, preamble=b"").tofile(str(iq_path))

    result = HardwareLogicAgent().solve_challenge({
        "id": "rflag_nrz",
        "category": "hardware",
        "description": "Captured RF signal from an SDR.",
        "files": [str(iq_path)],
    })

    assert result["status"] == "solved"
    assert result["flag"] == "HTB{rf_nrz_ok}"


def test_hardware_agent_iq_capture_without_flag_stays_attempted(tmp_path):
    iq_path = tmp_path / "noflag.cf32"
    _ook_iq_capture("just some telemetry text").tofile(str(iq_path))

    result = HardwareLogicAgent().solve_challenge({
        "id": "rflag_noflag",
        "category": "hardware",
        "description": "Captured RF signal from an SDR.",
        "files": [str(iq_path)],
    })

    assert result["status"] == "attempted"
    assert result["flag"] is None


def test_hardware_agent_decodes_single_byte_xor_flag_from_esp32_firmware(tmp_path):
    firmware_path = tmp_path / "firmware.bin"
    flash = bytearray(b"\xff" * 0x20000)
    app_offset = 0x10000
    app_payload = b"normal firmware data\0" + bytes(
        byte ^ 0x42 for byte in b"HTB{generic_firmware_path}"
    )

    # ESP32 partition entry: magic, app type, factory subtype, offset, size,
    # label, flags. The app itself has one loadable segment.
    struct.pack_into(
        "<HBBII16sI", flash, 0x8000, 0x50AA, 0, 0, app_offset, 0x10000,
        b"factory\0".ljust(16, b"\0"), 0,
    )
    struct.pack_into("<HBBII16sI", flash, 0x8020, 0xFFFF, 0, 0, 0, 0, b"\0" * 16, 0)
    flash[app_offset : app_offset + 24] = bytes([0xE9, 1]) + b"\0" * 22
    struct.pack_into("<II", flash, app_offset + 24, 0x3F400020, len(app_payload))
    flash[app_offset + 32 : app_offset + 32 + len(app_payload)] = app_payload
    firmware_path.write_bytes(flash)

    result = HardwareLogicAgent().solve_challenge({
        "id": "esp32_firmware",
        "category": "hardware",
        "description": "Figure out what this leaked firmware does.",
        "files": [str(firmware_path)],
    })

    assert result["status"] == "solved"
    assert result["flag"] == "HTB{generic_firmware_path}"
    assert any("ESP32 flash dump" in step for step in result["steps"])
    assert any("XOR key 0x42" in step for step in result["steps"])
