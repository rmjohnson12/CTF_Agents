import csv
import json
import struct
import zipfile

from agents.specialists.hardware_logic.hardware_agent import HardwareLogicAgent


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
