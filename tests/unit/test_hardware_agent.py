import csv

from agents.specialists.hardware_logic.hardware_agent import HardwareLogicAgent


def _bits_for_text(text):
    bits = []
    for char in text:
        value = ord(char)
        bits.extend((value >> shift) & 1 for shift in range(7, -1, -1))
    return bits


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
