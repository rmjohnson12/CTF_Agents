import zipfile
from html import escape

from agents.specialists.forensics.forensics_agent import ForensicsAgent


class _NoopTool:
    def run(self, *_args, **_kwargs):
        return type("Result", (), {})()


class _NoopStringsTool:
    def run(self, *_args, **_kwargs):
        return type("Result", (), {"strings": []})()


def _svg(char: str, x: int) -> str:
    escaped = escape(char)
    return f"""<?xml version="1.0" standalone="no"?>
<svg xmlns="http://www.w3.org/2000/svg" width="420.96pt" height="297.6pt">
  <text transform="translate({x}, 80.0)" style="font-size: 12;white-space: pre-wrap;">{escaped}</text>
</svg>
"""


def test_forensics_agent_reconstructs_hidden_krita_svg_flag(tmp_path):
    flag = "SVIBGR{Kik!_s@y$_T3ch_w/_<3!}"
    archive_path = tmp_path / "finalsvibgr.zip"
    layer_xml = "\n".join(
        f'<layer name="Vector Layer {idx}" filename="layer{idx}" visible="0" nodetype="shapelayer"/>'
        for idx, _char in enumerate(flag, start=16)
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("mimetype", "application/x-krita")
        archive.writestr("maindoc.xml", f"<DOC><IMAGE><layers>{layer_xml}</layers></IMAGE></DOC>")
        for idx, char in enumerate(flag, start=16):
            archive.writestr(f"finalsvi/layers/layer{idx}.shapelayer/content.svg", _svg(char, idx * 10))

    agent = ForensicsAgent(
        binwalk_tool=_NoopTool(),
        exiftool_tool=_NoopTool(),
        strings_tool=_NoopStringsTool(),
    )

    result = agent.solve_challenge({
        "id": "krita_hidden_svg",
        "category": "forensics",
        "files": [str(archive_path)],
        "description": "Recover the hidden flag from the drawing.",
    })

    assert result["status"] == "solved"
    assert result["flag"] == flag
    assert any("Reconstructed hidden SVG text" in step for step in result["steps"])
    assert result["artifacts"]["archives"][0]["recovered_text"] == flag
