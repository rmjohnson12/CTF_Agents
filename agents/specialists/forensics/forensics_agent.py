"""
Forensics Specialist Agent

Specialized agent for forensics-based CTF challenges.
"""

import json
import logging
import os
import re
from typing import Dict, Any, List, Optional, Tuple

from config.defaults import DEFAULT_ROCKYOU_PATHS
from agents.base_agent import BaseAgent, AgentType
from tools.forensics.binwalk import BinwalkTool
from tools.forensics.exiftool import ExiftoolTool
from tools.forensics.qpdf import QPDFTool
from tools.network.tshark import TsharkTool
from tools.network.scapy_tool import ScapyTool
from tools.common.strings import StringsTool
from tools.crypto.john import JohnTool
from tools.crypto.hashcat import HashcatTool
from core.utils.flag_utils import find_first_flag

logger = logging.getLogger(__name__)


class ForensicsAgent(BaseAgent):
    """
    Specialist agent for forensics challenges.
    """

    def __init__(
        self, 
        agent_id: str = "forensics_agent", 
        binwalk_tool: Optional[BinwalkTool] = None,
        exiftool_tool: Optional[ExiftoolTool] = None,
        strings_tool: Optional[StringsTool] = None,
        qpdf_tool: Optional[QPDFTool] = None,
        tshark_tool: Optional[TsharkTool] = None,
        scapy_tool: Optional[ScapyTool] = None,
        john_tool: Optional[JohnTool] = None,
        hashcat_tool: Optional[HashcatTool] = None
    ):
        super().__init__(agent_id, AgentType.SPECIALIST)
        self.binwalk_tool = binwalk_tool or BinwalkTool()
        self.exiftool_tool = exiftool_tool or ExiftoolTool()
        self.strings_tool = strings_tool or StringsTool()
        self.qpdf_tool = qpdf_tool or QPDFTool()
        self.tshark_tool = tshark_tool or TsharkTool()
        self.scapy_tool = scapy_tool or ScapyTool()
        self.john_tool = john_tool or JohnTool()
        self.hashcat_tool = hashcat_tool or HashcatTool()
        self.capabilities = [
            "forensics",
            "file_analysis",
            "binwalk",
            "exiftool",
            "strings",
            "pdf_decryption",
            "pcap_analysis",
            "artifact_extraction",
            "steganography",
            "metadata",
        ]

    def analyze_challenge(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        description = challenge.get("description", "").lower()
        files = challenge.get("files", [])
        tags = " ".join(challenge.get("tags", [])).lower()
        
        indicators = ["artifact", "file", "disk", "memory", "pcap", "extract", "binwalk", "forensics"]
        is_forensics = any(k in description or k in tags for k in indicators) or bool(files)
        
        detected_indicators = [k for k in indicators if k in description or k in tags]
        if bool(files):
            detected_indicators.append("files")

        confidence = 0.9 if is_forensics or challenge.get("category") == "forensics" else 0.2

        return {
            "agent_id": self.agent_id,
            "can_handle": is_forensics or challenge.get("category") == "forensics",
            "confidence": confidence,
            "approach": self._plan_approach(detected_indicators),
        }

    def solve_challenge(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        analysis = self.analyze_challenge(challenge)
        steps: List[str] = []
        flag = None

        files = challenge.get("files", [])
        if not files:
            live_result = self._try_live_ssh_forensics(challenge, steps)
            if live_result:
                return live_result

            steps.append("No files provided for forensics analysis.")
            return {
                "challenge_id": challenge.get("id"),
                "agent_id": self.agent_id,
                "status": "failed",
                "flag": None,
                "steps": steps,
            }

        steps.append(f"Analyzing {len(files)} files...")
        all_artifacts = {
            "binwalk": [],
            "exiftool": [],
            "strings": [],
            "pdf": [],
            "pcap": []
        }

        for file_path in files:
            # 0a. PDF Detection & Inspection
            if file_path.lower().endswith(".pdf"):
                steps.append(f"Detected PDF file: {file_path}")
                try:
                    pdf_res = self.qpdf_tool.run(file_path)
                    if pdf_res.is_encrypted:
                        steps.append(f"  [!] PDF is encrypted. Attempting to find password...")
                        
                        # 1. Try common wordlist (rockyou) via John
                        wordlist = next((p for p in DEFAULT_ROCKYOU_PATHS if os.path.exists(p)), None)
                        
                        steps.append(f"  Running pdf2john and john with wordlist: {wordlist or 'incremental'}")
                        
                        # We need the hash first. pdf2john is usually a script.
                        # For simplicity in this wrapper, let's see if we can use john directly or a helper.
                        # Most CTF environments have pdf2john.pl or pdf2john.py.
                        hash_res = self.run_shell_command(["pdf2john.py", file_path])
                        if hash_res.exit_code == 0:
                            pdf_hash = hash_res.stdout.strip()
                            crack_res = self.john_tool.run(pdf_hash, wordlist=wordlist)
                            if crack_res.cracked_password:
                                flag = crack_res.cracked_password
                                steps.append(f"  SUCCESS: PDF password found: {flag}")
                                # Try to actually decrypt to confirm
                                decrypt_res = self.qpdf_tool.run(file_path, password=flag)
                                if decrypt_res.decrypted_path:
                                    steps.append(f"  Successfully decrypted PDF to {decrypt_res.decrypted_path}")
                            else:
                                steps.append("  John could not crack the PDF password.")
                        else:
                            # Fallback: maybe just try john on the file directly if it supports it
                            crack_res = self.john_tool.run(file_path, wordlist=wordlist)
                            if crack_res.cracked_password:
                                flag = crack_res.cracked_password
                                steps.append(f"  SUCCESS: PDF password found via direct john: {flag}")
                            else:
                                steps.append("  Could not extract PDF hash or crack password.")

                        all_artifacts["pdf"].append({
                            "file": file_path,
                            "encrypted": True,
                            "password": flag,
                            "raw_info": pdf_res.raw.stdout or pdf_res.raw.stderr
                        })
                    else:
                        steps.append("  PDF is not encrypted. Proceeding with standard analysis.")
                except Exception as exc:
                    logger.debug("QPDF error on %s: %s", file_path, exc)
                    steps.append(f"  QPDF error: {exc}")

            # 0b. PCAP Detection & Analysis
            if file_path.lower().endswith(".pcap") or file_path.lower().endswith(".pcapng"):
                steps.append(f"Detected PCAP file: {file_path}")
                try:
                    # 1. Summary (IPs/Hosts)
                    pcap_res = self.tshark_tool.run(file_path)
                    steps.append(f"  Extracted {len(pcap_res.ips)} unique IPs and {len(pcap_res.hostnames)} hostnames.")
                    
                    # 2. Stream Reconstruction (Deep Analysis with Scapy)
                    steps.append("  Deep stream reconstruction (Scapy)...")
                    scapy_streams = self.scapy_tool.reconstruct_all_streams(file_path)
                    for i, stream in enumerate(scapy_streams):
                        # Combine c2s and s2c for full text search, but also analyze individually
                        stream_text_c2s = stream.data_c2s.decode('utf-8', errors='ignore')
                        stream_text_s2c = stream.data_s2c.decode('utf-8', errors='ignore')
                        
                        # Standard flag check
                        for text in [stream_text_c2s, stream_text_s2c]:
                            found_flag = find_first_flag(text)
                            if found_flag and not flag:
                                flag = found_flag
                                steps.append(f"  Flag found in stream {i}: {flag}")
                        
                        # Raw protocol analysis (custom structures)
                        if not flag:
                            # Try both directions
                            for raw_data in [stream.data_c2s, stream.data_s2c]:
                                raw_flag = self._analyze_raw_protocol(raw_data)
                                if raw_flag:
                                    flag = raw_flag
                                    steps.append(f"  Flag found via deep protocol analysis in stream {i}: {flag}")
                                    break

                        # NCL/SKY check
                        if not flag:
                            import re
                            for text in [stream_text_c2s, stream_text_s2c]:
                                m = re.search(r"(SKY|NCL)-[A-Z0-9-]+", text)
                                if m:
                                    flag = m.group(0)
                                    steps.append(f"  NCL/SKY flag found in stream {i}: {flag}")
                                    break

                    all_artifacts["pcap"].append({
                        "file": file_path,
                        "ips": pcap_res.ips[:20],
                        "hostnames": pcap_res.hostnames,
                        "streams_analyzed": len(scapy_streams)
                    })
                except Exception as exc:
                    logger.debug("PCAP analysis error on %s: %s", file_path, exc)
                    steps.append(f"  Tshark error: {exc}")

            # 1. Binwalk
            steps.append(f"Running binwalk on {file_path}")
            try:
                res = self.binwalk_tool.run(file_path)
                if res.signatures:
                    steps.append(f"  Found {len(res.signatures)} binwalk signatures")
                    for s in res.signatures:
                        all_artifacts["binwalk"].append({"file": file_path, "description": s.description})
                        found_flag = find_first_flag(s.description)
                        if found_flag and not flag:
                            flag = found_flag
                            steps.append(f"  Flag found in binwalk: {flag}")
            except Exception as exc:
                logger.debug("Binwalk error on %s: %s", file_path, exc)
                steps.append(f"  Binwalk error: {exc}")

            # 2. Exiftool
            steps.append(f"Running exiftool on {file_path}")
            try:
                res = self.exiftool_tool.run(file_path)
                if res.metadata:
                    all_artifacts["exiftool"].append({"file": file_path, "metadata": res.metadata})
                    # Scan metadata values for flags
                    metadata_str = json.dumps(res.metadata)
                    found_flag = find_first_flag(metadata_str)
                    if found_flag and not flag:
                        flag = found_flag
                        steps.append(f"  Flag found in metadata: {flag}")
            except Exception as exc:
                logger.debug("Exiftool error on %s: %s", file_path, exc)
                steps.append(f"  Exiftool error: {exc}")

            # 3. Strings
            steps.append(f"Running strings on {file_path}")
            try:
                res = self.strings_tool.run(file_path)
                if res.strings:
                    # Scan for flags in extracted strings
                    for s in res.strings:
                        found_flag = find_first_flag(s)
                        if found_flag and not flag:
                            flag = found_flag
                            steps.append(f"  Flag found in strings: {flag}")
                            break
            except Exception as exc:
                logger.debug("Strings error on %s: %s", file_path, exc)
                steps.append(f"  Strings error: {exc}")

        # Heuristic: Answer "What is the IP" questions if artifacts found
        if not flag and ("ip" in challenge.get("description", "").lower() or "server" in challenge.get("description", "").lower()):
            for pcap_art in all_artifacts.get("pcap", []):
                if pcap_art.get("ips"):
                    ips = pcap_art["ips"]
                    if ips:
                        answer = f"Possible server IPs found in PCAP: {', '.join(ips[:3])}"
                        steps.append(f"  Heuristic answer for IP question: {answer}")
                        flag = answer

        return {
            "challenge_id": challenge.get("id"),
            "agent_id": self.agent_id,
            "status": "solved" if flag else "attempted",
            "flag": flag,
            "steps": steps,
            "artifacts": all_artifacts
        }

    def _try_live_ssh_forensics(
        self,
        challenge: Dict[str, Any],
        steps: List[str],
    ) -> Optional[Dict[str, Any]]:
        context = self._extract_ssh_context(challenge)
        if not context:
            return None

        host, port, username, password = context
        description = challenge.get("description", "").lower()
        if not any(term in description for term in ("ssh", "rootkit", "library", "ld_preload", "linking", "filesystem")):
            return None

        steps.append(f"Detected live SSH forensics target: {username}@{host}:{port}")
        try:
            import paramiko
        except ImportError:
            steps.append("Paramiko is not installed; cannot perform live SSH forensics.")
            return {
                "challenge_id": challenge.get("id"),
                "agent_id": self.agent_id,
                "status": "failed",
                "flag": None,
                "steps": steps,
            }

        commands = [
            "id; uname -a; hostname",
            "printf '[ld.so.preload]\\n'; cat /etc/ld.so.preload 2>&1 || true",
            "printf '[loader env]\\n'; env | grep -E '^(LD_|PATH=)' || true",
            "printf '[library paths]\\n'; ls -la /lib /lib64 /usr/lib /usr/local/lib 2>&1 || true",
            "printf '[ldd ls]\\n'; ldd /bin/ls 2>&1 || true",
            "printf '[preload library details]\\n'; p=$(cat /etc/ld.so.preload 2>/dev/null | head -1); [ -n \"$p\" ] && { ls -la \"$p\" 2>&1; sha256sum \"$p\" 2>&1; } || true",
            "printf '[preload strings]\\n'; p=$(cat /etc/ld.so.preload 2>/dev/null | head -1); [ -n \"$p\" ] && strings -a \"$p\" 2>/dev/null | grep -E 'HTB|flag|hide|hook|secret|rootkit|readdir|open|stat|getdents|preload|/[^ ]+' | head -120 || true",
            "printf '[preload symbols]\\n'; p=$(cat /etc/ld.so.preload 2>/dev/null | head -1); [ -n \"$p\" ] && readelf -Ws \"$p\" 2>/dev/null | grep -E 'readdir|open|stat|access|fopen|__xstat|getdents|hook|hide|flag' | head -120 || true",
            "printf '[hidden-ish files]\\n'; find / -maxdepth 4 \\( -iname '*preload*' -o -iname '*rootkit*' -o -iname 'flag*' -o -iname '*hook*' \\) 2>/dev/null | head -80",
            "printf '[flag grep targeted]\\n'; grep -RIsE 'HTB\\{|CTF\\{|flag\\{' /root /home /tmp /var /opt 2>/dev/null | head -40",
        ]
        if os.getenv("CTF_AGENTS_ALLOW_SSH_PRELOAD_BYPASS") == "1":
            commands.append(
                "backup=/tmp/ctf_agents_ld_so_preload.bak; "
                "disabled=/tmp/ctf_agents_ld_so_preload.disabled; "
                "restore_preload(){ if [ -f \"$disabled\" ]; then mv \"$disabled\" /etc/ld.so.preload 2>/dev/null || true; "
                "elif [ -f \"$backup\" ] && [ ! -f /etc/ld.so.preload ]; then cp \"$backup\" /etc/ld.so.preload 2>/dev/null || true; fi; }; "
                "trap restore_preload EXIT; "
                "printf '[preload bypass search]\\n'; "
                "if [ -f /etc/ld.so.preload ]; then cp /etc/ld.so.preload \"$backup\" && mv /etc/ld.so.preload \"$disabled\"; fi; "
                "find / -maxdepth 4 \\( -iname '*flag*' -o -iname '*htb*' -o -iname '*secret*' -o -iname '*hidden*' -o -iname '*rootkit*' -o -iname '*hook*' \\) "
                "2>/dev/null | head -200 | tee /tmp/ctf_agents_suspicious_paths.txt; "
                "while IFS= read -r candidate; do [ -f \"$candidate\" ] && { printf '\\n[cat %s]\\n' \"$candidate\"; head -c 4096 \"$candidate\"; printf '\\n'; }; done "
                "</tmp/ctf_agents_suspicious_paths.txt; "
                "printf '[flag grep after preload disabled]\\n'; "
                "grep -RIsE 'HTB\\{|CTF\\{|flag\\{' /root /home /tmp /var /opt /srv /app 2>/dev/null | head -80; "
                "restore_preload"
            )
        elif any(term in description for term in ("rootkit", "preload", "library", "linking")):
            steps.append(
                "Live SSH preload bypass is disabled. Set CTF_AGENTS_ALLOW_SSH_PRELOAD_BYPASS=1 "
                "to temporarily disable /etc/ld.so.preload with backup/restore during authorized CTF analysis."
            )

        artifacts: Dict[str, Any] = {
            "ssh_target": f"{host}:{port}",
            "ssh_username": username,
            "live_forensics": [],
        }
        combined_output = []

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                host,
                port=port,
                username=username,
                password=password,
                timeout=10,
                banner_timeout=10,
                auth_timeout=10,
                look_for_keys=False,
                allow_agent=False,
            )

            for command in commands:
                steps.append(f"  [SSH] {command}")
                stdin, stdout, stderr = client.exec_command(command, timeout=20)
                out = stdout.read().decode("utf-8", errors="replace")
                err = stderr.read().decode("utf-8", errors="replace")
                text = (out + "\n" + err).strip()
                combined_output.append(text)
                artifacts["live_forensics"].append({
                    "command": command,
                    "stdout_preview": out[:4000],
                    "stderr_preview": err[:1000],
                })

                found = find_first_flag(text)
                if found:
                    steps.append(f"  SUCCESS: Flag found during live SSH forensics: {found}")
                    return {
                        "challenge_id": challenge.get("id"),
                        "agent_id": self.agent_id,
                        "status": "solved",
                        "flag": found,
                        "steps": steps,
                        "artifacts": artifacts,
                    }

            suspicious = self._summarize_rootkit_indicators("\n".join(combined_output))
            if suspicious:
                steps.extend(f"  Indicator: {item}" for item in suspicious)

            return {
                "challenge_id": challenge.get("id"),
                "agent_id": self.agent_id,
                "status": "attempted",
                "flag": None,
                "steps": steps,
                "artifacts": artifacts,
            }
        except Exception as exc:
            logger.debug("Live SSH forensics failed: %s", exc)
            steps.append(f"Live SSH forensics failed: {exc}")
            return {
                "challenge_id": challenge.get("id"),
                "agent_id": self.agent_id,
                "status": "failed",
                "flag": None,
                "steps": steps,
                "artifacts": artifacts,
            }
        finally:
            client.close()

    @staticmethod
    def _extract_ssh_context(challenge: Dict[str, Any]) -> Optional[Tuple[str, int, str, str]]:
        text = " ".join([
            str(challenge.get("description", "")),
            str(challenge.get("url", "")),
            str(challenge.get("connection_info", "")),
        ])

        creds = re.search(
            r"(?:creds?|credentials?)\s*:\s*([A-Za-z0-9_.-]+)\s*:\s*([^\s,;]+)",
            text,
            re.IGNORECASE,
        )
        target = re.search(
            r"\b((?:\d{1,3}\.){3}\d{1,3}|localhost|127\.0\.0\.1)\s*:\s*(\d{2,5})\b",
            text,
        )
        if not creds or not target:
            return None

        return target.group(1), int(target.group(2)), creds.group(1), creds.group(2)

    @staticmethod
    def _summarize_rootkit_indicators(output: str) -> List[str]:
        indicators = []
        lowered = output.lower()
        if "/etc/ld.so.preload" in lowered:
            indicators.append("Loader preload configuration referenced.")
        if "cannot be preloaded" in lowered or "wrong elf class" in lowered:
            indicators.append("Dynamic loader reported preload/library errors.")
        if "rootkit" in lowered or "hook" in lowered:
            indicators.append("Rootkit/hook-related filenames or text appeared in output.")
        if "no such file" in lowered and ("ld.so.preload" in lowered or "/lib" in lowered):
            indicators.append("Filesystem/library path inconsistencies observed.")
        return indicators

    def _analyze_raw_protocol(self, data: str) -> Optional[str]:
        """
        Heuristic analysis of raw protocol data (custom binary structures).
        Inspired by protocol reversing scripts (like analyze_pcap2.py).
        """
        # Convert to bytes for binary analysis if possible
        try:
            raw_bytes = data.encode('latin-1') if isinstance(data, str) else data
        except Exception as exc:
            logger.debug("Raw protocol encode failed: %s", exc)
            return None

        # NCL/SKY Pattern in common structured data (Base64 chunks)
        # 1. Try to find concatenated base64 chunks
        import base64
        import re

        # Look for magic numbers or structure (e.g., 4 bytes length + data)
        if len(raw_bytes) > 8:
            # Heuristic: Is the first 4 bytes a small integer (count)?
            try:
                n = int.from_bytes(raw_bytes[:4], byteorder='big')
                if 0 < n < 500: # Reasonable number of chunks
                    pos = 4
                    all_chunks = []
                    for _ in range(n):
                        if pos + 6 > len(raw_bytes): break
                        # Header: 2 bytes check + 4 bytes length
                        chunk_len = int.from_bytes(raw_bytes[pos+2:pos+6], byteorder='big')
                        if chunk_len > 10000: break # Too large for a chunk
                        chunk_data = raw_bytes[pos+6 : pos+6+chunk_len]
                        all_chunks.append(chunk_data)
                        pos += 6 + chunk_len
                    
                    if all_chunks:
                        combined = b"".join(all_chunks)
                        # Clean and decode
                        clean = combined.replace(b' ', b'').replace(b'\n', b'').replace(b'\r', b'')
                        while len(clean) % 4 != 0: clean += b'='
                        try:
                            decoded = base64.b64decode(clean)
                            found = find_first_flag(decoded.decode('utf-8', errors='ignore'))
                            if found: return found
                        except Exception as exc:
                            logger.debug("Base64 chunk decode failed: %s", exc)
                            pass
            except Exception as exc:
                logger.debug("Magic number chunk parsing failed: %s", exc)
                pass

        # 2. General greedy base64 extraction from raw stream
        # (Useful if the protocol structure isn't exactly as above)
        b64_pattern = b'[A-Za-z0-9+/]{20,}={0,2}'
        for m in re.finditer(b64_pattern, raw_bytes):
            try:
                decoded = base64.b64decode(m.group(0))
                found = find_first_flag(decoded.decode('utf-8', errors='ignore'))
                if found: return found
            except Exception as exc:
                logger.debug("Greedy base64 decode failed: %s", exc)
                continue

        return None

    def get_capabilities(self) -> List[str]:
        return self.capabilities
