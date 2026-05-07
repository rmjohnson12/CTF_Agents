"""
Recon Support Agent

Fast first-pass enumeration for network and web targets.
"""

from __future__ import annotations

import re
from dataclasses import asdict
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from agents.base_agent import AgentType, BaseAgent
from tools.network.nmap import NmapTool
from tools.web.dirsearch import DirsearchTool
from tools.web.http_fetch import HttpFetchTool


class ReconAgent(BaseAgent):
    """
    Support agent for lightweight target reconnaissance.

    It intentionally collects facts and artifacts instead of attempting
    exploitation. Downstream specialists can use the published facts to pick a
    sharper next step.
    """

    def __init__(
        self,
        agent_id: str = "recon_agent",
        http_tool: Optional[HttpFetchTool] = None,
        nmap_tool: Optional[NmapTool] = None,
        dirsearch_tool: Optional[DirsearchTool] = None,
    ):
        super().__init__(agent_id, AgentType.SUPPORT)
        self.http_tool = http_tool or HttpFetchTool(max_preview_chars=2000)
        self.nmap_tool = nmap_tool or NmapTool()
        self.dirsearch_tool = dirsearch_tool or DirsearchTool()
        self.capabilities = [
            "target_extraction",
            "http_probe",
            "service_enumeration",
            "directory_discovery",
            "technology_fingerprinting",
        ]

    def analyze_challenge(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        targets = self._extract_targets(challenge)
        description = (challenge.get("description") or "").lower()
        wants_recon = any(
            term in description
            for term in ("recon", "enumerate", "enumeration", "scan", "discover", "fingerprint")
        )

        can_handle = bool(targets)
        confidence = 0.86 if can_handle and wants_recon else 0.55 if can_handle else 0.05
        return {
            "agent_id": self.agent_id,
            "can_handle": can_handle,
            "confidence": confidence,
            "approach": "Collect target metadata, services, headers, and common paths.",
            "targets": targets,
        }

    def solve_challenge(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        steps: List[str] = []
        artifacts: Dict[str, Any] = {}
        targets = self._extract_targets(challenge)

        if not targets:
            return {
                "challenge_id": challenge.get("id"),
                "agent_id": self.agent_id,
                "status": "attempted",
                "flag": None,
                "steps": ["No URL, host, or IP target found for reconnaissance."],
                "artifacts": {},
            }

        artifacts["recon_targets"] = targets
        steps.append(f"Identified {len(targets)} target(s): {', '.join(targets)}")

        for target in targets:
            url = self._target_to_url(target)
            host = self._host_from_target(target)

            if url:
                self._probe_http(url, steps, artifacts)
                self._discover_paths(url, steps, artifacts)

            if host:
                self._scan_services(host, steps, artifacts)

        return {
            "challenge_id": challenge.get("id"),
            "agent_id": self.agent_id,
            "status": "attempted",
            "flag": None,
            "steps": steps,
            "artifacts": artifacts,
        }

    def get_capabilities(self) -> List[str]:
        return self.capabilities

    def _probe_http(
        self,
        url: str,
        steps: List[str],
        artifacts: Dict[str, Any],
    ) -> None:
        try:
            result = self.http_tool.fetch(url, timeout_s=10)
            steps.append(f"HTTP probe {url}: {result.status_code} -> {result.final_url}")
            artifacts.setdefault("http_probes", []).append(
                {
                    "url": result.url,
                    "final_url": result.final_url,
                    "status_code": result.status_code,
                    "headers": result.headers,
                    "body_preview": result.body_preview,
                }
            )
            technologies = self._fingerprint(result.headers, result.body_preview)
            if technologies:
                steps.append(f"Detected technologies: {', '.join(technologies)}")
                artifacts.setdefault("technologies", [])
                for tech in technologies:
                    if tech not in artifacts["technologies"]:
                        artifacts["technologies"].append(tech)
        except Exception as exc:
            steps.append(f"HTTP probe failed for {url}: {exc}")

    def _discover_paths(
        self,
        url: str,
        steps: List[str],
        artifacts: Dict[str, Any],
    ) -> None:
        try:
            result = self.dirsearch_tool.run(url, timeout_s=60)
            entries = [asdict(entry) for entry in result.entries]
            steps.append(f"Directory discovery found {len(entries)} path(s) on {url}.")
            if entries:
                artifacts.setdefault("discovered_paths", []).extend(entries[:25])
        except Exception as exc:
            steps.append(f"Directory discovery failed for {url}: {exc}")

    def _scan_services(
        self,
        host: str,
        steps: List[str],
        artifacts: Dict[str, Any],
    ) -> None:
        try:
            result = self.nmap_tool.scan_top(host, timeout_s=90)
            ports = [asdict(port) for port in result.ports if port.state == "open"]
            steps.append(f"Service scan found {len(ports)} open port(s) on {host}.")
            artifacts.setdefault("service_scans", []).append(
                {
                    "target": host,
                    "open_ports": ports,
                }
            )
        except Exception as exc:
            steps.append(f"Service scan failed for {host}: {exc}")

    @staticmethod
    def _extract_targets(challenge: Dict[str, Any]) -> List[str]:
        candidates: List[str] = []
        url = challenge.get("url") or challenge.get("target", {}).get("url")
        if url:
            candidates.append(str(url))

        text = " ".join(
            str(part)
            for part in [
                challenge.get("name", ""),
                challenge.get("description", ""),
                " ".join(challenge.get("hints", [])),
            ]
        )
        candidates.extend(
            re.findall(
                r"https?://[^\s<>\"']+|www\.[^\s<>\"']+|\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b",
                text,
            )
        )

        normalized: List[str] = []
        for candidate in candidates:
            cleaned = candidate.rstrip(".,);]'\"")
            if cleaned.startswith("www."):
                cleaned = "http://" + cleaned
            if cleaned and cleaned not in normalized:
                normalized.append(cleaned)
        return normalized

    @staticmethod
    def _target_to_url(target: str) -> Optional[str]:
        if target.startswith(("http://", "https://")):
            return target
        if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?$", target):
            return "http://" + target
        return None

    @staticmethod
    def _host_from_target(target: str) -> Optional[str]:
        parsed = urlparse(target if "://" in target else f"http://{target}")
        return parsed.hostname

    @staticmethod
    def _fingerprint(headers: Dict[str, str], body: str) -> List[str]:
        haystack = "\n".join([str(headers), body]).lower()
        checks = {
            "next.js": ("next.js", "__next", "x-powered-by': 'next.js", 'x-powered-by": "next.js'),
            "react": ("react", "__react"),
            "express": ("express", "x-powered-by': 'express", 'x-powered-by": "express'),
            "flask": ("flask", "werkzeug"),
            "php": ("php", "x-powered-by': 'php", 'x-powered-by": "php'),
            "jwt": ("jwt", "jsonwebtoken", "bearer "),
        }
        found: List[str] = []
        for name, needles in checks.items():
            if any(needle in haystack for needle in needles):
                found.append(name)
        return found
