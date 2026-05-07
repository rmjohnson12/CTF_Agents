"""
Docker Challenge Support Agent

Builds and launches local Docker web challenges when explicitly enabled.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any, Dict, List, Optional

from agents.base_agent import AgentType, BaseAgent
from tools.web.docker_challenge import DockerChallengeTool


class DockerChallengeAgent(BaseAgent):
    """Support agent that turns a local Docker challenge folder into a localhost URL."""

    def __init__(
        self,
        agent_id: str = "docker_agent",
        docker_tool: Optional[DockerChallengeTool] = None,
    ):
        super().__init__(agent_id, AgentType.SUPPORT)
        self.docker_tool = docker_tool or DockerChallengeTool()
        self.capabilities = [
            "docker_context_detection",
            "local_container_launch",
            "localhost_target_mapping",
        ]

    def analyze_challenge(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        files = challenge.get("files", [])
        context = self.docker_tool.find_context(files)
        description = (challenge.get("description") or "").lower()
        mentions_docker = any(term in description for term in ("docker", "container", "dockerfile"))
        return {
            "agent_id": self.agent_id,
            "can_handle": bool(context),
            "confidence": 0.90 if context and mentions_docker else 0.65 if context else 0.05,
            "approach": "Build and launch the local Docker challenge, then publish the mapped localhost URL.",
            "context_dir": str(context) if context else None,
        }

    def solve_challenge(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        steps: List[str] = []
        context = self.docker_tool.find_context(challenge.get("files", []))
        if not context:
            return {
                "challenge_id": challenge.get("id"),
                "agent_id": self.agent_id,
                "status": "attempted",
                "flag": None,
                "steps": ["No Dockerfile or docker-compose file found in provided paths."],
                "artifacts": {},
            }

        steps.append(f"Found Docker challenge context: {context}")
        try:
            launch = self.docker_tool.launch(str(context))
        except PermissionError as exc:
            return {
                "challenge_id": challenge.get("id"),
                "agent_id": self.agent_id,
                "status": "attempted",
                "flag": None,
                "steps": steps + [str(exc)],
                "artifacts": {
                    "docker_context_dir": str(context),
                    "docker_allowed": False,
                },
            }
        except Exception as exc:
            return {
                "challenge_id": challenge.get("id"),
                "agent_id": self.agent_id,
                "status": "failed",
                "flag": None,
                "steps": steps + [f"Docker launch failed: {exc}"],
                "artifacts": {
                    "docker_context_dir": str(context),
                    "docker_allowed": True,
                },
            }

        steps.extend(
            [
                f"Built image {launch.image_tag}.",
                f"Started container {launch.container_id[:12]} on {launch.url}.",
                "Published localhost URL for downstream web/recon agents.",
            ]
        )

        return {
            "challenge_id": challenge.get("id"),
            "agent_id": self.agent_id,
            "status": "attempted",
            "flag": None,
            "steps": steps,
            "artifacts": {
                "docker_context_dir": launch.context_dir,
                "docker_image_tag": launch.image_tag,
                "docker_container_id": launch.container_id,
                "docker_container_port": launch.container_port,
                "docker_host_port": launch.host_port,
                "docker_target_url": launch.url,
                "docker_logs_tail": launch.logs_tail,
                "docker_cleanup_command": f"docker rm -f {launch.container_id}",
                "docker_launch": {
                    "context_dir": launch.context_dir,
                    "image_tag": launch.image_tag,
                    "container_id": launch.container_id,
                    "container_port": launch.container_port,
                    "host_port": launch.host_port,
                    "url": launch.url,
                },
            },
        }

    def cleanup_artifacts(self, artifacts: Dict[str, Any], steps: Optional[List[str]] = None) -> None:
        container_id = artifacts.get("docker_container_id")
        if not container_id:
            return
        result = self.docker_tool.cleanup(container_id)
        if steps is not None:
            if result.exit_code == 0:
                steps.append(f"Cleaned up Docker container {container_id[:12]}.")
            else:
                steps.append(f"Docker cleanup failed for {container_id[:12]}: {result.stderr or result.stdout}")

    def get_capabilities(self) -> List[str]:
        return self.capabilities
