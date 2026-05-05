import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional

class ResultManager:
    """
    Manages the organization and persistence of challenge results.
    Creates a standardized directory structure for each challenge run.
    """
    def __init__(self, base_results_dir: str = "results", max_reports: Optional[int] = None):
        self.base_dir = Path(base_results_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.max_reports = max_reports if max_reports is not None else self._default_max_reports()

    @staticmethod
    def _default_max_reports() -> int:
        try:
            return max(0, int(os.getenv("CTF_MAX_REPORTS", "3")))
        except ValueError:
            return 3

    def get_challenge_dir(self, challenge_id: str) -> Path:
        """
        Get or create a directory for a specific challenge.
        Structure: results/{challenge_id}/
        """
        cdir = self.base_dir / challenge_id
        cdir.mkdir(parents=True, exist_ok=True)
        
        # Create subdirectories for organization
        (cdir / "artifacts").mkdir(exist_ok=True)
        (cdir / "reports").mkdir(exist_ok=True)
        (cdir / "flags").mkdir(exist_ok=True)
        
        return cdir

    def cleanup_reports(self, challenge_id: str):
        """
        Keep only the most recent reports for a given challenge.
        """
        report_dir = self.base_dir / challenge_id / "reports"
        if not report_dir.exists():
            return

        try:
            reports = sorted(
                [f for f in report_dir.glob("run_*.json")],
                key=lambda x: x.stat().st_mtime,
                reverse=True
            )
            if len(reports) > self.max_reports:
                for old_report in reports[self.max_reports:]:
                    old_report.unlink()
        except:
            pass

    def save_run_result(self, result: Dict[str, Any]):
        """
        Persist the final result of a coordinator run.
        """
        challenge_id = result.get("challenge_id", "unknown")
        cdir = self.get_challenge_dir(challenge_id)
        
        ts = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        report_path = cdir / "reports" / f"run_{ts}.json"
        
        with open(report_path, "w") as f:
            json.dump(result, f, indent=2)
            
        # If a flag was found, persist it separately for easy access
        flag = result.get("flag")
        if flag:
            flag_path = cdir / "flags" / "captured.txt"
            # Append flag if it's new
            with open(flag_path, "a") as f:
                f.write(f"[{ts}] {flag}\n")

        self.cleanup_reports(challenge_id)
        
        return report_path

    def get_artifact_path(self, challenge_id: str, filename: str) -> Path:
        """
        Generate a path for saving an artifact.
        """
        cdir = self.get_challenge_dir(challenge_id)
        return cdir / "artifacts" / filename
