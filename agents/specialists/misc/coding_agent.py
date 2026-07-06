"""
Coding Specialist Agent

Specialized agent for programming, scripting, and automation challenges.
"""

import json
import logging
from typing import Dict, Any, List, Optional

from config.defaults import COMMON_WEB_PATHS, DEFAULT_AUTH_HEADERS, SQLI_PAYLOADS
from agents.base_agent import BaseAgent, AgentType
from agents.registry import AgentRegistry
from tools.common.python_tool import PythonTool
from tools.common.embedding_analogy import EmbeddingAnalogySolver
from core.decision_engine.llm_reasoner import LLMReasoner
from core.utils.flag_utils import find_first_flag, KNOWN_FLAG_PREFIXES
import re

logger = logging.getLogger(__name__)


# Deterministic solver submitted to a coding autograder for the weighted-graph
# "safest/shortest path" class (e.g. HTB "Pivot Chain"). Reads all whitespace
# tokens so it is robust to single- vs multi-line input: N, M, start, target,
# then M directed edges "u v risk"; prints the minimum cumulative risk via
# Dijkstra. Node labels are arbitrary strings.
_SHORTEST_PATH_PROGRAM = r'''
import sys, heapq

def main():
    data = sys.stdin.read().split()
    if not data:
        return
    i = 0
    n = int(data[i]); i += 1
    m = int(data[i]); i += 1
    start = data[i]; i += 1
    target = data[i]; i += 1
    graph = {}
    for _ in range(m):
        u, v, w = data[i], data[i + 1], int(data[i + 2]); i += 3
        graph.setdefault(u, []).append((v, w))
    dist = {start: 0}
    pq = [(0, start)]
    answer = -1
    while pq:
        d, node = heapq.heappop(pq)
        if node == target:
            answer = d
            break
        if d > dist.get(node, float("inf")):
            continue
        for v, w in graph.get(node, []):
            nd = d + w
            if nd < dist.get(v, float("inf")):
                dist[v] = nd
                heapq.heappush(pq, (nd, v))
    print(answer)

main()
'''


@AgentRegistry.register(order=30)
class CodingAgent(BaseAgent):
    """
    Specialist agent for programming and scripting challenges.
    
    Handles:
    - Python/Bash/Ruby scripting
    - Algorithm implementation
    - Data parsing and transformation
    - Automation of repetitive tasks
    - Code debugging and fixing
    """
    
    def __init__(
        self,
        agent_id: str = "coding_agent",
        reasoner: Optional[LLMReasoner] = None,
        python_tool: Optional[PythonTool] = None,
        embedding_solver: Optional[EmbeddingAnalogySolver] = None,
    ):
        super().__init__(agent_id, AgentType.SPECIALIST)
        self.reasoner = reasoner or LLMReasoner()
        self.python_tool = python_tool or PythonTool()
        self.embedding_solver = embedding_solver or EmbeddingAnalogySolver()
        self.capabilities = [
            'programming',
            'scripting',
            'python',
            'bash',
            'automation',
            'algorithm',
            'debugging',
            'embedding_analogies',
            'interactive_coding_instance',
            'graph_shortest_path',
            'misc'
        ]
    
    def analyze_challenge(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a coding challenge.
        """
        description = challenge.get('description', '').lower()
        
        # Detect potential coding tasks
        coding_indicators = ['script', 'write a program', 'python', 'code', 'automate', 'parse', 'algorithm']
        is_coding = any(indicator in description for indicator in coding_indicators)
        
        detected = [k for k in coding_indicators if k in description]
        confidence = 0.9 if is_coding or challenge.get('category') == 'misc' else 0.2
        
        return {
            'agent_id': self.agent_id,
            'can_handle': is_coding or challenge.get('category') == 'misc',
            'confidence': confidence,
            'approach': self._plan_approach(detected)
        }
    
    def solve_challenge(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        """
        Attempt to solve a coding challenge by generating and running a script.
        Includes a self-correction loop.
        """
        # Get task description from inputs (passed by coordinator) or challenge description
        task_desc = challenge.get('current_task_description') or challenge.get('description', 'Solve the challenge')
        
        analysis = self.analyze_challenge(challenge)
        steps = []
        flag = None
        max_retries = 3
        
        steps.append(f"Analyzed task requirements: {task_desc}")

        # HTB web-based coding challenges serve the real problem statement on the
        # spawned instance page and grade submitted code through a /run endpoint.
        # Neither the statement nor the grader is in the challenge description, so
        # the generic script path below can never see them — handle them here.
        web_coding = self._try_web_coding_challenge(challenge, steps)
        if web_coding:
            web_flag, web_techniques = web_coding
            return {
                'challenge_id': challenge.get('id'),
                'agent_id': self.agent_id,
                'status': 'solved',
                'flag': web_flag,
                'steps': steps,
                'techniques': web_techniques,
                'artifacts': {'coding_challenge': {'technique': 'web_coding_autograder'}},
            }

        embedding_result = None
        embedding_handled = False
        for artifact in challenge.get("files", []):
            if not str(artifact).lower().endswith((".txt", ".csv")):
                continue
            try:
                candidate = self.embedding_solver.solve_file(
                    str(artifact),
                    description=task_desc,
                )
            except Exception as exc:
                embedding_handled = True
                steps.append(f"Embedding analogy solver could not complete: {exc}")
                break
            if candidate is not None:
                embedding_handled = True
                embedding_result = candidate
                break

        if embedding_result is not None:
            flag = find_first_flag(embedding_result.text)
            steps.append(
                f"Solved {len(embedding_result.answers)} embedding analogies with "
                f"{embedding_result.model_name} using raw vector offsets and ASCII/NFKC filtering."
            )
            if flag:
                steps.append(f"Recovered flag from concatenated nearest neighbors: {flag}")
                return {
                    'challenge_id': challenge.get('id'),
                    'agent_id': self.agent_id,
                    'status': 'solved',
                    'flag': flag,
                    'steps': steps,
                    'artifacts': {
                        'embedding_model': embedding_result.model_name,
                        'analogy_count': len(embedding_result.answers),
                    },
                }
            steps.append("Embedding answers did not form a recognized flag; continuing with AI generation.")
        elif embedding_handled:
            steps.append("Continuing with AI generation after the deterministic embedding attempt.")
        
        script_content = ""
        if not self.reasoner.is_available:
            prime_sum = self._solve_prime_sum_prompt(task_desc)
            if prime_sum:
                flag = prime_sum
                steps.append("LLM not available. Solved prime-sum task with deterministic heuristic.")
                return {
                    'challenge_id': challenge.get('id'),
                    'agent_id': self.agent_id,
                    'status': 'solved',
                    'flag': flag,
                    'steps': steps,
                    'artifacts': {
                        'generated_script': None,
                        'final_attempt': 0
                    }
                }
            # Heuristic: If it's a login bypass task, generate a simple script
            if "login" in task_desc.lower() or "bypass" in task_desc.lower() or "authenticate" in task_desc.lower():
                steps.append("LLM not available. Generating improved heuristic login bypass script...")
                script_content = f"""
import requests
import re

url = "{challenge.get('url', 'http://localhost')}"
if not url.endswith('/'): url += '/'

# Technique 1: SQL Injection payloads
sqli_payloads = {SQLI_PAYLOADS}

# Technique 2: Common admin paths
paths = {COMMON_WEB_PATHS[:8]}

# Technique 3: Auth cookies
cookies = {{"admin": "true", "auth": "true", "authenticated": "true"}}

session = requests.Session()

for path in paths:
    test_url = url + path
    print(f"--- Testing URL: {{test_url}} ---")
    
    # Try with admin cookies first
    try:
        r = session.get(test_url, cookies=cookies)
        if any(x in r.text for x in ["SKY-", "NCL-", "CTF{{", "HTB{{", "flag{{"]):
            print(f"Success with cookie manipulation on {{test_url}}!")
            print(r.text)
            break
    except Exception as exc:
        logger.debug("Cookie manipulation failed for %s: %s", test_url, exc)
        continue

    # Try SQLi on login form (if it's a login page)
    for p in sqli_payloads:
        try:
            # We try to POST to common field names
            r = session.post(test_url, data={{"username": p, "password": "password", "user": p, "pass": "password"}})
            if any(x in r.text for x in ["SKY-", "NCL-", "CTF{{", "HTB{{", "flag{{"]):
                print(f"Success with SQLi payload {{p}} on {{test_url}}!")
                print(r.text)
                break
        except Exception as exc:
            logger.debug("SQLi payload %s failed for %s: %s", p, test_url, exc)
            continue
"""
            else:
                steps.append("Error: LLM not available for script generation and no heuristic applies.")
                return {
                    'challenge_id': challenge.get('id'),
                    'agent_id': self.agent_id,
                    'status': 'failed',
                    'flag': None,
                    'steps': steps
                }
        else:
            steps.append("Generating solution script via LLM...")
            script_content = self.reasoner.generate_script(challenge, task_desc)

        backend_fn = getattr(self.python_tool, "execution_backend", None)
        execution_backend = backend_fn() if callable(backend_fn) else "custom"
        steps.append(f"Generated-script execution backend: {execution_backend}.")
        
        if not script_content:
            steps.append("LLM produced no script (service likely down). Bypassing to deterministic fallback...")
            
            # Check for prime sum task first
            prime_sum = self._solve_prime_sum_prompt(task_desc)
            if prime_sum:
                flag = prime_sum
                steps.append(f"SUCCESS: Recovered flag via prime-sum fallback: {flag}")
            else:
                flag = self._fallback_xor_solver(challenge, task_desc)
            
            if flag:
                return {
                    'challenge_id': challenge.get('id'),
                    'agent_id': self.agent_id,
                    'status': 'solved',
                    'flag': flag,
                    'steps': steps
                }

        if script_content.startswith("# LLM not available"):
            steps.append("Error: LLM not available for script generation.")
            return {
                'challenge_id': challenge.get('id'),
                'agent_id': self.agent_id,
                'status': 'failed',
                'flag': None,
                'steps': steps
            }

        for attempt in range(max_retries + 1):
            if not script_content or attempt > max_retries:
                # If LLM failed to produce a script or we exhausted retries, try the hardcoded fallback
                steps.append("LLM scripts failing or unavailable. Running deterministic XOR fallback solver...")
                flag = self._fallback_xor_solver(challenge, task_desc)
                if flag:
                    steps.append(f"SUCCESS: Recovered flag via deterministic fallback: {flag}")
                    break
                else:
                    steps.append("Fallback solver could not find a valid flag prefix.")
                    break

            if attempt > 0:
                steps.append(f"Attempt {attempt + 1}: Fixing script based on previous failure...")
                script_content = self.reasoner.fix_script(challenge, script_content, last_error, last_stdout)
            
            if not script_content:
                continue

            steps.append(f"Executing script (Attempt {attempt + 1})...")
            last_stdout = None
            try:
                res = self.python_tool.run(
                    script_content,
                    artifact_paths=challenge.get("files"),
                )
                last_stdout = res.stdout
                
                if res.timed_out:
                    last_error = "Execution timed out."
                    steps.append(f"  {last_error}")
                
                if res.stdout:
                    # Centralized flag detection
                    found_flag = find_first_flag(res.stdout)
                    if found_flag:
                        flag = found_flag
                        steps.append(f"  Found flag in stdout: {flag}")
                        break
                
                if res.stderr:
                    last_error = res.stderr
                    steps.append(f"  Stderr: {res.stderr[:200]}")
                elif not res.stdout:
                    last_error = "Script produced no output."
                    steps.append(f"  {last_error}")
                else:
                    last_error = "Script executed successfully but no flag was found in stdout."
                    steps.append("  No flag detected in output.")

                if res.exit_code != 0:
                    steps.append(f"  Script failed with exit code {res.exit_code}")

            except Exception as exc:
                logger.warning("Script execution failed (attempt %d): %s", attempt + 1, exc)
                last_error = str(exc)
                steps.append(f"  Error during script execution: {exc}")

            if attempt == max_retries:
                steps.append("Max retries reached. Self-correction failed.")

        if not flag:
            steps.append("Generated scripts did not recover a flag. Running deterministic XOR fallback solver...")
            flag = self._fallback_xor_solver(challenge, task_desc)
            if flag:
                steps.append(f"SUCCESS: Recovered flag via deterministic fallback: {flag}")

        return {
            'challenge_id': challenge.get('id'),
            'agent_id': self.agent_id,
            'status': 'solved' if flag else 'failed' if attempt == max_retries else 'attempted',
            'flag': flag,
            'steps': steps,
            'artifacts': {
                'generated_script': script_content,
                'final_attempt': attempt + 1,
                'execution_backend': execution_backend,
            }
        }

    # ------------------------------------------------------- web coding autograder
    def _try_web_coding_challenge(
        self, challenge: Dict[str, Any], steps: List[str]
    ) -> Optional[tuple]:
        """Solve an interactive HTB coding instance (Monaco editor + /run grader).

        Fetches the instance page, extracts the on-page problem statement, then
        submits a solving program to the ``/run`` autograder. Recognized problem
        classes (e.g. weighted-graph shortest path) get a deterministic solver so
        the challenge is solved even when the LLM backend is degraded; anything
        else falls back to an LLM program-synthesis loop guided by grader feedback.
        Returns ``(flag, techniques)`` or ``None``.
        """
        url = challenge.get('url')
        if not url:
            return None
        try:
            import requests  # noqa: F401
            from core.utils.security import assert_url_allowed, SecurityPolicyError
        except Exception:  # pragma: no cover - deps are project requirements
            return None

        base = str(url).rstrip('/')
        try:
            assert_url_allowed(base)
        except SecurityPolicyError as exc:
            steps.append(f"Coding instance blocked by network policy: {exc}")
            return None
        try:
            page = requests.get(base, timeout=20)
        except Exception as exc:
            steps.append(f"Could not fetch coding instance page: {exc}")
            return None

        html = page.text if page.status_code == 200 else ''
        run_ep = self._detect_run_endpoint(html)
        if not run_ep:
            return None
        run_url = base + run_ep
        problem = self._extract_problem_statement(html)
        steps.append(
            f"Detected interactive coding instance (grader {run_ep}); "
            f"extracted a {len(problem)}-char problem statement."
        )

        base_techniques = [
            'interactive_coding_instance',
            'problem_statement_extraction',
            'autograder_code_submission',
        ]

        # 1) Deterministic solvers for recognized problem classes.
        for label, language, code, extra in self._deterministic_coding_solutions(problem):
            flag, completed, feedback = self._submit_coding_run(run_url, code, language, steps)
            if flag:
                steps.append(f"Autograder accepted the deterministic {label} solution.")
                return flag, base_techniques + extra

        # 2) LLM program synthesis with grader-feedback self-correction.
        if getattr(self.reasoner, 'is_available', False) and problem:
            code = self._llm_coding_program(problem, challenge)
            feedback = ''
            for attempt in range(3):
                if not code:
                    break
                flag, completed, feedback = self._submit_coding_run(run_url, code, 'python', steps)
                if flag:
                    steps.append(f"Autograder accepted the LLM solution (attempt {attempt + 1}).")
                    return flag, base_techniques + ['llm_program_synthesis']
                code = self._llm_fix_coding_program(problem, challenge, code, feedback)
            steps.append("LLM program-synthesis loop did not satisfy the grader.")

        return None

    @staticmethod
    def _detect_run_endpoint(html: str) -> Optional[str]:
        """Find the code-submission endpoint the page POSTs code to."""
        if not html:
            return None
        match = re.search(
            r'fetch\(\s*["\'](/[\w\-/]+)["\'][^)]*?\bcode\b', html, re.S
        )
        if match:
            return match.group(1)
        if re.search(r'["\']/run["\']', html):
            return '/run'
        return None

    @staticmethod
    def _extract_problem_statement(html: str) -> str:
        """Return the page's visible text (problem statement + I/O + examples)."""
        import html as html_lib

        if not html:
            return ''
        body = re.sub(r'(?is)<script.*?</script>', ' ', html)
        body = re.sub(r'(?is)<style.*?</style>', ' ', body)
        text = re.sub(r'(?is)<[^>]+>', '\n', body)
        text = html_lib.unescape(text)
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        return '\n'.join(lines)

    def _deterministic_coding_solutions(self, problem: str):
        """Yield ``(label, language, code, extra_techniques)`` for known classes."""
        if self._looks_like_shortest_path(problem):
            yield (
                'graph shortest-path (Dijkstra)',
                'python',
                _SHORTEST_PATH_PROGRAM,
                ['graph_shortest_path', 'dijkstra'],
            )

    @staticmethod
    def _looks_like_shortest_path(problem: str) -> bool:
        text = (problem or '').lower()
        has_path = any(w in text for w in ('path', 'route', 'pivot'))
        has_weight = any(w in text for w in ('risk', 'cost', 'weight', 'distance', 'time'))
        wants_min = any(w in text for w in ('lowest', 'minimum', 'safest', 'shortest', 'least', 'cheapest', 'minimal'))
        has_graph = any(w in text for w in ('host', 'node', 'edge', 'vertex', 'graph', 'network'))
        return has_path and has_weight and wants_min and has_graph

    def _submit_coding_run(
        self, run_url: str, code: str, language: str, steps: List[str]
    ) -> tuple:
        """POST code to the grader. Returns ``(flag_or_None, completed, feedback)``.

        The grader sandbox cold-starts, so a generous timeout with one retry is
        used. Only a grader-validated flag is returned (an accepted submission),
        never an echo of the problem text.
        """
        import requests
        from core.utils.security import assert_url_allowed, SecurityPolicyError

        try:
            assert_url_allowed(run_url)
        except SecurityPolicyError:
            return None, False, ''
        payload = {"code": code, "language": language}
        for timeout in (90, 150):
            try:
                resp = requests.post(run_url, json=payload, timeout=timeout)
            except requests.exceptions.ReadTimeout:
                continue
            except Exception as exc:  # noqa: BLE001
                steps.append(f"Grader submission error: {exc}")
                return None, False, ''
            text = resp.text or ''
            completed = False
            feedback = text[:600]
            try:
                data = resp.json()
                completed = bool(data.get('challengeCompleted') or data.get('success'))
                if isinstance(data.get('result'), (dict, list)):
                    feedback = json.dumps(data['result'])[:600]
                explicit = data.get('flag')
                if explicit and find_first_flag(str(explicit)):
                    return find_first_flag(str(explicit)), True, feedback
            except ValueError:
                pass
            flag = find_first_flag(text)
            if flag and (completed or 'flag' in text.lower()):
                return flag, True, feedback
            return None, completed, feedback
        steps.append("Grader did not respond before timeout.")
        return None, False, ''

    def _llm_coding_program(self, problem: str, challenge: Dict[str, Any]) -> str:
        task = (
            "Write a COMPLETE Python 3 program that reads the problem input from "
            "standard input and prints ONLY the required answer to standard output. "
            "Do not hardcode the sample; parse stdin generically. Problem:\n\n" + problem
        )
        try:
            return self.reasoner.generate_script({"description": problem, "url": challenge.get("url")}, task)
        except Exception:
            return ""

    def _llm_fix_coding_program(
        self, problem: str, challenge: Dict[str, Any], code: str, feedback: str
    ) -> str:
        try:
            return self.reasoner.fix_script(
                {"description": problem, "url": challenge.get("url")},
                code,
                f"Autograder rejected the program. Grader feedback: {feedback}",
                "",
            )
        except Exception:
            return ""

    def _fallback_xor_solver(self, challenge: Dict[str, Any], task_desc: str) -> Optional[str]:
        """Deterministic solver for XOR challenges when LLM is unavailable."""
        import binascii
        
        # 1. Extract potential hex from files
        cipher_text = ""
        files = challenge.get("files", [])
        for f in files:
            if f.endswith(".txt"):
                try:
                    with open(f, "r") as file:
                        content = file.read().strip()
                        if "Flag:" in content: content = content.split("Flag:")[1].strip()
                        if all(c in "0123456789abcdefABCDEF" for c in content) and len(content) > 8:
                            cipher_text = content
                            break
                except: pass
        
        if not cipher_text:
            return None
            
        try:
            cipher_bytes = binascii.unhexlify(cipher_text)

            for prefix in (p.encode() for p in KNOWN_FLAG_PREFIXES):
                if len(prefix) > len(cipher_bytes):
                    continue
                # Guess the plaintext starts with this prefix and derive a
                # repeating key of length len(prefix).
                key = bytes(cipher_bytes[i] ^ prefix[i] for i in range(len(prefix)))
                decrypted = bytes(
                    cipher_bytes[i] ^ key[i % len(key)] for i in range(len(cipher_bytes))
                )
                res = decrypted.decode('utf-8', errors='ignore')
                # Validate with the real extractor (needs a closing brace and a
                # sane charset). The naive `prefix in res` check was tautological:
                # deriving the key from the prefix forces the first bytes to equal
                # it, so it "matched" even when the key length was wrong.
                found = find_first_flag(res)
                if found:
                    return found
        except Exception:
            pass
        return None

    def _solve_prime_sum_prompt(self, task_desc: str) -> Optional[str]:
        lowered = task_desc.lower()
        if "prime" not in lowered or "sum" not in lowered:
            return None

        nums = [int(n) for n in re.findall(r"\b\d+\b", task_desc)]
        if len(nums) < 2:
            return None

        start, end = min(nums[0], nums[1]), max(nums[0], nums[1])
        total = sum(n for n in range(start, end + 1) if self._is_prime(n))
        if "ctf" in lowered:
            return f"CTF{{{total}}}"
        return str(total)

    @staticmethod
    def _is_prime(n: int) -> bool:
        if n < 2:
            return False
        if n == 2:
            return True
        if n % 2 == 0:
            return False
        divisor = 3
        while divisor * divisor <= n:
            if n % divisor == 0:
                return False
            divisor += 2
        return True
    
    def get_capabilities(self) -> List[str]:
        return self.capabilities
