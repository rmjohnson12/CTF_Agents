# The Colony

Athene is a *colony* of burrowing owls. Each specialist agent is a **sentry** that guards one burrow — one category of challenge. The orchestrator is the **Lookout**: it scans the target, reads your request, and wakes the right sentry (or several) to dig.

Why owls, and why *this* owl? The burrowing owl's scientific name is *Athene cunicularia* — genus *Athene*, after Athena, goddess of wisdom and strategic warfare, whose emblem has been the owl for millennia. Unlike every other owl, the burrowing owl lives underground in burrows dug by other animals, hunts from a colony, stands sentinel at the burrow mouth, and digs in deep. Wisdom, reuse of existing structure, cooperation, watchfulness, and digging — the whole toolkit, in one bird.

## The roster

| Sentry | Agent | Guards | Digs with |
|---|---|---|---|
| **The Lookout** | Router / orchestrator | The mouth of every burrow | Intent parsing, file + path detection, category routing |
| **The Digger** | Reverse Engineering | Binaries and source | Static analysis, a constraint solver, live-execution verification |
| **The Prowler** | Web | Web apps | Playwright recon, dirsearch, sqlmap, login-bypass + cookie heuristics, parseInt() octal-bug detection |
| **The Cracker** | Crypto | Hashes and ciphers | Hashcat, John the Ripper, dictionary + raw-md5 attacks, wordlist auto-detection |
| **The Sifter** | Forensics | Files and artifacts | Binwalk, ExifTool, Strings, QPDF |
| **The Tinkerer** | Coding | Logic and math puzzles | Generates + runs Python, self-corrects crashing scripts |
| **The Scout** | OSINT | The open horizon | Metadata extraction, domain harvesting, info gathering |
| **The Watcher** | Log Analysis | Server and auth logs | Brute-force pattern + statistical anomaly detection |
| **The Listener** | Network Forensics | Packet captures | Scapy deep-packet inspection, custom TCP/UDP stream reconstruction |

## How the colony works a target

1. **The Lookout wakes.** It parses your plain-English request, finds any filenames or paths (including `~/`), and decides which burrow this belongs to.
2. **A sentry digs.** The matched specialist runs its tools inside strict timeouts and safety boundaries, persisting findings to `results/{challenge_id}/`.
3. **The colony observes and adapts.** Results feed the iterative loop — reason → act → observe → adapt — until a flag surfaces.
4. **The flag is caught.** Centralized detection catches `SKY-XXXX-####` (NCL Cyber Skyline) and `HTB{...}` patterns across every tool's output, logs, and artifacts.

> Naming convention: when you add a new specialist, give it a sentry name that reflects what it *does in the dirt* — a verb-creature, not a job title. The Burrower, the Tracker, the Snare. Keep the colony consistent.
