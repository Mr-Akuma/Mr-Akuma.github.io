"""Standardized threat taxonomy for the twelve handoff/exfil/persistence exploits.

Single source of truth mapping every lab exploit (A1-A12) to the recognized
security standards, so the lab reads like a defensive reference, not a demo:

  * OWASP Top 10 for LLM Applications (2025)   https://genai.owasp.org/llm-top-10/
  * MITRE ATLAS techniques                     https://atlas.mitre.org
  * CWE (Common Weakness Enumeration)          https://cwe.mitre.org
  * Real, disclosed CVEs / named findings

Identifiers here were verified against the published catalogs (July 2026). The
`kill_chain` field places each exploit on the AI kill chain that Rehberger's
corpus traces (inject -> comprehend -> act -> exfiltrate -> persist).

`build_standards_md()` renders STANDARDS.md from this table; test_taxonomy.py
asserts every entry is complete and every identifier is well-formed, so the
standardization can't silently rot.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Mapping:
    id: str
    name: str
    kill_chain: str          # inject | escalate | act | exfiltrate | persist | evade
    owasp: list = field(default_factory=list)   # ["LLM01:2025 Prompt Injection", ...]
    atlas: list = field(default_factory=list)    # ["AML.T0051.001 LLM Prompt Injection: Indirect", ...]
    cwe: list = field(default_factory=list)      # ["CWE-1427 Improper Neutralization of Input Used for LLM Prompting", ...]
    cve: list = field(default_factory=list)      # disclosed real-world instances (may be empty for lab-only vectors)
    severity: str = "High"   # informational | Low | Medium | High | Critical
    control: str = ""        # the FIXED-build control that closes it
    source: str = ""         # primary research citation


# --- shared identifier strings (kept consistent across entries) --------------
LLM01 = "LLM01:2025 Prompt Injection"
LLM02 = "LLM02:2025 Sensitive Information Disclosure"
LLM03 = "LLM03:2025 Supply Chain"
LLM04 = "LLM04:2025 Data and Model Poisoning"
LLM05 = "LLM05:2025 Improper Output Handling"
LLM06 = "LLM06:2025 Excessive Agency"
LLM08 = "LLM08:2025 Vector and Embedding Weaknesses"
LLM10 = "LLM10:2025 Unbounded Consumption"

PI_DIRECT = "AML.T0051.000 LLM Prompt Injection: Direct"
PI_INDIRECT = "AML.T0051.001 LLM Prompt Injection: Indirect"
ATLAS_LEAK = "AML.T0057 LLM Data Leakage"
ATLAS_TOOL = "AML.T0053 LLM Plugin Compromise / AI Agent Tool Invocation"
ATLAS_EXFIL_TOOL = "AML.T0086 Exfiltration via AI Agent Tool Invocation"
ATLAS_TOOL_POISON = "AML.T0110 AI Agent Tool Poisoning"
ATLAS_POISON = "AML.T0020 Poison Training Data (RAG/memory data sources)"
ATLAS_OBFUSCATE = "AML.T0068 LLM Prompt Obfuscation"
ATLAS_DOS = "AML.T0029 Denial of ML Service"

CWE_LLM = "CWE-1427 Improper Neutralization of Input Used for LLM Prompting"

TAXONOMY = [
    Mapping("A1", "Context-variable injection", "escalate",
            owasp=[LLM01, LLM02],
            atlas=[PI_DIRECT, ATLAS_LEAK],
            cwe=[CWE_LLM, "CWE-863 Incorrect Authorization", "CWE-200 Exposure of Sensitive Information"],
            severity="High",
            control="honor_untrusted_markers off (provenance) + scrub_context_on_handoff + role-gate at the tool",
            source="embracethered.com — context/shared-state injection"),

    Mapping("A2", "Handoff-target coercion", "act",
            owasp=[LLM01, LLM06],
            atlas=[PI_DIRECT, ATLAS_TOOL],
            cwe=[CWE_LLM, "CWE-862 Missing Authorization", "CWE-441 Unintended Proxy or Intermediary (Confused Deputy)"],
            severity="High",
            control="enforce_handoff_allowlist (authorize the route at the join) + ignore markers",
            source="OWASP LLM06 Excessive Agency; multi-agent routing"),

    Mapping("A3", "Capability jumping", "act",
            owasp=[LLM06, LLM01],
            atlas=[PI_DIRECT, ATLAS_TOOL],
            cwe=["CWE-269 Improper Privilege Management", "CWE-862 Missing Authorization", CWE_LLM],
            severity="Critical",
            control="enforce_tool_capabilities (per-agent least privilege) + ignore markers",
            source="OWASP LLM06; over-permissioned tool access"),

    Mapping("A4", "Rogue agent registration", "act",
            owasp=[LLM03, LLM06],
            atlas=[ATLAS_TOOL_POISON, ATLAS_TOOL],
            cwe=["CWE-306 Missing Authentication for Critical Function", "CWE-862 Missing Authorization"],
            severity="Critical",
            control="authed_registry (operator token; no override of existing names)",
            source="Rehberger — Cross-Agent Privilege Escalation / AgentHopper"),

    Mapping("A5", "Indirect injection via peer (RAG poisoning)", "escalate",
            owasp=[LLM01, LLM08, LLM02],
            atlas=[PI_INDIRECT, ATLAS_POISON, ATLAS_LEAK],
            cwe=[CWE_LLM, "CWE-829 Inclusion of Functionality from Untrusted Control Sphere"],
            severity="High",
            control="ignore markers (provenance) + scrub retrieved external content on handoff",
            source="embracethered.com — indirect prompt injection via retrieved content"),

    Mapping("A6", "Delegation loop (DoS)", "act",
            owasp=[LLM10, LLM01],
            atlas=[PI_INDIRECT, ATLAS_DOS],
            cwe=["CWE-835 Loop with Unreachable Exit Condition", "CWE-400 Uncontrolled Resource Consumption"],
            severity="Medium",
            control="detect_handoff_loops (a directed edge can't be taken twice) + ignore markers",
            source="OWASP LLM10 Unbounded Consumption; delegation ping-pong"),

    Mapping("A7", "Agent-card forgery (A2A)", "act",
            owasp=[LLM03],
            atlas=[ATLAS_TOOL_POISON, ATLAS_TOOL],
            cwe=["CWE-345 Insufficient Verification of Data Authenticity", "CWE-290 Authentication Bypass by Spoofing"],
            severity="Critical",
            control="verify_agent_cards (HMAC signature vs a known federation issuer key)",
            source="Google A2A protocol; cross-org Agent Card trust"),

    Mapping("A8", "Capability over-claim (A2A)", "act",
            owasp=[LLM06, LLM03],
            atlas=[ATLAS_TOOL],
            cwe=["CWE-269 Improper Privilege Management", "CWE-863 Incorrect Authorization"],
            severity="High",
            control="clamp declared caps to a local per-partner grant (authN != authZ), then enforce them",
            source="A2A federation; authN mistaken for authZ"),

    Mapping("A9", "Zero-click image-render exfiltration", "exfiltrate",
            owasp=[LLM02, LLM05, LLM01],
            atlas=[ATLAS_EXFIL_TOOL, ATLAS_LEAK, PI_INDIRECT],
            cwe=["CWE-201 Insertion of Sensitive Information Into Sent Data",
                 "CWE-200 Exposure of Sensitive Information", "CWE-116 Improper Encoding or Escaping of Output"],
            cve=["CVE-2025-54132 (Cursor — Mermaid image exfiltration)",
                 "CVE-2025-32711 (Microsoft 365 Copilot — EchoLeak)"],
            severity="High",
            control="enforce_egress_allowlist (client fetches only trusted hosts) + don't render untrusted-origin images",
            source="embracethered.com — ChatGPT Plugins 2023, Amp Code 2025, OpenAI mitigations paper 2026"),

    Mapping("A10", "SpAIware: memory-persistent exfiltration", "persist",
            owasp=[LLM01, LLM04, LLM02],
            atlas=[PI_INDIRECT, ATLAS_POISON, ATLAS_LEAK],
            cwe=[CWE_LLM, "CWE-349 Acceptance of Extraneous Untrusted Data With Trusted Data",
                 "CWE-201 Insertion of Sensitive Information Into Sent Data"],
            severity="Critical",
            control="provenance_on_memory (untrusted content may not persist long-term memory) + user confirmation",
            source="embracethered.com — SpAIware (ChatGPT) 2024, Windsurf 2025"),

    Mapping("A11", "Delayed tool invocation", "act",
            owasp=[LLM06, LLM01],
            atlas=[PI_INDIRECT, ATLAS_TOOL, ATLAS_TOOL_POISON],
            cwe=["CWE-807 Reliance on Untrusted Inputs in a Security Decision",
                 "CWE-862 Missing Authorization", "CWE-441 Unintended Proxy or Intermediary (Confused Deputy)"],
            severity="High",
            control="confirm_sensitive_after_taint (taint is sticky; a trigger word doesn't launder untrusted origin)",
            source="embracethered.com — Hacking Gemini's Memory with Delayed Tool Invocation 2025"),

    Mapping("A12", "ASCII smuggling (invisible Unicode instructions)", "evade",
            owasp=[LLM01],
            atlas=[ATLAS_OBFUSCATE, PI_INDIRECT],
            cwe=[CWE_LLM, "CWE-176 Improper Handling of Unicode Encoding",
                 "CWE-838 Inappropriate Encoding for Output Context"],
            severity="High",
            control="provenance (encoding-independent); DETECT strip-invisibles only blocks the known carrier",
            source="embracethered.com — ASCII Smuggling / Sneaky Bits 2025"),
]

BY_ID = {m.id: m for m in TAXONOMY}

# Ordered kill-chain phases for grouping/rendering.
KILL_CHAIN = ["inject", "escalate", "act", "exfiltrate", "persist", "evade"]


def build_standards_md() -> str:
    """Render STANDARDS.md — the human-readable standardized reference."""
    L = []
    L.append("# Standardized threat mapping — agent-handoff lab (A1–A12)\n")
    L.append("Every exploit in this lab, mapped to the recognized catalogs. This is the "
             "defensive reference view; each row's `control` is what the FIXED build enforces. "
             "Generated from `lab/taxonomy.py` (`python -c \"from lab.taxonomy import build_standards_md as b; "
             "open('STANDARDS.md','w',encoding='utf-8').write(b())\"`).\n")
    L.append("Standards: OWASP Top 10 for LLM Applications 2025 · MITRE ATLAS · CWE. "
             "Identifiers verified July 2026.\n")

    L.append("## Summary matrix\n")
    L.append("| # | Exploit | Kill-chain | OWASP (2025) | MITRE ATLAS | Severity |")
    L.append("|---|---------|-----------|--------------|-------------|----------|")
    for m in TAXONOMY:
        owasp = "<br>".join(x.split(" ", 1)[0] for x in m.owasp)
        atlas = "<br>".join(x.split(" ", 1)[0] for x in m.atlas)
        L.append(f"| {m.id} | {m.name} | {m.kill_chain} | {owasp} | {atlas} | {m.severity} |")
    L.append("")

    L.append("## Per-exploit detail\n")
    for m in TAXONOMY:
        L.append(f"### {m.id} — {m.name}")
        L.append(f"*Kill-chain phase:* **{m.kill_chain}**  ·  *Severity:* **{m.severity}**")
        L.append("")
        L.append(f"- **OWASP LLM Top 10 (2025):** {', '.join(m.owasp)}")
        L.append(f"- **MITRE ATLAS:** {', '.join(m.atlas)}")
        L.append(f"- **CWE:** {', '.join(m.cwe)}")
        if m.cve:
            L.append(f"- **Disclosed instances (CVE / named):** {', '.join(m.cve)}")
        L.append(f"- **Control (FIXED build):** {m.control}")
        L.append(f"- **Primary source:** {m.source}")
        L.append("")

    L.append("## The AI kill chain, by phase\n")
    for phase in KILL_CHAIN:
        ids = [m.id for m in TAXONOMY if m.kill_chain == phase]
        if ids:
            L.append(f"- **{phase}** — {', '.join(ids)}")
    L.append("")
    L.append("> A1–A8 cover inject → escalate → act. A9–A12 continue into exfiltrate "
             "→ persist → evade — the steps real incidents actually reach. The whole "
             "chain is one thesis: filtering the *content* trails the model's comprehension; "
             "only content-independent, structural controls (provenance + least privilege) "
             "reach 100%.\n")
    return "\n".join(L)


if __name__ == "__main__":
    import pathlib
    out = pathlib.Path(__file__).resolve().parent.parent / "STANDARDS.md"
    out.write_text(build_standards_md(), encoding="utf-8")
    print("wrote", out, f"({len(TAXONOMY)} exploits mapped)")
