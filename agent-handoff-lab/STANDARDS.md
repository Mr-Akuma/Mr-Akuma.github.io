# Standardized threat mapping — agent-handoff lab (A1–A12)

Every exploit in this lab, mapped to the recognized catalogs. This is the defensive reference view; each row's `control` is what the FIXED build enforces. Generated from `lab/taxonomy.py` (`python -c "from lab.taxonomy import build_standards_md as b; open('STANDARDS.md','w',encoding='utf-8').write(b())"`).

Standards: OWASP Top 10 for LLM Applications 2025 · MITRE ATLAS · CWE. Identifiers verified July 2026.

## Summary matrix

| # | Exploit | Kill-chain | OWASP (2025) | MITRE ATLAS | Severity |
|---|---------|-----------|--------------|-------------|----------|
| A1 | Context-variable injection | escalate | LLM01:2025<br>LLM02:2025 | AML.T0051.000<br>AML.T0057 | High |
| A2 | Handoff-target coercion | act | LLM01:2025<br>LLM06:2025 | AML.T0051.000<br>AML.T0053 | High |
| A3 | Capability jumping | act | LLM06:2025<br>LLM01:2025 | AML.T0051.000<br>AML.T0053 | Critical |
| A4 | Rogue agent registration | act | LLM03:2025<br>LLM06:2025 | AML.T0110<br>AML.T0053 | Critical |
| A5 | Indirect injection via peer (RAG poisoning) | escalate | LLM01:2025<br>LLM08:2025<br>LLM02:2025 | AML.T0051.001<br>AML.T0020<br>AML.T0057 | High |
| A6 | Delegation loop (DoS) | act | LLM10:2025<br>LLM01:2025 | AML.T0051.001<br>AML.T0029 | Medium |
| A7 | Agent-card forgery (A2A) | act | LLM03:2025 | AML.T0110<br>AML.T0053 | Critical |
| A8 | Capability over-claim (A2A) | act | LLM06:2025<br>LLM03:2025 | AML.T0053 | High |
| A9 | Zero-click image-render exfiltration | exfiltrate | LLM02:2025<br>LLM05:2025<br>LLM01:2025 | AML.T0086<br>AML.T0057<br>AML.T0051.001 | High |
| A10 | SpAIware: memory-persistent exfiltration | persist | LLM01:2025<br>LLM04:2025<br>LLM02:2025 | AML.T0051.001<br>AML.T0020<br>AML.T0057 | Critical |
| A11 | Delayed tool invocation | act | LLM06:2025<br>LLM01:2025 | AML.T0051.001<br>AML.T0053<br>AML.T0110 | High |
| A12 | ASCII smuggling (invisible Unicode instructions) | evade | LLM01:2025 | AML.T0068<br>AML.T0051.001 | High |

## Per-exploit detail

### A1 — Context-variable injection
*Kill-chain phase:* **escalate**  ·  *Severity:* **High**

- **OWASP LLM Top 10 (2025):** LLM01:2025 Prompt Injection, LLM02:2025 Sensitive Information Disclosure
- **MITRE ATLAS:** AML.T0051.000 LLM Prompt Injection: Direct, AML.T0057 LLM Data Leakage
- **CWE:** CWE-1427 Improper Neutralization of Input Used for LLM Prompting, CWE-863 Incorrect Authorization, CWE-200 Exposure of Sensitive Information
- **Control (FIXED build):** honor_untrusted_markers off (provenance) + scrub_context_on_handoff + role-gate at the tool
- **Primary source:** embracethered.com — context/shared-state injection

### A2 — Handoff-target coercion
*Kill-chain phase:* **act**  ·  *Severity:* **High**

- **OWASP LLM Top 10 (2025):** LLM01:2025 Prompt Injection, LLM06:2025 Excessive Agency
- **MITRE ATLAS:** AML.T0051.000 LLM Prompt Injection: Direct, AML.T0053 LLM Plugin Compromise / AI Agent Tool Invocation
- **CWE:** CWE-1427 Improper Neutralization of Input Used for LLM Prompting, CWE-862 Missing Authorization, CWE-441 Unintended Proxy or Intermediary (Confused Deputy)
- **Control (FIXED build):** enforce_handoff_allowlist (authorize the route at the join) + ignore markers
- **Primary source:** OWASP LLM06 Excessive Agency; multi-agent routing

### A3 — Capability jumping
*Kill-chain phase:* **act**  ·  *Severity:* **Critical**

- **OWASP LLM Top 10 (2025):** LLM06:2025 Excessive Agency, LLM01:2025 Prompt Injection
- **MITRE ATLAS:** AML.T0051.000 LLM Prompt Injection: Direct, AML.T0053 LLM Plugin Compromise / AI Agent Tool Invocation
- **CWE:** CWE-269 Improper Privilege Management, CWE-862 Missing Authorization, CWE-1427 Improper Neutralization of Input Used for LLM Prompting
- **Control (FIXED build):** enforce_tool_capabilities (per-agent least privilege) + ignore markers
- **Primary source:** OWASP LLM06; over-permissioned tool access

### A4 — Rogue agent registration
*Kill-chain phase:* **act**  ·  *Severity:* **Critical**

- **OWASP LLM Top 10 (2025):** LLM03:2025 Supply Chain, LLM06:2025 Excessive Agency
- **MITRE ATLAS:** AML.T0110 AI Agent Tool Poisoning, AML.T0053 LLM Plugin Compromise / AI Agent Tool Invocation
- **CWE:** CWE-306 Missing Authentication for Critical Function, CWE-862 Missing Authorization
- **Control (FIXED build):** authed_registry (operator token; no override of existing names)
- **Primary source:** Rehberger — Cross-Agent Privilege Escalation / AgentHopper

### A5 — Indirect injection via peer (RAG poisoning)
*Kill-chain phase:* **escalate**  ·  *Severity:* **High**

- **OWASP LLM Top 10 (2025):** LLM01:2025 Prompt Injection, LLM08:2025 Vector and Embedding Weaknesses, LLM02:2025 Sensitive Information Disclosure
- **MITRE ATLAS:** AML.T0051.001 LLM Prompt Injection: Indirect, AML.T0020 Poison Training Data (RAG/memory data sources), AML.T0057 LLM Data Leakage
- **CWE:** CWE-1427 Improper Neutralization of Input Used for LLM Prompting, CWE-829 Inclusion of Functionality from Untrusted Control Sphere
- **Control (FIXED build):** ignore markers (provenance) + scrub retrieved external content on handoff
- **Primary source:** embracethered.com — indirect prompt injection via retrieved content

### A6 — Delegation loop (DoS)
*Kill-chain phase:* **act**  ·  *Severity:* **Medium**

- **OWASP LLM Top 10 (2025):** LLM10:2025 Unbounded Consumption, LLM01:2025 Prompt Injection
- **MITRE ATLAS:** AML.T0051.001 LLM Prompt Injection: Indirect, AML.T0029 Denial of ML Service
- **CWE:** CWE-835 Loop with Unreachable Exit Condition, CWE-400 Uncontrolled Resource Consumption
- **Control (FIXED build):** detect_handoff_loops (a directed edge can't be taken twice) + ignore markers
- **Primary source:** OWASP LLM10 Unbounded Consumption; delegation ping-pong

### A7 — Agent-card forgery (A2A)
*Kill-chain phase:* **act**  ·  *Severity:* **Critical**

- **OWASP LLM Top 10 (2025):** LLM03:2025 Supply Chain
- **MITRE ATLAS:** AML.T0110 AI Agent Tool Poisoning, AML.T0053 LLM Plugin Compromise / AI Agent Tool Invocation
- **CWE:** CWE-345 Insufficient Verification of Data Authenticity, CWE-290 Authentication Bypass by Spoofing
- **Control (FIXED build):** verify_agent_cards (HMAC signature vs a known federation issuer key)
- **Primary source:** Google A2A protocol; cross-org Agent Card trust

### A8 — Capability over-claim (A2A)
*Kill-chain phase:* **act**  ·  *Severity:* **High**

- **OWASP LLM Top 10 (2025):** LLM06:2025 Excessive Agency, LLM03:2025 Supply Chain
- **MITRE ATLAS:** AML.T0053 LLM Plugin Compromise / AI Agent Tool Invocation
- **CWE:** CWE-269 Improper Privilege Management, CWE-863 Incorrect Authorization
- **Control (FIXED build):** clamp declared caps to a local per-partner grant (authN != authZ), then enforce them
- **Primary source:** A2A federation; authN mistaken for authZ

### A9 — Zero-click image-render exfiltration
*Kill-chain phase:* **exfiltrate**  ·  *Severity:* **High**

- **OWASP LLM Top 10 (2025):** LLM02:2025 Sensitive Information Disclosure, LLM05:2025 Improper Output Handling, LLM01:2025 Prompt Injection
- **MITRE ATLAS:** AML.T0086 Exfiltration via AI Agent Tool Invocation, AML.T0057 LLM Data Leakage, AML.T0051.001 LLM Prompt Injection: Indirect
- **CWE:** CWE-201 Insertion of Sensitive Information Into Sent Data, CWE-200 Exposure of Sensitive Information, CWE-116 Improper Encoding or Escaping of Output
- **Disclosed instances (CVE / named):** CVE-2025-54132 (Cursor — Mermaid image exfiltration), CVE-2025-32711 (Microsoft 365 Copilot — EchoLeak)
- **Control (FIXED build):** enforce_egress_allowlist (client fetches only trusted hosts) + don't render untrusted-origin images
- **Primary source:** embracethered.com — ChatGPT Plugins 2023, Amp Code 2025, OpenAI mitigations paper 2026

### A10 — SpAIware: memory-persistent exfiltration
*Kill-chain phase:* **persist**  ·  *Severity:* **Critical**

- **OWASP LLM Top 10 (2025):** LLM01:2025 Prompt Injection, LLM04:2025 Data and Model Poisoning, LLM02:2025 Sensitive Information Disclosure
- **MITRE ATLAS:** AML.T0051.001 LLM Prompt Injection: Indirect, AML.T0020 Poison Training Data (RAG/memory data sources), AML.T0057 LLM Data Leakage
- **CWE:** CWE-1427 Improper Neutralization of Input Used for LLM Prompting, CWE-349 Acceptance of Extraneous Untrusted Data With Trusted Data, CWE-201 Insertion of Sensitive Information Into Sent Data
- **Control (FIXED build):** provenance_on_memory (untrusted content may not persist long-term memory) + user confirmation
- **Primary source:** embracethered.com — SpAIware (ChatGPT) 2024, Windsurf 2025

### A11 — Delayed tool invocation
*Kill-chain phase:* **act**  ·  *Severity:* **High**

- **OWASP LLM Top 10 (2025):** LLM06:2025 Excessive Agency, LLM01:2025 Prompt Injection
- **MITRE ATLAS:** AML.T0051.001 LLM Prompt Injection: Indirect, AML.T0053 LLM Plugin Compromise / AI Agent Tool Invocation, AML.T0110 AI Agent Tool Poisoning
- **CWE:** CWE-807 Reliance on Untrusted Inputs in a Security Decision, CWE-862 Missing Authorization, CWE-441 Unintended Proxy or Intermediary (Confused Deputy)
- **Control (FIXED build):** confirm_sensitive_after_taint (taint is sticky; a trigger word doesn't launder untrusted origin)
- **Primary source:** embracethered.com — Hacking Gemini's Memory with Delayed Tool Invocation 2025

### A12 — ASCII smuggling (invisible Unicode instructions)
*Kill-chain phase:* **evade**  ·  *Severity:* **High**

- **OWASP LLM Top 10 (2025):** LLM01:2025 Prompt Injection
- **MITRE ATLAS:** AML.T0068 LLM Prompt Obfuscation, AML.T0051.001 LLM Prompt Injection: Indirect
- **CWE:** CWE-1427 Improper Neutralization of Input Used for LLM Prompting, CWE-176 Improper Handling of Unicode Encoding, CWE-838 Inappropriate Encoding for Output Context
- **Control (FIXED build):** provenance (encoding-independent); DETECT strip-invisibles only blocks the known carrier
- **Primary source:** embracethered.com — ASCII Smuggling / Sneaky Bits 2025

## The AI kill chain, by phase

- **escalate** — A1, A5
- **act** — A2, A3, A4, A6, A7, A8, A11
- **exfiltrate** — A9
- **persist** — A10
- **evade** — A12

> A1–A8 cover inject → escalate → act. A9–A12 continue into exfiltrate → persist → evade — the steps real incidents actually reach. The whole chain is one thesis: filtering the *content* trails the model's comprehension; only content-independent, structural controls (provenance + least privilege) reach 100%.
