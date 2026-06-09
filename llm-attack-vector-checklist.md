# LLM Attack Vector Checklist for Threat Modeling

Purpose: defensive checklist for threat modeling LLM applications, RAG systems, agentic workflows, MCP/tool integrations, and human approval flows.

References:
- OWASP Top 10 for LLM Applications 2025: https://genai.owasp.org/llm-top-10/
- MITRE ATLAS: https://atlas.mitre.org/
- NIST AI Risk Management Framework and Generative AI Profile: https://www.nist.gov/itl/ai-risk-management-framework

Use this as a backlog. Not every vector applies to every system. Prioritize by where untrusted input, sensitive data, tool permissions, memory, and human approval meet.

## A. Prompt and Input Manipulation

| ID | Attack vector | Threat-model question |
|---|---|---|
| LLM-001 | Direct prompt injection | Can a user override system, developer, policy, or task instructions? |
| LLM-002 | Indirect prompt injection from RAG | Can retrieved documents contain instructions the model treats as commands? |
| LLM-003 | Indirect prompt injection from webpages | Can fetched pages manipulate an agent or browser tool? |
| LLM-004 | Injection from email, tickets, chat, or CRM notes | Can operational content become model instructions? |
| LLM-005 | Injection from logs, alerts, or telemetry | Can attacker-controlled log fields influence LLM security analysis? |
| LLM-006 | Injection from filenames, titles, metadata, comments, or alt text | Are non-body fields passed into prompts without trust labels? |
| LLM-007 | Prompt smuggling in structured data | Can JSON, XML, CSV, YAML, or tables carry hidden instructions? |
| LLM-008 | Prompt template variable injection | Can user-controlled values break prompt delimiters or change instruction meaning? |
| LLM-009 | Delimiter confusion | Can the model confuse quoted data with higher-priority instructions? |
| LLM-010 | Role or authority impersonation | Can a user claim to be system, admin, auditor, developer, or another agent? |
| LLM-011 | Multi-turn manipulation | Can harmless turns accumulate into a policy or task bypass? |
| LLM-012 | Context stuffing | Can a large prompt bury critical policy, warnings, or tool constraints? |
| LLM-013 | Encoding or obfuscation bypass | Can encoded, translated, fragmented, or disguised text bypass filters? |
| LLM-014 | Cross-language jailbreak | Do controls hold when prompts mix languages or transliteration? |
| LLM-015 | Hypothetical, roleplay, or simulation jailbreak | Can the model be induced to ignore constraints under fictional framing? |
| LLM-016 | Instruction laundering through examples | Can malicious instructions be hidden inside "examples", quotes, tests, or docs? |
| LLM-017 | User-controlled system-like preamble | Can uploads or forms begin with text that looks like platform instructions? |
| LLM-018 | Tool error message injection | Can exception text or stack traces influence later model decisions? |
| LLM-019 | Evaluation harness injection | Can test cases or evaluation prompts manipulate scoring or safety checks? |
| LLM-020 | Prompt leak canary probing | Can users iteratively infer prompt, guardrails, hidden policies, or secrets? |

## B. RAG, Context, Memory, and Embeddings

| ID | Attack vector | Threat-model question |
|---|---|---|
| LLM-021 | RAG authorization bypass | Are retrieved documents filtered by the user's real permissions before entering context? |
| LLM-022 | Cross-tenant retrieval | Can one tenant retrieve another tenant's chunks, metadata, or embeddings? |
| LLM-023 | Vector namespace mix-up | Are indexes, collections, and namespaces isolated by tenant, environment, and user scope? |
| LLM-024 | Metadata filter bypass | Can attacker-controlled metadata defeat access-control filters? |
| LLM-025 | RAG document poisoning | Can untrusted users upload content that influences future answers? |
| LLM-026 | Retrieval content crafting | Can attacker text be written to reliably appear in top-k results? |
| LLM-027 | Embedding manipulation | Can adversarial text, repetition, or keyword stuffing distort semantic ranking? |
| LLM-028 | Chunk-boundary manipulation | Can harmful instructions be split across chunks or made to dominate chunk summaries? |
| LLM-029 | Stale or deleted document retrieval | Do revoked, deleted, or expired documents remain in vector stores or caches? |
| LLM-030 | Source attribution spoofing | Can attacker documents appear to come from trusted sources? |
| LLM-031 | Citation laundering | Can the model cite an untrusted or irrelevant source as evidence? |
| LLM-032 | Persistent memory poisoning | Can a user store malicious preferences, rules, or facts that affect later sessions? |
| LLM-033 | Cross-session memory leakage | Can memories from one user, role, or tenant affect another? |
| LLM-034 | Memory privilege mismatch | Can low-trust interactions write memory used in high-trust workflows? |
| LLM-035 | Conversation summary poisoning | Can summaries omit, alter, or elevate malicious instructions? |
| LLM-036 | Context over-sharing | Is more private context supplied than the task requires? |
| LLM-037 | Cache bleed | Can prompt, completion, embedding, or retrieval caches cross users or tenants? |
| LLM-038 | Retrieval of hidden document content | Are comments, tracked changes, hidden text, speaker notes, or OCR artifacts included unintentionally? |
| LLM-039 | Embedding sensitive data leakage | Can embeddings, vector DB exports, backups, or similarity queries reveal sensitive information? |
| LLM-040 | Model-context provenance loss | Can the system tell which data was user input, trusted policy, retrieved context, memory, or tool output? |

## C. Sensitive Data and Privacy

| ID | Attack vector | Threat-model question |
|---|---|---|
| LLM-041 | System prompt leakage | Can the model reveal hidden prompts, guardrails, internal URLs, or business logic? |
| LLM-042 | Developer prompt leakage | Can intermediate orchestration instructions be exposed? |
| LLM-043 | Secret-in-prompt exposure | Are API keys, tokens, credentials, or internal endpoints ever placed in prompts? |
| LLM-044 | PII disclosure | Can the model reveal personal data from context, retrieval, memory, or logs? |
| LLM-045 | Training data memorization | Can prompts elicit sensitive data memorized during training or fine-tuning? |
| LLM-046 | Fine-tuning data disclosure | Can proprietary fine-tune examples be reconstructed from outputs? |
| LLM-047 | Internal reasoning or debug trace leakage | Do debug modes expose sensitive intermediate data or hidden orchestration state? |
| LLM-048 | Tool response overexposure | Do tools return more data than the model needs? |
| LLM-049 | Browser/session data exposure | Can an agent read sensitive pages, cookies, forms, or account information? |
| LLM-050 | Prompt replay in analytics | Are prompts and completions sent to analytics, observability, or vendor systems? |
| LLM-051 | Log and trace secret leakage | Are prompts, tool arguments, headers, tokens, and retrieved docs redacted in logs? |
| LLM-052 | Data residency violation | Can prompts or outputs cross geographic, contractual, or regulatory boundaries? |
| LLM-053 | Retention mismatch | Are prompts, embeddings, memories, files, and outputs retained longer than allowed? |
| LLM-054 | Backup exposure | Are vector DB backups, transcript exports, or model artifacts protected like production data? |
| LLM-055 | Third-party connector leakage | Can connected apps receive sensitive data without user-visible consent? |
| LLM-056 | Screenshot or attachment leakage | Can generated screenshots, file previews, or exports contain hidden sensitive data? |
| LLM-057 | Privacy inference | Can repeated queries infer hidden attributes about users, records, or training examples? |
| LLM-058 | Token persistence | Are OAuth tokens or temporary credentials stored in memory, chat, logs, or files? |
| LLM-059 | Unredacted error disclosure | Do failures expose stack traces, internal object IDs, SQL, document paths, or secrets? |
| LLM-060 | Sensitive output transformation | Can the model summarize, translate, encode, or reformat data to bypass DLP? |

## D. Tool Use, Function Calling, and Execution

| ID | Attack vector | Threat-model question |
|---|---|---|
| LLM-061 | Excessive tool permissions | Does the agent have more tools or scopes than the task requires? |
| LLM-062 | Unsafe automatic tool invocation | Can tools run without explicit user intent or policy approval? |
| LLM-063 | Confused deputy through tools | Can a user make the agent use privileged credentials on the user's behalf? |
| LLM-064 | User-controlled tool arguments | Are tool parameters schema-validated and authorization-checked server-side? |
| LLM-065 | Prompt-to-API parameter tampering | Can the model alter IDs, scopes, filters, amounts, recipients, or destinations? |
| LLM-066 | Shell command injection | Can generated commands or user text reach a shell or process runner? |
| LLM-067 | SQL or query injection | Can generated queries execute without parameterization or review? |
| LLM-068 | Code execution abuse | Can generated code run outside a sandbox or with broad filesystem/network access? |
| LLM-069 | Path traversal through file tools | Can model-selected paths read or write outside the intended workspace? |
| LLM-070 | SSRF through fetch or browser tools | Can an agent access internal URLs, metadata services, localhost, or private APIs? |
| LLM-071 | Unsafe browser automation | Can an agent click, submit, purchase, delete, or authorize actions on websites? |
| LLM-072 | Email or messaging abuse | Can an agent send manipulated content externally or impersonate a user? |
| LLM-073 | Payment or transfer abuse | Can an agent initiate financial actions without strong approval? |
| LLM-074 | Production deployment abuse | Can an agent deploy code, change infrastructure, or rotate secrets without review? |
| LLM-075 | Destructive action abuse | Can an agent delete, revoke, overwrite, or mutate records irreversibly? |
| LLM-076 | Missing dry-run path | Are high-impact actions previewed with exact parameters before execution? |
| LLM-077 | Retry side effects | Can retries duplicate emails, payments, tickets, jobs, or deployments? |
| LLM-078 | Missing idempotency | Are tool calls protected against duplicate execution? |
| LLM-079 | Tool return-value injection | Are tool outputs treated as untrusted data rather than instructions? |
| LLM-080 | Tool description poisoning | Can a tool's name, description, or examples manipulate model behavior? |
| LLM-081 | Tool schema poisoning | Can schemas, defaults, enum labels, or parameter descriptions include hidden instructions? |
| LLM-082 | Tool error poisoning | Can errors or warnings from tools steer the agent into unsafe fallback behavior? |
| LLM-083 | Connector scope creep | Do OAuth scopes and API permissions expand without review? |
| LLM-084 | Arbitrary external API access | Can the agent call unapproved domains, APIs, or webhooks? |
| LLM-085 | File upload/download exfiltration | Can tools move sensitive files to attacker-controlled locations? |
| LLM-086 | Tool race condition | Can state change between model decision, approval, and tool execution? |
| LLM-087 | Parallel tool inconsistency | Can parallel calls observe inconsistent state or bypass sequencing controls? |
| LLM-088 | Agent self-modification | Can the agent edit its own instructions, tools, policy files, or memory rules? |
| LLM-089 | Unbounded agent loop | Can the agent keep planning, calling tools, or retrying without a hard cap? |
| LLM-090 | Action audit gap | Is every tool call tied to user, session, prompt, evidence, approval, and result? |

## E. Quorum, Approval, Consensus, and Control Gates

| ID | Attack vector | Threat-model question |
|---|---|---|
| LLM-091 | Quorum bypass | Can privileged actions execute without the required approvals? |
| LLM-092 | Threshold misconfiguration | Is the approval threshold too low for the action's impact? |
| LLM-093 | Timeout downgrade | Does the system reduce approval requirements after delay or failure? |
| LLM-094 | Abstain-as-approve | Are missing, failed, or abstained votes ever counted as approval? |
| LLM-095 | Fail-open approval gate | Does an approval service outage allow execution? |
| LLM-096 | Fake approval injection | Can an attacker forge an approval event, webhook, or message? |
| LLM-097 | Approval replay | Can an old approval be reused for a new action? |
| LLM-098 | Approval not bound to exact action | Is approval cryptographically or transactionally tied to exact parameters? |
| LLM-099 | Approval summary mismatch | Do approvers see a model-generated summary instead of exact raw action details? |
| LLM-100 | Hidden parameter change after approval | Can amount, recipient, query, target, or scope change after approval? |
| LLM-101 | Race between approval and execution | Can state change after approval but before execution? |
| LLM-102 | Approver identity spoofing | Can a user, agent, or service impersonate an approver? |
| LLM-103 | One actor, multiple votes | Can one account, model, service, or person satisfy multiple quorum slots? |
| LLM-104 | Agent self-approval | Can the requesting agent approve its own action? |
| LLM-105 | Shared-model non-independence | Are "multiple approvers" actually the same model, prompt, memory, or policy? |
| LLM-106 | Shared-context compromise | Can one poisoned RAG source influence all quorum agents? |
| LLM-107 | Shared-tool compromise | Can one poisoned tool output influence all voters? |
| LLM-108 | Majority manipulation through sub-agents | Can an orchestrator create or select favorable agents to form a majority? |
| LLM-109 | Voter selection bias | Can the agent choose which reviewers, models, or humans are asked? |
| LLM-110 | Veto bypass | Can a negative vote be ignored, overwritten, or reclassified? |
| LLM-111 | Tie-breaker abuse | Can tie-breaking rules be manipulated by ordering, timing, or reviewer choice? |
| LLM-112 | Quorum denial of service | Can attackers delay, exhaust, or block approvers to force fallback behavior? |
| LLM-113 | Human rubber-stamping | Are humans asked to approve vague summaries too often or too quickly? |
| LLM-114 | Approval UI spoofing | Can the user interface hide, truncate, or misrepresent action details? |
| LLM-115 | Broad pre-approval abuse | Can approval for a class of actions be stretched beyond the intended instance? |
| LLM-116 | Delegated approval abuse | Can approvers delegate to weaker identities, agents, or groups? |
| LLM-117 | Policy engine bypass | Can the agent route around policy-as-code or approval middleware? |
| LLM-118 | Conflicting approval sources | Do chat approvals, ticket approvals, API approvals, and UI approvals disagree? |
| LLM-119 | Missing separation of duties | Can the requester, implementer, approver, and executor be the same principal? |
| LLM-120 | Approval audit weakness | Can approval evidence be altered or lost after execution? |

## F. Identity, Authorization, and Tenant Boundaries

| ID | Attack vector | Threat-model question |
|---|---|---|
| LLM-121 | LLM-based authorization decision | Is the model trusted to decide access rather than deterministic policy? |
| LLM-122 | Prompt-supplied tenant or user ID | Can the user influence identity, tenant, role, or permission context? |
| LLM-123 | Session mix-up | Can one user's prompt, files, memory, or tool credentials bind to another session? |
| LLM-124 | User impersonation through agent action | Can outputs or tool calls appear to come from another user? |
| LLM-125 | Overprivileged service account | Does the agent run with broad service credentials instead of user-scoped tokens? |
| LLM-126 | Missing per-tool authorization | Is authorization checked for each operation, not just login? |
| LLM-127 | Long-lived integration tokens | Are tokens scoped, short-lived, revocable, and rotated? |
| LLM-128 | Weak service-to-service authentication | Can rogue agents, MCP servers, or connectors call internal services? |
| LLM-129 | Cross-workspace action | Can an agent act across repos, projects, tenants, or environments accidentally? |
| LLM-130 | Default-allow connector policy | Are new tools allowed unless explicitly blocked? |
| LLM-131 | Stale identity context | Are role changes, revocations, and terminations reflected immediately? |
| LLM-132 | Privilege escalation via connected app | Can a low-privilege user use a high-privilege connector indirectly? |
| LLM-133 | Multi-tenant prompt bleed | Are tenant-specific instructions or policies isolated? |
| LLM-134 | Shadow AI identity gap | Are unapproved AI tools missing from IAM, inventory, monitoring, and DLP? |
| LLM-135 | Weak delegated authority | Can an agent claim delegated user consent without proof? |

## G. Supply Chain, Models, Datasets, and Deployment

| ID | Attack vector | Threat-model question |
|---|---|---|
| LLM-136 | Compromised base model | Are models sourced, approved, scanned, and versioned? |
| LLM-137 | Backdoored model weights | Are model artifacts verified with signatures or hashes? |
| LLM-138 | Malicious fine-tune adapter | Are LoRA/adapters and checkpoints trusted like executable code? |
| LLM-139 | Poisoned training data | Is data provenance tracked for pretraining and fine-tuning? |
| LLM-140 | Poisoned evaluation data | Can benchmarks or red-team tests be manipulated to hide failures? |
| LLM-141 | Dependency compromise | Are inference, orchestration, parser, and plugin dependencies scanned and pinned? |
| LLM-142 | Typosquatting or dependency confusion | Can malicious packages replace internal or expected dependencies? |
| LLM-143 | Prompt template supply-chain attack | Are shared prompt libraries, agents, and templates reviewed and versioned? |
| LLM-144 | Model registry tampering | Can registry metadata, tags, or model versions be changed without approval? |
| LLM-145 | Unsafe model update | Can provider or model changes alter behavior without regression testing? |
| LLM-146 | Unsafe fallback model | Does outage handling route to a weaker or unapproved model? |
| LLM-147 | Container or runtime compromise | Are serving images, GPUs, drivers, and runtimes patched and isolated? |
| LLM-148 | CI/CD poisoning | Can build pipelines inject prompts, tools, configs, or model artifacts? |
| LLM-149 | Third-party plugin marketplace risk | Are plugins signed, reviewed, sandboxed, and monitored? |
| LLM-150 | Insecure parser dependency | Can PDF, image, office, archive, or HTML parsers be exploited during ingestion? |
| LLM-151 | Environment mix-up | Can dev prompts, test keys, staging data, or weaker policies reach production? |
| LLM-152 | Debug mode in production | Can debug prompts, traces, or bypass flags be enabled by users or attackers? |
| LLM-153 | Client-side prompt exposure | Are sensitive prompts or tool schemas exposed in browser/mobile code? |
| LLM-154 | Feature flag guardrail bypass | Can flags disable filters, approvals, logging, or sandboxing? |
| LLM-155 | Model artifact theft | Are weights, adapters, prompts, datasets, and evals protected as intellectual property? |

## H. Output Handling and Downstream Injection

| ID | Attack vector | Threat-model question |
|---|---|---|
| LLM-156 | XSS from generated HTML or Markdown | Is model output encoded and sanitized before rendering? |
| LLM-157 | Markdown link phishing | Can generated links mislead users or hide dangerous destinations? |
| LLM-158 | SQL injection from generated queries | Are generated queries parameterized and reviewed? |
| LLM-159 | Command injection from generated commands | Are commands structured without shell string concatenation? |
| LLM-160 | JSON or schema injection | Can output break parsers or smuggle fields into downstream systems? |
| LLM-161 | Template injection | Can generated templates execute code or access server objects? |
| LLM-162 | Deserialization risk | Can generated serialized data trigger unsafe object construction? |
| LLM-163 | Spreadsheet formula injection | Can CSV/XLSX output execute formulas when opened? |
| LLM-164 | Log injection | Can generated output forge or corrupt logs? |
| LLM-165 | Generated code dependency risk | Can the model recommend non-existent, malicious, or typosquatted packages? |
| LLM-166 | Unsafe infrastructure-as-code | Can generated IaC expose public resources, weak IAM, or secrets? |
| LLM-167 | Unsafe remediation instructions | Can generated operational guidance cause data loss or security weakening? |
| LLM-168 | Citation hallucination | Can the model invent sources, quote nonexistent evidence, or cite irrelevant documents? |
| LLM-169 | High-stakes misinformation | Can hallucinations affect medical, legal, financial, safety, or security outcomes? |
| LLM-170 | Hidden control characters | Can Unicode, ANSI, or invisible characters alter terminals, logs, or reviews? |
| LLM-171 | Data tampering in generated reports | Can summaries omit caveats, alter numbers, or misstate evidence? |
| LLM-172 | Policy-violating content generation | Can outputs support phishing, fraud, malware, abuse, or harmful instructions? |
| LLM-173 | Unsafe auto-ingestion of output | Is model output fed directly into tickets, code, databases, or tools? |
| LLM-174 | Output trust confusion | Do downstream systems know whether content is generated, user-provided, verified, or authoritative? |

## I. Denial of Service, Cost Abuse, and Reliability

| ID | Attack vector | Threat-model question |
|---|---|---|
| LLM-175 | Token exhaustion | Can users force very long prompts, contexts, or completions? |
| LLM-176 | Context-window stuffing | Can attackers crowd out safety instructions or needed evidence? |
| LLM-177 | Expensive tool-call abuse | Can users trigger costly search, scraping, code execution, or data processing? |
| LLM-178 | Recursive agent loop | Can an agent repeatedly plan, call itself, or spawn tasks? |
| LLM-179 | Retry storm | Can failures create repeated model calls or side-effecting tool calls? |
| LLM-180 | Model latency exhaustion | Can slow prompts tie up workers or streaming connections? |
| LLM-181 | Concurrent session flooding | Are per-user, per-tenant, and global limits enforced? |
| LLM-182 | Trial or account fan-out | Can attackers bypass limits using many identities, keys, or tenants? |
| LLM-183 | Vector query amplification | Can queries trigger large retrieval, reranking, or graph traversal work? |
| LLM-184 | Embedding ingestion flood | Can uploads create excessive embedding, OCR, parsing, or indexing costs? |
| LLM-185 | Parser bomb | Can archives, PDFs, images, or documents exhaust parsing resources? |
| LLM-186 | Cache bypass | Can small prompt changes defeat caching and multiply cost? |
| LLM-187 | Expensive model selection abuse | Can users force premium models or larger context windows unnecessarily? |
| LLM-188 | Approval queue exhaustion | Can attackers flood human or quorum review queues? |
| LLM-189 | Streaming abuse | Can long-running streams hold resources or evade response limits? |
| LLM-190 | Budget-drain denial of service | Can attackers consume API credits, quotas, or vendor budgets? |

## J. Model Extraction, Inference, and Safety Evasion

| ID | Attack vector | Threat-model question |
|---|---|---|
| LLM-191 | Model extraction | Can repeated queries approximate proprietary behavior or decision logic? |
| LLM-192 | Prompt extraction | Can attackers infer hidden prompts, policies, or routing rules? |
| LLM-193 | Membership inference | Can attackers determine whether a record was in training or fine-tuning data? |
| LLM-194 | Training data extraction | Can prompts elicit memorized snippets or confidential examples? |
| LLM-195 | Fine-tune inversion | Can attackers reconstruct proprietary fine-tune patterns or labels? |
| LLM-196 | Model fingerprinting | Can attackers identify model, version, safety layer, or provider for targeted attacks? |
| LLM-197 | Guardrail boundary probing | Can attackers map what filters allow and block? |
| LLM-198 | Safety classifier evasion | Can text transformation bypass moderation or policy classifiers? |
| LLM-199 | Adversarial suffix or trigger | Can crafted suffixes or triggers reliably alter behavior? |
| LLM-200 | Latent backdoor trigger | Can rare phrases, facts, or patterns activate hidden behavior? |
| LLM-201 | Eval overfitting | Are controls tuned only to known test cases rather than real adversarial behavior? |
| LLM-202 | Model theft via artifact access | Can insiders or compromised services download weights, adapters, or prompts? |

## K. Multi-Agent and Delegation Risks

| ID | Attack vector | Threat-model question |
|---|---|---|
| LLM-203 | Instruction laundering between agents | Can one agent pass malicious instructions to another as trusted work product? |
| LLM-204 | Delegation to weaker agent | Can a high-trust agent delegate to a less protected or less monitored agent? |
| LLM-205 | Transitive trust expansion | Does trusting Agent A unintentionally trust Agent B, tools, memory, and data sources? |
| LLM-206 | Shared workspace poisoning | Can files, notes, blackboards, or task queues manipulate multiple agents? |
| LLM-207 | Manager-agent blind trust | Does an orchestrator accept sub-agent conclusions without evidence validation? |
| LLM-208 | Cross-agent context leakage | Can one agent see another agent's private context, tokens, or tasks? |
| LLM-209 | Agent role confusion | Can agents confuse planner, reviewer, executor, and approver responsibilities? |
| LLM-210 | Malicious sub-agent registration | Can an attacker add a rogue agent to a workflow? |
| LLM-211 | Agent collusion or shared failure | Are independent agents actually diverse enough to catch each other's errors? |
| LLM-212 | Delegated tool misuse | Can a sub-agent use tools the parent agent should not expose? |
| LLM-213 | Task queue poisoning | Can queued instructions be modified before execution? |
| LLM-214 | Agent self-replication | Can agents create more agents, tasks, or workflows without governance? |
| LLM-215 | Evidence-free consensus | Can multiple agents agree without independently checking primary evidence? |

## L. Multimodal, Document, and File-Based Inputs

| ID | Attack vector | Threat-model question |
|---|---|---|
| LLM-216 | Hidden text in images | Can OCR reveal instructions invisible or unobvious to users? |
| LLM-217 | QR code or barcode injection | Can encoded visual content steer browser, fetch, or tool behavior? |
| LLM-218 | Audio prompt injection | Can spoken or background audio manipulate transcription and agent behavior? |
| LLM-219 | Video-frame injection | Can hidden frames, captions, or overlays influence multimodal analysis? |
| LLM-220 | PDF hidden-layer injection | Are hidden layers, annotations, forms, comments, and attachments handled safely? |
| LLM-221 | Office document metadata injection | Can comments, tracked changes, speaker notes, or macros affect prompts? |
| LLM-222 | Spreadsheet formula injection | Are formulas neutralized before summarization or export? |
| LLM-223 | EXIF and media metadata injection | Is image/video metadata included in context without trust labeling? |
| LLM-224 | OCR parser disagreement | Do humans and models see different content from the same file? |
| LLM-225 | Archive traversal or file confusion | Can uploaded archives create unsafe paths, names, or nested payloads? |
| LLM-226 | Attachment type spoofing | Can content-type, extension, and actual file content disagree? |
| LLM-227 | Document summarization poisoning | Can a document manipulate its own summary or classification? |

## M. Human Factors, UI, and Social Engineering

| ID | Attack vector | Threat-model question |
|---|---|---|
| LLM-228 | AI-generated phishing | Can outputs impersonate trusted people, brands, or internal systems? |
| LLM-229 | Fake confidence | Does the interface overstate certainty or hide uncertainty? |
| LLM-230 | Fabricated policy or legal authority | Can the model invent rules users will follow? |
| LLM-231 | Approval fatigue | Are humans asked to approve too many low-quality or vague actions? |
| LLM-232 | Unsafe suggested actions | Can suggested replies, buttons, or next steps nudge users into risky behavior? |
| LLM-233 | UI truncation of critical details | Are recipients, amounts, URLs, queries, and scopes visible before approval? |
| LLM-234 | Spoofed citations or provenance | Can generated evidence look official when it is not? |
| LLM-235 | Overreliance in high-stakes workflows | Are model outputs independently verified before consequential decisions? |
| LLM-236 | Social engineering via agent persona | Can a model's tone, authority, or identity manipulate users or operators? |
| LLM-237 | Hidden external communication | Can users miss when the agent will send data outside the organization? |
| LLM-238 | Unsafe copy-paste path | Can generated commands, code, or configs harm users when pasted elsewhere? |
| LLM-239 | Human override without accountability | Can users bypass model or policy warnings without reason capture? |

## N. Monitoring, Audit, Incident Response, and Governance

| ID | Attack vector | Threat-model question |
|---|---|---|
| LLM-240 | Missing prompt and tool audit trail | Can incidents reconstruct prompts, retrieved context, tool calls, approvals, and outputs? |
| LLM-241 | Secret-rich audit logs | Do logs create a second sensitive data store? |
| LLM-242 | Mutable audit evidence | Can logs, approvals, prompts, or tool records be altered after the fact? |
| LLM-243 | No anomaly detection | Are unusual prompts, retrievals, tool calls, costs, and approvals monitored? |
| LLM-244 | No abuse reporting path | Can users report bad outputs, prompt injection, or unsafe agent behavior? |
| LLM-245 | No kill switch | Can high-risk agents, tools, models, or connectors be disabled quickly? |
| LLM-246 | No model/version provenance | Can outputs be tied to model, prompt version, tool version, and policy version? |
| LLM-247 | No rollback plan | Can unsafe prompt, model, index, or tool changes be reverted? |
| LLM-248 | Missing red-team regression tests | Are known attack patterns tested after model, prompt, tool, and data changes? |
| LLM-249 | Shadow AI inventory gap | Are unofficial AI tools, browser extensions, SaaS copilots, and agents discovered? |
| LLM-250 | Policy drift | Are prompt policies, code policies, IAM policies, and human procedures kept aligned? |
| LLM-251 | Incomplete incident containment | Can compromised memory, vector content, approvals, and tokens be purged? |
| LLM-252 | Vendor incident dependency | Are provider outages, breaches, model changes, and logging policies accounted for? |

## O. MCP, Plugin, and Agent Server Specific Risks

| ID | Attack vector | Threat-model question |
|---|---|---|
| LLM-253 | MCP token mismanagement | Are MCP and connector tokens short-lived, scoped, redacted, and rotated? |
| LLM-254 | Unauthenticated MCP server | Can unauthorized clients register tools or call MCP endpoints? |
| LLM-255 | Missing per-tool MCP authorization | Does the server enforce authorization per tool and operation? |
| LLM-256 | Rogue tool registration | Can malicious tools be registered or discovered by agents? |
| LLM-257 | Tool shadowing | Can one tool description influence how the agent uses another trusted tool? |
| LLM-258 | Tool rug pull | Can a tool's behavior or manifest change after approval? |
| LLM-259 | Unsigned tool manifest | Are MCP tool definitions signed, pinned, or integrity-checked? |
| LLM-260 | MCP context over-sharing | Does the server expose more session, memory, or file context than needed? |
| LLM-261 | MCP protocol logging leak | Are tool arguments, secrets, and context redacted in protocol logs? |
| LLM-262 | Shadow MCP server | Are unapproved MCP servers discoverable, monitored, and blocked? |
| LLM-263 | Broad local filesystem access | Can an MCP server read or write outside intended directories? |
| LLM-264 | Broad network egress | Can an MCP server reach internal networks or attacker-controlled destinations? |
| LLM-265 | MCP sampling injection | Can sampling or model-callback features introduce untrusted instructions? |
| LLM-266 | MCP config tampering | Can users or compromised processes modify server config, tool scopes, or credentials? |
| LLM-267 | MCP dependency compromise | Are MCP SDKs, plugins, and server dependencies scanned and pinned? |

## P. High-Risk Combinations to Prioritize

These combinations usually deserve the first threat-modeling pass:

| ID | Combination | Why it is high risk |
|---|---|---|
| COMBO-001 | Untrusted content + RAG + tool use | A poisoned source can steer actions, not just answers. |
| COMBO-002 | Private data + weak retrieval authorization | The model becomes a data leakage interface. |
| COMBO-003 | Agent autonomy + irreversible actions | A prompt injection can create real-world consequences. |
| COMBO-004 | Shared memory + multiple tenants | One actor can influence or observe another actor's session. |
| COMBO-005 | Quorum + non-independent voters | Consensus gives false assurance when all voters share poisoned context. |
| COMBO-006 | Human approval + vague summaries | People approve actions they did not actually inspect. |
| COMBO-007 | Tool credentials + user-controlled parameters | The agent becomes a confused deputy. |
| COMBO-008 | Generated output + downstream execution | LLM text becomes code, queries, HTML, config, or API calls. |
| COMBO-009 | Shadow AI + sensitive data | Governance, DLP, logging, and incident response are bypassed. |
| COMBO-010 | Model updates + no regression tests | Previously mitigated prompt and tool attacks can reappear. |

## Q. Minimum Control Questions

Use these to turn the checklist into design-review findings:

1. What data, tools, and actions can the LLM access?
2. Which inputs are untrusted, and are they labeled as data rather than instructions?
3. Are retrieval results authorized before they enter the prompt?
4. Are tool calls authorized server-side for the real user and exact action?
5. Are high-impact actions previewed, approved, bound to exact parameters, and audited?
6. Are quorum voters independent in model, prompt, context, tool path, and identity?
7. Can prompts, memory, indexes, caches, logs, and embeddings cross tenants or sessions?
8. Are model outputs treated as untrusted before rendering, executing, storing, or forwarding?
9. Are costs, token usage, loops, retries, and tool calls bounded?
10. Can the team investigate and contain prompt injection, memory poisoning, tool abuse, and data leakage incidents?
