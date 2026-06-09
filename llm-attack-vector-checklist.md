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
| LLM-021 | Policy sandwiching | Can attackers place malicious instructions before and after trusted text to change how the model interprets the middle? |
| LLM-022 | Instruction hierarchy collision | Can conflicting system, developer, retrieved, and user instructions cause the model to follow the wrong authority? |
| LLM-023 | Prompt injection through code comments | Can comments in code, configs, or scripts be interpreted as instructions during analysis or refactoring? |
| LLM-024 | Prompt injection through search snippets | Can search result titles, snippets, or previews steer the model before the source page is opened? |
| LLM-025 | Tool-choice manipulation | Can user text persuade the model to choose a more privileged tool than the task requires? |
| LLM-026 | Markdown directive injection | Can blockquotes, headings, tables, or link text hide instruction-like content? |
| LLM-027 | Safety-policy quotation bypass | Can quoting or paraphrasing safety rules be used to make the model reveal or weaken them? |
| LLM-028 | Prefix or suffix trigger manipulation | Can crafted leading or trailing text reliably change model behavior? |
| LLM-029 | Calendar invite prompt injection | Can meeting titles, descriptions, attendees, or attachments become instructions to an assistant? |
| LLM-030 | Personalization preference poisoning | Can saved preferences or profile fields override secure behavior in later sessions? |
| LLM-031 | Issue or pull-request template injection | Can templates, review comments, or labels manipulate code-review agents? |
| LLM-032 | Browser DOM attribute injection | Can hidden DOM text, ARIA labels, tooltips, or data attributes influence a browsing agent? |
| LLM-033 | Recursive prompt expansion | Can the model be tricked into repeatedly expanding attacker-provided instructions? |
| LLM-034 | Instruction injection through translation tasks | Can translated content preserve hidden instructions that bypass filters in the original language? |
| LLM-035 | Adversarial prompt examples in documentation | Can examples inside docs be mistaken for instructions that the model should execute? |

## B. RAG, Context, Memory, and Embeddings

| ID | Attack vector | Threat-model question |
|---|---|---|
| LLM-036 | RAG authorization bypass | Are retrieved documents filtered by the user's real permissions before entering context? |
| LLM-037 | Cross-tenant retrieval | Can one tenant retrieve another tenant's chunks, metadata, or embeddings? |
| LLM-038 | Vector namespace mix-up | Are indexes, collections, and namespaces isolated by tenant, environment, and user scope? |
| LLM-039 | Metadata filter bypass | Can attacker-controlled metadata defeat access-control filters? |
| LLM-040 | RAG document poisoning | Can untrusted users upload content that influences future answers? |
| LLM-041 | Retrieval content crafting | Can attacker text be written to reliably appear in top-k results? |
| LLM-042 | Embedding manipulation | Can adversarial text, repetition, or keyword stuffing distort semantic ranking? |
| LLM-043 | Chunk-boundary manipulation | Can harmful instructions be split across chunks or made to dominate chunk summaries? |
| LLM-044 | Stale or deleted document retrieval | Do revoked, deleted, or expired documents remain in vector stores or caches? |
| LLM-045 | Source attribution spoofing | Can attacker documents appear to come from trusted sources? |
| LLM-046 | Citation laundering | Can the model cite an untrusted or irrelevant source as evidence? |
| LLM-047 | Persistent memory poisoning | Can a user store malicious preferences, rules, or facts that affect later sessions? |
| LLM-048 | Cross-session memory leakage | Can memories from one user, role, or tenant affect another? |
| LLM-049 | Memory privilege mismatch | Can low-trust interactions write memory used in high-trust workflows? |
| LLM-050 | Conversation summary poisoning | Can summaries omit, alter, or elevate malicious instructions? |
| LLM-051 | Context over-sharing | Is more private context supplied than the task requires? |
| LLM-052 | Cache bleed | Can prompt, completion, embedding, or retrieval caches cross users or tenants? |
| LLM-053 | Retrieval of hidden document content | Are comments, tracked changes, hidden text, speaker notes, or OCR artifacts included unintentionally? |
| LLM-054 | Embedding sensitive data leakage | Can embeddings, vector DB exports, backups, or similarity queries reveal sensitive information? |
| LLM-055 | Model-context provenance loss | Can the system tell which data was user input, trusted policy, retrieved context, memory, or tool output? |
| LLM-056 | Query rewriting abuse | Can attacker input manipulate query rewriting so retrieval searches for unauthorized or attacker-favorable content? |
| LLM-057 | Reranker manipulation | Can attacker documents exploit reranking rules to outrank more relevant trusted sources? |
| LLM-058 | Hybrid search keyword stuffing | Can repeated keywords or rare terms force attacker content into retrieval results? |
| LLM-059 | Chunk summary poisoning | Can generated summaries of chunks preserve attacker instructions while hiding the original context? |
| LLM-060 | Corpus permission drift | Can document permissions change without corresponding vector index updates? |
| LLM-061 | Index rebuild ACL loss | Can rebuilding or migrating the index drop access-control metadata? |
| LLM-062 | OCR ingestion poisoning | Can text extracted from images or scans introduce hidden instructions into the knowledge base? |
| LLM-063 | Source priority spoofing | Can attacker content claim to be official policy, FAQ, or documentation to gain ranking weight? |
| LLM-064 | Time-of-check retrieval race | Can a document be authorized at indexing time but unauthorized at query time? |
| LLM-065 | External link expansion poisoning | Can linked pages fetched during ingestion add untrusted instructions to trusted documents? |
| LLM-066 | Deduplication collision | Can attacker content replace or merge with trusted content during deduplication? |
| LLM-067 | External source sync compromise | Can a compromised wiki, drive, or ticket source poison synchronized RAG content? |
| LLM-068 | Query expansion leakage | Can generated retrieval queries reveal sensitive terms, project names, or user intent to logs or vendors? |
| LLM-069 | RAG grounding bypass | Can the model answer from prior context or memory when it should only answer from authorized retrieval results? |

## C. Sensitive Data and Privacy

| ID | Attack vector | Threat-model question |
|---|---|---|
| LLM-070 | System prompt leakage | Can the model reveal hidden prompts, guardrails, internal URLs, or business logic? |
| LLM-071 | Developer prompt leakage | Can intermediate orchestration instructions be exposed? |
| LLM-072 | Secret-in-prompt exposure | Are API keys, tokens, credentials, or internal endpoints ever placed in prompts? |
| LLM-073 | PII disclosure | Can the model reveal personal data from context, retrieval, memory, or logs? |
| LLM-074 | Training data memorization | Can prompts elicit sensitive data memorized during training or fine-tuning? |
| LLM-075 | Fine-tuning data disclosure | Can proprietary fine-tune examples be reconstructed from outputs? |
| LLM-076 | Internal reasoning or debug trace leakage | Do debug modes expose sensitive intermediate data or hidden orchestration state? |
| LLM-077 | Tool response overexposure | Do tools return more data than the model needs? |
| LLM-078 | Browser/session data exposure | Can an agent read sensitive pages, cookies, forms, or account information? |
| LLM-079 | Prompt replay in analytics | Are prompts and completions sent to analytics, observability, or vendor systems? |
| LLM-080 | Log and trace secret leakage | Are prompts, tool arguments, headers, tokens, and retrieved docs redacted in logs? |
| LLM-081 | Data residency violation | Can prompts or outputs cross geographic, contractual, or regulatory boundaries? |
| LLM-082 | Retention mismatch | Are prompts, embeddings, memories, files, and outputs retained longer than allowed? |
| LLM-083 | Backup exposure | Are vector DB backups, transcript exports, or model artifacts protected like production data? |
| LLM-084 | Third-party connector leakage | Can connected apps receive sensitive data without user-visible consent? |
| LLM-085 | Screenshot or attachment leakage | Can generated screenshots, file previews, or exports contain hidden sensitive data? |
| LLM-086 | Privacy inference | Can repeated queries infer hidden attributes about users, records, or training examples? |
| LLM-087 | Token persistence | Are OAuth tokens or temporary credentials stored in memory, chat, logs, or files? |
| LLM-088 | Unredacted error disclosure | Do failures expose stack traces, internal object IDs, SQL, document paths, or secrets? |
| LLM-089 | Sensitive output transformation | Can the model summarize, translate, encode, or reformat data to bypass DLP? |
| LLM-090 | Conversation export leakage | Can exported chats include hidden context, retrieved chunks, memory, or tool outputs users should not receive? |
| LLM-091 | Clipboard or autocomplete leakage | Can sensitive model output be copied, suggested, or auto-filled into unintended fields? |
| LLM-092 | Browser local storage exposure | Are prompts, responses, tokens, or retrieved documents stored in browser-accessible storage? |
| LLM-093 | Support console overexposure | Can support or admin users view full prompts, files, memories, or traces beyond their need? |
| LLM-094 | Evaluation dataset leakage | Can production prompts or customer data be reused in evals without filtering? |
| LLM-095 | Formatting-based redaction bypass | Can tables, base64, spacing, Unicode, or partial strings evade redaction? |
| LLM-096 | Embedding metadata PII leakage | Can vector metadata expose names, emails, document titles, or tenant identifiers? |
| LLM-097 | Telemetry vendor sharing | Can observability, monitoring, or analytics providers receive sensitive prompt content? |
| LLM-098 | Incident bundle leakage | Can support bundles include secrets, prompt traces, tool arguments, or retrieved documents? |
| LLM-099 | Shared prompt cache leakage | Can prompt or completion caches expose content across users, tenants, or environments? |
| LLM-100 | Failed tool argument retention | Are failed tool calls with sensitive arguments retained longer or logged more verbosely? |
| LLM-101 | Generated file preview leakage | Can previews or thumbnails reveal sensitive content from generated or uploaded files? |
| LLM-102 | Audit-log search exposure | Can users search or export logs containing sensitive prompt, memory, or tool data? |

## D. Tool Use, Function Calling, and Execution

| ID | Attack vector | Threat-model question |
|---|---|---|
| LLM-103 | Excessive tool permissions | Does the agent have more tools or scopes than the task requires? |
| LLM-104 | Unsafe automatic tool invocation | Can tools run without explicit user intent or policy approval? |
| LLM-105 | Confused deputy through tools | Can a user make the agent use privileged credentials on the user's behalf? |
| LLM-106 | User-controlled tool arguments | Are tool parameters schema-validated and authorization-checked server-side? |
| LLM-107 | Prompt-to-API parameter tampering | Can the model alter IDs, scopes, filters, amounts, recipients, or destinations? |
| LLM-108 | Shell command injection | Can generated commands or user text reach a shell or process runner? |
| LLM-109 | SQL or query injection | Can generated queries execute without parameterization or review? |
| LLM-110 | Code execution abuse | Can generated code run outside a sandbox or with broad filesystem/network access? |
| LLM-111 | Path traversal through file tools | Can model-selected paths read or write outside the intended workspace? |
| LLM-112 | SSRF through fetch or browser tools | Can an agent access internal URLs, metadata services, localhost, or private APIs? |
| LLM-113 | Unsafe browser automation | Can an agent click, submit, purchase, delete, or authorize actions on websites? |
| LLM-114 | Email or messaging abuse | Can an agent send manipulated content externally or impersonate a user? |
| LLM-115 | Payment or transfer abuse | Can an agent initiate financial actions without strong approval? |
| LLM-116 | Production deployment abuse | Can an agent deploy code, change infrastructure, or rotate secrets without review? |
| LLM-117 | Destructive action abuse | Can an agent delete, revoke, overwrite, or mutate records irreversibly? |
| LLM-118 | Missing dry-run path | Are high-impact actions previewed with exact parameters before execution? |
| LLM-119 | Retry side effects | Can retries duplicate emails, payments, tickets, jobs, or deployments? |
| LLM-120 | Missing idempotency | Are tool calls protected against duplicate execution? |
| LLM-121 | Tool return-value injection | Are tool outputs treated as untrusted data rather than instructions? |
| LLM-122 | Tool description poisoning | Can a tool's name, description, or examples manipulate model behavior? |
| LLM-123 | Tool schema poisoning | Can schemas, defaults, enum labels, or parameter descriptions include hidden instructions? |
| LLM-124 | Tool error poisoning | Can errors or warnings from tools steer the agent into unsafe fallback behavior? |
| LLM-125 | Connector scope creep | Do OAuth scopes and API permissions expand without review? |
| LLM-126 | Arbitrary external API access | Can the agent call unapproved domains, APIs, or webhooks? |
| LLM-127 | File upload/download exfiltration | Can tools move sensitive files to attacker-controlled locations? |
| LLM-128 | Tool race condition | Can state change between model decision, approval, and tool execution? |
| LLM-129 | Parallel tool inconsistency | Can parallel calls observe inconsistent state or bypass sequencing controls? |
| LLM-130 | Agent self-modification | Can the agent edit its own instructions, tools, policy files, or memory rules? |
| LLM-131 | Unbounded agent loop | Can the agent keep planning, calling tools, or retrying without a hard cap? |
| LLM-132 | Action audit gap | Is every tool call tied to user, session, prompt, evidence, approval, and result? |
| LLM-133 | Schema default abuse | Can default tool parameters cause broader access or more dangerous actions than the user requested? |
| LLM-134 | URL allowlist bypass | Can redirects, encoded hosts, alternate IP formats, or subdomains bypass destination restrictions? |
| LLM-135 | DNS rebinding through browsing tools | Can a browsing or fetch tool be steered from public content to internal services? |
| LLM-136 | Cloud metadata access through tools | Can tools reach cloud instance metadata or identity endpoints? |
| LLM-137 | Repository write misuse | Can an agent commit, push, tag, or modify protected files without proper review? |
| LLM-138 | Database migration misuse | Can generated migrations alter or destroy data without human approval? |
| LLM-139 | Secret rotation misuse | Can an agent rotate, revoke, print, or overwrite secrets incorrectly? |
| LLM-140 | Task scheduler abuse | Can an agent create scheduled jobs, automations, or reminders that execute later with stale authority? |
| LLM-141 | Webhook exfiltration | Can tool calls send sensitive data to attacker-controlled webhooks or callbacks? |
| LLM-142 | Generated filename overwrite | Can model-chosen filenames overwrite important files or hide malicious content? |
| LLM-143 | Archive extraction abuse | Can archive extraction write files outside the intended directory or create unsafe names? |
| LLM-144 | Tool chain pivot | Can a read-only tool output be used to trigger a later write or execution tool? |
| LLM-145 | Authenticated browser action abuse | Can the agent act through a logged-in browser session without explicit user intent? |
| LLM-146 | Unsafe fallback to shell | Does the agent fall back to shell commands when a safer structured tool fails? |
| LLM-147 | Partial failure side effects | Can a failed multi-step tool workflow leave external state changed? |
| LLM-148 | Missing egress policy for tools | Can tools reach arbitrary domains or internal network paths? |
| LLM-149 | Write-before-approval bug | Can a tool perform side effects while preparing a preview or approval request? |
| LLM-150 | Bulk action parameter abuse | Can a single tool call affect many records, users, repositories, or tenants unexpectedly? |

## E. Quorum, Approval, Consensus, and Control Gates

| ID | Attack vector | Threat-model question |
|---|---|---|
| LLM-151 | Quorum bypass | Can privileged actions execute without the required approvals? |
| LLM-152 | Threshold misconfiguration | Is the approval threshold too low for the action's impact? |
| LLM-153 | Timeout downgrade | Does the system reduce approval requirements after delay or failure? |
| LLM-154 | Abstain-as-approve | Are missing, failed, or abstained votes ever counted as approval? |
| LLM-155 | Fail-open approval gate | Does an approval service outage allow execution? |
| LLM-156 | Fake approval injection | Can an attacker forge an approval event, webhook, or message? |
| LLM-157 | Approval replay | Can an old approval be reused for a new action? |
| LLM-158 | Approval not bound to exact action | Is approval cryptographically or transactionally tied to exact parameters? |
| LLM-159 | Approval summary mismatch | Do approvers see a model-generated summary instead of exact raw action details? |
| LLM-160 | Hidden parameter change after approval | Can amount, recipient, query, target, or scope change after approval? |
| LLM-161 | Race between approval and execution | Can state change after approval but before execution? |
| LLM-162 | Approver identity spoofing | Can a user, agent, or service impersonate an approver? |
| LLM-163 | One actor, multiple votes | Can one account, model, service, or person satisfy multiple quorum slots? |
| LLM-164 | Agent self-approval | Can the requesting agent approve its own action? |
| LLM-165 | Shared-model non-independence | Are "multiple approvers" actually the same model, prompt, memory, or policy? |
| LLM-166 | Shared-context compromise | Can one poisoned RAG source influence all quorum agents? |
| LLM-167 | Shared-tool compromise | Can one poisoned tool output influence all voters? |
| LLM-168 | Majority manipulation through sub-agents | Can an orchestrator create or select favorable agents to form a majority? |
| LLM-169 | Voter selection bias | Can the agent choose which reviewers, models, or humans are asked? |
| LLM-170 | Veto bypass | Can a negative vote be ignored, overwritten, or reclassified? |
| LLM-171 | Tie-breaker abuse | Can tie-breaking rules be manipulated by ordering, timing, or reviewer choice? |
| LLM-172 | Quorum denial of service | Can attackers delay, exhaust, or block approvers to force fallback behavior? |
| LLM-173 | Human rubber-stamping | Are humans asked to approve vague summaries too often or too quickly? |
| LLM-174 | Approval UI spoofing | Can the user interface hide, truncate, or misrepresent action details? |
| LLM-175 | Broad pre-approval abuse | Can approval for a class of actions be stretched beyond the intended instance? |
| LLM-176 | Delegated approval abuse | Can approvers delegate to weaker identities, agents, or groups? |
| LLM-177 | Policy engine bypass | Can the agent route around policy-as-code or approval middleware? |
| LLM-178 | Conflicting approval sources | Do chat approvals, ticket approvals, API approvals, and UI approvals disagree? |
| LLM-179 | Missing separation of duties | Can the requester, implementer, approver, and executor be the same principal? |
| LLM-180 | Approval audit weakness | Can approval evidence be altered or lost after execution? |
| LLM-181 | Nested approval confusion | Can approval for a parent task implicitly approve unsafe child actions? |
| LLM-182 | Group membership drift | Can changes in approval group membership alter quorum requirements without review? |
| LLM-183 | Approver collusion | Can multiple approvers coordinate to bypass separation-of-duty expectations? |
| LLM-184 | Common evidence source failure | Do all approvers rely on the same poisoned summary, RAG result, or tool output? |
| LLM-185 | Break-glass approval misuse | Can emergency override paths become normal execution paths? |
| LLM-186 | Approval scope ambiguity | Is it unclear whether approval covers one action, a batch, a session, or future retries? |
| LLM-187 | Quorum route selection attack | Can the agent choose the easier approval path among multiple policy routes? |
| LLM-188 | Stale policy decision cache | Can cached approval or policy decisions survive role, tenant, or risk changes? |
| LLM-189 | Approval revocation race | Can an approval be revoked after the system has already queued execution? |
| LLM-190 | Shadow approval channel | Can chat messages, tickets, or comments be treated as approval outside the official gate? |
| LLM-191 | Approval evidence tampering | Can the evidence shown to approvers differ from what is stored or executed? |

## F. Identity, Authorization, and Tenant Boundaries

| ID | Attack vector | Threat-model question |
|---|---|---|
| LLM-192 | LLM-based authorization decision | Is the model trusted to decide access rather than deterministic policy? |
| LLM-193 | Prompt-supplied tenant or user ID | Can the user influence identity, tenant, role, or permission context? |
| LLM-194 | Session mix-up | Can one user's prompt, files, memory, or tool credentials bind to another session? |
| LLM-195 | User impersonation through agent action | Can outputs or tool calls appear to come from another user? |
| LLM-196 | Overprivileged service account | Does the agent run with broad service credentials instead of user-scoped tokens? |
| LLM-197 | Missing per-tool authorization | Is authorization checked for each operation, not just login? |
| LLM-198 | Long-lived integration tokens | Are tokens scoped, short-lived, revocable, and rotated? |
| LLM-199 | Weak service-to-service authentication | Can rogue agents, MCP servers, or connectors call internal services? |
| LLM-200 | Cross-workspace action | Can an agent act across repos, projects, tenants, or environments accidentally? |
| LLM-201 | Default-allow connector policy | Are new tools allowed unless explicitly blocked? |
| LLM-202 | Stale identity context | Are role changes, revocations, and terminations reflected immediately? |
| LLM-203 | Privilege escalation via connected app | Can a low-privilege user use a high-privilege connector indirectly? |
| LLM-204 | Multi-tenant prompt bleed | Are tenant-specific instructions or policies isolated? |
| LLM-205 | Shadow AI identity gap | Are unapproved AI tools missing from IAM, inventory, monitoring, and DLP? |
| LLM-206 | Weak delegated authority | Can an agent claim delegated user consent without proof? |
| LLM-207 | Service-to-service identity loss | Is the original user identity lost as requests move across orchestration services? |
| LLM-208 | Shared service account across tenants | Can tenants indirectly share the same agent credential or backend identity? |
| LLM-209 | Token audience mismatch | Can a token issued for one service be accepted by another service or tool? |
| LLM-210 | mTLS identity mapping gap | Does cryptographic service identity fail to map back to user, tenant, and action? |
| LLM-211 | Admin preview mode leakage | Can admin preview or impersonation modes expose or alter tenant data accidentally? |
| LLM-212 | Scheduled job identity confusion | Do delayed jobs run with the creator identity, current identity, or broad service identity? |
| LLM-213 | Orphaned connector credentials | Do connector tokens remain active after users leave, roles change, or apps are removed? |
| LLM-214 | Improper impersonation logging | Can actions performed through impersonation lose accountability in audit logs? |
| LLM-215 | Identity context in prompt only | Is authorization context represented only as text the model could ignore or alter? |

## G. Supply Chain, Models, Datasets, and Deployment

| ID | Attack vector | Threat-model question |
|---|---|---|
| LLM-216 | Compromised base model | Are models sourced, approved, scanned, and versioned? |
| LLM-217 | Backdoored model weights | Are model artifacts verified with signatures or hashes? |
| LLM-218 | Malicious fine-tune adapter | Are LoRA/adapters and checkpoints trusted like executable code? |
| LLM-219 | Poisoned training data | Is data provenance tracked for pretraining and fine-tuning? |
| LLM-220 | Poisoned evaluation data | Can benchmarks or red-team tests be manipulated to hide failures? |
| LLM-221 | Dependency compromise | Are inference, orchestration, parser, and plugin dependencies scanned and pinned? |
| LLM-222 | Typosquatting or dependency confusion | Can malicious packages replace internal or expected dependencies? |
| LLM-223 | Prompt template supply-chain attack | Are shared prompt libraries, agents, and templates reviewed and versioned? |
| LLM-224 | Model registry tampering | Can registry metadata, tags, or model versions be changed without approval? |
| LLM-225 | Unsafe model update | Can provider or model changes alter behavior without regression testing? |
| LLM-226 | Unsafe fallback model | Does outage handling route to a weaker or unapproved model? |
| LLM-227 | Container or runtime compromise | Are serving images, GPUs, drivers, and runtimes patched and isolated? |
| LLM-228 | CI/CD poisoning | Can build pipelines inject prompts, tools, configs, or model artifacts? |
| LLM-229 | Third-party plugin marketplace risk | Are plugins signed, reviewed, sandboxed, and monitored? |
| LLM-230 | Insecure parser dependency | Can PDF, image, office, archive, or HTML parsers be exploited during ingestion? |
| LLM-231 | Environment mix-up | Can dev prompts, test keys, staging data, or weaker policies reach production? |
| LLM-232 | Debug mode in production | Can debug prompts, traces, or bypass flags be enabled by users or attackers? |
| LLM-233 | Client-side prompt exposure | Are sensitive prompts or tool schemas exposed in browser/mobile code? |
| LLM-234 | Feature flag guardrail bypass | Can flags disable filters, approvals, logging, or sandboxing? |
| LLM-235 | Model artifact theft | Are weights, adapters, prompts, datasets, and evals protected as intellectual property? |
| LLM-236 | Prompt package poisoning | Can shared prompt libraries or agent templates be modified without review? |
| LLM-237 | Model routing configuration tampering | Can routing rules send sensitive tasks to unapproved models or providers? |
| LLM-238 | Benchmark or leaderboard poisoning | Can evaluation benchmarks be manipulated to hide unsafe behavior? |
| LLM-239 | Dataset license or provenance gap | Can unknown dataset origins create legal, privacy, or quality risk? |
| LLM-240 | Adversarial adapter merge | Can a fine-tune adapter introduce behavior that is hidden during normal evaluation? |
| LLM-241 | Model endpoint DNS or proxy hijack | Can traffic intended for a trusted model endpoint be redirected? |
| LLM-242 | Provider API key compromise | Can compromised provider credentials expose prompts, files, or model usage? |
| LLM-243 | Unpinned tokenizer behavior | Can tokenizer changes alter prompt boundaries, filters, or safety tests? |
| LLM-244 | Malicious tokenizer artifact | Can tokenizer files or preprocessing components manipulate model inputs? |
| LLM-245 | Annotation worker poisoning | Can labelers or data vendors insert biased, malicious, or backdoor examples? |
| LLM-246 | Guardrail dependency compromise | Can a third-party safety filter, policy engine, or scanner become the weak link? |

## H. Output Handling and Downstream Injection

| ID | Attack vector | Threat-model question |
|---|---|---|
| LLM-247 | XSS from generated HTML or Markdown | Is model output encoded and sanitized before rendering? |
| LLM-248 | Markdown link phishing | Can generated links mislead users or hide dangerous destinations? |
| LLM-249 | SQL injection from generated queries | Are generated queries parameterized and reviewed? |
| LLM-250 | Command injection from generated commands | Are commands structured without shell string concatenation? |
| LLM-251 | JSON or schema injection | Can output break parsers or smuggle fields into downstream systems? |
| LLM-252 | Template injection | Can generated templates execute code or access server objects? |
| LLM-253 | Deserialization risk | Can generated serialized data trigger unsafe object construction? |
| LLM-254 | Spreadsheet formula injection | Can CSV/XLSX output execute formulas when opened? |
| LLM-255 | Log injection | Can generated output forge or corrupt logs? |
| LLM-256 | Generated code dependency risk | Can the model recommend non-existent, malicious, or typosquatted packages? |
| LLM-257 | Unsafe infrastructure-as-code | Can generated IaC expose public resources, weak IAM, or secrets? |
| LLM-258 | Unsafe remediation instructions | Can generated operational guidance cause data loss or security weakening? |
| LLM-259 | Citation hallucination | Can the model invent sources, quote nonexistent evidence, or cite irrelevant documents? |
| LLM-260 | High-stakes misinformation | Can hallucinations affect medical, legal, financial, safety, or security outcomes? |
| LLM-261 | Hidden control characters | Can Unicode, ANSI, or invisible characters alter terminals, logs, or reviews? |
| LLM-262 | Data tampering in generated reports | Can summaries omit caveats, alter numbers, or misstate evidence? |
| LLM-263 | Policy-violating content generation | Can outputs support phishing, fraud, malware, abuse, or harmful instructions? |
| LLM-264 | Unsafe auto-ingestion of output | Is model output fed directly into tickets, code, databases, or tools? |
| LLM-265 | Output trust confusion | Do downstream systems know whether content is generated, user-provided, verified, or authoritative? |
| LLM-266 | HTML attribute injection | Can generated attributes such as href, src, style, or event handlers create browser risk? |
| LLM-267 | Unsafe URL scheme generation | Can generated links use dangerous, deceptive, or unexpected URL schemes? |
| LLM-268 | Regular-expression denial of service | Can generated regex patterns consume excessive CPU or hang validation paths? |
| LLM-269 | YAML or CI config injection | Can generated YAML alter pipelines, secrets, permissions, or build steps? |
| LLM-270 | Terraform or IaC destructive plan | Can generated infrastructure changes destroy or expose resources? |
| LLM-271 | Kubernetes manifest privilege escalation | Can generated manifests create privileged pods, host mounts, or broad RBAC? |
| LLM-272 | Email header injection | Can generated email content alter recipients, headers, or message routing? |
| LLM-273 | Prototype pollution through generated JSON | Can generated objects include fields that affect downstream JavaScript behavior? |
| LLM-274 | Tracking pixel in generated Markdown | Can generated Markdown include remote images that leak readers or context? |
| LLM-275 | Unsafe copy button content | Can a copy-to-clipboard helper copy a different command than what is visibly shown? |

## I. Denial of Service, Cost Abuse, and Reliability

| ID | Attack vector | Threat-model question |
|---|---|---|
| LLM-276 | Token exhaustion | Can users force very long prompts, contexts, or completions? |
| LLM-277 | Context-window stuffing | Can attackers crowd out safety instructions or needed evidence? |
| LLM-278 | Expensive tool-call abuse | Can users trigger costly search, scraping, code execution, or data processing? |
| LLM-279 | Recursive agent loop | Can an agent repeatedly plan, call itself, or spawn tasks? |
| LLM-280 | Retry storm | Can failures create repeated model calls or side-effecting tool calls? |
| LLM-281 | Model latency exhaustion | Can slow prompts tie up workers or streaming connections? |
| LLM-282 | Concurrent session flooding | Are per-user, per-tenant, and global limits enforced? |
| LLM-283 | Trial or account fan-out | Can attackers bypass limits using many identities, keys, or tenants? |
| LLM-284 | Vector query amplification | Can queries trigger large retrieval, reranking, or graph traversal work? |
| LLM-285 | Embedding ingestion flood | Can uploads create excessive embedding, OCR, parsing, or indexing costs? |
| LLM-286 | Parser bomb | Can archives, PDFs, images, or documents exhaust parsing resources? |
| LLM-287 | Cache bypass | Can small prompt changes defeat caching and multiply cost? |
| LLM-288 | Expensive model selection abuse | Can users force premium models or larger context windows unnecessarily? |
| LLM-289 | Approval queue exhaustion | Can attackers flood human or quorum review queues? |
| LLM-290 | Streaming abuse | Can long-running streams hold resources or evade response limits? |
| LLM-291 | Budget-drain denial of service | Can attackers consume API credits, quotas, or vendor budgets? |
| LLM-292 | Large document upload flood | Can repeated uploads trigger expensive parsing, OCR, embedding, and summarization? |
| LLM-293 | Streaming cancellation ignored | Do model or tool calls continue consuming resources after the user cancels? |
| LLM-294 | Many-small-prompts cost bypass | Can attackers avoid per-request limits by spreading work across many small calls? |
| LLM-295 | Tool cache stampede | Can many agents request the same expensive tool result at once? |
| LLM-296 | IP-only rate limit bypass | Can attackers bypass limits through accounts, tokens, tenants, or distributed clients? |
| LLM-297 | Prompt compression bomb | Can compact input expand into very large context, files, or generated work? |
| LLM-298 | Queue starvation | Can low-priority or malicious jobs block high-priority users or incident response? |
| LLM-299 | Failed approval loop | Can repeated failed approvals or denied tool calls keep consuming model and human-review capacity? |

## J. Model Extraction, Inference, and Safety Evasion

| ID | Attack vector | Threat-model question |
|---|---|---|
| LLM-300 | Model extraction | Can repeated queries approximate proprietary behavior or decision logic? |
| LLM-301 | Prompt extraction | Can attackers infer hidden prompts, policies, or routing rules? |
| LLM-302 | Membership inference | Can attackers determine whether a record was in training or fine-tuning data? |
| LLM-303 | Training data extraction | Can prompts elicit memorized snippets or confidential examples? |
| LLM-304 | Fine-tune inversion | Can attackers reconstruct proprietary fine-tune patterns or labels? |
| LLM-305 | Model fingerprinting | Can attackers identify model, version, safety layer, or provider for targeted attacks? |
| LLM-306 | Guardrail boundary probing | Can attackers map what filters allow and block? |
| LLM-307 | Safety classifier evasion | Can text transformation bypass moderation or policy classifiers? |
| LLM-308 | Adversarial suffix or trigger | Can crafted suffixes or triggers reliably alter behavior? |
| LLM-309 | Latent backdoor trigger | Can rare phrases, facts, or patterns activate hidden behavior? |
| LLM-310 | Eval overfitting | Are controls tuned only to known test cases rather than real adversarial behavior? |
| LLM-311 | Model theft via artifact access | Can insiders or compromised services download weights, adapters, or prompts? |
| LLM-312 | Latency side-channel probing | Can response timing reveal model routing, retrieval hits, safety checks, or data presence? |
| LLM-313 | Confidence score probing | Can scores or uncertainty signals leak hidden policy, data, or model behavior? |
| LLM-314 | Model routing inference | Can attackers determine which model or provider handled a sensitive request? |
| LLM-315 | Tokenizer boundary probing | Can tokenization quirks be used to bypass filters or infer implementation details? |
| LLM-316 | Watermark removal or evasion | Can generated content be transformed to remove provenance or safety markers? |
| LLM-317 | Safety prompt diffing | Can attackers compare outputs over time to infer hidden safety prompt changes? |
| LLM-318 | Canary token extraction | Can prompts reveal planted secrets, markers, or monitoring tokens? |
| LLM-319 | Behavior cloning through distillation | Can repeated Q&A collection approximate proprietary model or agent behavior? |

## K. Multi-Agent and Delegation Risks

| ID | Attack vector | Threat-model question |
|---|---|---|
| LLM-320 | Instruction laundering between agents | Can one agent pass malicious instructions to another as trusted work product? |
| LLM-321 | Delegation to weaker agent | Can a high-trust agent delegate to a less protected or less monitored agent? |
| LLM-322 | Transitive trust expansion | Does trusting Agent A unintentionally trust Agent B, tools, memory, and data sources? |
| LLM-323 | Shared workspace poisoning | Can files, notes, blackboards, or task queues manipulate multiple agents? |
| LLM-324 | Manager-agent blind trust | Does an orchestrator accept sub-agent conclusions without evidence validation? |
| LLM-325 | Cross-agent context leakage | Can one agent see another agent's private context, tokens, or tasks? |
| LLM-326 | Agent role confusion | Can agents confuse planner, reviewer, executor, and approver responsibilities? |
| LLM-327 | Malicious sub-agent registration | Can an attacker add a rogue agent to a workflow? |
| LLM-328 | Agent collusion or shared failure | Are independent agents actually diverse enough to catch each other's errors? |
| LLM-329 | Delegated tool misuse | Can a sub-agent use tools the parent agent should not expose? |
| LLM-330 | Task queue poisoning | Can queued instructions be modified before execution? |
| LLM-331 | Agent self-replication | Can agents create more agents, tasks, or workflows without governance? |
| LLM-332 | Evidence-free consensus | Can multiple agents agree without independently checking primary evidence? |
| LLM-333 | Planner and executor shared memory | Can planning context leak into execution context without validation? |
| LLM-334 | Task title prompt injection | Can a malicious task title steer a downstream agent? |
| LLM-335 | Malicious agent marketplace package | Can installed agents or skills introduce hidden behavior or permissions? |
| LLM-336 | Circular delegation loop | Can agents delegate to each other until cost, time, or context is exhausted? |
| LLM-337 | Reviewer agent ignored | Can an executor proceed despite reviewer objections or missing evidence? |
| LLM-338 | Cross-agent secret sharing | Can one agent pass secrets to another with lower trust or broader logging? |
| LLM-339 | Agent priority inversion | Can a low-priority agent block, override, or starve a high-priority workflow? |
| LLM-340 | Unauthorized agent tool grant | Can a child agent receive tools or scopes the parent should not delegate? |
| LLM-341 | Stale task context reuse | Can old task context be reused after requirements, permissions, or data have changed? |

## L. Multimodal, Document, and File-Based Inputs

| ID | Attack vector | Threat-model question |
|---|---|---|
| LLM-342 | Hidden text in images | Can OCR reveal instructions invisible or unobvious to users? |
| LLM-343 | QR code or barcode injection | Can encoded visual content steer browser, fetch, or tool behavior? |
| LLM-344 | Audio prompt injection | Can spoken or background audio manipulate transcription and agent behavior? |
| LLM-345 | Video-frame injection | Can hidden frames, captions, or overlays influence multimodal analysis? |
| LLM-346 | PDF hidden-layer injection | Are hidden layers, annotations, forms, comments, and attachments handled safely? |
| LLM-347 | Office document metadata injection | Can comments, tracked changes, speaker notes, or macros affect prompts? |
| LLM-348 | Spreadsheet formula injection | Are formulas neutralized before summarization or export? |
| LLM-349 | EXIF and media metadata injection | Is image/video metadata included in context without trust labeling? |
| LLM-350 | OCR parser disagreement | Do humans and models see different content from the same file? |
| LLM-351 | Archive traversal or file confusion | Can uploaded archives create unsafe paths, names, or nested payloads? |
| LLM-352 | Attachment type spoofing | Can content-type, extension, and actual file content disagree? |
| LLM-353 | Document summarization poisoning | Can a document manipulate its own summary or classification? |
| LLM-354 | Steganographic instruction content | Can visually hidden or embedded content influence OCR or multimodal analysis? |
| LLM-355 | Web image alt-text injection | Can alt text or captions from web content manipulate a multimodal agent? |
| LLM-356 | ASR homophone injection | Can speech-to-text ambiguity convert harmless audio into harmful instructions? |
| LLM-357 | Subtitle or caption injection | Can video captions or transcripts carry instructions not obvious in the video? |
| LLM-358 | OCR hallucination risk | Can poor scans cause OCR to invent or alter text used in decisions? |
| LLM-359 | Polyglot file confusion | Can a file valid in multiple formats bypass type-specific controls? |
| LLM-360 | Nested archive expansion | Can nested files overwhelm scanners or hide malicious content from review? |
| LLM-361 | Media thumbnail parser exploit | Can thumbnail or preview generation process risky file content before validation? |

## M. Human Factors, UI, and Social Engineering

| ID | Attack vector | Threat-model question |
|---|---|---|
| LLM-362 | AI-generated phishing | Can outputs impersonate trusted people, brands, or internal systems? |
| LLM-363 | Fake confidence | Does the interface overstate certainty or hide uncertainty? |
| LLM-364 | Fabricated policy or legal authority | Can the model invent rules users will follow? |
| LLM-365 | Approval fatigue | Are humans asked to approve too many low-quality or vague actions? |
| LLM-366 | Unsafe suggested actions | Can suggested replies, buttons, or next steps nudge users into risky behavior? |
| LLM-367 | UI truncation of critical details | Are recipients, amounts, URLs, queries, and scopes visible before approval? |
| LLM-368 | Spoofed citations or provenance | Can generated evidence look official when it is not? |
| LLM-369 | Overreliance in high-stakes workflows | Are model outputs independently verified before consequential decisions? |
| LLM-370 | Social engineering via agent persona | Can a model's tone, authority, or identity manipulate users or operators? |
| LLM-371 | Hidden external communication | Can users miss when the agent will send data outside the organization? |
| LLM-372 | Unsafe copy-paste path | Can generated commands, code, or configs harm users when pasted elsewhere? |
| LLM-373 | Human override without accountability | Can users bypass model or policy warnings without reason capture? |
| LLM-374 | Fake verified indicator | Can generated UI text imply a result is verified, approved, or official when it is not? |
| LLM-375 | Dark-pattern approval prompt | Can approval UI wording pressure users into accepting risky actions? |
| LLM-376 | Hidden scroll in approval panel | Can important parameters be below the fold or outside the visible approval area? |
| LLM-377 | Long URL disguise | Can generated links hide dangerous destinations behind truncation or lookalike domains? |
| LLM-378 | Citation authority bias | Can users over-trust outputs because they include citations, even when citations are weak? |
| LLM-379 | Urgency manipulation | Can generated tone create false urgency that reduces human review quality? |
| LLM-380 | Accessibility mismatch | Can screen readers, labels, or keyboard navigation present different information than the visual UI? |
| LLM-381 | Notification spoofing | Can model-generated notifications look like system, security, or admin messages? |
| LLM-382 | Copy-to-clipboard social engineering | Can users be encouraged to paste commands or configs into privileged environments? |

## N. Monitoring, Audit, Incident Response, and Governance

| ID | Attack vector | Threat-model question |
|---|---|---|
| LLM-383 | Missing prompt and tool audit trail | Can incidents reconstruct prompts, retrieved context, tool calls, approvals, and outputs? |
| LLM-384 | Secret-rich audit logs | Do logs create a second sensitive data store? |
| LLM-385 | Mutable audit evidence | Can logs, approvals, prompts, or tool records be altered after the fact? |
| LLM-386 | No anomaly detection | Are unusual prompts, retrievals, tool calls, costs, and approvals monitored? |
| LLM-387 | No abuse reporting path | Can users report bad outputs, prompt injection, or unsafe agent behavior? |
| LLM-388 | No kill switch | Can high-risk agents, tools, models, or connectors be disabled quickly? |
| LLM-389 | No model/version provenance | Can outputs be tied to model, prompt version, tool version, and policy version? |
| LLM-390 | No rollback plan | Can unsafe prompt, model, index, or tool changes be reverted? |
| LLM-391 | Missing red-team regression tests | Are known attack patterns tested after model, prompt, tool, and data changes? |
| LLM-392 | Shadow AI inventory gap | Are unofficial AI tools, browser extensions, SaaS copilots, and agents discovered? |
| LLM-393 | Policy drift | Are prompt policies, code policies, IAM policies, and human procedures kept aligned? |
| LLM-394 | Incomplete incident containment | Can compromised memory, vector content, approvals, and tokens be purged? |
| LLM-395 | Vendor incident dependency | Are provider outages, breaches, model changes, and logging policies accounted for? |
| LLM-396 | Alert fatigue | Can too many low-quality AI alerts hide real prompt injection, data leakage, or tool abuse? |
| LLM-397 | Model version missing from logs | Can incidents be investigated without knowing the exact model and prompt version? |
| LLM-398 | Redaction blocks forensics | Can aggressive redaction remove evidence needed to investigate abuse? |
| LLM-399 | Evidence hash missing | Can prompts, retrieved chunks, approvals, or tool results be disputed after an incident? |
| LLM-400 | No customer notification trigger | Is there a defined threshold for notifying users or customers after AI data exposure? |
| LLM-401 | No memory purge runbook | Can poisoned or sensitive memory be found, revoked, and verified as removed? |
| LLM-402 | No vector index rebuild process | Can poisoned or stale embeddings be rebuilt safely after remediation? |
| LLM-403 | No abuse metrics by tenant | Can abnormal usage be detected per tenant, user, model, tool, and connector? |

## O. MCP, Plugin, and Agent Server Specific Risks

| ID | Attack vector | Threat-model question |
|---|---|---|
| LLM-404 | MCP token mismanagement | Are MCP and connector tokens short-lived, scoped, redacted, and rotated? |
| LLM-405 | Unauthenticated MCP server | Can unauthorized clients register tools or call MCP endpoints? |
| LLM-406 | Missing per-tool MCP authorization | Does the server enforce authorization per tool and operation? |
| LLM-407 | Rogue tool registration | Can malicious tools be registered or discovered by agents? |
| LLM-408 | Tool shadowing | Can one tool description influence how the agent uses another trusted tool? |
| LLM-409 | Tool rug pull | Can a tool's behavior or manifest change after approval? |
| LLM-410 | Unsigned tool manifest | Are MCP tool definitions signed, pinned, or integrity-checked? |
| LLM-411 | MCP context over-sharing | Does the server expose more session, memory, or file context than needed? |
| LLM-412 | MCP protocol logging leak | Are tool arguments, secrets, and context redacted in protocol logs? |
| LLM-413 | Shadow MCP server | Are unapproved MCP servers discoverable, monitored, and blocked? |
| LLM-414 | Broad local filesystem access | Can an MCP server read or write outside intended directories? |
| LLM-415 | Broad network egress | Can an MCP server reach internal networks or attacker-controlled destinations? |
| LLM-416 | MCP sampling injection | Can sampling or model-callback features introduce untrusted instructions? |
| LLM-417 | MCP config tampering | Can users or compromised processes modify server config, tool scopes, or credentials? |
| LLM-418 | MCP dependency compromise | Are MCP SDKs, plugins, and server dependencies scanned and pinned? |
| LLM-419 | MCP context leakage through sampling | Can model-sampling features expose context from one tool or server to another? |
| LLM-420 | MCP tool name collision | Can two tools with similar names cause the agent to call the wrong one? |
| LLM-421 | Insecure local MCP transport | Can local processes observe or manipulate MCP traffic or configuration? |
| LLM-422 | OAuth token reuse across MCP servers | Can a token intended for one server be accepted by another? |
| LLM-423 | MCP auto-discovery risk | Can agents discover and trust servers without user or organization approval? |
| LLM-424 | MCP server path hijacking | Can a malicious local executable or config path replace a trusted server? |
| LLM-425 | Overbroad MCP schema capability | Can a generic schema such as arbitrary file, URL, or command create hidden privilege? |
| LLM-426 | MCP permission prompt spoofing | Can tool descriptions or UI copy misrepresent what permission is being granted? |
| LLM-427 | Remote MCP downgrade | Can secure transport or authentication be downgraded to a weaker mode? |
| LLM-428 | MCP request forgery | Can one server cause the agent or client to make unintended requests to another server? |

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
