"""Core runtime for the multi-agent handoff lab.

An offline, stdlib-only recreation of the *handoff* semantics used by real
frameworks (OpenAI Agents SDK / Swarm, CrewAI delegation, LangGraph edges,
Google A2A): an agent transfers control **plus shared context** to another
agent.

The `_decide` "mock LLM" is a deterministic router. It faithfully reproduces
the real-world failure mode: an LLM cannot reliably tell DATA apart from
INSTRUCTIONS, so control markers ([[HANDOFF:..]] / [[TOOL:..]] / [[SETROLE:..]])
embedded in *untrusted* content (the user message OR carried context notes OR
content a peer retrieved) get honored as if the agent itself emitted them.

Two policies switch every planted flaw on/off:
  VULN  - flaws live (what an unhardened stack looks like)
  FIXED - each flaw mitigated; legitimate tasks still succeed
"""
from __future__ import annotations

import hmac
import hashlib
import re
from dataclasses import dataclass, field
from typing import Callable

from lab import nlp

# Control markers an attacker can smuggle into untrusted text.
MARKER_RE = re.compile(r"\[\[(HANDOFF|TOOL|SETROLE):(.*?)\]\]", re.IGNORECASE)


@dataclass
class Note:
    """One entry of carried context, tagged with where it came from.

    `source` records provenance so a hardened build can reason about trust:
      'user'     - text the end user supplied
      'agent'    - a note an agent itself wrote
      'external' - content a peer *retrieved* (RAG / knowledge base / tool
                   output) — attacker-influenceable, the indirect-injection
                   channel.
    """
    text: str
    source: str = "user"


@dataclass
class Context:
    """Shared state carried across a handoff — the covert channel."""
    user_id: str
    role: str = "customer"                      # customer | staff | admin
    notes: list = field(default_factory=list)   # list[Note] carried downstream
    trace: list = field(default_factory=list)
    edges: set = field(default_factory=set)     # directed handoffs already taken (loop guard)

    def __post_init__(self) -> None:
        # Accept plain strings for ergonomics; coerce to user-sourced Notes.
        self.notes = [n if isinstance(n, Note) else Note(str(n), "user") for n in self.notes]

    def add_note(self, text: str, source: str = "agent") -> None:
        self.notes.append(Note(text, source))

    def notes_text(self) -> str:
        return " ".join(n.text for n in self.notes)

    def log(self, line: str) -> None:
        self.trace.append(line)


@dataclass
class Tool:
    name: str
    fn: Callable
    required_capability: str                     # agent must hold this to call it


@dataclass
class Agent:
    name: str
    capabilities: set = field(default_factory=set)
    allowed_handoffs: set = field(default_factory=set)
    intent_route: dict = field(default_factory=dict)   # keyword -> agent (legit routing)
    intent_tool: dict = field(default_factory=dict)    # keyword -> (tool, arg_fn)
    retriever: Callable | None = None                  # peer that pulls external content
    return_to: str | None = None                       # where a retriever hands back
    route_keywords: tuple = ()                          # keywords a retriever consumes on return


@dataclass
class AgentCard:
    """An A2A-style capability advertisement fetched from a (possibly remote,
    cross-organization) partner agent.

    In Google's A2A protocol a client agent discovers a partner by pulling its
    *Agent Card* — a descriptor of who the agent is and what it can do — and
    then delegates work to it. The card crosses a trust boundary: both the
    self-declared `capabilities` and the `skills` blurbs are attacker-
    influenceable in transit, so until the card's `sig` is verified against a
    known federation issuer it is untrusted DATA. And even once authenticated,
    a card's declared capabilities are a *request*, not a grant — proving WHO
    published a card says nothing about WHAT it may do.

    `tool_grants` maps an intent keyword to a declarative (tool_name, args)
    pair; `$user` in args is bound to the caller's user_id at federation time.
    """
    issuer: str
    agent_name: str
    capabilities: set = field(default_factory=set)
    skills: list = field(default_factory=list)
    tool_grants: dict = field(default_factory=dict)   # keyword -> (tool_name, [args])
    routes: dict = field(default_factory=dict)        # keyword -> agent_name
    allowed_handoffs: set = field(default_factory=set)
    sig: str = ""                                     # HMAC set by issue_card()


@dataclass
class SecurityPolicy:
    name: str
    honor_untrusted_markers: bool     # act on instructions found in untrusted text at all
    enforce_handoff_allowlist: bool
    scrub_context_on_handoff: bool
    enforce_tool_capabilities: bool
    authed_registry: bool
    detect_handoff_loops: bool        # block a directed handoff edge taken twice
    verify_agent_cards: bool          # require a signed card + clamp caps to local grant
    sanitize_untrusted: bool = False  # DETECT strawman: strip injections a static filter recognizes
    # --- extended controls for the exfiltration / persistence labs (A9-A12) ---
    # Appended with defaults so the positional presets above and keyword-only
    # construction elsewhere both keep working untouched.
    enforce_egress_allowlist: bool = False   # A9: render/fetch only to allow-listed hosts
    provenance_on_memory: bool = False       # A10: untrusted content may not write instruction-bearing long-term memory
    confirm_sensitive_after_taint: bool = False  # A11: a sensitive call fired by a delayed trigger needs confirmation once context is tainted


# VULN   - a gullible stack: it acts on any instruction it comprehends in
#          untrusted text (literal markers OR natural language), no guardrails.
# DETECT - the popular-but-insufficient answer: keep honoring untrusted
#          instructions, but run them through a static input filter first. Blocks
#          the phrasings the filter knows; leaks the paraphrases it doesn't.
# FIXED  - the real answer: never grant untrusted content authority (provenance),
#          and enforce a least-privilege agent graph. Content-independent, so it
#          cannot be paraphrased around.
VULN   = SecurityPolicy("VULN",   True,  False, False, False, False, False, False, False,
                        enforce_egress_allowlist=False, provenance_on_memory=False,
                        confirm_sensitive_after_taint=False)
DETECT = SecurityPolicy("DETECT", True,  False, False, False, False, False, False, True,
                        enforce_egress_allowlist=False, provenance_on_memory=False,
                        confirm_sensitive_after_taint=False)
FIXED  = SecurityPolicy("FIXED",  False, True,  True,  True,  True,  True,  True,  False,
                        enforce_egress_allowlist=True, provenance_on_memory=True,
                        confirm_sensitive_after_taint=True)


class Decision:
    def __init__(self, kind: str, **kw):
        self.kind = kind                 # 'reply' | 'tool' | 'handoff'
        self.source = kw.pop("source", "intent")
        self.__dict__.update(kw)


class System:
    def __init__(self, policy: SecurityPolicy, secret: bytes = b"lab-secret"):
        self.policy = policy
        self.secret = secret
        self.agents: dict = {}
        self.tools: dict = {}
        self._config: dict = {}          # e.g. operator token for the registry

    # ---------- setup ----------
    def add_tool(self, tool: Tool) -> None:
        self.tools[tool.name] = tool

    def add_agent(self, agent: Agent) -> None:
        self.agents[agent.name] = agent

    def register_agent(self, agent: Agent, operator_token: str | None = None):
        """Runtime agent-registration endpoint (attack surface #4)."""
        if self.policy.authed_registry:
            if agent.name in self.agents:
                return False, f"DENIED: cannot override existing agent '{agent.name}'"
            if operator_token != self._config.get("operator_token"):
                return False, "DENIED: registration requires a valid operator token"
        self.agents[agent.name] = agent
        return True, f"registered '{agent.name}'"

    # ---------- signed handoff tokens (FIXED) ----------
    def _sign(self, frm: str, to: str) -> str:
        return hmac.new(self.secret, f"{frm}->{to}".encode(), hashlib.sha256).hexdigest()[:16]

    # ---------- A2A federation: signed Agent Cards (attack surface #7/#8) ----------
    @staticmethod
    def _canonical_card(card: "AgentCard") -> str:
        """Deterministic serialization of a card's declarative claims — the bytes
        the issuer signs. Sorted so semantically-equal cards hash identically."""
        tools = ";".join(f"{k}->{v[0]}({','.join(v[1])})"
                         for k, v in sorted(card.tool_grants.items()))
        routes = ";".join(f"{k}->{v}" for k, v in sorted(card.routes.items()))
        return "\n".join([
            f"issuer={card.issuer}",
            f"name={card.agent_name}",
            f"caps={','.join(sorted(card.capabilities))}",
            f"skills={'|'.join(card.skills)}",
            f"tools={tools}",
            f"routes={routes}",
            f"handoffs={','.join(sorted(card.allowed_handoffs))}",
        ])

    def _sign_card(self, card: "AgentCard", key: bytes) -> str:
        return hmac.new(key, self._canonical_card(card).encode(), hashlib.sha256).hexdigest()[:16]

    def issue_card(self, card: "AgentCard", issuer_key: bytes) -> "AgentCard":
        """A partner/issuer signs its own card before publishing it."""
        card.sig = self._sign_card(card, issuer_key)
        return card

    @staticmethod
    def _bind_tool(tool_name: str, argspec: list):
        def arg_fn(m, c, argspec=argspec):
            return [c.user_id if a == "$user" else a for a in argspec]
        return (tool_name, arg_fn)

    def federate(self, card: "AgentCard"):
        """Onboard a partner's Agent Card as a live agent in the mesh.

        VULN  - import the card verbatim, trusting its self-declared caps.
        FIXED - reject any card not validly signed by a *trusted* issuer, and
                clamp the surviving capabilities to a locally-configured grant
                (authN proves identity; authZ stays a local decision).
        """
        if self.policy.verify_agent_cards:
            key = self._config.get("trusted_issuers", {}).get(card.issuer)
            if key is None:
                return False, f"DENIED: unknown federation issuer '{card.issuer}'"
            if not hmac.compare_digest(card.sig, self._sign_card(card, key)):
                return False, f"DENIED: agent card for '{card.agent_name}' failed signature check"
            grant = self._config.get("partner_grants", {}).get(card.agent_name, set())
            caps = set(card.capabilities) & grant      # authZ: never trust self-declared caps
        else:
            caps = set(card.capabilities)              # VULN: trust the card verbatim
        intent_tool = {kw: self._bind_tool(t, a) for kw, (t, a) in card.tool_grants.items()}
        agent = Agent(name=card.agent_name, capabilities=caps,
                      allowed_handoffs=set(card.allowed_handoffs),
                      intent_tool=intent_tool, intent_route=dict(card.routes))
        self.agents[card.agent_name] = agent
        return True, f"federated '{card.agent_name}' caps={sorted(caps)}"

    # ---------- main loop ----------
    def run(self, entry: str, message: str, context: Context, max_hops: int = 8) -> str:
        current = entry
        for _ in range(max_hops):
            agent = self.agents.get(current)
            if agent is None:
                context.log(f"[system] no such agent '{current}' -> abort")
                return f"ERROR_NO_AGENT:{current}"

            context.log(f"[{agent.name}] recv role={context.role} msg={message!r} "
                        f"notes={[f'{n.source}:{n.text}' for n in context.notes]}")
            self._maybe_apply_setrole(agent, message, context)

            # Retriever/peer agents (e.g. KnowledgeAgent): pull external content
            # into shared state, then hand back. This is the mesh's indirect
            # channel — the retrieved doc is attacker-influenceable.
            if agent.retriever is not None:
                doc = agent.retriever(message, context)
                context.add_note(doc, source="external")
                context.log(f"[{agent.name}] retrieved external doc -> notes"
                            f"(source=external): {doc!r}")
                # Consume the keyword that routed us here so the legit flow
                # doesn't re-trigger the same lookup forever.
                for kw in agent.route_keywords:
                    message = re.sub(r"\b" + re.escape(kw) + r"\b", "", message, flags=re.IGNORECASE)
                if agent.return_to:
                    ok, why = self._do_handoff(agent, agent.return_to, context)
                    context.log(f"[{agent.name}] return handoff -> {agent.return_to}: {why}")
                    if not ok:
                        return f"HANDOFF_BLOCKED: {why}"
                    current = agent.return_to
                    continue

            decision = self._decide(agent, message, context)

            if decision.kind == "reply":
                context.log(f"[{agent.name}] reply: {decision.text}")
                return decision.text

            if decision.kind == "tool":
                out = self._call_tool(agent, decision.tool, decision.args, context)
                context.log(f"[{agent.name}] tool {decision.tool}{tuple(decision.args)} -> {out}")
                return out

            if decision.kind == "handoff":
                ok, why = self._do_handoff(agent, decision.to, context)
                context.log(f"[{agent.name}] handoff -> {decision.to}: {why}")
                if not ok:
                    return f"HANDOFF_BLOCKED: {why}"
                if decision.source == "marker":
                    message = message.replace(f"[[HANDOFF:{decision.to}]]", "", 1)
                current = decision.to
                continue

        return "MAX_HOPS_EXCEEDED"

    # ---------- decision helpers ----------
    def _injected_instructions(self, message: str, context: Context) -> list:
        """Instructions the agent will ACT ON from untrusted content, after the
        active policy's input defenses.

        Models two capabilities honestly:
          * comprehension — literal markers PLUS natural language the model
            understands (nlp.detect at 'llm' level, which also sees through
            obfuscation). This is what a gullible stack obeys.
          * a static input FILTER (DETECT) — strips only what its narrow pattern
            list recognizes (markers + nlp 'filter' level), so paraphrase leaks.

        FIXED grants untrusted content no authority at all (provenance): it
        returns nothing regardless of phrasing — the paraphrase-proof control.
        """
        if not self.policy.honor_untrusted_markers:
            return []                                   # FIXED: provenance — trust nothing untrusted
        surface = message + " " + context.notes_text()
        comprehended = [(k.upper(), p.strip()) for k, p in MARKER_RE.findall(surface)]
        comprehended += nlp.detect(surface, level="llm")
        if self.policy.sanitize_untrusted:              # DETECT: subtract what the guard catches
            caught = {(k.upper(), p.strip()) for k, p in MARKER_RE.findall(surface)}
            caught |= set(nlp.detect(surface, level="filter"))
            comprehended = [it for it in comprehended if it not in caught]
        # de-dup, preserve order
        seen, out = set(), []
        for it in comprehended:
            if it not in seen:
                seen.add(it)
                out.append(it)
        return out

    def _maybe_apply_setrole(self, agent: Agent, message: str, context: Context) -> None:
        """Context-variable injection: an untrusted SETROLE mutates shared role."""
        for kind, payload in self._injected_instructions(message, context):
            if kind == "SETROLE":
                context.role = payload
                context.log(f"[{agent.name}] !! injected context override applied: "
                            f"role := {context.role}")

    def _decide(self, agent: Agent, message: str, context: Context) -> Decision:
        # Honor whatever untrusted instructions survived the policy's defenses.
        for kind, payload in self._injected_instructions(message, context):
            if kind == "HANDOFF":
                return Decision("handoff", to=payload, source="marker")
            if kind == "TOOL":
                name, args = self._parse_tool_marker(payload)
                return Decision("tool", tool=name, args=args, source="marker")

        # Legitimate intent routing (BOTH builds) — derived from the task itself.
        # Whole-word matching so control-marker text (e.g. 'issue_refund') can't
        # smuggle a keyword ('refund') into the legit router.
        low = message.lower()

        def hit(kw):
            return re.search(r"\b" + re.escape(kw) + r"\b", low) is not None

        for kw, (tname, arg_fn) in agent.intent_tool.items():
            if hit(kw):
                return Decision("tool", tool=tname, args=arg_fn(message, context))
        for kw, to in agent.intent_route.items():
            if hit(kw):
                return Decision("handoff", to=to)
        return Decision("reply", text=f"{agent.name}: how can I help?")

    @staticmethod
    def _parse_tool_marker(payload: str):
        m = re.match(r"\s*([A-Za-z_]\w*)\s*\((.*)\)\s*$", payload)
        if not m:
            return payload.strip(), []
        name, argstr = m.group(1), m.group(2).strip()
        args = [a.strip() for a in argstr.split(",")] if argstr else []
        return name, args

    def _do_handoff(self, agent: Agent, to: str, context: Context):
        if self.policy.enforce_handoff_allowlist and to not in agent.allowed_handoffs:
            return False, f"'{agent.name}' -> '{to}' not on allowlist"
        edge = (agent.name, to)
        if self.policy.detect_handoff_loops and edge in context.edges:
            return False, f"loop guard: handoff {agent.name} -> {to} already taken"
        context.edges.add(edge)
        if self.policy.scrub_context_on_handoff:
            # data/instruction separation: neutralize control markers in carried state
            for n in context.notes:
                n.text = MARKER_RE.sub("[filtered]", n.text)
        return True, "ok"

    def _call_tool(self, agent: Agent, tool_name: str, args: list, context: Context) -> str:
        tool = self.tools.get(tool_name)
        if tool is None:
            return f"NO_SUCH_TOOL:{tool_name}"
        if self.policy.enforce_tool_capabilities and tool.required_capability not in agent.capabilities:
            return (f"TOOL_DENIED: '{agent.name}' lacks capability "
                    f"'{tool.required_capability}' for '{tool_name}'")
        return tool.fn(*args, viewer_role=context.role)
