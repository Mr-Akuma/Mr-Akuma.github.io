"""Extended runtime for the exfiltration / persistence labs (A9-A12).

A1-A8 stop at the moment an agent is coerced into *acting*. Johann Rehberger's
research (embracethered.com) is overwhelmingly about the two steps that come
next in the AI kill chain: **exfiltrate** the data and **persist** the foothold.
This module adds exactly those, as an additive subclass so the A1-A8 decision
path in `lab.runtime` is untouched (its 30 tests stay green).

Four documented techniques become policy-switchable exploits:

  A9  Zero-click exfiltration via Markdown image rendering
      -> "ChatGPT Plugins: Data Exfiltration via Images" (2023),
         "Data Exfiltration via Image Rendering Fixed in Amp Code" (2025),
         "OpenAI Explains URL-Based Data Exfiltration Mitigations" (2026)
      fix: enforce_egress_allowlist  (URL/image-domain allow-list; the OpenAI
           url_safe / Bing CSP class of control) — closes the *channel*, which
           Rehberger stresses is independent of fixing the injection.

  A10 SpAIware: instruction-bearing memory that persists across sessions
      -> "Spyware Injection Into Your ChatGPT's Long-Term Memory (SpAIware)" (2024),
         "Windsurf: Memory-Persistent Data Exfiltration" (2025)
      fix: provenance_on_memory  (untrusted content may not write long-term
           memory; reloaded memories keep their source tag and are never honored)

  A11 Delayed tool invocation
      -> "Hacking Gemini's Memory with Prompt Injection and Delayed Tool
          Invocation" (2025)
      fix: confirm_sensitive_after_taint  (once context carries untrusted data, a
           sensitive call fired by a planted trigger needs confirmation — a user
           trigger word does not launder an untrusted instruction's origin)

  A12 ASCII smuggling (invisible Unicode instructions)
      -> "ASCII Smuggling and Hidden Prompt Instructions",
         "Sneaky Bits: Advanced Data Smuggling Techniques" (2025)
      fix: provenance (honor_untrusted_markers off) — content-independent, so the
           carrier/encoding is irrelevant. DETECT's "strip invisible characters"
           mitigation blocks the known carrier but not the next one.
"""
from __future__ import annotations

import re

from lab.runtime import (Agent, Context, Note, System, Tool, MARKER_RE,
                         SecurityPolicy)
from lab import nlp, tools

# A delayed-trigger marker: [[ONTRIGGER:<word>|<instruction>]] planted in
# untrusted content. When the user later utters <word>, <instruction> fires as
# if the user asked for it. Modelled after Rehberger's Gemini delayed-tool
# invocation ("if the user says 'yes', save these memories").
ONTRIGGER_RE = re.compile(r"\[\[ONTRIGGER:([^|\]]+)\|(.+?)\]\]", re.IGNORECASE)

# Sensitive tools that, once context is tainted, must not be fired by a delayed
# trigger without confirmation.
_SENSITIVE_TOOLS = {"remember", "render", "issue_refund", "run_sql", "read_file"}


class AdvancedSystem(System):
    """System plus a long-term memory, an egress-controlled render channel, and
    delayed-trigger handling — the surface A9-A12 exercise."""

    # -- comprehension: also read instructions smuggled in invisible carriers --
    def _injected_instructions(self, message: str, context: Context) -> list:
        if not self.policy.honor_untrusted_markers:
            return []                                   # FIXED: provenance
        raw = message + " " + context.notes_text()
        if self.policy.sanitize_untrusted:
            # DETECT: strip invisible carriers (Rehberger's "remove invisible
            # characters" mitigation), then subtract what the byte-level filter
            # recognizes. A payload in a *known* carrier vanishes; a paraphrase,
            # a homoglyph, or an unknown carrier survives — the same gap A1-A8
            # measure, now including encoding.
            surface = nlp.strip_invisibles(raw)
            comp = [(k.upper(), p.strip()) for k, p in MARKER_RE.findall(surface)]
            comp += nlp.detect(surface, level="llm")
            caught = {(k.upper(), p.strip()) for k, p in MARKER_RE.findall(surface)}
            caught |= set(nlp.detect(surface, level="filter"))
            comp = [it for it in comp if it not in caught]
        else:
            # VULN: the model reads through invisible carriers, no filter.
            surface = nlp.reveal_smuggled(raw)
            comp = [(k.upper(), p.strip()) for k, p in MARKER_RE.findall(surface)]
            comp += nlp.detect(surface, level="llm")
        seen, out = set(), []
        for it in comp:
            if it not in seen:
                seen.add(it)
                out.append(it)
        return out

    # -- provenance helpers ---------------------------------------------------
    @staticmethod
    def _tainted(context: Context) -> bool:
        """True once any attacker-influenceable content has entered context."""
        return any(n.source in ("external", "stored") for n in context.notes)

    @staticmethod
    def _user_secret(context: Context) -> str:
        """The sensitive user-side data an exfil channel would leak — the chat
        history the user themselves supplied (an API key they pasted, etc.)."""
        return " ".join(n.text for n in context.notes if n.source == "user")

    # -- session lifecycle: load persistent memory, handle delayed triggers ---
    def run(self, entry: str, message: str, context: Context, max_hops: int = 8) -> str:
        if not getattr(context, "_mem_loaded", False):
            # Session open: reload this user's long-term memories into context.
            # Each keeps the provenance tag it was stored under.
            for text, src in tools.load_memories(context.user_id):
                context.notes.append(Note(text, "stored"))
                context.log(f"[memory] reloaded persistent memory (source={src}): {text!r}")
            context._mem_loaded = True

        # Register any delayed triggers planted in untrusted content this turn.
        self._register_triggers(context)

        # If the user's message matches a planted trigger, that is A11.
        fired = self._maybe_fire_trigger(entry, message, context)
        if fired is not None:
            return fired

        # 0-click exfiltration: the client auto-renders any Markdown image in the
        # working context — including one injected via untrusted content. This is
        # A9/A12 and the reload half of A10.
        self._auto_render(context)

        return super().run(entry, message, context, max_hops)

    def _auto_render(self, context: Context) -> None:
        """Model the client auto-fetching Markdown images in the response surface.

        VULN   - fetch every image, whatever its origin (0-click leak).
        DETECT - strip invisible carriers first (kills a smuggled image URL, A12),
                 but a visible injected image still renders: an input filter does
                 not close the exfiltration channel.
        FIXED  - provenance: never render an image that came from untrusted content
                 (external/stored notes); and, independently, an egress allow-list
                 refuses any fetch to a non-allow-listed host.
        """
        secret = self._user_secret(context)
        allow = tools.EGRESS_ALLOWLIST if self.policy.enforce_egress_allowlist else None
        for note in context.notes:
            if (not self.policy.honor_untrusted_markers) and note.source in ("external", "stored"):
                context.log(f"[render] provenance: refused image from untrusted note "
                            f"(source={note.source})")
                continue
            # Model comprehension normalizes obfuscation (reveals invisible carriers,
            # strips zero-width, defolds homoglyphs, decodes base64). DETECT runs its
            # invisible-character stripper FIRST — which only removes the carriers it
            # knows; the model then comprehends whatever survived.
            raw = nlp.strip_invisibles(note.text) if self.policy.sanitize_untrusted else note.text
            text = nlp.normalize(raw)
            text = MARKER_RE.sub("", text)   # an image still inside a tool-marker isn't output yet
            if "![" in text:
                out = tools.render(text, secret=secret, viewer_role=context.role,
                                   egress_allowlist=allow)
                context.log(f"[render] {out}")

    def _register_triggers(self, context: Context) -> None:
        pending = getattr(context, "pending_triggers", None)
        if pending is None:
            pending = context.pending_triggers = []
        surface = nlp.reveal_smuggled(context.notes_text())
        for word, instruction in ONTRIGGER_RE.findall(surface):
            entry = (word.strip().lower(), instruction.strip())
            if entry not in pending:
                pending.append(entry)
                context.log(f"[trigger] delayed instruction armed on '{entry[0]}': {entry[1]!r}")

    def _maybe_fire_trigger(self, entry: str, message: str, context: Context):
        pending = getattr(context, "pending_triggers", [])
        low = message.lower()
        for word, instruction in pending:
            if re.search(r"\b" + re.escape(word) + r"\b", low):
                tool_name, args = self._parse_tool_marker(instruction)
                agent = self.agents.get(entry)
                if (self.policy.confirm_sensitive_after_taint
                        and self._tainted(context)
                        and tool_name in _SENSITIVE_TOOLS):
                    context.log(f"[trigger] '{word}' would fire {tool_name} but context is "
                                f"tainted -> confirmation required, NOT executed")
                    return (f"CONFIRM_REQUIRED: '{tool_name}' was requested by a delayed "
                            f"trigger from untrusted content; user confirmation needed")
                context.log(f"[trigger] user said '{word}' -> firing planted {tool_name} "
                            f"as if user-authorized")
                return self._call_tool(agent, tool_name, args, context)
        return None

    # -- tool dispatch: memory provenance -------------------------------------
    def _call_tool(self, agent: Agent, tool_name: str, args: list, context: Context) -> str:
        if tool_name == "remember":
            return self._remember(agent, args, context)
        return super()._call_tool(agent, tool_name, args, context)

    def _capability_ok(self, agent: Agent, tool_name: str) -> bool:
        tool = self.tools.get(tool_name)
        if tool is None or not self.policy.enforce_tool_capabilities:
            return True
        return tool.required_capability in agent.capabilities

    def _remember(self, agent: Agent, args: list, context: Context) -> str:
        if not self._capability_ok(agent, "remember"):
            return f"TOOL_DENIED: '{agent.name}' lacks capability for 'remember'"
        text = args[0] if args else ""
        untrusted = self._tainted(context)
        if self.policy.provenance_on_memory and untrusted:
            tools._AUDIT.append(("memory_write_blocked", text))
            context.log("[memory] write refused: untrusted content may not persist "
                        "long-term memory")
            return "MEMORY_DENIED: untrusted content may not write long-term memory"
        source = "external" if untrusted else "user"
        return tools.remember(text, source=source, user_id=context.user_id,
                              viewer_role=context.role)


def build_advanced_system(policy: SecurityPolicy) -> AdvancedSystem:
    """A single support assistant with a render (image) channel and long-term
    memory — the minimal surface for the exfil/persistence exploits. Legit
    topology is trivial; the interest is entirely in what untrusted content can
    make the assistant do with these two capabilities."""
    sysm = AdvancedSystem(policy)

    sysm.add_tool(Tool("remember", tools.remember,     required_capability="memory"))
    sysm.add_tool(Tool("get_account", tools.get_account, required_capability="account_read"))
    sysm.add_tool(Tool("read_file",   tools.read_file,   required_capability="ops"))

    assistant = Agent(
        name="AssistantAgent",
        # holds render + memory legitimately, so the *new* controls (egress
        # allow-list, memory provenance, taint-confirmation), not a blanket
        # capability denial, are what stop the abuse.
        capabilities={"render", "memory", "account_read"},
        allowed_handoffs=set(),
        intent_tool={},
        intent_route={},
    )
    sysm.add_agent(assistant)
    return sysm
