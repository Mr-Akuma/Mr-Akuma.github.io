"""Generate handoff-standards-matrix.html — the standardized reference view.

Renders the taxonomy (lab/taxonomy.py) as a series-styled page: a 12-exploit
matrix mapped to OWASP LLM Top 10 2025 / MITRE ATLAS / CWE / CVE, grouped by
AI-kill-chain phase, plus the control catalog. Reuses the shared CSS/JS from an
existing series page so it matches pixel-for-pixel.

    python build_standards_page.py
"""
import re
import pathlib

from lab.taxonomy import TAXONOMY, KILL_CHAIN

HERE = pathlib.Path(__file__).parent
TEMPLATE = (HERE / "handoff-a1-context-injection.html").read_text(encoding="utf-8")
STYLE = re.search(r"<style>.*?</style>", TEMPLATE, re.S).group(0)
SCRIPT = re.search(r"<script>.*?</script>", TEMPLATE, re.S).group(0)

PHASE_BLURB = {
    "inject": "get untrusted content in front of the model",
    "escalate": "borrow authority the caller doesn't have",
    "act": "make the system do something privileged",
    "exfiltrate": "get the data out",
    "persist": "keep the foothold across sessions",
    "evade": "defeat the detector, not the control",
}


def ids(items):
    return "<br>".join(f'<span class="tag">{x.split(" ", 1)[0]}</span>' for x in items)


def sev_pill(s):
    cls = {"Critical": "ex", "High": "ex", "Medium": "dt", "Low": "bl",
           "informational": "bl"}.get(s, "dt")
    return f'<span class="pill {cls}">{s}</span>'


rows = []
for m in TAXONOMY:
    cve = ("<br>".join(m.cve) if m.cve else '<span class="none">—</span>')
    rows.append(f"""<tr>
      <td class="ctl"><b style="color:var(--accent)">{m.id}</b><br>{m.name}</td>
      <td>{ids(m.owasp)}</td>
      <td>{ids(m.atlas)}</td>
      <td>{ids(m.cwe)}</td>
      <td style="font-size:.8rem">{cve}</td>
      <td>{sev_pill(m.severity)}</td>
    </tr>""")
matrix = "\n".join(rows)

# kill-chain grouping
chain = []
for phase in KILL_CHAIN:
    members = [m for m in TAXONOMY if m.kill_chain == phase]
    if not members:
        continue
    pills = " ".join(f'<span class="tag"><b>{m.id}</b></span>' for m in members)
    chain.append(f"""<div class="root">
      <div class="k">{phase}</div>
      <h4>{PHASE_BLURB.get(phase, '')}</h4>
      <p>{pills}</p>
    </div>""")
chain_html = "\n".join(chain)

# control catalog
controls = "\n".join(
    f'<tr><td class="ctl"><b>{m.id}</b></td><td>{m.control}</td></tr>' for m in TAXONOMY)

article = f"""
      <p class="lead opener">Twelve exploits, one reference. This page is the standardized view of the lab: every attack (A1&ndash;A12) mapped to the catalogs a security team actually reports against &mdash; <strong>OWASP Top&nbsp;10 for LLM Applications 2025</strong>, <strong>MITRE ATLAS</strong>, and <strong>CWE</strong> &mdash; with disclosed CVEs where the class has been found in shipping products. The mappings live in <code>lab/taxonomy.py</code> as the single source of truth; <code>test_taxonomy.py</code> fails the build if any exploit is missing a mapping or an identifier is malformed. Identifiers verified July&nbsp;2026.</p>

      <h2><span class="n">the matrix</span>A1&ndash;A12 &times; the standards</h2>
      <div class="tblwrap"><table class="tm">
        <thead><tr><th>exploit</th><th>OWASP 2025</th><th>MITRE ATLAS</th><th>CWE</th><th>disclosed as</th><th>sev</th></tr></thead>
        <tbody>
        {matrix}
        </tbody>
      </table></div>

      <h2><span class="n">the kill chain</span>Where each exploit sits</h2>
      <p>A1&ndash;A8 cover <em>inject &rarr; escalate &rarr; act</em>. A9&ndash;A12 continue into <em>exfiltrate &rarr; persist &rarr; evade</em> &mdash; the phases real incidents actually reach, drawn from Johann Rehberger&rsquo;s corpus (embracethered.com).</p>
      <div class="roots">
        {chain_html}
      </div>

      <h2><span class="n">the controls</span>What FIXED enforces, per exploit</h2>
      <p>Each mapping resolves to one structural control (or a small defense-in-depth stack). None of them read the wording of an attack &mdash; that is the point, and the measured reason they reach 100% where a static input filter tops out at 43% (see <code>metrics.py</code>) and blocks only 1 of 5 smuggling carriers (see <code>metrics_advanced.py</code>).</p>
      <div class="tblwrap"><table class="tm">
        <thead><tr><th>#</th><th>control (FIXED build)</th></tr></thead>
        <tbody>
        {controls}
        </tbody>
      </table></div>

      <div class="note">
        <div class="k">how to read this as a defender</div>
        <p>Pick your framework&rsquo;s column. If you report against OWASP, the matrix tells you which of the LLM Top&nbsp;10 each lab exercises and which control retires it. If you thread MITRE ATLAS, the technique IDs slot straight into a coverage map. The CWE column is for your SAST/AppSec pipeline. Every row&rsquo;s control is content-independent, so it holds against paraphrase and novel encodings &mdash; the property an input filter can&rsquo;t buy.</p>
      </div>
"""

html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Standards matrix (A1–A12) — The handoff is the soft joint</title>
<meta name="description" content="Every exploit in the agent-handoff lab (A1–A12) mapped to OWASP Top 10 for LLM Applications 2025, MITRE ATLAS, CWE, and disclosed CVEs, grouped by AI-kill-chain phase, with the structural control that closes each. The standardized defensive reference view.">
{STYLE}
</head>
<body>

<div id="progress"></div>

<div class="page">
  <header class="hero">
    <div class="wrap">
      <div class="eyebrow">handoff series · standardized reference</div>
      <h1>The standards <span class="em">matrix</span></h1>
      <p class="dek">All twelve exploits, mapped to OWASP LLM Top 10 (2025), MITRE ATLAS, and CWE — grouped by kill-chain phase, each resolved to the structural control that retires it.</p>
      <div class="byline">
        <span><a href="the-handoff-is-the-soft-joint.html">&larr; series hub</a></span>
        <span>OWASP 2025 · MITRE ATLAS · CWE</span>
        <span>source: lab/taxonomy.py</span>
      </div>
    </div>
  </header>

  <article>
    <div class="wrap">
{article}
    </div>

    <footer>
      <div class="wrap">
        <p class="kick">Standards are how a lab becomes a reference. Every exploit here has a catalog ID and a control that closes it.</p>
        <p>Generated from <code>lab/taxonomy.py</code>; validated by <code>test_taxonomy.py</code>. <a href="the-handoff-is-the-soft-joint.html">Back to the hub &rarr;</a></p>
      </div>
    </footer>
  </article>
</div>

{SCRIPT}
</body>
</html>
"""

(HERE / "handoff-standards-matrix.html").write_text(html, encoding="utf-8")
print("wrote handoff-standards-matrix.html", f"({len(html)} bytes)")
