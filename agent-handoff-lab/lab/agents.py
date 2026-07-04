"""Wiring for the 'VulnBank' support system — a 2-to-4 agent mesh.

Legitimate topology (privilege gradient rises left to right):

    user -> TriageAgent --(account/balance/complaint)--> AccountAgent
                                                            |  \
                                          (refund/execute) OpsAgent
                                                            |  /
                                              (policy) --> KnowledgeAgent
                                                            (retrieves, hands back)

Trust / privilege gradient:
    TriageAgent (none) < AccountAgent (account_read) < OpsAgent (ops, db_admin)
    KnowledgeAgent (kb_read) sits *beside* AccountAgent as a peer — adding it
    turns the chain into a mesh, where trust propagates transitively through a
    retrieved document (indirect injection) and delegation can loop.

The SAME builder produces both the VULN and FIXED systems; the SecurityPolicy
passed in decides whether the planted flaws are live.
"""
from lab.runtime import Agent, System, Tool, SecurityPolicy
from lab import tools


def build_system(policy: SecurityPolicy) -> System:
    sysm = System(policy)

    # --- tools with the capability each requires ---
    sysm.add_tool(Tool("get_account",  tools.get_account,  required_capability="account_read"))
    sysm.add_tool(Tool("run_sql",      tools.run_sql,      required_capability="db_admin"))
    sysm.add_tool(Tool("issue_refund", tools.issue_refund, required_capability="ops"))
    sysm.add_tool(Tool("read_file",    tools.read_file,    required_capability="ops"))

    # --- Tier 0: user-facing, no capabilities ---
    triage = Agent(
        name="TriageAgent",
        capabilities=set(),
        allowed_handoffs={"AccountAgent"},                 # may ONLY escalate to AccountAgent
        intent_route={"balance": "AccountAgent", "account": "AccountAgent",
                      "complaint": "AccountAgent", "refund": "AccountAgent",
                      "policy": "AccountAgent"},
    )

    # --- Tier 1: can read account data; consults the KnowledgeAgent peer ---
    account = Agent(
        name="AccountAgent",
        capabilities={"account_read"},
        allowed_handoffs={"OpsAgent", "KnowledgeAgent"},
        intent_tool={"balance": ("get_account", lambda m, c: [c.user_id]),
                     "account": ("get_account", lambda m, c: [c.user_id])},
        # 'policy' is checked first so a policy question consults the KB peer
        # before any account action.
        intent_route={"policy": "KnowledgeAgent",
                      "refund": "OpsAgent", "execute": "OpsAgent"},
    )

    # --- Tier 2: privileged operations ---
    ops = Agent(
        name="OpsAgent",
        capabilities={"ops", "db_admin", "account_read"},
        allowed_handoffs=set(),
        intent_tool={"refund": ("issue_refund", lambda m, c: [c.user_id, "100"])},
    )

    # --- Peer: retrieval-only knowledge agent (the 4th agent) ---
    knowledge = Agent(
        name="KnowledgeAgent",
        capabilities={"kb_read"},
        allowed_handoffs={"AccountAgent"},                 # only hands back to its caller
        retriever=lambda m, c: tools.kb_lookup(m),
        return_to="AccountAgent",
        route_keywords=("policy",),                        # consumed so lookups don't re-loop
    )

    for a in (triage, account, ops, knowledge):
        sysm.add_agent(a)

    # operator token that the FIXED registry demands for new registrations
    sysm._config["operator_token"] = "S3CRET-OP-TOKEN"

    # --- A2A federation trust anchors (used by the FIXED build) ---
    # Issuers we recognize, keyed by their signing key, plus the *maximum*
    # capabilities we're willing to grant each named partner regardless of
    # what its card claims. FraudCheckPartner is a real fraud-screening peer
    # that legitimately needs read-only account access — and nothing more.
    sysm._config["trusted_issuers"] = {"AcmeFraudCorp": b"acme-federation-key"}
    sysm._config["partner_grants"] = {"FraudCheckPartner": {"account_read"}}
    return sysm
