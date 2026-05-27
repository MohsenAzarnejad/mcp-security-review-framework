# MCP Security Review & Threat Modeling Standard

# Table of Contents

1. [Core Security Principles](#1-core-security-principles)
2. [MCP Threat Landscape](#2-mcp-threat-landscape)
3. [Security Reviewer Mindset](#3-security-reviewer-mindset)
4. [End-to-End Review Workflow](#4-end-to-end-review-workflow)
5. [Threat Modeling Methodology](#5-threat-modeling-methodology)
6. [Dynamic Testing Guidance](#6-dynamic-testing-guidance)
7. [Risk Scoring Methodology](#7-risk-scoring-methodology)
8. [Classification & Trust Tiering](#8-classification--trust-tiering)
9. [Security Decision Framework](#9-security-decision-framework)
10. [Appendix A: Quick Decision Cheat Sheet](#10-appendix-a-quick-decision-cheat-sheet)
11. [Appendix B: Glossary of Common Anti-Patterns](#11-appendix-b-glossary-of-common-anti-patterns)
12. [Appendix C: Related Documents](#12-appendix-c-related-documents)


---

# 1. Core Security Principles

## 1.1 The Most Important Principle

> An MCP server does not create new access. It amplifies existing access by making it callable via an LLM.

This is the core framing principle for every MCP review.

The primary risk introduced by MCP is not necessarily new backend access. It is that the access becomes amplified through autonomous LLM behavior.

MCP risk is amplified because LLMs can autonomously chain tools, persist context, and repeatedly attempt actions at machine speed.

The access becomes:

- reachable through natural-language requests;
- callable through LLM reasoning;
- influenced by prompt injection;
- chainable with other tools;
- executable at machine speed and scale.

Therefore:

> Credential scope is the single highest-leverage control in any MCP deployment.

A perfectly hardened MCP server with broad administrator credentials is more dangerous than a moderately implemented MCP server with tightly scoped read-only credentials.


## 1.2 Security Review Philosophy

Do not ask:

> Would the model normally call this dangerous tool?

Ask instead:

> Could an attacker eventually influence the model, tool output, metadata, or user context so that this dangerous tool is called?

Assume the model can eventually become confused, manipulated, prompt-injected, socially engineered, or poisoned by external content.

The MCP server must remain safe even when:
- tool outputs are malicious;
- resources contain prompt injection;
- the model is manipulated;
- the user is tricked;
- external systems are compromised;
- prompts are poisoned.

Security must exist in deterministic server-side logic.

Human-in-the-loop (HITL) approval means a sensitive or destructive action requires explicit user confirmation before execution.

HITL approval is one of the primary mitigations for dangerous tool chaining, prompt injection, and unintended autonomous actions.


## 1.3 Never Trust These Inputs

Treat the following as untrusted by default:

- Tool output
- Resource content
- Prompt templates
- Tool descriptions from external sources
- User-provided URLs
- User-provided file paths
- LLM-generated parameters
- External documents
- Logs
- Tickets
- Emails
- Web pages
- SaaS content
- Dynamic tool registration

---

# 2. MCP Threat Landscape

Before applying the checklist, the reviewer should internalize the unique attack surface of MCP. The three "poisoning" vectors below are deliberately separated because each demands a different control:

1. **Description Poisoning** *(vector: tool description / schema)*. Tool metadata (name, description, parameter docs) is part of the LLM's input. A malicious or compromised description can hijack model behavior before any tool is even invoked. Mitigation: schema review at audit, manifest hash-pinning, internal forks, immutable registry.
2. **Execution Poisoning** *(vector: tool implementation code)*. The tool description is benign but the underlying code executes secondary, hidden behavior (data exfil, dropper, etc.). Mitigation: static analysis, supply-chain verification, sandboxed execution, internal forks.
3. **Prompt Injection via Response** *(vector: tool output / fetched content)*. Tool descriptions and code are clean, but the *data the tool returns* (a fetched page, a ticket body, a log line) contains injected instructions. This is the most common production failure mode. Mitigation: untrusted-content boundary markers, scoped data sources, no instruction-following on tool output, output classification labels.
4. **Tool output is LLM input.** Anything a tool returns becomes part of the model's context and can carry injected instructions. The MCP server is not just an API — it is a **prompt injection delivery surface**.
5. **Tool descriptions are LLM input.** See "Description Poisoning" above — re-emphasized because most reviewers underestimate it.
6. **Capabilities are dynamic.** Tools can be added, removed, or renamed after initial connection. Approval at T0 ≠ safety at T30. *(Dynamic Tool Modification — the "rug pull" attack.)*
7. **The MCP server is a confused deputy.** It typically holds a service account or OAuth token to backend systems. A clever prompt can cause it to perform actions the *user* could not perform directly. Token passthrough — insecurely forwarding a client token to downstream APIs — is the canonical anti-pattern.
8. **Cross-server interference.** A client connected to multiple MCP servers can leak data from Server A through Server B (e.g., "use the email tool to send the contents of the database resource"). Tool name collisions allow shadowing.
9. **Local transport ≠ safe transport.** stdio-based MCP servers run as child processes — command-injection and binary-provenance risks apply.
10. **Sampling and elicitation features** (where the server requests LLM completions or user input mid-flow) reverse the trust direction and require explicit review.
11. **Long-lived sessions** carry state, tokens, and accumulated context — session hijack and replay attacks apply.

---

# 3. Security Reviewer Mindset

## 3.1 Think Like an Attacker

Assume:
- the model can be manipulated;
- prompt injection will eventually happen;
- users can be socially engineered;
- tools can be chained;
- metadata may become malicious;
- external content is adversarial.


## 3.2 Focus on Blast Radius

Always ask:
- What can this server read?
- What can this server modify?
- Which systems can it reach?
- Which credentials does it hold?
- What happens if prompt injection succeeds?
- What happens if authorization fails?
- What is the worst possible chain?


## 3.3 Most Dangerous Pattern

The highest-risk MCP pattern is:

> Untrusted-read + sensitive-write in the same effective workflow.

Examples:
- read_ticket + send_email
- fetch_url + exec_shell
- read_logs + deploy
- read_document + create_pr

---

# 4. End-to-End Review Workflow

The recommended review process contains 8 phases.

```text
1. Intake
2. Architecture Review
3. Threat Modeling
4. Configuration Review
5. Permission Review
6. Dynamic Testing
7. Risk Scoring
8. Final Recommendation
```


## Phase 1: Intake

**Reviewer collects:**

- Server name, owner, sponsor team, business justification.
- Source (vendor / OSS repo / internal build) and version/commit hash.
- Transport (stdio / SSE / Streamable HTTP / WebSocket).
- Hosting model (on user endpoint / internal K8s / vendor SaaS).
- Data classifications the server will touch (Public / Internal / Confidential / Restricted).
- Identity model (service account / per-user OAuth / personal access token).
- Tool inventory (name + description + side-effect summary).
- Expected user population (single team / org-wide).

### Deliverable
Intake page or review ticket (status = `Under Review`).


## Phase 2: Architecture Review

- Diagram trust boundaries (client ↔ server ↔ downstream).
- Identify where credentials live and what scope they hold.
- Identify all egress paths (DNS, HTTP, DBs, message buses).
- Identify where tool inputs/outputs are persisted (logs, caches, vector DBs).
- Map the **blast radius**: if a prompt injection succeeds, what is reachable?

### Questions
- What credentials exist?
- Where are they stored?
- What systems are reachable?
- What happens if prompt injection succeeds?

### Deliverable
Architecture diagram and blast-radius analysis.


## Phase 3: Threat Modeling

- Apply STRIDE *plus* MCP-specific categories: **Tool Poisoning**, **Indirect Prompt Injection**, **Confused Deputy**, **Cross-Server Interference**, **Rug Pull**.
- Build at least one *abuse story* per high-impact tool ("Attacker plants instructions in a Jira ticket so that `read_ticket` causes `send_email` to leak data").
- Identify any tool that combines **read-from-untrusted** + **write-to-sensitive** in a single agent loop — this is the highest-risk pattern.

### Build Abuse Stories

Example:
```text
Attacker places malicious instructions inside a Jira ticket.
The model reads the ticket through read_ticket.
The model calls send_email and leaks internal data.
```

### Deliverable
Threat model document with abuse cases.


## Phase 4: Configuration Review

- Walk the security review checklist/control catalog against deployed config, manifests, Helm charts, Dockerfiles, IaC.
- Verify hardening (non-root user, read-only root FS, dropped capabilities, no host mounts).
- Verify TLS, cipher suites, certificate validation, auth config.

### Validate
- non-root execution;
- read-only filesystem;
- seccomp/AppArmor/SELinux;
- no host mounts;
- least-exposed interfaces;
- secure secret handling.


## Phase 5: Permission Review

- Enumerate every identity the server uses (IAM roles, OAuth scopes, DB grants, K8s RBAC, GitHub app permissions, etc.).
- Confirm **least privilege** against each tool's actual needs.
- Flag any wildcard, `*:*`, `Owner`, `admin`, `repo`-wide, or unscoped tokens.

### Flag
- wildcard permissions;
- shared admin accounts;
- long-lived credentials;
- unscoped service accounts.


## Phase 6: Dynamic Testing

Perform live testing against a non-prod instance:
- **Auth tests:** missing/expired/forged tokens, replay, downgrade.
- **Authz tests:** cross-tenant access, IDOR, privilege escalation.
- **Injection tests:** prompt injection in tool outputs and resources; tool poisoning via crafted descriptions if reviewer can modify server.
- **Tool abuse:** chain tools to reach an unsafe outcome; test the "untrusted-read → sensitive-write" pattern.
- **Network tests:** SSRF from any tool that accepts a URL; DNS rebinding for HTTP-bound servers; egress to unexpected destinations.
- **Resource exhaustion:** payload size, recursive structures, slow-loris, unbounded streaming.
- **Logging tests:** verify expected events appear; verify no secrets are logged.


## Phase 7: Risk Scoring

- Score each finding per Section 9.
- Aggregate to an overall **Residual Risk Rating**.

### Questions
- Can any user trigger this?
- Is authentication required?
- Can prompt injection drive exploitation?
- Does this impact sensitive systems?
- Can the issue chain with other tools?


## Phase 8: Final Recommendation

Possible decisions:

| Decision | Meaning |
|---|---|
| Approved | No blocking issues |
| Approved with Restrictions | Allowed with constraints |
| Pilot Only | Limited deployment |
| Under Review | Missing information |
| Rejected | Critical risk exists |

### Deliverables
- final report;
- findings;
- risk rating;
- compensating controls;
- review owner;
- re-review triggers.

---

# 5. Threat Modeling Methodology

## 5.1 Core Questions

Ask:
- What can the model cause this server to do?
- What happens if tool output is malicious?
- What happens if credentials leak?
- What happens if a downstream system is compromised?
- What systems become reachable after compromise?


## 5.2 Threat Categories

| Category | Example |
|---|---|
| Spoofing | Session hijack |
| Tampering | Tool metadata modification |
| Repudiation | Missing audit logs |
| Information Disclosure | Excessive exports |
| Denial of Service | Unbounded queries |
| Elevation of Privilege | Shared admin token |
| Prompt Injection | Malicious external content |
| Tool Poisoning | Malicious tool descriptions |
| Cross-Server Abuse | Server-to-server exfiltration |


## 5.3 Abuse Story Template

```text
Actor:
Goal:
Entry Point:
Trust Boundary Crossed:
Affected Systems:
Worst-Case Outcome:
Mitigations:
Residual Risk:
```

---

# 6. Dynamic Testing Guidance

## 6.1 Recommended Runtime Validation

Validate:
- initialize
- tools/list
- prompts/list
- resources/list
- authentication
- authorization
- schema enforcement
- transport behavior
- capability changes


## 6.2 Recommended Security Tests

| Test | Purpose |
|---|---|
| Prompt Injection | Detect unsafe instruction following |
| SSRF | Detect internal network access |
| Command Injection | Detect unsafe execution |
| Path Traversal | Detect filesystem escape |
| Excessive Export | Detect data overexposure |
| Replay Testing | Detect weak session handling |
| Rate Limit Testing | Detect DoS exposure |
| Dynamic Tool Changes | Detect rug-pull behavior |

---

# 7. Risk Scoring Methodology

We use a **Likelihood × Impact** matrix, with an AI-specific amplification factor. Each finding is scored 1–5 on each axis.

## 7.1 Likelihood

1. Requires multiple pre-conditions and insider access.
2. Requires authenticated user + specific knowledge.
3. Authenticated user, common knowledge.
4. Any user can trigger.
5. Unauthenticated / drive-by.

## 7.2 Impact

1. Negligible (informational disclosure of public data).
2. Low (limited internal info).
3. Moderate (confidential data for one user/tenant).
4. High (confidential data org-wide; or write to production systems).
5. Critical (restricted/regulated data; broad RCE; identity compromise).


### 7.3 Risk Score = Likelihood × Impact (range 1–25)

| Score | Rating | Maps to Severity |
|---|---|---|
| 20–25 | Critical | Critical |
| 12–19 | High | High |
| 6–11 | Medium | Medium |
| 1–5 | Low | Low |

## 7.4 AI Amplification Factor (+1 to Impact, max 5) — applies when ANY of:

- Finding allows untrusted data into LLM context.
- Finding allows tool/description manipulation visible to LLM.
- Finding enables chaining tools toward an outcome no single tool authorizes alone.
- Finding affects a tool that combines untrusted-read with sensitive-write.


## 7.5 Residual Risk

| Condition | Result |
|---|---|
| Any unresolved Critical | Reject |
| 3+ unresolved High | Critical residual risk |
| Medium/Low only | Usually acceptable with tracking |

---

# 8. Classification & Trust Tiering

## 8.1 Server Classification

| Class | Definition | Audit Depth |
|---|---|---|
| **C1 — First-party / Anthropic-published** | MCP server published by the foundation model vendor. | Standard checklist, light dynamic test. |
| **C2 — Reputable Vendor** | Commercial vendor under MSA + security questionnaire. | Standard checklist + vendor SIG/CAIQ + dynamic test. |
| **C3 — Open Source** | Public OSS project. | Full checklist + supply chain deep-dive + code review of high-risk tools. |
| **C4 — Internal-built** | Built by an internal team. | Full checklist + SDLC evidence + code review + threat model sign-off. |
| **C5 — Experimental / Unknown** | Pre-release, prototype, or unvetted code. | Sandbox tier only; restricted access until reclassified. |


## 8.2 Trust Tiers

| Tier | Name | Where Allowed | Data Allowed | Examples |
|---|---|---|---|---|
| **T0** | Sandbox | Isolated dev environment, no prod identities | Synthetic only | Experimental servers |
| **T1** | Individual / Personal Productivity | Endpoint, single user | Internal, non-sensitive | Personal note-taking server |
| **T2** | Team Internal | Internal infra, scoped to team | Internal + Confidential (need-to-know) | Team Jira/Confluence reader |
| **T3** | Org Production | Production infra, multi-team | Up to Restricted with explicit DPIA | Org-wide knowledge base server |

A server's status (§8) and tier (§6.2) are independent: a server can be **Approved at T1** but **Rejected for T3**.


### 8.3 Audit Depth Proportionality

Not every audit needs to be exhaustive. Audit depth scales with **Classification × Requested Trust Tier × Data Sensitivity**. Reviewers should be explicit in the page about the depth applied and why.

| Combination | Audit Depth |
|---|---|
| C1–C2 server, T0–T1, Public/Internal data | **Lightweight:** Intake + mandatory controls subset (auth, scope, secrets, deployment model). Skip threat model and dynamic test unless red flags. |
| C2–C3 server, T1–T2, Internal/Confidential | **Standard:** Full Architecture Review + Threat Model + Configuration + Permission Review. Dynamic test on high-risk tools only. |
| C3–C5 server, T2–T3, any sensitive data | **Full:** All eight phases, full control catalog, code review of high-risk tools, abuse story per high-impact tool, formal sign-off chain. |
| Any server with code-execution or admin tools | **Full**, regardless of class/tier. |
| Any server touching Restricted data | **Full** + Privacy/DPIA. |

The reviewer should state in the executive summary: *"This audit was performed at **Standard** depth based on C3 × T2 × Confidential. A full audit would additionally cover X, Y, Z."* This is honest, gives readers calibration, and creates a clear trigger for deeper review if scope changes.

---

# 9. Security Decision Framework

## Immediate Reject Conditions

| Condition | Decision |
|---|---|
| Unauthenticated endpoint | Reject |
| Shared admin credential | Reject |
| Arbitrary code execution without sandbox | Reject |
| Embedded credentials | Reject |
| Broad unrestricted URL fetcher | Reject until fixed |


## Conditional Approval Conditions

| Condition | Result |
|---|---|
| Missing audit logging | Restrict deployment |
| Weak runtime isolation | Restrict deployment |
| Missing dynamic testing | Pilot only |
| Missing threat model | Under Review |
| Weak dependency hygiene | Restricted rollout |


---


## 10. Appendix A: Quick Decision Cheat Sheet

Use only after the full checklist is done; for first-pass triage of obvious blockers.

| Observed Condition | Implication |
|---|---|
| Unauthenticated endpoint | **Reject.** |
| Service account with `Owner` / `Administrator` / `*` IAM | **Reject** until scoped. |
| Arbitrary code execution tool with no sandbox | **Reject** for any tier > T0. |
| Untrusted-read + sensitive-write tools in one session, no HITL | **Approved with Risks** at most; document compensating control or reject for T3. |
| No tool inventory, no documented data flows | **Under Review** — block until provided. |
| Vendor server, no DPA / sub-processor disclosure | **Under Review** — block until provided. |
| Tool descriptions/schemas not pinned | High finding; require CI guard before approval. |
| stdio binary unsigned / unverified provenance | High finding; require signing before approval for any C3+/T2+. |
| Embedded credentials in repo / image | **Reject** + rotate immediately. |


---

## 11. Appendix B: Glossary of Common Anti-Patterns

| Name | Pattern | Why it's dangerous |
|---|---|---|
| **The Swiss Army Server** | One MCP server exposing read, write, exec across many systems. | Largest possible blast radius; every prompt injection lands in a privileged context. |
| **The Shared Service Account** | One backend identity used for all users. | Confused deputy; no per-user audit; over-privilege almost guaranteed. |
| **The Open Loopback** | Local server bound to `0.0.0.0`, no auth, "it's just localhost." | LAN-reachable; DNS-rebinding from browser; trivial unauthorized access. |
| **The Live-Reloading Tool List** | Server dynamically adds tools post-connection without re-consent. | Rug pull; user consent meaningless. |
| **The Echo Chamber** | Tool returns raw third-party content as model context with no labeling. | Indirect prompt injection delivery vehicle. |
| **The Sampler Trojan** | Server uses `sampling` to invoke the client's model on its own prompts. | Server steers the model invisibly; potential exfil via model calls. |
| **The Universal URL Fetcher** | A `fetch(url)` tool with no allow-list. | SSRF to cloud metadata, internal services, exfil targets. |
| **The Eternal Token** | Long-lived service tokens never rotated. | Maximum breach blast radius; minimum forensics confidence. |

---

## 12. Appendix C: Related Documents

| Document | Purpose |
|---|---|
| `4-mcp-server-security-review-checklist.md` | Detailed control-by-control MCP review checklist |
| `script/mcp_first_pass_evidence_collector_v1_0_release.py` | First-pass automated evidence collection tool |
| `script/MCP_Security_Smoke_Test_README.md` | Tool documentation and usage guidance |

### Recommended Review Order

```text
1. Architecture Review
2. Threat Modeling
3. First-Pass Evidence Collection
4. Dynamic Testing
5. Checklist Validation
6. Final Security Decision
```
