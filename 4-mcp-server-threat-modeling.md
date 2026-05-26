# 1. MCP Server Review Workflow

**Reviewer Mindset**

Do not ask:

> Would the model normally call this dangerous tool?

Ask:

> Could an attacker eventually influence the model, tool output, metadata, or user context so that this dangerous tool is called?

The MCP server must remain safe even when the model is confused, manipulated, operating on malicious external content, receiving poisoned tool outputs, and even interacting with untrusted resources.

As general rules, never trust:
- Tool output
- Resource content
- Tool descriptions from untrusted sources
- User-provided URLs or file paths
- The model's intent

Always enforce security in **deterministic** server-side logic.


An MCP server does not create new access — it amplifies existing access by making it callable via an LLM.**

Scope the credentials; everything else follows.


---

## Step 1: Inventory
- Identify all tools, resources, and prompts.
- Identify backend systems and credentials.
- Identify deployment model and transport.

## Step 2: Data Flow

What systems does it connect to? What credentials does it use? What can it read/write?

Draw a simple flow:

```text
User → Host → MCP Client → MCP Server → Backend System
```

Add:
- Trust boundaries
- Credentials
- Sensitive data
- Logs
- Network paths

## Step 3: Threat Model
Ask:
- What can the LLM cause this server to do?
- What happens if prompt injection succeeds?
- What happens if tool output is malicious?
- What happens if credentials leak?

## Step 4: Code Review
Focus on:
- Tool handlers
- Auth checks
- Input validation
- File access
- Network calls
- Command execution
- Secrets
- Logging

## Step 5: Abuse Testing
Test:
- Prompt injection
- Authorization bypass
- SSRF
- Command injection
- Path traversal
- Excessive data export
- Missing confirmations

## Step 6: Risk Decision

| Decision | Meaning |
|---|---|
| Approved | No blocking issues |
| Approved with restrictions | Allowed only with documented constraints |
| Blocked | Critical findings exist |

---

# 2. Reviewer Scoring

| Result | Meaning |
|---|---|
| 0 Critical + 0 High | Usually acceptable for approval |
| Any Critical | Block production use |
| 1-3 High | Restrict deployment until mitigated |
| More than 3 High | Block broad rollout |
| Medium/Low only | Track in remediation backlog |

---