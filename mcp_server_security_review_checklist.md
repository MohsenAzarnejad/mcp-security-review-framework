# MCP Server Security Review Checklist

**Version:** 1.0  
**Purpose:** Security review checklist for internal, third-party, and forked MCP servers  
**Audience:** Security reviewers, AppSec engineers, platform engineers, AI/LLM engineers  
**Review style:** Severity-ranked controls, evidence collection, and practical abuse tests  

---

# Table of Contents

1. [How to Use This Checklist](#0-how-to-use-this-checklist)
2. [Severity Definitions](#1-severity-definitions)
3. [Reviewer Mindset](#3-reviewer-mindset)
4. [Review Summary Template](#2-review-summary-template)
5. [MCP Server Review Workflow](#4-mcp-server-review-workflow)
6. [Severity-Sorted Control Index](#5-severity-sorted-control-index)
7. [Reviewer Scoring](#6-reviewer-scoring)
8. [Critical Controls](#7-critical-controls)
9. [High-Severity Controls](#8-high-severity-controls)
10. [Medium-Severity Controls](#9-medium-severity-controls)
11. [Low-Severity Controls](#10-low-severity-controls)
12. [References](#11-references)

---

# 0. How to Use This Checklist

Use this document when reviewing any MCP server, including:

- Internal MCP servers
- Forked third-party MCP servers
- Locally executed MCP servers using `stdio`
- Remote MCP servers using HTTP/SSE or Streamable HTTP

For each control, record:

| Field | Meaning |
|---|---|
| Status | Pass / Fail / Partial / Not Applicable |
| Evidence | Code links, screenshots, logs, tests |
| Risk | Critical / High / Medium / Low |
| Owner | Responsible team or engineer |

---

# 1. Severity Definitions

| Severity | Meaning |
|---|---|
| Critical | Could allow credential theft, destructive actions, RCE, broad data exposure, or cross-user compromise. Must be fixed before production use. |
| High | Could allow unauthorized access, privilege escalation, sensitive data leakage, or major audit gaps. |
| Medium | Security weakness that increases attack surface or reduces defense-in-depth. |
| Low | Hygiene, documentation, maintainability, or minor hardening improvement. |

---

# 2. Review Summary Template

| Item | Answer |
|---|---|
| MCP Server Name |  |
| Owner Team |  |
| Repository / Source |  |
| Internal / Third-Party / Forked |  |
| Deployment Model | Local stdio / Remote HTTP / SSE / Streamable HTTP |
| Backend Systems Accessed |  |
| Authentication Method |  |
| Credential Type | OAuth / Service token / API key / Environment variable |
| Tool Count |  |
| Read-only Tools |  |
| Write Tools |  |
| Destructive Tools |  |
| Sensitive Data Types | Logs / PII / Secrets / Metrics / Source Code / Other |
| Final Decision | Approved / Restricted / Blocked |
| Reviewer |  |
| Review Date |  |

---

# 3. Reviewer Mindset

Do not ask:

> Would the model normally call this dangerous tool?

Ask:

> Could an attacker eventually influence the model, tool output, metadata, or user context so that this dangerous tool is called?

The MCP server must remain safe even when the model is:
- Confused
- Manipulated
- Operating on malicious external content
- Receiving poisoned tool outputs
- Interacting with untrusted resources

Never trust:
- Tool output
- Resource content
- Tool descriptions from untrusted sources
- User-provided URLs or file paths
- The model's intent

Always enforce security in deterministic server-side logic.

---

# 4. MCP Server Review Workflow

## Step 1: Inventory
- Identify all tools, resources, and prompts.
- Identify backend systems and credentials.
- Identify deployment model and transport.

## Step 2: Data Flow
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

# 5. Severity-Sorted Control Index

## Critical
| ID | Control |
|---|---|
| CR-01 | Enforce server-side authorization |
| CR-02 | Use least-privilege credentials |
| CR-03 | Require confirmation for dangerous actions |
| CR-04 | Treat tool/resource output as untrusted |
| CR-05 | Prevent command injection |
| CR-06 | Prevent SSRF and unsafe URL fetching |

## High
| ID | Control |
|---|---|
| HI-01 | Inventory all tools/resources/prompts |
| HI-02 | Validate tool arguments strictly |
| HI-03 | Protect tool metadata integrity |
| HI-04 | Isolate MCP servers at runtime |
| HI-05 | Secure HTTP/SSE transport |
| HI-06 | Avoid unsafe token passthrough |
| HI-07 | Use OAuth 2.1 with PKCE |
| HI-08 | Prevent cross-server confusion |
| HI-09 | Protect sensitive data in tool results |
| HI-10 | Implement audit logging |

## Medium
| ID | Control |
|---|---|
| ME-01 | Disable unused tools |
| ME-02 | Rate limit expensive operations |
| ME-03 | Sanitize errors/debug output |
| ME-04 | Pin and scan dependencies |
| ME-05 | Verify installation/consent security |
| ME-06 | Enforce tenant boundaries |
| ME-07 | Secure local stdio deployment |
| ME-08 | Add MCP abuse-case security tests |

## Low
| ID | Control |
|---|---|
| LO-01 | Document threat model |
| LO-02 | Use safe tool naming |
| LO-03 | Maintain review decision record |

---

# 6. Reviewer Scoring

| Result | Meaning |
|---|---|
| 0 Critical + 0 High | Usually acceptable for approval |
| Any Critical | Block production use |
| 1-3 High | Restrict deployment until mitigated |
| More than 3 High | Block broad rollout |
| Medium/Low only | Track in remediation backlog |

---

# 7. Critical Controls

## CR-01: Enforce Server-Side Authorization

**Severity:** Critical

### Control
Every tool must enforce authorization independently of the LLM and host.

### Review Questions
- Does every tool verify user permissions?
- Can users access other users' resources?
- Is auth enforced server-side?

### Evidence
- Auth middleware
- IAM policies
- Authorization tests

### Pass Criteria
- All sensitive actions enforce deterministic authorization checks.

---

## CR-02: Use Least-Privilege Credentials

**Severity:** Critical

### Control
Use minimal scopes and avoid broad shared admin tokens.

### Preferred Order
1. Per-user OAuth
2. Short-lived scoped service tokens
3. Read-only service credentials
4. Shared admin credentials (avoid)

### Review Questions
- Are credentials scoped minimally?
- Are tokens rotated?
- Are tokens logged?

### Pass Criteria
- Credentials are minimal, rotated, and attributable.

---

## CR-03: Require Confirmation for Dangerous Actions

**Severity:** Critical

### Control
Destructive or externally visible actions must require explicit user confirmation.

### Examples
- Delete dashboard
- Send email
- Trigger deployment
- Export data

### Pass Criteria
- Dangerous actions cannot execute silently.

---

## CR-04: Treat Tool and Resource Output as Untrusted

**Severity:** Critical

### Control
All external content must be treated as untrusted input.

### Risks
- Prompt injection
- Tool poisoning
- Instruction hijacking

### Pass Criteria
- Returned content cannot silently trigger privileged actions.

---

## CR-05: Prevent Command Injection

**Severity:** Critical

### Control
Never pass model-controlled input directly to shell commands or interpreters.

### Review Questions
- Are subprocesses used?
- Is input parameterized?
- Is string concatenation used for commands?

### Pass Criteria
- Commands are allowlisted and safely parameterized.

---

## CR-06: Prevent SSRF and Unsafe URL Fetching

**Severity:** Critical

### Control
Block localhost, internal IP ranges, metadata services, and unsafe redirects.

### Pass Criteria
- URL fetching is allowlisted and restricted.

---

# 8. High-Severity Controls

## HI-01: Inventory All Tools, Resources, and Prompts

**Severity:** High

### Pass Criteria
- Full inventory exists and is reviewed.

---

## HI-02: Validate Tool Arguments Strictly

**Severity:** High

### Pass Criteria
- All tool inputs use strict validation schemas.

---

## HI-03: Protect Tool Metadata Integrity

**Severity:** High

### Pass Criteria
- Tool descriptions are version-controlled and reviewed.

---

## HI-04: Isolate MCP Servers at Runtime

**Severity:** High

### Pass Criteria
- Runtime is sandboxed with least privilege.

---

## HI-05: Secure HTTP/SSE and Streamable HTTP Transport

**Severity:** High

### Pass Criteria
- TLS, authentication, and session controls are enforced.

---

## HI-06: Avoid Unsafe Token Passthrough

**Severity:** High

### Pass Criteria
- Tokens are audience-bound and minimally scoped.

---

## HI-07: Use OAuth 2.1 with PKCE

**Severity:** High

### Pass Criteria
- OAuth follows modern security guidance.

---

## HI-08: Prevent Cross-Server and Cross-Tool Confusion

**Severity:** High

### Pass Criteria
- Untrusted MCP servers cannot silently influence trusted tools.

---

## HI-09: Protect Sensitive Data in Tool Results

**Severity:** High

### Pass Criteria
- Secrets and unnecessary PII are redacted.

---

## HI-10: Implement Audit Logging

**Severity:** High

### Pass Criteria
- Tool usage is fully auditable.

---

# 9. Medium-Severity Controls

## ME-01: Disable Unused Tools

**Severity:** Medium

### Pass Criteria
- Debug and unused tools are disabled.

---

## ME-02: Rate Limit Expensive Operations

**Severity:** Medium

### Pass Criteria
- Expensive queries and exports are bounded.

---

## ME-03: Sanitize Errors and Debug Output

**Severity:** Medium

### Pass Criteria
- Errors do not expose secrets or internals.

---

## ME-04: Pin and Scan Dependencies

**Severity:** Medium

### Pass Criteria
- Dependencies are pinned and scanned regularly.

---

## ME-05: Verify Installation and Consent Security

**Severity:** Medium

### Pass Criteria
- Users understand permissions before installation.

---

## ME-06: Enforce Tenant Boundaries

**Severity:** Medium

### Pass Criteria
- Cross-tenant access is impossible.

---

## ME-07: Secure Local stdio Deployment

**Severity:** Medium

### Pass Criteria
- Local execution is least-privileged.

---

## ME-08: Add MCP Abuse-Case Security Tests

**Severity:** Medium

### Pass Criteria
- Prompt injection and abuse-case tests exist.

---

# 10. Low-Severity Controls

## LO-01: Document Threat Model

**Severity:** Low

### Pass Criteria
- Threat model exists and is maintained.

---

## LO-02: Use Safe Tool Naming

**Severity:** Low

### Pass Criteria
- Tool names clearly describe behavior.

---

## LO-03: Maintain Review Decision Record

**Severity:** Low

### Pass Criteria
- Risk decisions and exceptions are documented.

---

# 11. References

1. OWASP MCP Security Cheat Sheet  
https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html

2. Official MCP Security Best Practices  
https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices

3. Official MCP Authorization Specification  
https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization

4. Microsoft: Protecting Against Indirect Prompt Injection Attacks in MCP  
https://developer.microsoft.com/blog/protecting-against-indirect-injection-attacks-mcp

5. Model Context Protocol Security Checklist  
https://modelcontextprotocol-security.io/hardening/checklist.html
