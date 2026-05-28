# 🛡️ MCP Server Security Audit

> A practical, vendor-neutral framework for security-reviewing Model Context Protocol (MCP) servers before they touch your data, code, or production systems.

[![License: CC BY 4.0](https://img.shields.io/badge/License-CC%20BY%204.0-blue.svg)](https://creativecommons.org/licenses/by/4.0/)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen.svg)]()
[![Controls](https://img.shields.io/badge/Controls-38-informational.svg)]()
[![Workflow](https://img.shields.io/badge/Workflow-6%20Phases-informational.svg)]()

---

## Who this is for

- **Security engineers** running MCP reviews.
- **Platform / AI teams** preparing servers for review.
- **CISOs and risk managers** defining MCP governance.

---

## Pages

- [MCP Foundations](1-mcp-foundations.md)
- [MCP Architecture](2-mcp-architecture.md)
- [MCP Security Review & Threat Modeling Standard](3-mcp-security-review-and-threat-modeling-standard.md)
- [MCP Server Security Review Checklist](4-mcp-server-security-review-checklist.md)
- [MCP First-Pass Evidence Collector](script/README.md)

---

## Review Workflow

This framework uses a six-phase MCP security review workflow:

```text
1. Architecture Review
2. Threat Modeling
3. Security Control Validation
4. Dynamic Testing
5. Risk Assessment
6. Final Approval Decision
```

Architecture review and threat modeling identify what can go wrong. Security control validation then verifies whether the required mitigations, configurations, permissions, logging, schemas, and deployment controls are actually implemented.

---

## Tooling

This repository includes a first-pass evidence collector in the `script/` folder:

```text
script/mcp_first_pass_evidence_collector_v1_0.py
```

The tool helps collect static and runtime evidence for review, but it does not replace manual threat modeling, authorization review, dynamic testing, or final risk approval.

---

## Purpose & Scope

This document defines the **mandatory security review methodology** for MCP (Model Context Protocol) servers before they are approved for internal use. It applies whenever an MCP server is:

1. Connected to an internal AI assistant, IDE, agent, or workflow.
2. Granted access to corporate data, identities, secrets, code, or infrastructure.
3. Run on company hardware, employee endpoints, or cloud accounts.

MCP servers are treated as **privileged software with agentic reach**: they extend LLM capabilities into real systems, often acting on a user's behalf. A weakly-controlled MCP server is functionally equivalent to giving an external party an authenticated shell on the user's behalf, with the added twist that **the "operator" is an LLM susceptible to prompt injection**.

### Out of scope
- The LLM/foundation model itself (covered by AI Model Risk Standard).
- The MCP *client* (IDE, chat UI) - covered separately.
- General application security review - this document supplements, not replaces, AppSec review.

---


## References

The checklist is based on the following public guidance:

1. OWASP MCP Security Cheat Sheet  
   https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html

2. Official MCP Security Best Practices  
   https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices

3. Official MCP Authorization Specification  
   https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization

4. Microsoft: Protecting Against Indirect Prompt Injection Attacks in MCP  
   https://developer.microsoft.com/blog/protecting-against-indirect-injection-attacks-mcp

5. Model Context Protocol Security Checklist / CSA Community Project  
   https://modelcontextprotocol-security.io/hardening/checklist.html

6. Model Context Protocol Security: OAuth Security Patterns  
   https://modelcontextprotocol-security.io/build/oauth-security/

7. OWASP MCP Tool Poisoning  
   https://owasp.org/www-community/attacks/MCP_Tool_Poisoning
   