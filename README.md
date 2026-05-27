# 🛡️ MCP Server Security Audit

> A practical, vendor-neutral framework for security-reviewing Model Context Protocol (MCP) servers before they touch your data, code, or production systems.

[![License: CC BY 4.0](https://img.shields.io/badge/License-CC%20BY%204.0-blue.svg)](https://creativecommons.org/licenses/by/4.0/)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen.svg)]()
[![Controls](https://img.shields.io/badge/Controls-70%2B-informational.svg)]()
[![Domains](https://img.shields.io/badge/Domains-16-informational.svg)]()

---

## Who this is for

- **Security engineers** running MCP reviews.
- **Platform / AI teams** preparing servers for review.
- **CISOs and risk managers** defining MCP governance.

---

## 🎯 Purpose & Scope

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
   