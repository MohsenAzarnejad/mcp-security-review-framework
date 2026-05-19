# MCP Security Smoke Test Tool

A lightweight security smoke-test and review helper for Model Context Protocol (MCP) servers.

This tool helps security reviewers and platform teams perform:
- Static security review of MCP server repositories
- Live MCP metadata enumeration
- Risky tool and schema analysis
- Basic abuse-case testing
- Inspector-style MCP inventory generation

---

# Features

## Static Repository Scanning

The tool scans MCP repositories for:

- Hardcoded secrets
- Command execution patterns
- SSRF indicators
- Dangerous tool capabilities
- Prompt injection indicators
- Missing schema validation
- Dependency and supply-chain indicators
- HTTP/SSE transport indicators
- Audit logging hints
- Error sanitization weaknesses

---

## Live MCP Enumeration

Supports live MCP discovery using:

- stdio transport
- HTTP transport

The tool can:
- Call `initialize`
- Enumerate `tools/list`
- Enumerate `resources/list`
- Enumerate `prompts/list`

---

## Inspector-Style Inventory

The generated HTML report includes:
- Tool inventory
- Resource inventory
- Prompt inventory
- Tool schemas
- Raw MCP metadata
- Security findings
- Checklist coverage summary

---

# Supported Review Controls

The tool currently provides full or partial coverage for controls such as:

| Control | Description |
|---|---|
| CR-02 | Secret exposure detection |
| CR-03 | Dangerous tools |
| CR-04 | Prompt injection indicators |
| CR-05 | Command injection patterns |
| CR-06 | SSRF indicators |
| HI-01 | MCP inventory |
| HI-02 | Schema validation quality |
| HI-03 | Metadata integrity |
| HI-05 | HTTP/SSE review indicators |
| HI-09 | Sensitive data indicators |
| HI-10 | Audit logging review |
| ME-04 | Dependency/supply-chain review |
| LO-01 | Security documentation |
| LO-02 | Safe naming conventions |

---

# Requirements

- Python 3.10+
- Optional: `requests` package for HTTP mode

Install dependency:

```bash
pip install requests
```

---

# Usage

## Static Repository Scan

```bash
python mcp_security_smoke_test_v1_0.py --repo ./my-mcp-server
```

---

## Live stdio MCP Scan

```bash
python mcp_security_smoke_test_v1_0.py \
  --transport stdio \
  --command "node dist/index.js"
```

---

## Live HTTP MCP Scan

```bash
python mcp_security_smoke_test_v1_0.py \
  --transport http \
  --url http://localhost:8080/mcp
```

---

## Run Safe Live Negative Tests

```bash
python mcp_security_smoke_test_v1_0.py \
  --transport stdio \
  --command "python server.py" \
  --safe-live-tests
```

---

# Output Files

The tool generates:

- HTML report
- JSON report
- Optional Markdown report

Example:

```text
mcp_security_smoke_test_report_grafana_20260519_1.html
mcp_security_smoke_test_report_grafana_20260519_1.json
```

---

# Finding Status Meanings

| Status | Meaning |
|---|---|
| REVIEW REQUIRED | Evidence detected that requires manual verification |
| WARN | Potentially risky implementation or missing control |
| FAIL | Stronger evidence of a likely unsafe implementation |

---

# Severity Levels

| Severity | Meaning |
|---|---|
| Critical | Likely exploitable or high-impact issue |
| High | Important security concern |
| Medium | Weakness or missing hardening |
| Low | Governance or hygiene issue |

---

# Example Review Workflow

1. Clone the MCP repository
2. Run static scan
3. Review generated findings
4. Run live MCP enumeration
5. Validate dangerous tools manually
6. Verify authorization and tenant isolation
7. Review confirmation flows
8. Finalize manual security assessment

---

# Limitations

This tool does NOT:
- Prove authorization correctness
- Replace manual security review
- Perform destructive testing
- Exploit systems
- Guarantee absence of vulnerabilities

Manual verification is still required for:
- Authorization
- Tenant isolation
- OAuth implementation
- Credential scoping
- Runtime isolation
- Human confirmation flows

---

# Recommended Repository Structure

```text
mcp-security-smoke-test/
├── mcp_security_smoke_test_v1_0.py
├── README.md
├── examples/
├── reports/
└── docs/
```

---

# Recommended Usage

This tool is intended for:
- Internal platform security teams
- MCP server reviewers
- AI security engineers
- AppSec teams
- Third-party MCP onboarding reviews

---

# License

Internal security review tool.
Adapt and extend based on your organization's requirements.
