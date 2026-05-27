# MCP First-Pass Evidence Collector

Version: 1.0

## Purpose

The MCP First-Pass Evidence Collector is a lightweight review-support tool for collecting early security evidence from Model Context Protocol (MCP) server repositories and, optionally, live MCP endpoints.

It is designed to help security reviewers quickly identify areas that need manual review. It does **not** prove that an MCP server is secure, and it does **not** replace threat modeling, code review, authorization testing, or dynamic runtime validation.

Use it as the first step in an MCP security review.

---

## What the Tool Does

The collector can perform:

1. **Static repository review**
   - Searches for risky implementation patterns.
   - Looks for possible hardcoded secrets.
   - Detects unsafe subprocess, shell, URL-fetching, and logging patterns.
   - Reviews Dockerfile, Kubernetes/YAML, `server.json`, and dependency indicators.
   - Attempts to infer MCP tool groups from source layout.
   - Highlights risky tool names, dangerous capability indicators, and schema concerns.

2. **Live MCP metadata review**
   - Connects to an MCP server using `stdio` or HTTP mode.
   - Sends JSON-RPC MCP requests such as:
     - `initialize`
     - `tools/list`
     - `resources/list`
     - `prompts/list`
   - Collects runtime tool, resource, and prompt inventory.
   - Reviews live tool schemas and metadata.

3. **Optional safe negative tests**
   - Runs conservative, non-destructive tests against selected live tools.
   - Avoids obvious destructive/write/export tools.
   - Helps identify weak schema validation or unsafe reflection.

4. **Formal control audit summary**
   - Produces a Claude-style formal control audit section.
   - Marks controls as:
     - `pass`
     - `fail`
     - `needs_human_review`
     - `not_applicable`
   - Includes hard-gate indicators for severe findings.

5. **Reviewer-friendly reports**
   - HTML report
   - JSON report
   - Optional Markdown report

---

## What the Tool Does Not Do

The collector does **not**:

- prove authorization is correct;
- prove tenant isolation is correct;
- prove OAuth flows are secure;
- exploit systems;
- run destructive tests;
- fully validate business logic;
- replace manual code review;
- replace MCP threat modeling;
- replace live security testing.

Any result labeled `No issue detected by automated checks` only means the tool did not detect evidence of a problem. It does **not** mean the control is fully secure.

---

## Recommended Review Workflow

Use the tool as part of this workflow:

```text
1. Run static scan against the repository.
2. Review the generated HTML report.
3. Run live MCP metadata collection, if possible.
4. Compare runtime tools/list with documented inventory.
5. Perform manual review for authorization, tenant isolation, credentials, and confirmation flows.
6. Perform dynamic abuse testing for high-risk tools.
7. Record final review decision and accepted risks.
```

---

## Basic Usage

### Static Repository Scan

Run this from a folder outside the MCP repository:

```bash
python mcp_first_pass_evidence_collector.py --repo ./path/to/mcp-server
```

Example:

```bash
python mcp_first_pass_evidence_collector.py --repo ./dovetail-mcp
```

The tool will ask for review metadata such as:

- MCP Server Name
- Owner Team
- Source
- Version / Tag
- Internal / Third-Party / Forked
- Reviewer

Reports are written to the current working directory.

---

## Non-Interactive Static Scan

Use this mode for CI or scripted execution:

```bash
python mcp_first_pass_evidence_collector.py --repo ./path/to/mcp-server --no-interactive
```

---

## Live stdio MCP Scan

Use this when the MCP server runs as a local command:

```bash
python mcp_first_pass_evidence_collector.py \
  --repo ./path/to/mcp-server \
  --transport stdio \
  --command "node ./dist/index.js"
```

Python example:

```bash
python mcp_first_pass_evidence_collector.py \
  --repo ./path/to/mcp-server \
  --transport stdio \
  --command "python server.py"
```

---

## Live HTTP MCP Scan

Use this when the MCP server exposes an HTTP endpoint:

```bash
python mcp_first_pass_evidence_collector.py \
  --transport http \
  --url https://example.com/mcp \
  --token "$MCP_TOKEN"
```

For authenticated HTTP endpoints, provide a bearer token with `--token`.

---

## Optional Safe Live Tests

By default, live mode only collects metadata.

To run conservative negative tests:

```bash
python mcp_first_pass_evidence_collector.py \
  --repo ./path/to/mcp-server \
  --transport stdio \
  --command "python server.py" \
  --safe-live-tests
```

The safe tests may send malformed or boundary-style inputs such as:

- localhost URL probes
- cloud metadata URL probes
- path traversal strings
- oversized strings
- prompt-injection strings

The tool skips obvious destructive/write/export tools.

Run safe live tests only in a non-production or approved test environment.

---

## Output Files

The tool generates files like:

```text
mcp_first_pass_evidence_report_<server>_<date>_<number>.html
mcp_first_pass_evidence_report_<server>_<date>_<number>.json
```

If Markdown output is requested:

```bash
python mcp_first_pass_evidence_collector.py \
  --repo ./path/to/mcp-server \
  --out-md report.md
```

The tool will also create a Markdown report.

---

## Report Sections

The HTML report includes:

- Metadata
- Scan statistics
- Suppressed noisy signals
- Inspector-style tool inventory
- Resource inventory
- Prompt inventory
- Raw MCP metadata, when live metadata exists
- Legend
- Control review summary
- Findings
- Formal control audit
- Notes

---

## Understanding Status Values

| Status | Meaning |
|---|---|
| `FAIL` | Strong evidence of a likely security issue or unsafe implementation. Requires immediate manual verification. |
| `NEEDS REVIEW` | Evidence detected that requires human verification. Does not automatically mean the server is vulnerable. |
| `Manual` | The tool cannot honestly verify the control without human review. |
| `No issue detected by automated checks` | The tool did not detect evidence of a problem for that control. This is not proof of security. |

---

## Understanding Confidence Values

| Confidence | Meaning |
|---|---|
| High | Strong static evidence or specific policy violation was detected. |
| Medium | Specific pattern detected, but exploitability depends on context. |
| Low | Weak heuristic signal. Useful for review, but likely to need triage. |

---

## Important Limitations

Static mode can infer possible tool groups, but inferred groups are **not confirmed exposed MCP tools**.

For accurate runtime inventory, run live mode and collect:

- `initialize`
- `tools/list`
- `resources/list`
- `prompts/list`

The following areas usually require manual or dynamic testing:

- authorization;
- tenant isolation;
- OAuth and session handling;
- credential scope;
- human-in-the-loop confirmation;
- cross-server behavior;
- prompt-injection behavior;
- output trust boundaries;
- business logic.

---

## Recommended Commands

### First-Pass Static Review

```bash
python mcp_first_pass_evidence_collector.py --repo ./mcp-server
```

### Static Review in CI

```bash
python mcp_first_pass_evidence_collector.py \
  --repo ./mcp-server \
  --no-interactive \
  --ci-exit-code
```

### Static + Live stdio Inventory

```bash
python mcp_first_pass_evidence_collector.py \
  --repo ./mcp-server \
  --transport stdio \
  --command "python server.py"
```

### Static + Live stdio + Safe Negative Tests

```bash
python mcp_first_pass_evidence_collector.py \
  --repo ./mcp-server \
  --transport stdio \
  --command "python server.py" \
  --safe-live-tests
```

---

## CI/CD Usage

For CI/CD, use:

```bash
python mcp_first_pass_evidence_collector.py \
  --repo . \
  --no-interactive \
  --ci-exit-code
```

`--ci-exit-code` returns exit code `1` when the formal audit contains Critical or High failed controls.

This is useful for blocking obvious unsafe changes, but it should not be treated as complete approval.

---

## Optional External Tools

If installed locally or in CI, the collector can detect or use:

- `gitleaks`
- `syft`
- `grype`
- `trivy`

Recommended CI additions:

```bash
gitleaks detect --source .
syft . -o cyclonedx-json
grype .
trivy fs .
```

These tools improve secret scanning, SBOM generation, and dependency/container vulnerability visibility.

---

## How to Interpret Results

A good review result is not necessarily a report with zero findings.

A useful report should help the reviewer answer:

- What tools may be exposed?
- Which capabilities are dangerous?
- Are credentials likely over-scoped?
- Is HTTP/SSE exposed safely?
- Are Docker/Kubernetes settings hardened?
- Are secrets or sensitive logging patterns present?
- Which controls require manual review?
- What should be tested dynamically?

Treat the report as evidence for a security review, not as an automatic approval decision.

---

## Suggested Manual Follow-Up

After running the collector, reviewers should manually verify:

1. Runtime `tools/list` matches approved inventory.
2. Dangerous tools require explicit user confirmation.
3. Authorization is enforced per tool.
4. Cross-tenant access is blocked.
5. Credentials are least-privileged.
6. Tool outputs are treated as untrusted.
7. Logs do not contain secrets or sensitive tool arguments.
8. HTTP/SSE endpoints require authentication and safe origin/host handling.
9. Dynamic/proxied tools are disabled or reviewed.
10. Third-party or forked repositories are pinned and maintained.

---

## Versioning

This document describes **MCP First-Pass Evidence Collector v1.0**.

Use version `1.0` when publishing the tool internally unless the script has breaking changes or major new behavior.

---

## Safety Note

Do not run dynamic tests against production MCP servers unless you have explicit approval.

Prefer non-production environments with test credentials and synthetic data.
