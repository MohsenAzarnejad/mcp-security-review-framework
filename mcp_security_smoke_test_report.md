# MCP Security Smoke Test Report

Generated: `2026-05-19T21:39:49Z`  
Tool version: `1.1.0`

## Summary

| Severity | Count |
|---|---:|
| Critical | 1 |
| High | 10 |
| Medium | 0 |
| Low | 0 |

## Metadata

```json
{
  "started_at": "2026-05-19T21:39:49Z",
  "static_scan": {
    "dependency_files": [
      "package.json",
      "yarn.lock"
    ],
    "files_scanned": 13,
    "repo": "C:\\Users\\MohsenAzarnejad\\Desktop\\script test\\dovetail-mcp-main"
  },
  "version": "1.1.0"
}
```

## Tool Inventory

| Tool | Risk Words | Description |
|---|---|---|
| `get_project_insight` | - | Get a specific insight by ID |
| `get_insight_content` | - | Get insight content in markdown format |
| `list_project_insights` | - | List insights for a specific project |
| `get_data_content` | - | Get data content in markdown format |
| `get_project_data` | - | Get specific project data by ID |
| `list_project_data` | - | List data for a specific project |
| `get_dovetail_projects` | all | Get all Dovetail projects |
| `list_personal_project_insights` | - | List insights for a specific user |

## Control Summary Table

| Control | Status | Highest Severity | Findings |
|---|---|---|---:|
| `CR-03` | WARN | High | 1 |
| `CR-06` | WARN | Critical | 1 |
| `HI-02` | WARN | High | 8 |
| `HI-09` | WARN | High | 1 |

## Findings

### Critical: CR-06 - Potential risky implementation: JavaScript fetch usage

**Status:** WARN  
**Location:** `src\index.ts`  
**Evidence:** Pattern found in src\index.ts

**Recommendation:** Review whether untrusted model/user input can reach this code path. Add allowlists, validation, sandboxing, and tests.

### High: CR-03 - Risky tool capability: get_dovetail_projects

**Status:** WARN  
**Location:** `src\index.ts`  
**Evidence:** Risk words in tool name/description: all

**Recommendation:** Confirm this tool has authorization checks, confirmation controls, strict input validation, and audit logging.

### High: HI-02 - Tool schema not found or empty: get_data_content

**Status:** WARN  
**Location:** `src\index.ts`  
**Evidence:** No input schema detected.

**Recommendation:** Ensure the tool has a strict JSON schema with required fields, type constraints, enums, length/range limits, and additionalProperties=false where possible.

### High: HI-02 - Tool schema not found or empty: get_dovetail_projects

**Status:** WARN  
**Location:** `src\index.ts`  
**Evidence:** No input schema detected.

**Recommendation:** Ensure the tool has a strict JSON schema with required fields, type constraints, enums, length/range limits, and additionalProperties=false where possible.

### High: HI-02 - Tool schema not found or empty: get_insight_content

**Status:** WARN  
**Location:** `src\index.ts`  
**Evidence:** No input schema detected.

**Recommendation:** Ensure the tool has a strict JSON schema with required fields, type constraints, enums, length/range limits, and additionalProperties=false where possible.

### High: HI-02 - Tool schema not found or empty: get_project_data

**Status:** WARN  
**Location:** `src\index.ts`  
**Evidence:** No input schema detected.

**Recommendation:** Ensure the tool has a strict JSON schema with required fields, type constraints, enums, length/range limits, and additionalProperties=false where possible.

### High: HI-02 - Tool schema not found or empty: get_project_insight

**Status:** WARN  
**Location:** `src\index.ts`  
**Evidence:** No input schema detected.

**Recommendation:** Ensure the tool has a strict JSON schema with required fields, type constraints, enums, length/range limits, and additionalProperties=false where possible.

### High: HI-02 - Tool schema not found or empty: list_personal_project_insights

**Status:** WARN  
**Location:** `src\index.ts`  
**Evidence:** No input schema detected.

**Recommendation:** Ensure the tool has a strict JSON schema with required fields, type constraints, enums, length/range limits, and additionalProperties=false where possible.

### High: HI-02 - Tool schema not found or empty: list_project_data

**Status:** WARN  
**Location:** `src\index.ts`  
**Evidence:** No input schema detected.

**Recommendation:** Ensure the tool has a strict JSON schema with required fields, type constraints, enums, length/range limits, and additionalProperties=false where possible.

### High: HI-02 - Tool schema not found or empty: list_project_insights

**Status:** WARN  
**Location:** `src\index.ts`  
**Evidence:** No input schema detected.

**Recommendation:** Ensure the tool has a strict JSON schema with required fields, type constraints, enums, length/range limits, and additionalProperties=false where possible.

### High: HI-09 - Potential risky implementation: Sensitive keyword in code

**Status:** WARN  
**Location:** `README.md`  
**Evidence:** Pattern found in README.md

**Recommendation:** Review whether untrusted model/user input can reach this code path. Add allowlists, validation, sandboxing, and tests.

## Notes

This is a smoke-test report. It is intended to support, not replace, manual MCP security review.
Pay special attention to authorization, tenant isolation, credential scope, and dangerous tool confirmation,
because these controls usually require manual verification.
