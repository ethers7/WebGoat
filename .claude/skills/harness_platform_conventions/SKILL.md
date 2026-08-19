---
name: harness-conventions
description: >-
  ALWAYS load this skill when creating, updating, or generating any Harness pipeline, trigger,
  template, or YAML entity. Contains required fields, naming rules, tagging conventions, and
  API body formats that cause failures or rejections if missed.
metadata:
  author: Harness
  version: 1.1.2
  mcp-server: harness-mcp-v2
license: Apache-2.0
compatibility: Requires Harness MCP v2 server (harness-mcp-v2)
---

# Harness Platform Conventions

## Template-First Workflow

When creating **v1 pipelines**, always run semantic template discovery before writing YAML:

1. Load the **harness_create_pipeline_v1** skill.
2. Call `harness_search(query="<capability>", resource_types=["template_search"])` once per capability.
3. Call `harness_get(resource_type='template_v1', ...)` for each selected template and honor `ui.visible` / `layout`.
4. Only then assemble `template: uses: id` steps from successful gets — never invent template names from memory; add `@version` only when pinning.
5. Validate with `mcp__harness_local__validate_pipeline_yaml` (`resource_type='pipeline_v1'`)
   up to twice before `harness_create`.

**CD stage shape (harness-schema):** stage `service` may be a plain id; stage `environment` must be `{ id: … }` (optional `deploy-to`). Plain `environment: prod` on a stage fails validation. Stage/step `id` is schema-optional; if you use a runtime input (`<+input>`), set `id` on that node and its ancestors before create.

Never invent template names — only use names returned by `harness_search` / `harness_list` search results.
If no matching template is found after semantic search, fall back to verified spec `action:` steps, then `run` steps.

When creating **v0 / standard pipelines**, load the **harness_create_pipeline_v0** skill and follow it.
Validate with `mcp__harness_local__validate_pipeline_yaml` (`resource_type='pipeline'`)
up to twice before `harness_create` or `harness_update`.

**v0 CI codebase (semantic):** if any CI stage has `cloneCodebase: true`, the pipeline must
include `properties.ci.codebase` (`connectorRef` + `build`) at the pipeline level — otherwise
semantic validation fails with "CI Codebase Configuration is missing" at runtime.

## AI-Generated Tagging

All pipelines created by AI must include the tag `ai_generated: ""` in their tags map.

v0: `tags: { ai_generated: "" }`
v1: add `tags: { ai_generated: "" }` under `pipeline:`

## Pipeline Creation API

`harness_create` accepts a different `resource_type` and body shape for v0 vs v1 pipelines.
**Pick the resource type that matches the YAML you are generating** — they hit different MCP endpoints.

### v1 pipelines (YAML with `pipeline:` as the root key, `${{ }}` expressions, `run:` steps)

```
resource_type: "pipeline_v1"
body: {
  pipeline_yaml: "<YAML string, including 'pipeline:' root>",
  identifier:    "<unique pipeline identifier>",
  name:          "<pipeline display name>"
}
```

- **Required field name is `pipeline_yaml`** (snake_case). `yamlPipeline` is accepted only as a
  backwards-compat alias and should NOT be used for new v1 pipelines.
- **`identifier` and `name` are required** as top-level body fields in addition to being present
  inside the YAML. The MCP uses them for routing.
- Do NOT use `resource_type: "pipeline"` for v1 YAML — that's the v0 legacy endpoint. It may
  tolerate v1 YAML on some Harness versions but is fragile across MCP/backend versions.

### v0 pipelines (YAML with `type: CI`/`type: Deployment` stages, `<+...>` expressions)

```
resource_type: "pipeline"
body: { yamlPipeline: "<YAML string>" }
```

- For v0, the `yamlPipeline` field name (camelCase) is the correct one.
- Do NOT pass a nested JSON `pipeline` object — it causes serialization errors.

## Required Fields the API Rejects Without

- **`failureStrategies`** on every CI and CD stage (v0). v1 equivalent: `on-failure:` block.
  CI stages: use `MarkAsFailure` (v0) or `fail` (v1). CD stages: use `StageRollback` (v0) or `stage-rollback` (v1).
- **`disallowPipelineExecutor: true`** on `HarnessApproval` steps. API returns
  "disallowPipelineExecutor: is missing but it is required" without it.

## Strategy Placement

`strategy` (matrix/for/while) must be a sibling of `spec` at stage level (v0) or directly
on the stage (v1). Placing it inside `spec` causes the matrix to silently not apply.

## Naming Rules

- **Identifiers:** `^[a-zA-Z_][0-9a-zA-Z_]{0,127}$` — letters, numbers, underscores only.
- **Stage/step names:** `^[a-zA-Z_0-9-.][-0-9a-zA-Z_\s.]{0,127}$` — no commas.
  Use `Build Test and Push` not `Build, Test and Push`.
- **File names (v1):** alphabets and underscores only (e.g. `build_and_deploy.yaml`).

## Scope and Runtime Inputs

- Use `<+input>` for unknown `connectorRef`, `serviceRef`, `environmentRef`, `infrastructureDefinitions`.
- `orgIdentifier` and `projectIdentifier` must use actual values — never `<+input>`.
- Scope resolution: Account > Org > Project. An entity not found usually means wrong scope,
  not that it doesn't exist.

## Secrets

Always reference via expressions — never hardcode secret values.
`<+secrets.getValue("secret_id")>` (works in both v0 and v1).
