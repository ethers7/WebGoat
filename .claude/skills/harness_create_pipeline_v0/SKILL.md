---
name: harness_create_pipeline_v0
description: >-
  Use when asked to create or update a Harness pipeline using v0/standard syntax (default when
  the user does not explicitly request v1/simplified). Focuses on CI pipelines (`type: CI`):
  nested spec/execution steps, `<+...>` expressions, failureStrategies, templateRef composition,
  and `properties.ci.codebase` when `cloneCodebase: true`. ALWAYS validate with
  mcp__harness_local__validate_pipeline_yaml (resource_type='pipeline') — schema + semantic
  (+ OPA when enabled) — before harness_create or harness_update. Do NOT use for v1/simplified
  pipelines (use harness_create_pipeline_v1). Trigger phrases: "create pipeline", "CI pipeline",
  "standard pipeline", "v0 pipeline", "classic pipeline". For CD-only requests without v1, still
  use v0 syntax but gather service/environment/infrastructure refs via harness_list — this skill
  does not ship a CD example yet.
metadata:
  author: Harness
  version: 1.2.0
  mcp-server: harness-mcp-v2
license: Apache-2.0
compatibility: Requires Harness MCP v2 server (harness-mcp-v2) with the `pipeline` resource type
---

# Create Pipeline v0 (Standard)

Generate Harness **v0 / standard** Pipeline YAML and optionally push to Harness via MCP.

Use this skill when the user asks to create or update a pipeline and does **not** explicitly
request v1 / simplified / modern syntax. If they ask for v1, load **harness_create_pipeline_v1**
instead.

**Scope:** Examples and shape guidance here focus on **CI** (`type: CI`). CD (`type: Deployment`)
uses the same v0 nesting and validation flow, but this skill does not ship a CD example — list
`service`, `environment`, and `infrastructure` via MCP before drafting CD YAML; do not invent refs.

## Non-Negotiable: Template Discovery Before YAML

**Every v0 pipeline request starts with template discovery — no exceptions.**

You **must not** draft step YAML, invent `templateRef` / step identifiers, or call create/update
MCP tools until template discovery is complete.

1. `harness_list(resource_type='template', params={"global": "true"})` and/or
   `harness_list(resource_type='template', org_id='<org>')`
2. Use `search_term` when helpful (`"docker"`, `"kubernetes"`, `"Run"`, etc.)
3. For each chosen template: `harness_get(resource_type='template', ...)` (v0 template type)
4. Prefer `templateRef` / `template:` references over inventing identifiers from memory

If no matching template exists after listing, use verified native step types (`Run`, `RunTests`, …)
only after search confirms none exists.

## Instructions

1. **Confirm v0 format** — Default to v0 unless the user clearly wants v1/simplified.
2. **Clarify requirements** — CI vs CD vs both, language/framework, deployment target, approvals.
3. **Discover reusable templates (REQUIRED)** — See **Non-Negotiable** above. Never invent
   template or step identifiers from memory.
4. **Generate v0 YAML** — Nested `pipeline → stages → stage → spec → execution → steps` shape,
   stage `type:` fields (`CI`, `Deployment`, …), `<+...>` expressions, `command:` on Run steps.
   When any CI stage has `cloneCodebase: true`, add `properties.ci.codebase` at the pipeline level.
5. **Validate before create/update (REQUIRED)** — Call
   `mcp__harness_local__validate_pipeline_yaml` with:
   - `yaml`: the full generated YAML (including `pipeline:` root)
   - `resource_type`: `"pipeline"`
   - If `valid=false`, fix from the returned errors and call validation **once more**
     (at most **two** validation calls total).
   - Only proceed when `valid=true`. If the second validation still fails,
     stop and report the remaining schema, semantic, or policy errors — do **not** call
     `harness_create` or `harness_update`.
6. **Create or update via MCP** — See **Creating via MCP** / **Updating via MCP** below
   (`resource_type: "pipeline"`).

## v0 Shape Reminders

| Area | v0 expectation |
|------|----------------|
| Expressions | `<+pipeline.variables.x>`, `<+input>`, `<+secrets.getValue("id")>` |
| Stages | Each stage has `type:` (`CI`, `Deployment`, `Custom`, …) |
| Nesting | Deep `spec:` / `execution:` / `steps:` structure |
| Run steps | `type: Run` with `command:` (not v1 `run:` / `script:`) |
| CI codebase | If any CI stage has `cloneCodebase: true`, pipeline **must** include `properties.ci.codebase` with `connectorRef` and `build` — semantic validation fails without it |
| Deploy steps | Native types (`K8sRollingDeploy`, `HelmDeploy`, …) or template refs |
| Failure handling | `failureStrategies` on CI/CD stages |
| Tags | Include `ai_generated: ""` |

Do **not** mix v1 syntax into v0 YAML (`${{ }}`, flat `run:` steps, no stage `type`, etc.).

## Minimal CI Example

Shape-only — replace every `<PLACEHOLDER>` with values from the user request
and discovered connectors/templates. Do **not** copy placeholder literals into
create/update payloads.

```yaml
pipeline:
  name: <PIPELINE_NAME>
  identifier: <PIPELINE_IDENTIFIER>
  projectIdentifier: <PROJECT>
  orgIdentifier: <ORG>
  tags:
    ai_generated: ""
  properties:
    ci:
      codebase:
        connectorRef: <+input>
        build:
          type: branch
          spec:
            branch: <BRANCH>
  stages:
    - stage:
        name: <STAGE_NAME>
        identifier: <STAGE_IDENTIFIER>
        type: CI
        failureStrategies:
          - onFailure:
              errors:
                - AllErrors
              action:
                type: <FAILURE_ACTION>   # e.g. MarkAsFailure, Ignore, Retry
        spec:
          cloneCodebase: true
          infrastructure:
            type: KubernetesDirect
            spec:
              connectorRef: <+input>
              namespace: <+input>
          execution:
            steps:
              - step:
                  type: Run
                  name: <STEP_NAME>
                  identifier: <STEP_IDENTIFIER>
                  spec:
                    connectorRef: <+input>
                    image: <IMAGE>
                    shell: Sh
                    command: <SCRIPT>
```

## Creating via MCP

**CRITICAL: Use `resource_type: "pipeline"` — NOT `"pipeline_v1"`.**

### Step 0 — Validate the draft YAML

```
mcp__harness_local__validate_pipeline_yaml
  yaml: "<full v0 pipeline YAML>"
  resource_type: "pipeline"
```

- On `valid=false`: fix using `errors` / `feedback`, then validate again (max two calls).
- On second failure: do not call `harness_create` or `harness_update`; report remaining errors.

### Step 1 — Verify the project exists

List projects with `harness_list` (`resource_type: "project"`, `org_id`). Create or ask if missing.

### Step 2 — Create the pipeline

```
resource_type: "pipeline"
org_id:        "<organization>"
project_id:    "<project>"
body: { yamlPipeline: "<full v0 pipeline YAML string>" }
```

Notes:

- For v0, **`yamlPipeline`** (camelCase) is the correct body field.
- Do **not** pass a nested JSON `pipeline` object for v0 create — it causes serialization errors.
- Ensure `identifier` / `name` / org / project inside the YAML match the target scope.

### Step 3 — Report the result

Confirm create success (or surface API errors). The chat review card may still run
additional create-time checks after your local validation
(schema + semantic + OPA when enabled).

## Updating via MCP

Use the same validation flow and `resource_type: "pipeline"`.

1. `harness_get(resource_type='pipeline', resource_id='...', org_id='...', project_id='...')`
   to load the current YAML and note `gitDetails` when the pipeline is stored in remote Git.
2. Apply edits; run `mcp__harness_local__validate_pipeline_yaml` (max two calls).
3. `harness_update` with a **full** `yamlPipeline` replacement (not a partial patch):

```
resource_type: "pipeline"
resource_id:   "<pipeline_identifier>"
org_id:        "<organization>"
project_id:    "<project>"
body: { yamlPipeline: "<full updated v0 pipeline YAML string>" }
```

For remote Git pipelines, include conflict-detection fields from the get response when the API
requires them (`lastObjectId` / `lastCommitId` or equivalent in the update body).

- **`DUPLICATE_IDENTIFIER` on create** — Pipeline exists; switch to `harness_update` with the same body shape.

## Common Rationalizations

| Excuse | Reality |
|--------|---------|
| "I'll invent a Run step — faster than listing templates" | Template discovery is required. Invented refs fail at create or runtime. |
| "cloneCodebase alone is enough" | Semantic validation requires `properties.ci.codebase` when `cloneCodebase: true`. |
| "Schema passed, so create is safe" | Run validation once more if semantic/OPA failed; do not create on `valid=false`. |
| "This skill covers CD fully" | CI is fully exemplified here; for CD, list refs via MCP — do not hallucinate service/env IDs. |

## Troubleshooting

- **Schema errors from `validate_pipeline_yaml`** — Fix YAML before create/update; do not retry hoping the API will accept it.
- **Semantic: missing `properties.ci.codebase`** — Add pipeline-level `properties.ci.codebase` when any CI stage has `cloneCodebase: true` (see Minimal CI Example).
- **Using `resource_type: "pipeline_v1"` for v0 YAML** — Wrong endpoint; use `"pipeline"`.
- **Using `pipeline_yaml` body field for v0** — Prefer `yamlPipeline` for v0.
- **Missing `failureStrategies`** — Add on CI/CD stages; API/schema may reject without them.
- **Mixing v1 syntax** — No `${{ }}`, no flat `run:` / `action:` / `template: uses:` v1 forms in a v0 pipeline.
