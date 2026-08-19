---
name: harness_create_pipeline_v1
description: >-
  Use when asked to create a Harness pipeline using v1/simplified syntax, when user mentions
  v1 pipeline format, new pipeline syntax, simplified pipelines, or explicitly requests v1
  over v0/standard format — even when they do NOT mention templates. ALWAYS run
  harness_search with resource_types=['template_search'] before writing any v1 YAML.
  Supports CI stages (run, run-test, background), CD stages (service/environment with action
  steps for K8s, Helm, ECS), approval steps (dedicated stage or inline), parallel execution,
  matrix/for/while strategies, caching, volumes, and template composition. Uses flat structure,
  ${{ }} expressions, and script field. Do NOT use for v0/standard pipelines (use harness_create_pipeline_v0).
  Trigger phrases: "v1 pipeline", "simplified pipeline", "new pipeline format", "create v1",
  "modern pipeline syntax", "global template pipeline", "build and push docker".
metadata:
  author: Harness
  version: 4.4.6
  mcp-server: harness-mcp-v2
license: Apache-2.0
compatibility: Requires Harness MCP v2 server (harness-mcp-v2) with the `pipeline_v1` resource type
---

# Create Pipeline v1

Generate Harness v1 simplified Pipeline YAML and optionally push to Harness via MCP.

## Non-Negotiable: Template Search Before YAML

**Every v1 pipeline request starts with template discovery — no exceptions.**

This applies when the user:
- Explicitly asks for a **v1** / simplified / modern pipeline
- Names a task ("build and push Docker", "deploy to K8s") but **does not** mention templates
- Asks you to move fast or "just write the YAML"

You **must not** draft pipeline YAML, invent `template: uses:` identifiers, or call create/update MCP tools until Step 3 is complete.

### Mandatory first tool calls (one per capability)

For each distinct capability the pipeline needs (build, test, deploy, scan, upload, approve, etc.), call:

```
harness_search(
  query="<natural-language description of the capability>",
  resource_types=["template_search"]
)
```

Examples:
- Docker build/push → `harness_search(query="build and push a docker image", resource_types=["template_search"])`
- K8s deploy → `harness_search(query="deploy to kubernetes", resource_types=["template_search"])`
- Security scan → `harness_search(query="run a security scan", resource_types=["template_search"])`

Review ranked results (`template_identifier`, `similarity_score`, `template_type`) before choosing a template. Only use identifiers returned by discovery — never guess names like `buildAndPushToDocker` from memory.

If `harness_search` with `template_search` is unavailable (tool missing or hard error), **stop**, tell the user, then fall back to `harness_list` as documented in **Template Discovery & Usage**. Do not skip discovery.

## Instructions (Template-First Workflow)

The primary workflow is: **template_search → harness_get → assemble pipeline**. Only fall back to `run:` steps for custom build/test/lint commands that have no template or action equivalent **after** search confirms none exists.

1. **Confirm v1 format** — User must specifically want v1 syntax. Default to v0 (**harness_create_pipeline_v0**) if unclear. **Choosing v1 does not skip template search.**
2. **Clarify requirements** — Pipeline type (CI, CD, or both), language/framework, deployment target, approval needs.
3. **Discover available templates (REQUIRED)** — Before writing ANY step YAML:
   - **MUST call `harness_search` with `resource_types=['template_search']`** once per capability (see **Non-Negotiable** above). Semantic search matches *intent*, not keywords — e.g. `"build and push a docker image"` finds `buildAndPushToDocker` even when the name differs.
   - **Then complement with `harness_list`** for account/org templates or browsing a scope: `harness_list(resource_type='template', params={"global": "true"})`, `harness_list(resource_type='template', org_id='<org>')`, etc. Keyword `search_term` filters (e.g. `"docker"`, `"kubernetes"`) are a supplement, not a substitute for `template_search`.
   - Build a candidate list of templates that match the user's requirements from **search results only**.
4. **Fetch template inputs** — For each template you plan to use, call `harness_get(resource_type='template_v1', ...)` to read its full YAML. Parse `template.inputs`, `template.layout`, and each input's `ui` block (`visible`, `inputs`, `tooltip`). See **Template Discovery & Usage** below.
5. **Match requirements to templates** — Map each pipeline step to its best implementation:
   - **First choice**: `template: uses:` — a discovered template that matches the task
   - **Second choice**: `action: uses:` — a spec-defined action (see `references/native-actions.md`)
   - **Last resort**: `run:` — only for custom build/test/lint commands with no native equivalent
6. **Consult the spec reference** — Use `references/v1-spec-schema.md` for pipeline structure, expressions, strategies, and other v1 syntax details.
7. **Generate v1 YAML** — Assemble the pipeline from templates and actions. Use flat structure, `${{ }}` expressions, and `script` field for any `run:` steps.
8. **Validate before create (REQUIRED)** — Call `mcp__harness_local__validate_pipeline_yaml` with:
   - `yaml`: the full generated YAML (including `pipeline:` root)
   - `resource_type`: `"pipeline_v1"`
   - If `valid=false`, fix the YAML from the returned errors and call validation **once more** (at most **two** validation calls total).
   - Only proceed to create when `valid=true`. If the second validation still fails, stop and report the remaining schema, semantic, or policy errors to the user — do **not** call `harness_create`.
9. **Create via MCP** — See the "Creating via MCP" section below (`resource_type: "pipeline_v1"`, NOT `"pipeline"`).

### Step Selection Priority

```
┌─────────────────────────────────────────────────────────┐
│ 1. template: uses: <discovered_template>                │  ← PREFERRED
│    (global or account template from harness_list)       │
├─────────────────────────────────────────────────────────┤
│ 2. action: uses: <spec_action>                          │  ← GOOD
│    (spec-defined actions: k8s, helm, terraform, etc.)   │
├─────────────────────────────────────────────────────────┤
│ 3. run: / run-test:                                     │  ← LAST RESORT
│    (only custom build/test/lint with no native equiv)   │
└─────────────────────────────────────────────────────────┘
```

### Never Use `run:` For

Use a template or action for these — never `run:` / kubectl / helm CLI as the primary step. Names below are the usual targets; still discover + `harness_get` and emit the verified template id (do not paste a catalog id after get failed). Bare `uses: id` is fine; add `@version` only when pinning.

- Docker build/push → `template: uses: buildAndPushToDocker` / `buildAndPushToECR` / `buildAndPushToGAR`
- K8s deploy → `action: uses: kubernetes-rolling-deploy` or `template: uses: k8sRollingDeployStep`
- Helm deploy → `action: uses: helm-deploy` or `template: uses: helmDeployBasicStep`
- ECS deploy → `template: uses: ecsBluegreenDeployStep`
- Terraform → `template: uses: terraformStep`
- Security scanning → `template: uses: gitleaksStep` / `banditStep` / `sbomOrchestrationStep`
- Uploads → `template: uses: uploadArtifactsToS3` / `uploadArtifactsToGCS`
- Approvals → step-level `approval: uses: harness` or `approval: uses: jira` (inside a stage’s `steps:`)
- Ticketing → `action: uses: jira-create` / `snow-create`
- HTTP requests → `action: uses: http` or `template: uses: httpStep`

## Common Rationalizations

Agents under pressure rationalize skipping the template-first workflow. These excuses are all invalid:

| Excuse | Reality |
|--------|---------|
| "User didn't ask for templates" | v1 pipelines **always** use template search first. The request format doesn't matter. |
| "User asked for v1 only, not templates" | v1 + template search are the same workflow. Explicit v1 requests still require Step 3. |
| "Template discovery is slow" | 30 seconds now saves hours debugging invalid YAML. Always worth it. |
| "I already know the templates" | Templates change. New ones are added. You must verify with `harness_search` / `harness_list`. |
| "This pipeline is too simple for templates" | Simple pipelines still use templates. Complexity is irrelevant. Always discover. |
| "No templates exist for this task" | You can't know until you call `harness_search` with `template_search`. Never assume. |
| "run: is more flexible" | Templates provide better error handling, UI integration, and rollback. Not worth flexibility trade. |
| "I'll discover templates later" | Later = after you've written invalid YAML. Discovery must come first. |
| "Custom build steps don't need templates" | Check spec-defined actions first. `run:` is last resort, not first instinct. |
| "I can invent a template identifier" | Invented identifiers = runtime failures. Only use identifiers returned by `harness_search` / `harness_list`. |
| "I'll guess the template inputs" | Guessing = pipeline breaks at runtime. Always call `harness_get(template_v1)` and honor `ui.visible`, `layout`, and `ui.inputs`. |
| "User wants this done fast" | Fast wrong is slower than correct. Template search is the fast path. |
| "I'll use harness_list instead of harness_search" | `harness_list` is complementary. `harness_search` + `template_search` is mandatory first for each capability. |
| "Get failed so I'll use the skill example id" | Invalid. Skill/catalog names are candidates only. Failed `harness_get` → do not emit that id. |
| "I'll invent a version / empty @version" | Invalid. Prefer bare `uses: id` from a successful get. Add `@version` only when pinning to a `versionLabel` from discovery — never invent or emit empty `@`. |

## Red Flags - STOP and Discover Templates

These thoughts mean you're about to violate template-first discipline:

- "User didn't mention templates"
- "They only asked for v1"
- "I'll just use run: for this"
- "Templates probably don't exist for this"
- "No need to call harness_search / harness_list / harness_get"
- "I'll skip template_search and use harness_list only"
- "I can invent a template identifier"
- "Custom run: is simpler than templates"
- "This is too simple for template discovery"
- "I know which template to use"
- "Template discovery wastes time"
- "I'll guess the inputs"
- "User wants this done quickly"
- "Get failed; I'll use the cookbook id from the skill"

**All of these mean: Go back to step 3 — call `harness_search` with `resource_types=['template_search']` first.**

## v1 Key Differences from v0

| v0 Syntax | v1 Syntax |
|-----------|-----------|
| `<+variable>` expressions | `${{ variable }}` expressions |
| `type: CI` / `type: Deployment` stage types | Flat stages -- no `type` field |
| `command:` field in Run steps | `script:` field in `run:` steps |
| Native steps (`K8sRollingDeploy`, `HelmDeploy`) | Action steps (`action: uses: kubernetes-rolling-deploy`) |
| `failureStrategies:` | `on-failure:` |
| `HarnessApproval` step type | `approval: uses: harness` (step inside a stage — dedicated stage or inline) |
| Deep nesting (`spec: execution: steps:`) | Flat structure (`steps:`) |
| `strategy: matrix:` under stage `spec` | `strategy: matrix:` directly on stage or step |

## Pipeline Structure

```yaml
pipeline:
  name: My Pipeline
  repo:                          # optional: repository config
    connector: account.github
    name: myorg/my-repo
  clone:                         # optional: clone config
    depth: 1
  on:                            # optional: event triggers
  - push:
      branches: [main]
  env:                           # optional: global env vars
    NODE_ENV: production
  inputs:                        # optional: pipeline inputs
    branch:
      type: string
      default: main
  stages:
  - name: build
    steps:
    - run:
        script: go build
```

No `version:`, `kind:`, or `spec:` wrapper -- `pipeline:` is the root key.

## Stages

Stages have no `type` field. Their purpose is determined by their keys.

**Stage/step `id`:** optional in schema. On create, if a stage or step (or anything under it) uses a runtime input (`<+input>`), that node **and every ancestor** up to the pipeline must have an `id`. Without runtime inputs, omitting stage/step `id` is fine. Local schema validate does not enforce this. Prefer `${{ }}` for ordinary expressions; do not treat `${{ inputs.… }}` as a runtime input for this rule.

```yaml
# Runtime input present → id required on that node and ancestors
- id: deploy
  name: deploy
  delegate: <+input>
  service: my-service
  environment:
    id: staging
  steps:
  - name: Rolling Deploy      # no runtime input here → step id optional
    action:
      uses: kubernetes-rolling-deploy
```

Omitting the stage `id` above fails create with `Missing id at: pipeline.stages[0]` (schema validate may still pass).

### CI Stage

```yaml
- name: build
  runtime: cloud
  platform:
    os: linux
    arch: arm64
  cache:
    path: node_modules
    key: npm.${{ branch }}
  steps:
  - run:
      script: npm ci
```

### Deployment Stage

Stage `service` may be a plain id string. Stage `environment` must be an **object** (`id`, optional `deploy-to`) — not a plain id string.

```yaml
- name: deploy
  service: my-service
  environment:
    id: staging
    deploy-to: k8s_staging_infra   # InfraItem string or { id: ... }
  steps:
  - name: Rolling Deploy
    action:
      uses: kubernetes-rolling-deploy     # only if this action exists for the account/spec
      with:
        dry-run: false
```

Do **not** write stage-level `environment: staging` (plain id). That fails harness-schema `EnvironmentV1` validation.

### Approval (step inside a stage)

`approval:` is a **step**, not a bare stage. Nest it under `steps:` (dedicated stage or inline between other steps).

```yaml
- name: Approve deployment
  steps:
  - approval:
      uses: harness
      with:
        timeout: 30m
        message: "Approve deployment?"
        groups: [admins, ops]
        min-approvers: 1
```

## Step Types

### Run Step

Uses `script:` field (not `command:` or `run:`).

```yaml
# long syntax
- run:
    script: npm test

# short syntax
- run: npm test

# with container
- run:
    container: node:18
    script: npm test

# with shell and env
- run:
    shell: bash
    script: |
      npm ci
      npm test
    env:
      NODE_ENV: test

# with output variables — step id needed to reference steps.<id>.output
- id: build
  run:
    script: echo "TAG=v1" >> $HARNESS_OUTPUT
    output: [TAG]
```

### Run Test Step

```yaml
- run-test:
    container: maven
    script: mvn test
    report:
      type: junit
      path: target/surefire-reports/*.xml
    splitting:
      concurrency: 4
```

### Action Step

Actions replace v0 native steps. See `references/v1-spec-schema.md` for the full action catalog.

```yaml
# Kubernetes deploy
- action:
    uses: kubernetes-rolling-deploy
    with:
      dry-run: false

# Helm deploy
- action:
    uses: helm-deploy
    with:
      timeout: 10m

# Terraform plan
- action:
    uses: terraform-plan
    with:
      command: apply
      aws-provider: account.aws_connector

# HTTP request
- action:
    uses: http
    with:
      method: GET
      endpoint: https://acme.com
```

### Background Step

```yaml
- background:
    container: redis
- run:
    script: npm test
```

### Template Step

```yaml
- template:
    uses: account.docker
    with:
      push: true
      tags: latest
```

## AI Agent Steps

AI agents are templates. Reference them with `uses:` and pass custom inputs via `with:`:

```yaml
- template:
    uses: agent_uid@version
    with:
      custom_input: ${{ inputs.value }}
```

`llmConnector` and `mcpConnectors` are configured at agent level. Override if needed:

```yaml
- template:
    uses: code_review_agent@1.0.0
    with:
      llmConnector: custom_connector_id
      modelName: custom_model_arn
      repo_name: ${{ inputs.repo_name }}
```

### Approval Step (inline)

```yaml
- approval:
    uses: jira
    with:
      connector: account.jira
      project: PROJ
```

## Parallel and Group

```yaml
# parallel steps
- parallel:
    steps:
    - run:
        script: npm run lint
    - run:
        script: npm test

# parallel stages
- parallel:
    stages:
    - steps:
      - run: go test
    - steps:
      - run: npm test

# step group
- group:
    steps:
    - run:
        script: go build
    - run:
        script: go test
```

## Strategy

```yaml
# matrix (stage-level)
- strategy:
    matrix:
      node: [16, 18, 20]
      os: [linux, macos]
    max-parallel: 3
  steps:
  - run:
      container: node:${{ matrix.node }}
      script: npm test

# matrix (step-level)
- strategy:
    matrix:
      go: [1.19, 1.20, 1.21]
  run:
    container: golang:${{ matrix.go }}
    script: go test
```

## Failure Strategy

```yaml
# step-level
- run:
    script: go test
  on-failure:
    errors: all
    action: ignore       # abort, ignore, retry, fail, success

# retry with attempts
- run:
    script: go test
  on-failure:
    errors: [unknown]
    action:
      retry:
        attempts: 5
        interval: 10s
        failure-action: fail

# stage-level
- steps:
  - run:
      script: go test
  on-failure:
    errors: all
    action: abort
```

## Conditional Execution

```yaml
# stage conditional
- if: ${{ branch == "main" }}
  steps:
  - run:
      script: deploy.sh

# step conditional
- if: ${{ branch == "main" }}
  run:
    script: deploy.sh
```

## Template Discovery & Usage

This is the core of the template-first workflow. **Every pipeline starts here** — discover what already exists before writing anything.

### Discovery Strategy

**Step 1 (mandatory): semantic search** — call `harness_search` with `resource_types=['template_search']` once per pipeline capability **before any YAML**. This is required for every v1 pipeline, including explicit "create v1 CI pipeline" requests with no template mention.

```
# One query per capability; returns matches ranked by similarity with
# template_identifier, version_label, template_type, and similarity_score.
harness_search(query="build and push a docker image", resource_types=["template_search"])
harness_search(query="deploy to kubernetes", resource_types=["template_search"])

# Equivalent via harness_list when narrowing by entity type (after harness_search)
harness_list(resource_type="template_search", search_term="run a security scan", filters={"template_type": "Step"})
```

**Step 2 (complement): keyword / scope listing** — use `harness_list` after `harness_search` to check account/org templates or browse a scope. Do **not** skip Step 1 and jump straight here:

```
# 1. Global templates (Harness-maintained, always available)
harness_list(resource_type='template', params={"global": "true"})

# 2. Filtered global search by domain
harness_list(resource_type='template', params={"global": "true"}, search_term='docker')
harness_list(resource_type='template', params={"global": "true"}, search_term='kubernetes')

# 3. Account/org templates (user-created, may have org-specific logic)
harness_list(resource_type='template', org_id='<org>')
harness_list(resource_type='template', org_id='<org>', project_id='<project>')
```

Regardless of which discovery tool you use, the next steps are the same: confirm inputs with `harness_get`, then reference the template with `template: uses:`.

If `harness_search` with `template_search` is missing from the tool list or returns a hard error, report that to the user and fall back to the `harness_list` queries below. Never skip discovery entirely.

| Parameter | Required | Description |
|---|---|---|
| `params` | for global | Pass `{"global": "true"}` to discover global (Harness-maintained) templates |
| `org_id` | for account/org | Required when discovering account or org-level templates |
| `search_term` | no | Keyword to filter (e.g., `"docker"`, `"helm"`, `"terraform"`, `"security"`) |
| `template_type` | no | Filter: `Pipeline`, `Stage`, `Step` |
| `size` | no | Number of results to return |

Each result contains:
- `identifier` — use this in the `uses:` field
- `name` — human-readable template name
- `templateEntityType` — `Pipeline`, `Stage`, or `Step`
- `versionLabel` — pass to `harness_get` in the next step

### Template Preference Order

When multiple templates could serve the same purpose:

1. **Account/org templates** — prefer these if they exist (they encode org-specific conventions, connectors, and policies)
2. **Global templates** — use Harness-maintained templates as the standard fallback
3. **Spec actions** — use `action: uses:` only when no template covers the task

### Fetching Template Inputs

For **every** template you plan to reference, fetch its input schema before writing YAML:

```
# Global v1 template (preferred — returns full inputs + ui + layout)
harness_get(resource_type='template_v1', resource_id='<identifier>', params={"global": true})

# Account/org v1 template
harness_get(resource_type='template_v1', resource_id='<identifier>', org_id='<org>')

# Legacy v0 template (fallback only)
harness_get(resource_type='template', template_id='<identifier>', version_label='<versionLabel>', params={"global": "true"})
```

The response includes `template.yaml` (string). **This is the only source of truth** for input names, defaults, visibility, list column keys, and layout — not this skill file, not `v1-spec-schema.md`, and not examples from other templates.

Parse the fetched YAML and read three sections:

| Section | Purpose |
|---------|---------|
| `template.inputs` | Full input schema — type, required, default, label, options |
| `template.layout` | Which inputs Harness surfaces in the UI (primary vs advanced) |
| `inputs.<name>.ui` | Per-input UI metadata — visibility, list columns, tooltips |

#### Basic required/optional rules

- **Required + no default + visible** — must supply in `with:` or pipeline `inputs:`
- **Has default + visible** — omit from `with:` unless overriding
- **Default expressions** like `${{infra.namespace}}` — leave as-is; they resolve at runtime
- **Hidden by `ui.visible`** — do not wire or promote to pipeline inputs (see below)

Common default patterns:

| Input | Typical Default | Source |
|-------|-----------------|--------|
| `namespace` | `${{infra.namespace}}` | Infrastructure definition |
| `kubeconfig` | `${{infra.kube_config_path}}` | Infrastructure definition |
| `release` | `${{infra.releaseName}}` | Infrastructure definition |
| `manifests` | `${{runtime.manifestPath}}` | Runtime context |

#### Honor `ui.visible` (conditional fields)

Templates may hide inputs behind `ui.visible` expressions in the **fetched** YAML (e.g. `${{values.caching == false}}`, `${{skipSteadyStateCheck == false}}`). Read the expression from `harness_get` — do not assume visibility from memory or from docs.

**Agent rules for `ui.visible`:**

1. If `ui.visible` is **absent**, treat the input as visible.
2. **Evaluate** `ui.visible` using each referenced input's **default value** from the **fetched** YAML (not from docs or other templates).
3. Inputs that evaluate to **hidden** with defaults — **omit** from `template.with:` and from pipeline-level `inputs:` unless the user explicitly asked for that scenario.
4. When the user changes a controlling input, re-evaluate visibility using values from the fetch and wire newly visible fields.
5. Do **not** treat hidden conditional inputs as "required" even if `required: true` in schema — they are not applicable in the default configuration.

#### Honor `ui.inputs` (list / grid columns)

For `type: list` / `type: array` inputs, read `ui.inputs[]` from the **fetched** YAML — one entry per grid column with `relativePath`, `label`, and optional `inputType` / `inputConfig`.

**Agent rules for `ui.inputs`:**

1. Read column keys from `ui.inputs[].relativePath` in the fetch — never invent key names unless the template defines them.
2. Wire list values in `with:` as an array of row objects; keys = `relativePath` values from the fetch.
3. Use `ui.tooltip` and nested `ui.placeholder` from the fetch when explaining values to the user.
4. For `inputType: select` columns, use options from the fetched `inputConfig.options`.
5. Only include list inputs in `with:` when visible (per fetched `ui.visible`) and the user needs them.

Example shape (keys come from the fetch, not from this doc):

```yaml
with:
  <list_input_name>:
    - <relativePath_from_fetch>: <value>
      <other_relativePath_from_fetch>: <value>
```

#### Honor `layout` (primary vs advanced inputs)

The fetched YAML may include a top-level `template.layout` list. Entries are input names or `variant: more` groups (advanced/collapsed in Harness UI).

**Agent rules for `layout`:**

1. Inputs listed **directly** in `layout` (not under `variant: more`) are **primary** — prefer these for pipeline-level `inputs:` when they lack defaults and need user values.
2. Inputs under `variant: more` (or nested `title:` groups) are **advanced** — omit from `with:` and pipeline `inputs:` unless the user asks for them.
3. Use `label` and `ui.tooltip` from the **fetched** YAML for pipeline input `description` text.
4. Respect `ui.allowedValueTypes` — when only `fixed` is allowed, hardcode in `with:`; when `runtime` is allowed, expose as pipeline input.

#### End-to-end schema flow

```
harness_search / harness_list  →  pick template identifier
        ↓
harness_get(template_v1)  →  parse template.yaml
        ↓
For each input in template.inputs:
  - skip if ui.visible hides it (evaluate with defaults)
  - skip advanced fields (not in primary layout) unless requested
  - required + visible + no default  →  pipeline inputs: + with:
  - has default + visible            →  omit from with:
  - type: list + ui.inputs           →  wire rows using relativePath keys
        ↓
Assemble pipeline YAML with template: uses: / with:
```

### Referencing Templates in v1 YAML

```yaml
# Account/org template — bare id from a successful get (default)
- name: Build and Push
  template:
    uses: account.my_docker_build
    with:
      repo: myorg/myapp
      tags: [${{ pipeline.sequenceId }}, latest]

# Global template — same default
- name: Build and Push
  template:
    uses: buildAndPushToDocker
    with:
      connector: dockerhub
      repo: myorg/myapp

# Pinned version (only when user explicitly requests, or you choose to pin)
- name: Build and Push
  template:
    uses: account.my_docker_build@2.0.0
    with:
      repo: myorg/myapp
```

**Rules:**
- For **templates**, write `uses: templateName` from a successful `harness_get` — bare id is schema-valid. Add `@version` only when pinning to a `versionLabel` from discovery (or the user asks).
- Spec **actions** (`action: uses: …`) are not template library refs — use the action name from the spec after confirming it applies; do not invent action names.
- Never invent a template identifier — it must be returned by template discovery and confirmed with `harness_get(resource_type='template_v1', …)`
- Provide only **visible** required inputs in `with:` — honor `ui.visible` and `layout` (see above)
- Omit optional inputs with defaults from `with:` — omit advanced (`variant: more`) inputs unless requested
- Wire pipeline-level `inputs:` only for **primary, visible** fields the user must supply at runtime
- For `type: list` inputs, use `ui.inputs` column keys (`relativePath`) in each row object

## Template-First Validation Checklist

Before finalizing the pipeline, verify you followed template-first discipline:

- [ ] **`harness_search` with `resource_types=['template_search']` was called once per capability before any YAML** (required even for explicit v1-only requests)
- [ ] Templates were also listed/complemented via `harness_list` where needed (account/org scope)
- [ ] Every `uses:` value was returned by template discovery (never invented)
- [ ] `harness_get(resource_type='template_v1')` succeeded for every referenced template
- [ ] No `@version` on `uses:` unless pinning to a discovered `versionLabel` (or the user requested a pin)
- [ ] `ui.visible` was evaluated with schema defaults — hidden inputs omitted from `with:` and pipeline `inputs:`
- [ ] Primary `layout` inputs promoted to pipeline `inputs:`; advanced (`variant: more`) inputs omitted unless requested
- [ ] List inputs use `ui.inputs` column keys (`relativePath`) in `with:` row objects
- [ ] All visible required inputs (no defaults) are provided in `with:` or pipeline `inputs:`
- [ ] Optional inputs with defaults are **omitted** from `with:`
- [ ] `run:` steps are used ONLY where no template or action exists for the task

## Pre-Create Checklist

Before calling create/update, verify schema shape and create-time rules:

- [ ] If any stage/step uses a runtime input (`<+input>`), that node and all ancestors have an `id` (see Stages; schema does not enforce this)
- [ ] Stage `environment` is `{ id: … }` (optional `deploy-to`) — not a plain id string
- [ ] `mcp__harness_local__validate_pipeline_yaml` (`resource_type='pipeline_v1'`) called at most twice; if still invalid, stop and ask — do not thrash

## Complete CI Example (Template-First)

This example shows a pipeline composed primarily from discovered templates. The agent would have:
1. Run `harness_search(query="build and push a docker image", resource_types=["template_search"])` → finds `buildAndPushToDocker`
2. Run `harness_search(query="run a security scan", resource_types=["template_search"])` → finds `gitleaksStep`
3. Run `harness_get(resource_type='template_v1', ...)` for each selected template to confirm inputs and `ui.visible`
4. Used `run:` only for the custom `npm ci` / `npm test` commands (no template equivalent after search)

```yaml
pipeline:
  name: My App CI
  identifier: my_app_ci
  tags:
    ai_generated: ""
  repo:
    connector: account.github
    name: myorg/my-app
  clone:
    depth: 1
  on:
  - push:
      branches: [main]
  - pull_request:
      branches: [main]
  stages:
  - name: build-and-test
    runtime: cloud
    platform:
      os: linux
      arch: arm64
    cache:
      path: node_modules
      key: npm.${{ branch }}
    steps:
    - run:
        script: npm ci
    - parallel:
        steps:
        - run:
            script: npm run lint
        - run-test:
            script: npm test
            report:
              type: junit
              path: junit.xml
    - template:
        uses: gitleaksStep
    - template:
        uses: buildAndPushToDocker
        with:
          connector: dockerhub
          repo: myorg/my-app
          tags: [${{ pipeline.sequenceId }}, latest]
```

## Complete CD Example (Template-First)

This example shows a deployment pipeline where the agent:
1. Discovered a rolling-deploy template via `harness_list` / `harness_search` (ids below are placeholders — use values from your get)
2. Fetched inputs via `harness_get(resource_type='template_v1', …)` — confirmed optional inputs
3. Used spec actions for manifest-download/bake only after confirming no template covers them

```yaml
pipeline:
  name: Petstore Deploy
  identifier: petstore_deploy
  tags:
    ai_generated: ""
  inputs:
    skip_dry_run:
      type: boolean
      default: false
  stages:
  - name: deploy-staging
    service: petstore
    environment:
      id: staging
      deploy-to: k8s_staging_infra
    steps:
    - name: Download Manifests
      action:
        uses: manifest-download
    - name: Bake Manifests
      action:
        uses: manifest-bake
    - name: Rolling Deploy
      template:
        uses: k8sRollingDeployStep   # id from harness_get — do not invent
        with:
          skip_dry_run: ${{ inputs.skip_dry_run }}
  - name: Approve Production
    steps:
    - approval:
        uses: harness
        with:
          timeout: 1d
          message: "Approve production deployment?"
          groups: [prod-approvers]
          min-approvers: 1
  - name: deploy-prod
    service: petstore
    environment:
      id: prod
      deploy-to: k8s_prod_infra
    steps:
    - name: Download Manifests
      action:
        uses: manifest-download
    - name: Bake Manifests
      action:
        uses: manifest-bake
    - name: Rolling Deploy
      template:
        uses: k8sRollingDeployStep
        with:
          skip_dry_run: false
```

## Complete Multi-Template Example

A pipeline that composes multiple templates for a full CI/CD flow:

```yaml
pipeline:
  name: Full Stack Deploy
  identifier: full_stack_deploy
  tags:
    ai_generated: ""
  inputs:
    environment:
      type: string
      enum: [staging, prod]
    docker_tag:
      type: string
      default: latest
  stages:
  - name: build
    runtime: cloud
    platform:
      os: linux
      arch: arm64
    steps:
    - name: Install and Build
      run:
        script: npm ci && npm run build
    - name: Secret Scan
      template:
        uses: gitleaksStep
    - name: Build and Push
      template:
        uses: buildAndPushToDocker
        with:
          connector: account.dockerhub
          repo: myorg/fullstack-app
          tags: [${{ inputs.docker_tag }}, ${{ pipeline.sequenceId }}]
    - name: Upload Artifacts
      template:
        uses: uploadArtifactsToS3
        with:
          connector: account.aws
          bucket: myorg-artifacts
          source: dist/
          target: fullstack-app/${{ pipeline.sequenceId }}/
  - name: Approve Deploy
    steps:
    - approval:
        uses: harness
        with:
          timeout: 1h
          message: "Deploy ${{ inputs.docker_tag }} to ${{ inputs.environment }}?"
          groups: [devops]
          min-approvers: 1
  - name: deploy
    service: fullstack-app
    environment:
      id: staging
    steps:
    - name: Download Manifests
      action:
        uses: manifest-download
    - name: Bake Manifests
      action:
        uses: manifest-bake
    - name: Rolling Deploy
      template:
        uses: k8sRollingDeployStep
        with:
          skip_dry_run: false
```

## Creating via MCP

**CRITICAL: Use `resource_type: "pipeline_v1"` — NOT `"pipeline"`.** The `"pipeline"` resource type is the v0 legacy endpoint; it may tolerate v1 YAML on some Harness versions but is not the native v1 path and may fail on future versions.

### Step 0 — Validate the draft YAML

Before create/update, call:

```
mcp__harness_local__validate_pipeline_yaml
  yaml: "<full v1 pipeline YAML>"
  resource_type: "pipeline_v1"
```

- On `valid=false`: fix using `errors` / `feedback`, then validate again (max two calls).
- On second failure: do not call `harness_create`; report remaining errors.

### Step 1 — Verify the project exists

List projects with `harness_list` (`resource_type: "project"`, `org_id`) to confirm. If the project does not exist, create it first with `harness_create` (`resource_type: "project"`, `body: { identifier, name }`) or ask the user.

### Step 2 — Create the pipeline

Call `harness_create` with:

```
resource_type: "pipeline_v1"
org_id:        "<organization>"
project_id:    "<project>"
body: {
  pipeline_yaml: "<full v1 pipeline YAML string, including 'pipeline:' root key>",
  identifier:    "<unique pipeline identifier>",
  name:          "<pipeline display name>"
}
```

Notes on the body:

- **`pipeline_yaml`** is the required field name (snake_case). Do not use `yamlPipeline` — that's the v0 legacy field.
- **`identifier`** and **`name`** must also be passed as top-level body fields (the MCP uses these for URL routing; they must match the values inside the YAML).
- The `version` field defaults to `"1"` — do not set it explicitly unless the user requests a different version.
- Alternative body shapes accepted by the MCP for `pipeline_v1`:
  - Raw YAML string as body — `identifier` and `name` are extracted from the YAML.
  - `{ pipeline: { ... } }` JSON object — serialized to YAML automatically.
  - `{ yamlPipeline: "..." }` — accepted as backwards-compat alias of `pipeline_yaml`.

Prefer the explicit `{ pipeline_yaml, identifier, name }` shape above for clarity and version safety.

### Step 3 — Report the result

On success, report the pipeline URL. The MCP response contains the pipeline identifier and a UI path — surface both.

## Examples

### Create a v1 CI pipeline

```
/create-pipeline-v1
Create a v1 CI pipeline for a Node.js app with caching, parallel lint and test, and Docker push
```

Agent workflow:
1. `harness_search(query="build and push a docker image", resource_types=["template_search"])` → finds `buildAndPushToDocker`
2. `harness_get(resource_type='template_v1', resource_id='buildAndPushToDocker', params={"global": true})` → confirms inputs: connector, repo, tags; honors `ui.visible`
3. Generates pipeline using template for Docker push, `run:` only for npm commands

### Create a v1 deployment pipeline

```
/create-pipeline-v1
Create a v1 Kubernetes deployment pipeline with staging approval and production stages
```

Agent workflow:
1. `harness_search(query="deploy to kubernetes", resource_types=["template_search"])` → finds `k8sRollingDeployStep`
2. `harness_list(resource_type='template', org_id='default')` → checks for org-specific deploy templates
3. Prefers org template if found, otherwise uses global template from search results

### Create a v1 matrix build

```
/create-pipeline-v1
Create a v1 pipeline that tests across Go 1.19, 1.20, and 1.21 using matrix strategy
```

Agent workflow:
1. `harness_search(query="run go tests", resource_types=["template_search"])` → checks for Go build/test templates
2. No matching template in search results → uses `run:` with matrix strategy (custom test command, no template equivalent)

## Performance Notes

- **`harness_search` + `template_search` is mandatory for every v1 pipeline** — call it once per capability before writing steps, even when the user explicitly requests v1 syntax without mentioning templates. Then complement with `harness_list` for account/org scope.
- **Never skip `harness_get(template_v1)`** — always fetch and parse `template.inputs`, `template.layout`, and `ui.visible` / `ui.inputs` before referencing a template. Guessing inputs leads to runtime failures and over-exposed pipeline inputs.
- Always check `references/native-actions.md` before falling back to a `run:` step. Native actions provide better error handling, rollback support, and UI integration.
- Always consult `references/v1-spec-schema.md` for the complete v1 spec before generating YAML.
- Use `script:` field in run steps, never `command:` or `run:` as the field name.
- Use `action: uses:` or `template: uses:` for deployments, never v0 native step types like `K8sRollingDeploy`.
- Do not mix v0 and v1 structure: no `type:` on stages, no `spec:` wrapper. Prefer `${{ }}` for ordinary expressions; keep `<+input>` when a runtime input is intentional (see Stages).

## Troubleshooting

### Template Input Errors

- Wiring inputs hidden by `ui.visible` (e.g. `build_mode` when `caching: true` is default) — evaluate visibility with defaults first
- Promoting advanced `layout` fields (`variant: more`) to pipeline inputs when user didn't ask for them
- Wrong list row shape — use `relativePath` keys from `ui.inputs` (e.g. `path1`/`path2`, not `key`/`value`)
- Treating every `required: true` schema field as mandatory when `ui.visible` hides it in the default configuration
- Using `harness_get(resource_type='template')` (v0) instead of `template_v1` — v0 responses lack `ui` / `layout` metadata

### Common v1 Syntax Errors

- Prefer `${{ ... }}` over v0-style `<+...>` for ordinary value references; keep `<+input>` when a runtime input is intentional
- Adding `type:` field on stages (v1 stages have no type)
- Using `command:` or `run:` as the field name instead of `script:`
- Wrapping pipeline in `version:`, `kind:`, `spec:` (v1 uses bare `pipeline:`)
- Using v0 step types (`K8sRollingDeploy`) instead of actions (`action: uses: kubernetes-rolling-deploy`) or discovered templates
- Using `failureStrategies:` instead of `on-failure:`
- Stage-level `environment: <plain-id>` — invalid under harness-schema `EnvironmentV1` (use `{ id: … }`, optional `deploy-to`)
- Runtime input (`<+input>`) without `id` on that node **and** every ancestor — see Stages; create fails with `Missing id at: pipeline.stages[…]` (or similar path)
- Emitting empty `@version` or inventing a version — resolve failures; prefer bare `uses: id` unless pinning
- Emitting cookbook template ids after `harness_get` failed
- Treating `mcp__harness_local__validate_pipeline_yaml` pass as create-ready without runtime-input `id` ancestry (see Stages / Pre-Create Checklist)
- Treating `mcp__harness_local__validate_pipeline_yaml` pass as create-ready without verified templates (`harness_get` succeeded)

### MCP Errors

- **Using `resource_type: "pipeline"` for a v1 pipeline** — that's the v0 legacy endpoint. Use `resource_type: "pipeline_v1"` so you hit the native v1 API. The v0 endpoint may tolerate v1 YAML on some versions but is fragile and will silently produce unexpected behavior.
- **Project not found** — Verify the project exists with `harness_list` (`resource_type: "project"`, `org_id`). Create it first or confirm `org_id`/`project_id` are correct.
- **Missing required fields for pipeline_v1** — Pass the body as `{ pipeline_yaml: "<YAML string>", identifier: "<id>", name: "<name>" }`. All three fields are required.
- **`DUPLICATE_IDENTIFIER`** — Pipeline exists; use `harness_update` with the same `resource_type: "pipeline_v1"`.
- **`INVALID_REQUEST`** — Check YAML structure matches v1 schema. Consult `references/v1-spec-schema.md`.
- **`Missing id at: pipeline.stages[…]`** — Runtime input (`<+input>`) without `id` on that node **and** every ancestor (see Stages). Example: stage with `delegate: <+input>` needs a stage `id`. Local schema validate will not catch this.
