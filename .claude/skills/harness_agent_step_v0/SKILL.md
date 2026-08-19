---
name: harness-agent-step-v0
description: >-
  How to add an AI agent step to a Harness v0/standard pipeline. Use when adding,
  generating, or modifying an Agent step in a v0 pipeline. Do NOT use for v1/simplified
  pipelines.
metadata:
  author: Harness
  version: 1.0.0
  mcp-server: harness-mcp-v2
license: Apache-2.0
compatibility: Requires Harness MCP v2 server (harness-mcp-v2)
---

# Adding an AI Agent Step to a Harness v0 Pipeline

In v0 pipelines, agents are referenced using the `Agent` step type, which internally references the v1 agent template. The step expands the v1 template and converts it to a v0 Run Step at execution time.

## Basic Agent Step Example

```yaml
- step:
    type: Agent
    name: ReviewPRAgent
    identifier: ReviewPRAgent
    spec:
      agentName: code_review_agent
      agentSettings: |-
        {
          "repo_name": "my-org/my-repo",
          "branch": "feature/new-feature",
          "llmConnector": "account.my_llm_connector_id",
          "mcpConnectors": ["account.github_mcp_connector", "account.slack_mcp_connector"]
        }
```

## Complete Pipeline Example with Variables

```yaml
pipeline:
  name: Code Review Pipeline
  identifier: code_review_pipeline
  projectIdentifier: myproject
  orgIdentifier: default
  variables:
    - name: repo_name
      type: String
      description: Repository name
      required: true
      value: <+input>
    - name: branch
      type: String
      description: Branch to review
      required: true
      value: <+input>
  stages:
    - stage:
        name: Review Stage
        identifier: review_stage
        type: Deployment
        spec:
          execution:
            steps:
              - stepGroup:
                  stepGroupInfra:
                    type: KubernetesDirect
                  steps:
                    - step:
                        type: Agent
                        name: ReviewPRAgent
                        identifier: ReviewPRAgent
                        spec:
                          agentName: code_review_agent
                          agentSettings: |-
                            {
                              "repo_name": "<+pipeline.variables.repo_name>",
                              "branch": "<+pipeline.variables.branch>",
                              "llmConnector": "account.my_llm_connector_id",
                              "mcpConnectors": ["account.github_mcp_connector", "account.slack_mcp_connector"]
                            }
```

## Key Fields Explained

### Required Fields
- **`type: Agent`** — Step type for v0 pipelines that references a v1 agent template
- **`name`** — Display name for the step in the pipeline UI
- **`identifier`** — Unique identifier for the step within the pipeline
- **`agentName`** — The agent's UID (v1 template identifier) created via `harness_create`

### Optional Fields
- **`agentSettings`** — JSON string containing all agent configuration:
  - **llmConnector**: LLM connector ID (hardcoded in yaml, e.g., `"account.my_llm_connector_id"`)
  - **mcpConnectors**: Array of MCP connector IDs (hardcoded in yaml, e.g., `["account.github_mcp_connector"]`)
  - **Custom inputs**: Agent-specific fields like `repo_name`, `branch`, thresholds, etc.
  - Can reference pipeline variables using `<+pipeline.variables.variable_name>` syntax for custom inputs
- **Backend selection** — Do not add backend/provider selection as an ad hoc
  `agentSettings` key. If an Agent supports selectable backends, define a
  first-class `backend` input in the Agent resource spec and map it in the
  Agent template env, for example `PLUGIN_HARNESS_AGENT_BACKEND:
  ${{inputs.backend}}`. Supported values are `claude`, `codex`, `openai`, and
  `deepagent`.

## Configuration Precedence Rules

1. **`agentSettings` JSON values** override agent template defaults for all fields
2. **Agent template defaults** — used when `agentSettings` does not provide a value

## Step output variables (`agent_output`)

The CLI appends `agent_output=__B64__…` (and cost fields) to
`$HARNESS_OUTPUT_FILE` / `$DRONE_OUTPUT` / `$HARNESS_OUTPUT`. Worker Agents must
also declare the key under the step's `output:` list or
`<+steps.<id>.output.outputVariables.agent_output>` stays null:

```yaml
- step:
    type: Agent
    name: ReviewPRAgent
    identifier: ReviewPRAgent
    spec:
      agentName: code_review_agent
      agentSettings: |-
        { "llmConnector": "account.my_llm_connector_id" }
```

For v1 agent specs, declare output on the run step:

```yaml
agent:
  step:
    run:
      with:
        task: Review the PR and summarize findings.
      output:
        - agent_output
```

## Creating via MCP

```
resource_type: "pipeline"
body: { yamlPipeline: "<full v0 pipeline YAML string>" }
```
