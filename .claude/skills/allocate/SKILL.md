---
name: allocate
description: Task allocator for QLure. Classifies a task and dispatches it to the cheapest suitable sub-agent (planner/opus, coder/haiku, fixer/sonnet, setup/sonnet). Use with /allocate <task>.
---

Task: $ARGUMENTS

1. Classify the task using the routing table in CLAUDE.md.
2. Print one line: `agent: <name> (<model>) - <reason>`.
3. Dispatch with the Agent tool using that `subagent_type`. For a non-trivial or unclear task, dispatch `qlure-planner` first, then dispatch each plan step to the agent it names.
4. Escalate: if `qlure-coder` fails the same check twice, re-dispatch to `qlure-fixer`; if the plan proves wrong, go back to `qlure-planner`.
5. Do no heavy work in the main session. Relay each agent's short report to the user.
