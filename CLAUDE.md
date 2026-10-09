# QLure

Python 3.12+ defensive honeypot and threat-observation system. Install: `pip install -e '.[dev]'`. Checks: `pytest -q`, `ruff check .`, `ruff format --check .`, `qlure schema --check`.

## Task allocation (cost control)

The main session is a thin dispatcher. Route work to sub-agents by task type (also available as `/allocate <task>`):

| Task | Agent | Model |
|---|---|---|
| New feature, unclear task, architecture, root-cause analysis, review | `qlure-planner` (run first) | opus |
| Long or repetitive code, tests, docs, boilerplate | `qlure-coder` | haiku |
| Critical bugs, security, data integrity, failing CI coder could not fix | `qlure-fixer` | sonnet |
| Dependencies, Docker, CI, env, tooling, setup | `qlure-setup` | sonnet |
| git status/commit/push/pull/fetch/merge/conflicts | `qlure-git` | haiku |
| Vercel/Render deploys, logs, env vars, auto-deploy config | `qlure-deploy` | sonnet |
| Find/move/rename/organize files, .gitignore, cleanup | `qlure-files` | haiku |

Rules:
- Planner output tags each step with an agent; dispatch steps accordingly.
- Never use opus to write code. Never use haiku for `qlure/store`, `qlure/correlate`, `qlure/rules`, or `dashboard/auth.py`.
- If `qlure-coder` fails the same check twice, escalate to `qlure-fixer`. If a plan proves wrong, return to `qlure-planner`.
- Trivial one-line edits can be done directly in the main session.
- Decoys stay fake and harmless; no real credentials or exploit capability.
