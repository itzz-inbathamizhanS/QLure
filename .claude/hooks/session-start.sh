#!/bin/bash
# Installs dev dependencies in cloud sessions so pytest and ruff work.
set -euo pipefail

if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

cd "${CLAUDE_PROJECT_DIR:-.}"
pip install -q -e '.[dev]'
