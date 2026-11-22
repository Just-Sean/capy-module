#!/usr/bin/env bash
# wt-env.sh — run once inside a fresh git worktree before an agent starts work.
# A reusable app's tests use an in-memory SQLite database (already isolated per
# process), so a worktree just needs its own virtualenv.
set -euo pipefail
uv sync
echo "worktree ready (uv sync done; tests use isolated in-memory SQLite)"
