#!/usr/bin/env bash
set -euo pipefail

DOTFILES_SKILLS=~/dotfiles/claude/.claude/skills

SKILLS=(
  brainstorming build-autonomous dispatching-parallel-agents executing-plans
  finishing-a-development-branch orchestrate plan spec-driven
  subagent-driven-development three-experts writing-plans
  clean-comments code-review edge-case-discovery refactoring
  test-as-guardrails test-driven-development verification-before-completion
  engineering-principles gitignore-policy llm-context makefile-builds
  git-ops receiving-code-review requesting-code-review using-git-worktrees
  go-performance go-usb postgresql rest-api-design web-frontend
  documentation codebase-memory evidence-based-debugging systematic-debugging
  learn onboard refine reverse-engineer
)

echo "Removing ${#SKILLS[@]} migrated skills from dotfiles..."
for skill in "${SKILLS[@]}"; do
  if [[ -d "$DOTFILES_SKILLS/$skill" ]]; then
    rm -rf "$DOTFILES_SKILLS/$skill"
    echo "  removed: $skill"
  else
    echo "  missing (skipped): $skill"
  fi
done

echo ""
echo "Remaining skills in dotfiles:"
ls "$DOTFILES_SKILLS/"

echo ""
echo "Refreshing stow..."
make -C ~/dotfiles restow

echo ""
echo "Committing dotfiles..."
git -C ~/dotfiles add claude/.claude/skills/
git -C ~/dotfiles commit -m "agent: migrate 39 skills to gherlein/claude-skills plugin"

echo ""
echo "Done. Open a fresh Claude Code session and verify:"
echo "  /using-superpowers        (personal skill - should work)"
echo "  /gherlein:code-review     (plugin skill - should work)"
