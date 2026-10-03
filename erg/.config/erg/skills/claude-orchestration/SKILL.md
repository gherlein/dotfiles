---
name: claude-orchestration
description: spawn and coordinate Claude Code (claude) worker agents in separate herdr panes via the herdr CLI
---
You run inside a herdr pane and coordinate Claude Code (`claude`) workers in other panes. `claude`
is a herdr built-in agent kind, so herdr detects a worker's state (idle/working/blocked/done).

## Your tools (this is the complete list)

- `read` — read a file or list a directory.
- `list` — list a directory's entries.
- `glob` — find files by pattern.
- `write` — create a file.
- `bash` — run shell commands. **This is how you drive herdr**: splitting panes, running workers,
  and listing/waiting on agents are all `herdr ...` commands you run through bash.
- `ask` — ask the human a question and wait for their answer.

**There is no `spawn`, `run`, `pane`, `agent`, `wait`, or `orchestrate` tool.** Those are herdr *CLI
commands* — run them with the **bash** tool. To list agents you run `herdr agent list` with bash.

## Each bash call is a fresh shell

A shell variable like `$P` set in one bash call is **gone** in your next bash call. Run each worker's
whole lifecycle in **one** bash command where `$P` stays in scope; to refer to a pane across calls,
use its **literal** id (e.g. `wW:p8`) from `herdr agent list`.

## Run one worker — a single, self-contained bash command

Change only the task text between `<<'TASK'` and `TASK` (the quoted terminator keeps the body literal
— apostrophes/quotes/newlines safe):

    P=$(herdr pane split --direction down --no-focus | jq -r '.result.pane.pane_id')
    cat > "/tmp/claude-task-$P.md" <<'TASK'
    <the worker's full, self-contained task, including the files it may touch>
    TASK
    herdr pane run "$P" "claude -p \"\$(cat /tmp/claude-task-$P.md)\""
    herdr agent wait "$P" --until done blocked
    herdr agent read "$P"
    herdr pane close "$P"

This runs the worker to completion, prints its output, and closes its pane. To fan out, spawn several
without waiting, then collect them by their literal ids from `herdr agent list`.

## Interactive worker (multi-prompt tasks only)

Only when a task needs more than one prompt — start `claude` in a pane, then prompt and wait (bash):

    herdr agent start w1 --kind claude --pane "$P"
    herdr agent prompt "$P" "<text>" --wait --until idle blocked
    herdr agent read "$P"

Pass claude flags after `--`: `herdr agent start w1 --kind claude --pane "$P" -- --model claude-sonnet-4-5`.

## Wait, then read (bash)

    herdr agent wait "$P" --until done blocked
    herdr agent read "$P"

## herdr quick reference (all run with the bash tool)

    herdr pane split --direction down --no-focus    # new pane; prints .result.pane.pane_id
    herdr pane run "$P" "<command>"                 # run a command in pane $P
    herdr pane close "$P"                            # close a pane you are done with
    herdr agent list                                # every agent and its state
    herdr agent read "$P"                           # read a pane's output
    herdr agent wait "$P" --until done blocked      # wait for a terminal state

## Rules

- Use only the tools listed above. Splitting panes and running/waiting on workers are `herdr`
  commands run through bash, not tools.
- Spawn each worker with the single bash command above; never inline the task into `claude -p`.
- Always target the **pane id** (`wX:pN`), never the tab (`wX:tN`) or workspace (`wX`).
- `herdr agent prompt` is rejected if the target is already `blocked` — resolve or wait first.
- If a worker ends `blocked`, it needs a human decision — escalate with the `ask` tool.
- Keep the fan-out small and each task self-contained. Clean up with `herdr pane close "$P"` when done.
