---
name: herdr-orchestration
description: spawn and coordinate erg worker agents in separate herdr panes via the herdr CLI
---
You run inside a herdr pane and coordinate erg workers that run in other panes.

## Your tools (this is the complete list)

- `read` — read a file or list a directory.
- `list` — list a directory's entries.
- `glob` — find files by pattern (e.g. `src/*.c`).
- `write` — create a file.
- `bash` — run shell commands. **This is how you drive herdr**: splitting panes, running workers,
  and listing/waiting on agents are all `herdr ...` commands you run through bash.
- `ask` — ask the human a question and wait for their answer.

**There is no `spawn`, `run`, `pane`, `agent`, `wait`, or `orchestrate` tool.** Those are herdr *CLI
commands* — run them with the **bash** tool. If you start to call a tool that is not in the list
above, stop and run a `herdr` command with bash instead. To list agents you run `herdr agent list`
with bash; to wait you run `herdr agent wait ...` with bash.

## Each bash call is a fresh shell

A shell variable like `$P` set in one bash call is **gone** in your next bash call. So run each
worker's whole lifecycle — split, write task, run, wait, read — in **one** bash command, where `$P`
stays in scope. Never set `$P` in one call and use it in another; that runs as `herdr agent wait ""`
and fails. If you must refer to a pane across calls, use its **literal** id (e.g. `wW:p8`), which you
can always recover from `herdr agent list`.

## Run one worker — a single, self-contained bash command

Copy this verbatim and change only the task text between `<<'TASK'` and `TASK`. The quoted `'TASK'`
terminator makes the body literal, so apostrophes, quotes, `$`, and newlines are all safe:

    P=$(herdr pane split --direction down --no-focus | jq -r '.result.pane.pane_id')
    cat > "/tmp/erg-task-$P.md" <<'TASK'
    Implement input-length limits in the tool layer. Touch only src/agent_tool.c and src/util.c.
    Apostrophes, quotes, and multiple lines are fine here.
    TASK
    herdr pane run "$P" "erg -p \"\$(cat /tmp/erg-task-$P.md)\""
    herdr agent wait "$P" --until done blocked
    herdr agent read "$P"
    herdr pane close "$P"

This runs the worker to completion, prints its output, and closes its pane — all in one call.

- Always use `erg -p` (one-shot). A bare `erg` opens an interactive REPL with no keyboard in the
  pane, hits EOF, and exits with `bye` without doing the work.
- Add `--shape <name>` before `-p` to give the worker a role; omit it for the default.
- To hand workers a directory and config, split with `--cwd /abs/dir --env ERG_CONFIG=/abs/config.json`.

## Running workers in parallel

The block above is sequential (it waits before returning). To fan out, spawn several without waiting,
then collect them. Because ids do not survive between calls, get them from `herdr agent list`:

    herdr agent list                              # find each worker's pane id (wX:pN)
    herdr agent wait wW:p8 --until done blocked && herdr agent read wW:p8 && herdr pane close wW:p8
    herdr agent wait wW:p9 --until done blocked && herdr agent read wW:p9 && herdr pane close wW:p9

## herdr quick reference (all run with the bash tool)

    herdr pane split --direction down --no-focus    # new pane; prints .result.pane.pane_id
    herdr pane run "$P" "<command>"                 # run a command in pane $P
    herdr pane close "$P"                            # close a pane you are done with
    herdr agent list                                # every agent and its state
    herdr agent read "$P"                           # read a pane's output
    herdr agent wait "$P" --until done blocked      # wait for a terminal state
    herdr agent prompt "$P" "<text>" --wait --until done   # prompt an interactive agent

## Rules

- Use only the tools listed above. Splitting panes and running/waiting on workers are `herdr`
  commands run through bash, not tools.
- Spawn each worker with the single bash command above; never inline the task text into `erg -p`
  (an apostrophe would hang the worker shell), and never bare `erg` (use `erg -p`).
- Always target the **pane id** (`wX:pN`), never the tab (`wX:tN`) or workspace (`wX`).
- Keep the fan-out small (2–4), each task self-contained with the exact files it may touch.
- `herdr agent prompt` is rejected if the target is already `blocked` — resolve or wait first.
- erg registers with herdr automatically on start; use `herdr pane run … erg …`, not
  `herdr agent start --kind …` (erg is not a herdr built-in agent kind).
- If a worker ends `blocked`, it needs a human decision — escalate with the `ask` tool.
- You orchestrate; the workers touch the code. Clean up with `herdr pane close "$P"` when done.
