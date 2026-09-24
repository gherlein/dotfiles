---
name: goprojdex
description: Use when you need to find out where a project lives on disk, what its git remote is, what state it is in, or when it was last worked on - and when registering, touching, tagging, or re-describing a project in the personal project index. Covers the goprojdex CLI and the plain-Markdown store it keeps at ~/.goprojdex.
---

# Looking Up Projects with goprojdex

## Overview

`goprojdex` is a personal, git-backed index of every project on this machine, from [github.com/gherlein/goprojdex](https://github.com/gherlein/goprojdex). One project is one Markdown file. Use it to answer:

- Where does project X live on disk, and what is its git remote?
- What was it for, in a sentence or two?
- When was it last touched, and what has gone stale?
- What state is it in — **but read [Status](#status-what-it-means-and-what-it-doesnt) first; in a scan-built store this field is usually uncurated and answers nothing.**

**The store is two things at once**, and you should use whichever is cheaper for the question:

1. **The CLI** — `goprojdex show` / `find` / `list`, with `--json` for parsing.
2. **Plain files** — `<store>/projects/<slug>.md`, one YAML-frontmatter record each. `grep` them directly. Still the better tool for field-scoped questions the CLI can't express (see [Read the files directly](#read-the-files-directly)).

It indexes **where projects are and what state they are in**. It is not a task tracker, an issue system, or a backup.

## Before Your First Command

**Help works: `--help`, `-h`, and `help` all print usage at exit 0**, and `help <command>` / `<command> --help` print that command's flags. Help never opens or creates a store, so it is always safe to run first. Bare `goprojdex` with no arguments is still a usage error — usage to stderr, exit 2.

> **Version check.** `show`, `list --limit`, `list --tag`, help, and `find` matching slugs are all recent additions. If any of them errors with `unknown command "show"` or `flag provided but not defined: -limit`, the binary predates them: rebuild with `make install` from the goprojdex source repo, or fall back to the file recipes in this skill, which work against any version.

### Set the store path once

The store defaults to `~/.goprojdex`, and **normally you should pass no `--store` at all**. But the CLI flag and the file recipes in this skill must always point at the *same* store, so set a variable up front and use it in both:

```bash
STORE="${HOME}/.goprojdex"          # default
# STORE=/path/the/user/named        # only if the user named an alternate store
```

Then `goprojdex --store "$STORE" ...` and `grep ... "$STORE"/projects/*.md` can never drift apart. **Shell state does not persist between tool calls** — re-set `STORE=` at the top of every command you run, or the variable will be empty and your greps will silently hit `/projects/*.md`.

**Watch for binary drift** if the working directory is the goprojdex source repo itself: a built `./bin/goprojdex` and the installed `~/bin/goprojdex` can be different versions. `command -v goprojdex` tells you which one is on PATH but **not** which one is current — there is no `version` subcommand to ask. If the source tree has uncommitted changes under `internal/` or `cmd/`, the installed binary is likely stale; `make install` before relying on it, or say which binary you used.

> **REQUIRED — never guess a `--store` path, and never let the CLI and the greps disagree.**
>
> - A `--store` pointing at a directory that doesn't exist is **not an error**: the tool silently creates a fresh empty store there and every query answers `no projects` / `[]` with **exit 0**. A typo therefore looks exactly like "you have no such project."
> - Conversely, if the user named an alternate store and you grep `~/.goprojdex` out of habit, you will silently read the user's *real* index and report plausible, wrong numbers.
>
> Before trusting any result from a non-default store, confirm it has content: `ls "$STORE"/projects/*.md | wc -l`.

**`--store` must come BEFORE the subcommand.** It is a global flag, not a subcommand flag:

```bash
goprojdex --store "$STORE" list    # correct
goprojdex list --store "$STORE"    # FAILS: flag provided but not defined: -store
```

## Quick Reference

| Goal | Command |
|---|---|
| **Everything about one project** | `goprojdex show <slug>` — by slug, path, or `.` |
| Search by concept/keyword | `goprojdex find <words>` |
| Search, machine-readable | `goprojdex find <words> --json` |
| One status, machine-readable | `goprojdex list --status active --json` |
| By tag | `goprojdex list --tag go` |
| Gone stale | `goprojdex list --stale 90` |
| Everything, safely capped | `goprojdex list --limit 20` — **see size hazard** |
| Register cwd as a project | `cd <dir> && goprojdex here` |
| Bump "last worked on" to today | `goprojdex touch .` |
| Edit curated fields | `goprojdex set <slug> --status active --tag go` |
| Delete a record | `goprojdex rm <slug>` — **review gate**, see below |
| Rebuild by walking trees | `goprojdex scan [root ...]` — **review gate**, see below |
| Regenerate `INDEX.md` | `goprojdex reindex` |

## Recipe: "where does X live and when did I last touch it?"

The most common question, and the four steps that answer it honestly. Details for each are further down; this is the chain.

```bash
STORE="${HOME}/.goprojdex"

# 1. Identify the project. Path or cwd needs no slug; otherwise search broadly.
goprojdex --store "$STORE" show /abs/path/to/dir     # or: show .   / show <slug>
goprojdex --store "$STORE" find <concept> --json | jq -r '.[].path'

# 2. Is `status` real, or is it the scan default stamped on everything?
grep -h '^status:' "$STORE"/projects/*.md | sort | uniq -c | sort -rn

# 3. Is `updated` a work date, or the scan date falling back?
git -C "$STORE" log --format='%h %ad %s' --date=short | grep 'scan:'

# 4. Date the work from disk. git log -1 FAILS on zero-commit repos — the
#    exact case that made step 3 ambiguous — so keep the mtime fallback.
git -C <project-path> log -1 --format='%h %ad %s' --date=short
find <project-path> -type f -not -path '*/.git/*' -printf '%TY-%Tm-%Td %p\n' | sort -r | head -5
```

Skipping steps 2–4 is how you confidently report a scan artifact as a work date.

## The Size Hazard — Applies to Every Enumeration

> **A real store runs to 1000+ records. Any command that enumerates the whole store will flood and truncate your context — and a truncated result gives you a random prefix with no signal that data is missing, which is worse than no answer.**

This is **not** just about `list`. It applies equally to `ls`, `grep`, and `cat` over `projects/`. Concretely, on a 1195-record store: `list` is ~400 KB (the table pads every column to the widest slug), `list --json` ~600 KB, and an unfiltered `ls projects/ | grep -i brightsign` returns ~250 filenames.

**Reach for `--limit` by default.** It caps output *after* sorting and filtering, so it yields the N most recently updated matches, and it prints `... N more (use --limit 0 for all)` when it truncates — so a capped result is never mistakable for a complete one. On a 1195-record store, `--limit 20` is 3.5 KB against 397 KB unlimited.

**Size the store first, then never enumerate without a limit, a filter, a `wc -l`, or a `head`:**

```bash
ls "$STORE"/projects/*.md | wc -l                    # how big is this store?

goprojdex --store "$STORE" list --limit 20           # cap it — the default move
goprojdex --store "$STORE" list --status active      # narrow by status
goprojdex --store "$STORE" list --tag go --limit 20  # filters compose
goprojdex --store "$STORE" list --stale 90           # narrow by staleness
ls "$STORE"/projects/ | grep -i unifi | head -20     # cap file enumeration too
grep -l '^status: active' "$STORE"/projects/*.md | wc -l   # count before listing
```

The `ls`/`grep` recipes have no `--limit` of their own — the size discipline is on you there.

**When the user genuinely wants the whole set** (a machine-readable dump to process), do not stream it into context — redirect to a file, verify, and report the path:

```bash
goprojdex --store "$STORE" list --status vision --json > /tmp/vision-raw.json
jq length /tmp/vision-raw.json                                  # verify it parsed
jq -c 'map({path, title, tags})' /tmp/vision-raw.json > /tmp/vision.json
```

Dropping bodies with `jq 'map(del(.body))'` cuts roughly 40% when you do need it inline.

**Filtering by tag is `--tag`**, which matches a **whole tag, case-insensitively** — `--tag go` does *not* match a record tagged only `golang`. All filters compose as a conjunction:

```bash
goprojdex --store "$STORE" list --tag go
goprojdex --store "$STORE" list --tag go --status active --limit 20
```

There is still no CLI way to *enumerate* the tags in use, so that one goes through JSON:

```bash
goprojdex --store "$STORE" list --json > /tmp/all.json
jq -r '.[].tags[]' /tmp/all.json | sort | uniq -c | sort -rn             # every tag in use
```

## Reading the Index

### `find` — substring search

```bash
goprojdex --store "$STORE" find unifi
goprojdex --store "$STORE" find kubernetes --json
```

Output is one record per two lines: path, then title, status, and updated date.

```
/home/you/src/gofi
  UniFi Fixed Hosts CLI  [active]  updated 2026-08-05
```

**Know exactly what `find` does, because it is simpler than it looks:**

- It joins all your query words with single spaces into **one string**, lowercases it, and does a plain **substring** test.
- It tests that substring against six haystacks: **`title`, `slug`, body, `path`, `repo`, and the tags joined by spaces**.
- Results are sorted by `updated` descending. **There is no relevance ranking**, no field scoping, no phrase quoting, and no regex. `find` has no `--limit` either — that flag is on `list` only, so a broad query on a large store can still flood you.

Consequences worth internalizing:

- `find "brightsign os"` matches only records containing the literal run `brightsign os` — it does **not** OR the two words. A broad single word usually finds more than a careful phrase.
- Because tags are joined with spaces, `find "go mqtt"` matches a record tagged `[go, mqtt]` — but only in that adjacency order.
- `--json` may appear anywhere in the arguments; it is split out before the query is assembled.

> **A `find` result that approaches the store size has told you nothing.** Because `path` is one of the haystacks, any term that appears in a common directory prefix matches nearly everything — on a store whose projects mostly live under `~/src/brightsign-playground/`, `find brightsign` returns 1161 of 1195 records. That is not a search result, it is the whole index. Compare the hit count against `ls "$STORE"/projects/*.md | wc -l`; when they are close, narrow the term or switch to a field-scoped `grep`, and never present it as "your BrightSign projects."

> **REQUIRED — search abbreviations and acronyms, not just the full concept name.** Substring matching plus scan-created records is a trap: those records often have an **empty body** and a slug that is just a terse directory name, so the only text `find` can see is a path and an abbreviation. A record named `bsoe` at `src/gerrit/bsoe` is invisible to `find "brightsign os"` — the most important project can be entirely absent from the results, and you will not know it.
>
> For any domain concept, run the full name **and** its abbreviations, and cross-check against paths:
>
> ```bash
> goprojdex --store "$STORE" find brightsign --json | jq -r '.[].path'
> grep -h '^path:' "$STORE"/projects/*.md | grep -iE 'bsoe|bos' | sort -u
> ```
>
> Never report "you have nothing related to X" on the strength of one `find`.

### `show` — one complete record

**When you want everything about one project, use `show`, not `find`.** It prints every frontmatter field plus the body, and resolves its argument three ways — a slug, an absolute path, or the working directory:

```bash
goprojdex --store "$STORE" show radio-telemetry-daemon    # by slug
goprojdex --store "$STORE" show /home/you/src/rtd         # by path
goprojdex --store "$STORE" show .                         # by cwd
goprojdex --store "$STORE" show radio-telemetry-daemon --json
```

```
title:   Radio Telemetry Daemon
slug:    radio-telemetry-daemon
path:    /home/you/src/rtd
repo:    (none)
status:  active
updated: 2026-08-05
created: 2026-06-01
tags:    go, mqtt

Telemetry daemon for the shop floor.
```

Three things to know:

- **Absent optional fields render as `(none)`**, so you can tell "no remote recorded" from "the tool didn't show me the remote."
- **`show .` walks upward** to the nearest enclosing indexed project, exactly like `touch` — so it works from a subdirectory, and inside nested repos the innermost project wins.
- **`--json` emits a one-element array**, the same shape as `list`/`find`, so one parser handles all three.

`show <path>` is the answer to "I'm looking at this directory — is it indexed?" You do **not** need to know the slug, which matters because the slug is derived from the README heading and is often unguessable from the directory name.

### Read the files directly

`show` covers single-record reads, so reach for the files when you need something the CLI cannot express: **field-scoped matching, counting, or set operations across the whole store.**

```bash
cat "$STORE"/projects/<slug>.md      # equivalent to `show <slug>`, if you have the slug
```

> **You cannot derive the record filename from a directory path.** The slug comes from the README heading, so a directory named `rtd` can be recorded in `radio-telemetry-daemon.md` — the two share no substring, and both `cat .../rtd.md` and `ls | grep rtd` fail. **Prefer `show <abs-path>`**, which resolves this for you. Falling back to files:
>
> ```bash
> grep -l '^path: /abs/path/to/dir$' "$STORE"/projects/*.md
> ```
>
> Anchor with `$` — without it, a path that prefixes another project's path matches both. Use `test -d` rather than `ls -d` to check existence; `ls` emits ANSI color escapes that land as noise in captured output.

A record is YAML frontmatter plus a free-text body:

```markdown
---
title: UniFi Fixed Hosts CLI
slug: gofi-unifi
path: /home/you/src/gofi
repo: "https://github.com/you/gofi.git"
status: active
updated: 2026-08-05
created: 2026-06-01
tags: [go, cli, unifi]
---

gofi tools to read/add/delete fixed-IP DHCP reservations on a UniFi controller.
```

> **Empty fields are omitted from the frontmatter entirely — they are not written as empty values.** A project with no remote and no tags has **no `repo:` line and no `tags:` line at all**. This matters for greps: in a scan-built store nearly every record lacks a `tags:` line, so `grep '^tags:' projects/*.md` returns almost nothing and looks like a broken store when it is merely an untagged one. The JSON follows the same rule (see [JSON shape](#json-shape)).

Because these are plain files, `grep` beats `find` for anything field-scoped — which `find` cannot do at all:

```bash
grep -l '^status: active' "$STORE"/projects/*.md          # scoped to one field
grep -rl 'tinygo' "$STORE"/projects/                      # any field, incl. body
grep -L '^repo:' "$STORE"/projects/*.md                   # no git remote — STORE-WIDE
ls "$STORE"/projects/ | grep -i unifi                     # slug prefix/substring browse
```

**Prefer `ls "$STORE"/projects/ | grep` over `grep -l "$STORE"/projects/*.md` when you only need names.** Both answer "which records match," but `grep -l` prints a full absolute path per hit — and a store path can be 100+ characters, so twenty hits cost kilobytes for information already carried by the bare filename.

> **`grep -L '^repo:'` is store-wide and does not compose with a filter.** If the question is scoped ("which of my *active* projects lack a remote"), the unscoped recipe silently returns a superset and you will report a wrong count. Intersect explicitly:
>
> ```bash
> grep -L '^repo:' "$STORE"/projects/*.md | xargs grep -l '^status: active' | wc -l
> ```
>
> Or do it in one pass from JSON, which is less error-prone: `jq '[.[] | select(has("repo")|not)]'`.

`INDEX.md` is a **generated** rollup table, a pure function of the record files. Never hand-edit it, and don't grep it as a data source — **its rows key on `title`, not `slug`**, so grepping it for a slug yields a false "missing record." Grep `projects/` instead.

### JSON shape

`list --json`, `find --json`, and `show --json` all emit the same array of objects — `show` always with exactly one element. Bare `[]` when nothing matched.

| Field | Notes |
|---|---|
| `title`, `slug`, `path`, `status`, `updated`, `created` | Always present |
| `tags` | Always present in JSON; `[]` when empty (**unlike the frontmatter, which omits the line**) |
| `repo` | **Omitted entirely when the project has no git remote** |
| `body` | **Omitted entirely when empty** |

Do not read a missing `repo` key as a serializer bug — it means no remote is recorded. Select on key presence, not on emptiness: `select(has("repo")|not)`, never `select(.repo == "")` (which matches nothing and reports a false zero). For display, `.repo // "none"`.

### Empty results are exit 0, not errors

This tool reports "nothing matched" as success. Two silent-empty cases to guard:

| Command | No-match output | Exit |
|---|---|---|
| `find <query>` | `no matches` (or `[]`) | **0** |
| `list --status <typo>` | `no projects` | **0** |

**`--status` is not validated on read.** `list --status activ` returns `no projects` with exit 0 — indistinguishable from a genuinely empty result. If a status filter returns nothing, re-check the spelling against the vocabulary before reporting "you have none."

Genuine failures do exit **1**: an unknown slug (`error: no project with slug "x"`), an out-of-vocabulary status on `set`, an unreadable store.

### If two counts disagree, check the store's git log

The store is a git repo and every mutation commits, so another session or agent writing to it will shift your numbers mid-task. Before assuming you made an error, check:

```bash
git -C "$STORE" log --oneline -5
git -C "$STORE" status --porcelain
```

Commit subjects are the commands themselves (`here <slug>`, `set <slug>`, `scan: +N ~N !N`), so the log tells you exactly what changed and when.

## Status: What It Means, and What It Doesn't

The vocabulary is configured, not hard-coded. Read it before asserting anything about states:

```bash
cat "$STORE"/config.toml
```

```toml
scan_roots = []
statuses = ["vision", "active", "paused", "polishing", "done", "archived"]
default_status = "vision"
scan_ignore = ["node_modules", "vendor", ".git", "target", "dist", "build"]
```

| Status | Meaning |
|---|---|
| `vision` | Drafting the vision; not yet building |
| `active` | In development |
| `paused` | On hold, will return |
| `polishing` | Nearly done, cleanup and edges |
| `done` | Pretty done / shipped |
| `archived` | Dead, or kept only for reference |

> **`vision` on a scan-created record usually means "never triaged," not "at the vision stage."** `scan` stamps every project it discovers with `default_status`. In a store built by a bulk scan, nearly every record reads `vision` — that is the default leaking through, not a curated judgment.

**Always check the distribution before reporting a status as a finding:**

```bash
grep -h '^status:' "$STORE"/projects/*.md | sort | uniq -c | sort -rn
```

If one status dominates and matches `default_status`, the field carries no information. Say so, and **answer the state question from disk instead** — which the index cannot do for you:

> **A status filter is not automatically a meaningful filter.** When the user asks for "everything with status X" and the result count approaches the store size, the filter selected *nothing* — you are handing back the entire index dressed up as a curated subset. Compare `jq length` against `ls "$STORE"/projects/*.md | wc -l` and tell the user plainly when the two match.
>
> The same goes for `tags` in a scan-built store: `scan` never assigns tags, so the field is typically `[]` on every record. Before promising tags in a deliverable, confirm any exist: `jq '[.[]|select(.tags|length>0)]|length'`.

```bash
git -C <project-path> status -sb
git -C <project-path> log -1 --format='%h %ad %s' --date=short
git -C <project-path> remote -v
```

### The states the index cannot show you

Two distinct real-world states both appear in the index as "a record with no `repo`," and neither is visible without looking at disk:

- **Git-init'ed but never committed** — a real directory, `git init`ed, no remote, zero commits, everything untracked. `git log` fails with *"does not have any commits yet"*. This is common for freshly-started work and is worth reporting as its own state.
- **A real project whose remote simply was never recorded.**

### What `updated` actually means

`scan` sets `updated` from the repo's **last-commit date**, and it is monotonic — a later scan never moves it backwards. But **a repo with zero commits has no last-commit date, so it falls back to the scan date instead.**

So `updated` equal to the scan date is ambiguous: it can mean "committed that day" or "has never been committed at all." A hand-run `touch` is the only unambiguous "I worked on this" signal.

**To resolve the ambiguity, learn the scan date from the store's own git log** — scan commits are subjected `scan: +N ~N !N`:

```bash
git -C "$STORE" log --format='%h %ad %s' --date=short | grep '^.* scan:'
```

If a record's `updated` equals a scan commit's date, treat it as a fallback, not a work date.

**Then date the work from disk. Note that `git log -1` fails on exactly the repos that need it** — a zero-commit repo errors with *"does not have any commits yet"*, so the recipe dead-ends where it matters most. Fall back to file mtimes:

```bash
git -C <path> log -1 --format='%h %ad %s' --date=short          # real commit date, or fails
find <path> -type f -not -path '*/.git/*' -printf '%TY-%Tm-%Td %p\n' | sort -r | head -5
```

The newest mtime is the best available activity signal for an uncommitted tree.

`status` and `updated` are independent: `status` is what state the project is in, `updated` is when it was last worked on. A newly registered project already carries today's `updated`, so `touch` right after `here` is a no-op.

## Writing to the Index

**Every mutating command commits to the store's git repo, and pushes if a remote is configured.** `here`, `touch`, `set`, `rm`, and a non-dry-run `scan` all regenerate `INDEX.md`, `git add -A && git commit`, then `pull --rebase && push`. A push failure is a loud stderr warning, not an error — the local commit stands and the store is simply ahead of its remote.

### The common workflow: register, then curate

Adding a new project is always two commands, because `here` creates the record and `set` curates it:

```bash
cd /home/you/src/new-project
goprojdex --store "$STORE" here
# -> registered radio-telemetry-daemon (/home/you/src/new-project)
#              ^^^^^^^^^^^^^^^^^^^^^^^ the slug you need for the next command

goprojdex --store "$STORE" set radio-telemetry-daemon \
  --status active --tag go --tag mqtt --desc "Telemetry daemon for the shop floor"

cat "$STORE"/projects/radio-telemetry-daemon.md    # confirm
```

> **`here` prints the slug it assigned — capture it.** The slug is derived from the **README's `# ` heading**, not from the directory name, so a directory called `new-project` can perfectly well produce the slug `radio-telemetry-daemon`. That stdout line is the quickest way to learn it, and guessing from the directory name is wrong whenever a README exists. If you lose it, `show <abs-path>` recovers the record without needing the slug at all.

**Slug collisions never clobber.** If the derived slug is already taken by an unrelated record, `here` appends a numeric suffix — `my-project`, then `my-project-2`, `my-project-3`. So a slug ending in `-2` or higher usually signals a duplicate title, not a deliberate name.

### `here` — register the current directory

**`here` takes no arguments.** It reads the working directory and errors on any argument, so you must `cd` (or `cd <dir> && goprojdex here` in a single command). There is no way to register a path you are not standing in — but `set --path` can correct one afterwards.

On a new project it seeds `title` and the body from the README's heading and intro (falling back to the directory basename), reads `repo` from `git remote get-url origin`, and assigns `default_status`. If the path or repo already matches an existing record, it refreshes `path`/`repo` on that record instead of creating a duplicate.

### `touch` — bump last-worked-on to today

```bash
goprojdex touch            # resolves the working directory
goprojdex touch .          # identical
goprojdex touch <slug>     # explicit
```

With no argument or `.`, it walks **upward** from the working directory to the nearest enclosing registered project — so it works from a subdirectory, and inside nested repos the innermost project wins. If nothing is registered at or above the cwd it errors with a pointer to run `here` first.

### `set` — edit curated fields

**The slug is positional and must come first**, before any flags:

```bash
goprojdex set gofi-unifi --status active --tag networking --untag old-tag \
  --desc "UniFi fixed-host CLI"
```

| Flag | Effect |
|---|---|
| `--title` | Sets the title. **Does not change the slug** — the slug is stable once assigned. |
| `--status` | Must be in the configured vocabulary, or it errors (exit 1). |
| `--path` | Corrects a moved project. |
| `--repo` | Sets the git remote URL. |
| `--tag` | Adds a tag. Repeatable; adding an existing tag is a no-op. |
| `--untag` | Removes a tag. Repeatable. |
| `--desc` | **Replaces the entire body.** There is no append. |

**On `--desc`: when the user dictates a description, just set it** — replacing the README-seeded text is the intended outcome. Only read-then-compose when the user asks to *add to* an existing description, since there is no append flag.

Archiving is a status change, not a separate command: `goprojdex set <slug> --status archived`.

### `rm` and `scan` — confirm before running

> **REQUIRED — review gate.** `rm` is a hard delete of a curated record, and `scan` bulk-writes across the whole index. Both commit immediately. Do not run either on the user's behalf without explicit confirmation of the specific action.
>
> - **`rm <slug>`** destroys the curated title, status, tags, and body. There is no undo beyond `git revert` inside the store. Show the user the record (`cat "$STORE"/projects/<slug>.md`) and get approval before deleting.
> - **`scan`** always has a `--dry-run`. Run it, show the report, get approval, then run for real.

```bash
goprojdex scan ~/src --dry-run     # report only: no writes, no commit
goprojdex scan ~/src               # apply
```

With no roots, `scan` uses `scan_roots` from `config.toml`, and errors if that is empty. It treats any directory containing `.git` as a project and **keeps descending**, so repos nested inside repos are indexed too; `--no-nested` stops at the first `.git`. `--include-markers` also treats `go.mod` / `package.json` / `Makefile` directories as projects.

The report reads `scan: N new, N moved, N missing, N skipped`. **`missing` means a recorded path no longer exists on disk — it is reported, never auto-deleted.** Follow up with `set --status archived` or `rm`. `skipped` counts unreadable directories, which never abort the scan.

### Curated vs derived — the rule scan obeys

- **Derived** (`path`, `repo`, and the `updated` floor) come from the filesystem and git. `scan` refreshes them freely.
- **Curated** (`title`, `status`, `tags`, body) are the user's. `scan` sets them once on first discovery, then **never touches them again**.

So a `set` is durable: a later `scan` will not undo it.

## Interpreting a Scanned Store

A bulk `scan` indexes anything with a `.git`, which sweeps in a great deal that is not really "a project." **Before reading any keyword result, find out how much of the store is noise** — in a real store it can be 40% or more:

```bash
grep -h '^path:' "$STORE"/projects/*.md | grep -c 'mirror/'          # mirrors
grep -h '^path:' "$STORE"/projects/*.md | grep -cE 'worktrees|/vendor/|/themes/'
```

What to look for, and how to report it:

- **Local mirror trees** — the reliable tell is a **repeated path segment** (`.../github-docs-mirror/data/mirror/...`), not the duplicate titles or remote-spelling differences you might expect. Find the segment once and filter on it for the rest of the task. A mirror yields a second record for a repo the user also has checked out.
- **Mirror-only projects** — some projects exist *only* as a mirror, with no working checkout anywhere. Prove it before reporting, but **don't assume the non-mirror path is a mechanical substring removal**: a mirror tree usually inserts an org segment too (`.../data/mirror/<org>/<repo>`), so the real checkout would be at `<src-root>/<org>/<repo>` or `<src-root>/<repo>`, not at the path you get by deleting `data/mirror/`. Derive the candidate from the repo name and `test -d` it. If nothing is there, say plainly that the only copy on disk is a read-only mirror and the user would need to clone — do not present the mirror path as "where your project lives."
- **Monorepo and Yocto-style trees** — one project with many submodules explodes into dozens of records (a Yocto tree yields `bitbake`, `oe-core`, every `meta-*` layer, every `sources/*`). These will swamp a keyword search by 30:1. Collapse them to their parent project when reporting, and name the parent as the answer.
- **Vendored dependencies and themes** — e.g. a Hugo theme under `website/themes/`.
- **Agent worktrees** — paths containing `.claude/worktrees/`.
- **Git submodules generally** — a submodule's working directory has a `.git` entry, so nesting indexes it as its own project.

When two records look like the same project, prefer the real working checkout, and say why you picked it.

## Common Mistakes

- **Using `find` to read one project** — `show <slug|path|.>` prints the whole record, resolves a path or the cwd, and can't return three near-misses.
- **Guessing a record's filename from a directory path** — the slug comes from the README heading and often shares no substring with the directory. Use `show <abs-path>`, or `grep -l '^path: <abs-path>$'`.
- **Handing back a status-filtered set that is the whole store** — that filter selected nothing. Compare the count to the record count and say so.
- **Promising `tags` from a scan-built store** — `scan` never assigns tags; the field is usually `[]` everywhere. Check before offering it.
- **Reporting "nothing related to X" after one `find`** — substring-only search plus empty bodies hides records whose slug is an abbreviation. Search the acronym too, and grep `^path:`.
- **Enumerating the whole store** — via `list`, `ls`, `grep`, or `cat`. Hundreds of KB, truncated, context destroyed. Use `--limit` on `list`; size first and `head`/`wc -l` the file recipes; redirect a genuine full dump to a file.
- **Expecting `--tag go` to match `golang`** — it matches whole tags, not substrings.
- **Letting the CLI and the greps point at different stores** — set `$STORE` once and use it in both, or you will grep the user's real index while querying a different one.
- **Guessing a `--store` path** — a wrong path silently creates an empty store and every answer becomes "no projects" at exit 0. Omit `--store` unless the user named one.
- **Putting `--store` after the subcommand** — it is a global flag and must precede the command, or you get `flag provided but not defined: -store`.
- **Treating "no matches" as a failure** — it exits 0. Conversely, a mistyped `--status` also returns empty at exit 0; verify the spelling before reporting absence.
- **`select(.repo == "")`** — empty `repo` and `body` are *omitted*, in both the JSON and the frontmatter. Use `has("repo")|not`, and don't read a missing `tags:` line as a broken store.
- **Using the store-wide `grep -L '^repo:'` to answer a filtered question** — it doesn't compose; intersect with the filter or work from JSON.
- **Reporting `vision` as a curated state** — it is `default_status`, stamped on everything `scan` finds. Check the distribution, then answer from disk with `git status`/`git log`.
- **Reading `updated` as "worked on that day"** — a repo with zero commits gets the scan date as a fallback. Cross-check the scan dates in `git -C "$STORE" log`, then date the work from `git log -1` or, when that fails, file mtimes.
- **Expecting `find` to OR the query words or rank results** — it is one lowercase substring test, sorted by `updated` descending.
- **Assuming a feature is missing when the binary is old** — `unknown command "show"` or `flag provided but not defined: -limit` means a stale build, not a store problem. `make install` from the source repo.
- **Grepping `INDEX.md` for a slug** — it is generated and keys on title. Grep `projects/` instead, and never hand-edit `INDEX.md` (run `reindex`).
- **Passing a path to `here`** — it takes no arguments; `cd` first, then fix with `set --path` if needed.
- **Guessing the new slug from the directory name** — it comes from the README heading. Capture the slug `here` prints.
- **Using `--desc` to add to a description** — it replaces the whole body. Read, compose, then set.
- **Assuming your own numbers are wrong when counts shift** — another session may be writing. Check `git -C "$STORE" log`.
- **Running `rm` or a live `scan` unprompted** — both commit immediately; confirm first, and use `scan --dry-run` to preview.
