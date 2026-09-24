# How to Package Agent Skills as a Claude Code Plugin

This guide covers everything needed to go from a collection of `SKILL.md` files to an installable plugin distributed through a GitHub-based marketplace.

---

## Concepts First

**Skill** — a folder containing a `SKILL.md` file. The content the agent loads and follows. The unit of authoring.

**Plugin** — a directory that bundles one or more skills (plus optional hooks, MCP servers, agents, LSP configs). The unit of distribution and installation.

**Marketplace** — a git repo containing a `marketplace.json` catalog that lists plugins. The unit of discovery.

The relationship: you author skills, bundle them into a plugin, publish the plugin in a marketplace, users install via `/plugin install`.

Standalone skills (files dropped in `.claude/skills/`) get short names: `/code-review`.
Plugin skills are namespaced: `/my-plugin:code-review`. This prevents conflicts when multiple plugins define similarly named skills.

---

## 1. Skill Authoring

Each skill is a directory with a `SKILL.md`:

```
skills/
└── code-review/
    └── SKILL.md
```

`SKILL.md` structure:

```markdown
---
name: code-review
description: "Reviews code for architecture, correctness, and maintainability. Triggers on: review this code, check my PR, assess code quality."
disable-model-invocation: false
---

# Code Review

When reviewing code, check these four categories...
```

### Frontmatter fields

| Field | Required | Purpose |
|-------|----------|---------|
| `name` | No (defaults to directory name) | Invocation name within the plugin namespace |
| `description` | Yes | One-line trigger text. Claude matches this against the task to decide whether to auto-invoke. Write it as a list of trigger phrases. |
| `disable-model-invocation` | No (default: false) | Set `true` to make the skill manual-only — only invoked when explicitly called with `/plugin:skill`. Use for orchestration/meta skills that should not auto-fire. |

### Skill body best practices

- **Lead with the trigger condition** — the first sentence should state when to use this skill
- **Use structured markdown** — headings, numbered steps, tables. Agents navigate structure better than prose paragraphs.
- **State success criteria explicitly** — what does "done" look like?
- **Reference other skills by name** when they chain, but don't assume they're available
- **Keep progressive disclosure in mind** — the description loads every turn (cheap); the body loads only on activation (use it for depth)

### Skill arguments

Use `$ARGUMENTS` to capture text passed after the skill name:

```markdown
---
description: Deploy the named service to the target environment
---

Deploy service "$ARGUMENTS" following the deployment checklist...
```

Invoked as: `/my-plugin:deploy api-gateway staging`

### Supporting files

A skill directory can contain more than just `SKILL.md`:

```
skills/
└── deploy/
    ├── SKILL.md
    ├── checklist.md        # loaded by the skill body via relative reference
    └── scripts/
        └── validate.sh     # executed by the agent during the skill
```

Reference supporting files from the skill body using relative paths.

---

## 2. Plugin Structure

```
my-plugin/
├── .claude-plugin/
│   └── plugin.json         # manifest (required for marketplace distribution)
├── skills/
│   └── <skill-name>/
│       └── SKILL.md
├── agents/                 # optional: custom sub-agents
│   └── <agent-name>/
│       └── AGENT.md
├── hooks/
│   └── hooks.json          # optional: event hooks
├── bin/                    # optional: executables added to PATH
├── .mcp.json               # optional: MCP server configs
├── .lsp.json               # optional: LSP server configs
├── settings.json           # optional: default settings when plugin is active
└── README.md
```

**Critical**: `commands/`, `skills/`, `agents/`, `hooks/` must be at the **plugin root**, not inside `.claude-plugin/`. Only `plugin.json` lives in `.claude-plugin/`.

### Single-skill shortcut

A plugin shipping exactly one skill can place `SKILL.md` directly at the plugin root instead of creating a `skills/` directory:

```
my-plugin/
├── .claude-plugin/
│   └── plugin.json
└── SKILL.md
```

Use the `skills/` layout for anything that might grow beyond one skill.

---

## 3. The Manifest (`plugin.json`)

```json
{
  "name": "my-plugin",
  "description": "Short description shown in the plugin manager.",
  "version": "1.0.0",
  "author": {
    "name": "Your Name"
  },
  "homepage": "https://github.com/yourusername/my-plugin",
  "repository": "https://github.com/yourusername/my-plugin",
  "license": "MIT"
}
```

| Field | Purpose |
|-------|---------|
| `name` | Plugin identifier and skill namespace prefix. Skill `/hello` in plugin `"name": "my-plugin"` invokes as `/my-plugin:hello`. |
| `description` | Shown in the plugin manager. Keep it under two sentences. |
| `version` | Optional. When set, users receive updates only when you bump this. When omitted, every git commit is treated as a new version. |
| `author` | Attribution. |
| `homepage` | Link shown in the plugin manager detail pane. |

If the manifest is omitted entirely, Claude Code infers the plugin from the directory structure alone. The manifest is required for marketplace distribution.

---

## 4. Hooks in Plugins

Hooks let your plugin react to agent events. Place them in `hooks/hooks.json`:

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Write|Edit",
        "hooks": [
          {
            "type": "command",
            "command": "jq -r '.tool_input.file_path' | xargs npm run lint:fix"
          }
        ]
      }
    ],
    "SessionStart": [
      {
        "matcher": "startup",
        "hooks": [
          {
            "type": "command",
            "command": "./bin/session-init"
          }
        ]
      }
    ]
  }
}
```

Hook scripts that ship with the plugin go in `bin/` and are referenced as `./bin/<script>` (relative to the plugin dir). The hook receives agent event data as JSON on stdin — use `jq` to extract fields.

Available hook events: `PreToolUse`, `PostToolUse`, `SessionStart`, `SessionStop`, `Notification`.

**Important**: avoid hooks that reference absolute paths like `~/.claude/hooks/...` in a shared plugin — those paths won't exist on other machines. Bundle the scripts in `bin/` instead.

---

## 5. Testing Locally

Test without installing via the `--plugin-dir` flag:

```bash
claude --plugin-dir ./my-plugin
```

Inside the session:
```
/my-plugin:hello          # invoke a skill
/help                     # verify skill appears in listing
/reload-plugins           # pick up changes without restarting
```

Also accepts a zip archive (useful for testing CI build artifacts):

```bash
claude --plugin-dir ./my-plugin.zip
```

Load multiple plugins simultaneously during development:

```bash
claude --plugin-dir ./plugin-one --plugin-dir ./plugin-two
```

Validate before publishing:

```bash
claude plugin validate
```

---

## 6. Versioning

Two strategies:

**Explicit version** — set `"version": "1.0.0"` in `plugin.json`. Users receive updates only when you bump this field and push. Good for stable, curated releases.

**Commit-SHA versioning** — omit `version`. Every commit is a new version. Users always get the latest. Good for fast-moving personal plugins where you always want the tip.

For public plugins shared with others, use explicit versioning so they don't get breaking changes unexpectedly.

---

## 7. Creating a Marketplace

A marketplace is a git repo with a single file at `.claude-plugin/marketplace.json`:

```
my-marketplace/
└── .claude-plugin/
    └── marketplace.json
```

```json
{
  "plugins": [
    {
      "name": "my-plugin",
      "description": "Short description.",
      "source": {
        "type": "github",
        "repo": "yourusername/my-plugin"
      }
    },
    {
      "name": "another-plugin",
      "description": "Another description.",
      "source": {
        "type": "github",
        "repo": "yourusername/another-plugin"
      }
    }
  ]
}
```

Push the marketplace repo to GitHub. Users register it with:

```
/plugin marketplace add yourusername/my-marketplace
```

Then install individual plugins from it:

```
/plugin install my-plugin@yourusername
```

The marketplace and the plugin(s) can be in separate repos (recommended) or the same repo. Separate repos let you add new plugins to the catalog without touching plugin code, and keep git histories clean.

---

## 8. Team / Project Distribution

To auto-register your marketplace for everyone on a project, add it to the project's `.claude/settings.json`:

```json
{
  "extraKnownMarketplaces": {
    "my-team": {
      "source": {
        "source": "github",
        "repo": "your-org/claude-marketplace"
      }
    }
  }
}
```

Commit this file. When teammates trust the repository, Claude Code prompts them to register the marketplace and install any listed plugins.

For plugins you want on every machine automatically (not just suggested), add them to `"enabledPlugins"` in managed settings — but that's an org-admin feature.

---

## 9. Installation Scopes

When installing, choose the right scope:

| Scope | Location | Shared? | Use for |
|-------|----------|---------|---------|
| User | `~/.claude/` | No | Personal tools across all projects |
| Project | `.claude/settings.json` | Yes, committed | Team-shared tools for this repo |
| Local | `.claude/settings.local.json` | No | Personal project-specific experiments |

Install to a specific scope from the CLI:

```bash
claude plugin install my-plugin@marketplace --scope project
claude plugin install my-plugin@marketplace --scope user
```

---

## 10. Full Lifecycle Example

```bash
# Develop
mkdir my-plugin && cd my-plugin
mkdir -p .claude-plugin skills/hello
echo '{"name":"my-plugin","description":"My plugin","version":"1.0.0"}' > .claude-plugin/plugin.json
cat > skills/hello/SKILL.md << 'EOF'
---
description: Greet the user. Triggers on: say hello, greet me.
---
Greet the user warmly by name using "$ARGUMENTS" and ask what they need.
EOF

# Test locally
claude --plugin-dir .
# in session: /my-plugin:hello World

# Validate
claude plugin validate

# Publish
git init && git add . && git commit -m "initial"
gh repo create yourusername/my-plugin --public --push

# Create marketplace
mkdir my-marketplace && cd my-marketplace
mkdir -p .claude-plugin
cat > .claude-plugin/marketplace.json << 'EOF'
{"plugins":[{"name":"my-plugin","description":"My plugin.","source":{"type":"github","repo":"yourusername/my-plugin"}}]}
EOF
git init && git add . && git commit -m "initial"
gh repo create yourusername/claude-marketplace --public --push

# Install
/plugin marketplace add yourusername/claude-marketplace
/plugin install my-plugin@yourusername
/reload-plugins

# Remove atomically
/plugin marketplace remove yourusername
# or just uninstall the plugin:
/plugin uninstall my-plugin@yourusername
```

---

## 11. Cross-Agent Portability

Claude Code's `SKILL.md` format is the [Agent Skills open standard](https://agentskills.io), adopted by 30+ agents including Cursor, Gemini CLI, GitHub Copilot, OpenAI Codex, Roo Code, and more. A skill you write for Claude Code works in any of them without modification.

The Claude Code plugin system (marketplace, `plugin.json`, hooks, agents) is Claude Code-specific. The `SKILL.md` files inside are portable. The plugin wrapper is not.

To distribute skills for cross-agent use, the [skills.sh](https://skills.sh) ecosystem provides a `npx skills add` CLI that installs individual skills into whatever agent's config directory is appropriate for the current machine.

---

## Quick Reference

```
# Scaffold a plugin
claude plugin init my-plugin

# Test locally
claude --plugin-dir ./my-plugin

# Validate before publishing
claude plugin validate

# List installed plugins
/plugin list

# Install from marketplace
/plugin marketplace add owner/marketplace-repo
/plugin install plugin-name@marketplace-name
/reload-plugins

# Disable without removing
/plugin disable plugin-name@marketplace-name

# Remove completely
/plugin uninstall plugin-name@marketplace-name

# Remove all plugins from a marketplace (atomic)
/plugin marketplace remove marketplace-name
```
