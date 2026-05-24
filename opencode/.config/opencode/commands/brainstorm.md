---
description: "Design gate: explore intent and requirements before any implementation. Hard gate — no code until design is approved."
agent: planner
---

Load the `brainstorming` skill and follow it exactly.

Topic: $ARGUMENTS

HARD GATE: Do not write any code, scaffold any project, or take any implementation action until you have presented a design and the user has explicitly approved it.

Process:
1. Explore project context (files, docs, recent commits)
2. Ask clarifying questions one at a time
3. Propose 2-3 approaches with trade-offs and your recommendation
4. Present design sections, get approval after each
5. Write design doc to `docs/specs/YYYY-MM-DD-<topic>-design.md`
6. Self-review the spec; iterate until approved
7. Ask user to review the spec before proceeding
8. Load `writing-plans` skill to create the implementation plan
