---
name: plan-todo
description: Create task checklists in .llm/todo.md and implement tasks one at a time with user confirmation
disable-model-invocation: true
---

# Plan and Todo

Two workflows for managing implementation task lists.

## /plan-todo plan

Create a markdown checklist in `.llm/todo.md`:

1. Analyze the request or current state of the project
2. Break it into tasks, each of which can be implemented and committed independently
3. Arrange tasks in implementation order (dependencies first)
4. Write as a checkbox list:

```markdown
# Implementation Plan: [Feature/Goal]

- [ ] Task 1 description
- [ ] Task 2 description
- [ ] Task 3 description
```

Each task should be specific enough to implement without ambiguity.

## /plan-todo next

Find and implement the next incomplete task from `.llm/todo.md`:

1. Search for `.llm/todo.md` in the current repo (check `git rev-parse --git-common-dir` if needed)
2. Find the first unchecked `- [ ]` item
3. Echo the previous completed task and the current task to the user
4. Confirm the plan with the user before proceeding
5. Focus only on the specific task -- ignore all other tasks and TODOs in source code
6. After successful implementation, mark the task as done: `- [x]`

## Rules

- Do not `git add` anything in `.llm/` -- it is excluded via `.git/info/exclude`
- Keep the task list relevant -- edit it as plans change
- Each task should be committable on its own
