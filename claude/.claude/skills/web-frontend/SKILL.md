---
name: web-frontend
description: "React/TypeScript conventions, Tailwind/shadcn styling, frontend testing (testing-library, Playwright). Triggers on: build a React component, TypeScript frontend, Tailwind or shadcn styling, write a frontend test, Playwright e2e, fix a UI bug, React state management."
---

# Web Frontend Guidelines

## React and TypeScript

- Use React functional components exclusively
- Use hooks (useState, useMemo) for state management
- Prefer types over interfaces (except when extending/merging)
- Prefer named exports over default exports (except Next.js special files)
- Prefer direct named imports (e.g., `import { FC } from 'react'` not `React.FC`)

## Styling

- Use Tailwind CSS classes for styling
- Use shadcn/ui components for consistent UI elements

## Testing

- Use `@testing-library/react` for unit tests
- Test file naming: `*.test.tsx` or `*.spec.tsx`
- Use Playwright for E2E tests
- Ensure components are accessible and responsive

## General

- Ensure components are accessible (ARIA attributes, keyboard navigation)
- Test responsive behavior across viewport sizes
