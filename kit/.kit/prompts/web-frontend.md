---
description: React/TypeScript conventions, Tailwind/shadcn styling, and frontend testing
---
Frontend work: $@

## Conventions

### React/TypeScript
- Functional components only
- Use TypeScript strict mode
- Props interfaces, not inline types
- Custom hooks for shared stateful logic
- Avoid prop drilling: use context or state management for deep trees
- Meaningful component names that describe their purpose

### Styling
- Tailwind CSS utility classes preferred
- shadcn/ui for component primitives
- No inline styles unless truly dynamic
- Responsive design: mobile-first breakpoints

### Testing
- React Testing Library for component tests
- Test behavior, not implementation details
- Playwright for E2E tests
- Test accessible roles and labels, not CSS selectors

### State Management
- Start with React state and context
- Reach for external state management only when context causes performance issues
- Server state: use TanStack Query or SWR
- Form state: use react-hook-form with zod validation

### Performance
- Lazy load routes and heavy components
- Memoize expensive computations (useMemo, not everything)
- Virtualize long lists
- Optimize images (next/image or equivalent)
