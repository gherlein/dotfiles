---
description: RESTful API conventions including status codes, pagination, error format, auth
---
REST API design: $@

## Conventions

### URLs
- Nouns, not verbs: `/users`, not `/getUsers`
- Plural resources: `/users`, not `/user`
- Nested for relationships: `/users/{id}/orders`
- Use kebab-case for multi-word resources

### Status Codes
- 200: Success with body
- 201: Created (include Location header)
- 204: Success, no body (DELETE)
- 400: Client error (validation, malformed request)
- 401: Unauthenticated
- 403: Unauthorized (authenticated but insufficient permissions)
- 404: Not found
- 409: Conflict (duplicate, state conflict)
- 422: Unprocessable entity (valid syntax, invalid semantics)
- 429: Rate limited
- 500: Server error (never expose internals)

### Error Format
```json
{
  "error": {
    "code": "VALIDATION_FAILED",
    "message": "Human-readable description",
    "details": [{"field": "email", "reason": "invalid format"}]
  }
}
```

### Pagination
- Cursor-based for large datasets: `?cursor=abc&limit=50`
- Offset-based for small datasets: `?page=2&per_page=50`
- Include `next`, `prev` links in response

### Auth
- Bearer tokens in Authorization header
- Short-lived access tokens, long-lived refresh tokens
- API keys for service-to-service, OAuth2 for user-facing

### Versioning
- URL prefix: `/v1/users`
- Only increment for breaking changes
