---
name: rest-api-design
description: RESTful API conventions including status codes, pagination, error format, auth, caching, and OpenAPI documentation
---

# REST API Design

## URL and Method Conventions

- Resource-based URLs with nouns (not verbs): `/api/v1/users`, `/api/v1/orders`
- Version APIs explicitly (URL versioning preferred: `/api/v1/`)
- HTTP methods: GET (read), POST (create), PUT (full replace), PATCH (partial update), DELETE (remove)
- Design for idempotency: GET, PUT, DELETE are idempotent; POST is not

## Status Codes

- 200 OK, 201 Created, 204 No Content
- 400 Bad Request, 401 Unauthorized, 403 Forbidden, 404 Not Found, 409 Conflict, 422 Unprocessable Entity
- 500 Internal Server Error

## Response Structure

Consistent JSON envelope:
```json
{
  "data": {},
  "meta": { "page": 1, "total": 100 },
  "error": null
}
```

## Error Responses

- Consistent format: `{ "error": { "code": "VALIDATION_ERROR", "message": "...", "details": [...] } }`
- Include `X-Request-ID` header for debugging
- Use RFC 7807 problem details format for complex errors

## Pagination and Filtering

- Support limit/offset or cursor-based pagination with metadata
- Filtering, sorting, and field selection via query params
- Use ISO 8601 for dates

## Validation and Security

- Validate request payloads with Zod or similar
- Bearer tokens (JWT) in Authorization header with refresh token rotation
- HTTPS exclusively in production
- Rate limiting per endpoint/user

## Documentation and Performance

- Use OpenAPI/Swagger for API documentation
- HTTP caching headers (`Cache-Control`, `ETag`)
- Response compression (gzip/brotli)
