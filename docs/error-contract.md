# API Error Contract

_Phase 1.4 — applies to every JSON error response from the MBS API._

Every error the API returns (validation, authentication, authorization, not-found,
conflict, and unexpected internal faults) uses **one consistent envelope**. This lets
clients handle errors programmatically while remaining backward-compatible with older
integrations.

## Standard response shape

```json
{
  "detail": "...",
  "error": "stable_error_code",
  "correlation_id": "0f1e2d3c4b5a6978..."
}
```

| Field | Type | Purpose |
| --- | --- | --- |
| `detail` | string \| array | Human-readable message. For validation errors this is the standard FastAPI list of per-field errors. **Unchanged from previous releases** (see [Backward compatibility](#backward-compatibility)). |
| `error` | string | A **stable, low-cardinality** machine code for branching in client code. Never changes wording across releases. |
| `correlation_id` | string | The request's trace id, echoed from the `X-Request-ID` request header or generated per request. Also returned in the `X-Request-ID` **response header**. |

## Supported error codes

| `error` | HTTP status | When |
| --- | --- | --- |
| `validation_error` | 422 | Request body/query/path failed schema validation. `detail` is the per-field error list. |
| `unauthorized` | 401 | Missing/invalid/expired credentials (bearer token or API key). |
| `forbidden` | 403 | Authenticated but not permitted — not a member of the workspace, or missing an RBAC permission. |
| `not_found` | 404 | The resource does not exist **or is outside the caller's scope** (out-of-scope resources return 404, not 403, to avoid leaking their existence). |
| `conflict` | 409 | State conflict (e.g. duplicate unique value). |
| `rate_limited` | 429 | Reserved code for any route-raised 429. **Note:** the global rate limiter emits its own lightweight 429 — see [Rate limiting](#rate-limiting-429). |
| `http_error` | other 4xx | Any 4xx without a more specific code (e.g. 405). |
| `internal_error` | 500 | An unhandled server-side fault. `detail` is always the fixed string `"Internal Server Error"`. |

The `error` value is drawn from a fixed set, so the `mbs_api_errors_total{type}` metric
stays low-cardinality (the label is the code above — never a path, id, or message).

## Correlation IDs

Every request is bound to a correlation id by `ObservabilityMiddleware`:

- If the client sends an `X-Request-ID` header, that value is **honored and propagated**.
- Otherwise a new id is generated.
- The id is returned on **every** response in the `X-Request-ID` header, and included in
  the body of **error** responses as `correlation_id`.

This gives one identifier that ties together: the client-visible error, the structured
server log line for that request, and (in a load-balanced deployment) the specific worker
that handled it.

### Debugging workflow

1. A client hits an error. Capture the `correlation_id` from the response body (or the
   `X-Request-ID` response header).
2. Search the structured logs for that id:
   ```
   correlation_id="<the id>"
   ```
   Error log lines carry `event="api.error"` plus `error`, `status`, `method`, and `path`.
3. For `internal_error` (500), the matching server log line includes the **full exception
   and traceback** (logged server-side only — never sent to the client). 4xx are logged
   without a traceback (client faults, not server bugs).
4. To trace a request proactively (e.g. from a frontend or another service), send your own
   `X-Request-ID` and it will appear verbatim in both the response and the logs.

## Backward compatibility

The envelope is **purely additive**. The historical `detail` field is preserved verbatim
for every error type — existing clients and tests that read `response.json()["detail"]`
continue to work unchanged. Only the `error` and `correlation_id` keys (and the
re-asserted `X-Request-ID` header) are new.

## No sensitive information is returned

- `internal_error` responses **never** include the exception message, type, stack trace,
  or any secret. The body is always exactly:
  ```json
  { "detail": "Internal Server Error", "error": "internal_error", "correlation_id": "..." }
  ```
  The full detail is available only in the server logs, keyed by `correlation_id`.
- 4xx `detail` messages are the application's own human-readable strings and do not echo
  internal state, credentials, or stack information.

## Rate limiting (429)

The global rate limiter (`RateLimitMiddleware`) runs **before routing and exception
handling** as an early short-circuit. Its 429 response **intentionally stays outside the
JSON error envelope** and keeps its lightweight shape:

```json
{ "detail": "Rate limit exceeded. Try again later." }
```

with a `Retry-After` header. Rationale:

- It is a middleware-level protection, not an application error, so it must be cheap and
  independent of the routing/handler stack it is protecting.
- It still carries the `X-Request-ID` correlation header (the limiter runs **inside**
  `ObservabilityMiddleware`, which stamps the header on the way out), so it remains
  traceable.

The `rate_limited` error code above is therefore reserved for any 429 that a route itself
raises via `HTTPException` — those flow through the standard envelope. This behavior is
by design and is **not** slated for change in Phase 1.4.
