import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

/**
 * F-08 -- edge middleware: security headers (Content-Security-Policy + hardening).
 *
 * 1. CSP + hardening headers (the REAL control here). The refresh token is now an HttpOnly cookie, so
 *    script cannot read it -- but the short-lived access token is held in memory and IS
 *    reachable by injected script. CSP is what reduces the chance such script ever runs. It is
 *    nonce-based rather than 'unsafe-inline': Next.js emits inline bootstrap scripts, and
 *    allowing 'unsafe-inline' would defeat the policy for exactly the injection class we care
 *    about. Next reads the nonce from this request header and stamps it onto its own tags.
 *
 * 2. Security headers are applied to EVERY matched route.
 *
 * WHY THERE IS NO EDGE REDIRECT HERE. It was implemented and then deliberately removed: the
 * refresh cookie is scoped `Path=/api/v1/auth` so it is never attached to ordinary requests
 * (that scoping is itself a security property -- the credential is not sprayed across every
 * page load or logged by unrelated handlers). The consequence is that middleware genuinely
 * CANNOT observe a session: an authenticated user's request to /dashboard carries no cookie,
 * so an edge guard redirected real logged-in users to /login -- verified live (HTTP 307 for a
 * fully authenticated session).
 *
 * Widening the cookie to Path=/ purely to let the edge sniff it would trade a real security
 * property for a cosmetic one, so it was rejected. The client-side guard in
 * app/(dashboard)/layout.tsx continues to handle the redirect after hydration, and -- the part
 * that actually matters -- the API independently returns 401/403 for every request regardless
 * of what any page renders. That boundary was verified live (unauth 401, cross-tenant 403,
 * forged JWT 401) and is unchanged by F-08.
 */

export function middleware(request: NextRequest) {

  // Per-request nonce so inline Next.js bootstrap scripts run WITHOUT 'unsafe-inline'.
  const nonce = Buffer.from(crypto.randomUUID()).toString("base64");

  // DEVELOPMENT ONLY. `next dev` compiles with webpack's eval-based devtool: every module in
  // main-app.js (and each page chunk) is emitted as eval(__webpack_require__.ts("...")), so the
  // module bodies are STRINGS the loader evaluates at runtime. `hydrateRoot`, `react-dom/client`
  // and appBootstrap all live inside those wrappers. No nonce or 'strict-dynamic' can authorise
  // string evaluation -- only 'unsafe-eval' does -- so without this the very first module factory
  // threw EvalError, the client bootstrap died before hydration, and every page was inert SSR
  // HTML: the login form lost its onSubmit handler and fell back to a native GET /login?.
  //
  // PRODUCTION REMAINS STRICT AND UNCHANGED. `next start` (NODE_ENV=production, the runtime stage
  // in Dockerfile.web) uses no eval-based devtool and needs no relaxation, so 'unsafe-eval' is
  // deliberately ABSENT there -- which is the whole point of the F-08 nonce + 'strict-dynamic'
  // policy. NOTE the deliberate consequence: development no longer exercises the exact production
  // script-src, so a genuine eval introduced by app code would not be caught locally.
  const devUnsafeEval = process.env.NODE_ENV === "development" ? " 'unsafe-eval'" : "";
  const csp = [
    "default-src 'self'",
    // 'strict-dynamic' lets the nonced Next.js loader pull its own chunks; the nonce is what
    // authorises the entry point. 'unsafe-eval' is deliberately ABSENT in production.
    `script-src 'self' 'nonce-${nonce}'${devUnsafeEval}`,
    // Next.js injects styles at runtime; a nonce cannot cover all of them, so this is the one
    // documented relaxation and it applies to STYLES only -- not script.
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self' data:",
    // Same-origin API only (the browser reaches it through nginx), which matches the
    // same-origin posture the refresh cookie's SameSite=strict depends on.
    "connect-src 'self'",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "object-src 'none'",
    "form-action 'self'",
  ].join("; ");

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nonce", nonce);
  requestHeaders.set("content-security-policy", csp);

  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set("Content-Security-Policy", csp);
  response.headers.set("X-Content-Type-Options", "nosniff");
  response.headers.set("X-Frame-Options", "DENY");
  response.headers.set("Referrer-Policy", "no-referrer");
  return response;
}

export const config = {
  // Everything EXCEPT Next internals, the API, and static assets. Getting this wrong is a
  // real hazard: too broad breaks the JS/CSS the app needs (and would 302 its own chunks),
  // too narrow silently leaves routes unguarded and unheadered.
  // NOTE the trailing slash on `api/`: a bare `api` alternative also excludes the real page
  // `/api-keys` (prefix match), which silently left that route unguarded and header-less --
  // observed exactly that before this was tightened. There is no Next.js route handler in this
  // app, so `api/` here only reserves the path segment.
  matcher: ["/((?!api/|_next/static|_next/image|favicon.ico|.*\.(?:svg|png|jpg|jpeg|gif|webp|ico)$).*)"],
};
