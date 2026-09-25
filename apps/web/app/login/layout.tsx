// Server Component (deliberately no "use client"): Next.js only honours route segment
// config on server components -- collectSegments() skips any module that is a client
// reference -- so this is the layer that can opt /login out of static prerendering.
// That opt-out is what lets Next.js inject the per-request CSP nonce into the HTML.
export const dynamic = "force-dynamic";

export default function LoginLayout({ children }: { children: React.ReactNode }) {
  return children;
}
