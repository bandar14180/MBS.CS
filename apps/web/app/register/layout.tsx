// Server Component (deliberately no "use client") -- see app/login/layout.tsx for why the
// segment config has to live on a server component rather than on the client page itself.
export const dynamic = "force-dynamic";

export default function RegisterLayout({ children }: { children: React.ReactNode }) {
  return children;
}
