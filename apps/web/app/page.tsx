// Opt `/` out of static prerendering so Next.js can stamp the per-request CSP nonce from
// middleware.ts into the inline bootstrap scripts. As a build-time prerender this page's HTML
// was frozen with NO nonce, while middleware still sent a rotating `nonce-` in script-src --
// and a nonce in script-src makes the browser ignore 'self' for inline script, so all six
// __next_f bootstrap scripts were blocked and the page never hydrated.
// Unlike /login and /register this needs no wrapper layout: page.tsx is already a server
// component, and segment config is only honoured on server components.
export const dynamic = "force-dynamic";

import { LandingNav } from "@/components/landing/LandingNav";
import { Hero } from "@/components/landing/Hero";
import { Services } from "@/components/landing/Services";
import { AgentsWorkflow } from "@/components/landing/AgentsWorkflow";
import { TrustSection } from "@/components/landing/TrustSection";
import { CTASection } from "@/components/landing/CTASection";
import { Footer } from "@/components/landing/Footer";

export default function Home() {
  return (
    <div className="relative min-h-screen bg-cyber-bg">
      <LandingNav />
      <main>
        <Hero />
        <Services />
        <AgentsWorkflow />
        <TrustSection />
        <CTASection />
      </main>
      <Footer />
    </div>
  );
}
