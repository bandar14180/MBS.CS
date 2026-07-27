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
