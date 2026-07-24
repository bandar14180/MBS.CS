// Server-side rendering runs inside the web container, where the browser-facing
// NEXT_PUBLIC_API_URL (localhost) doesn't reach the api container — it needs the
// Docker-network service name instead. API_INTERNAL_URL covers that case; the
// browser (client components) always uses NEXT_PUBLIC_API_URL.
const API_BASE_URL =
  typeof window === "undefined"
    ? process.env.API_INTERNAL_URL ?? process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000"
    : process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

export type HealthResponse = {
  status: string;
  service: string;
  environment: string;
};

export async function getHealth(): Promise<HealthResponse> {
  const res = await fetch(`${API_BASE_URL}/health`, { cache: "no-store" });
  if (!res.ok) {
    throw new Error(`API health check failed: ${res.status}`);
  }
  return res.json();
}
