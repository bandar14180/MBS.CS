import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}", "./lib/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // Cybersecurity brand: deep ink base + cyan/indigo AI accent.
        brand: {
          50: "#eef6ff",
          100: "#d9ecff",
          300: "#7cc4ff",
          400: "#38a8ff",
          500: "#0e8bff",
          600: "#006fe6",
          700: "#0057b4",
        },
        cyber: {
          bg: "#060913",
          panel: "#0b1020",
          border: "#1b2440",
        },
        accent: {
          cyan: "#22d3ee",
          violet: "#7c5cff",
        },
      },
      fontFamily: {
        sans: [
          "Inter",
          "system-ui",
          "-apple-system",
          "Segoe UI",
          "Roboto",
          "Helvetica Neue",
          "Arial",
          "Noto Sans Arabic",
          "sans-serif",
        ],
      },
      boxShadow: {
        glow: "0 0 40px -8px rgba(34, 211, 238, 0.35)",
        "glow-violet": "0 0 50px -10px rgba(124, 92, 255, 0.45)",
      },
      keyframes: {
        "fade-up": {
          "0%": { opacity: "0", transform: "translateY(16px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
        float: {
          "0%, 100%": { transform: "translateY(0)" },
          "50%": { transform: "translateY(-10px)" },
        },
        "pulse-slow": {
          "0%, 100%": { opacity: "0.6" },
          "50%": { opacity: "1" },
        },
        "flow-dash": {
          to: { "stroke-dashoffset": "-24" },
        },
        shimmer: {
          "100%": { transform: "translateX(100%)" },
        },
      },
      animation: {
        "fade-up": "fade-up 0.7s cubic-bezier(0.22, 1, 0.36, 1) both",
        float: "float 6s ease-in-out infinite",
        "pulse-slow": "pulse-slow 4s ease-in-out infinite",
        "flow-dash": "flow-dash 1s linear infinite",
      },
    },
  },
  plugins: [],
};

export default config;
