/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        background: "#070b14",
        foreground: "#f8fafc",
        card: {
          DEFAULT: "#0d1527",
          foreground: "#f8fafc",
          hover: "#111c34",
        },
        navy: {
          950: "#05080f",
          900: "#070b14",
          850: "#0a0f1d",
          800: "#0d1527",
          700: "#131f38",
          600: "#1a2b4c",
          500: "#243b66",
        },
        cyan: {
          glow: "rgba(0, 240, 255, 0.15)",
          electric: "#00f0ff",
          400: "#22d3ee",
          500: "#06b6d4",
          600: "#0891b2",
        },
        violet: {
          glow: "rgba(139, 92, 246, 0.15)",
          electric: "#8b5cf6",
          500: "#8b5cf6",
          600: "#7c3aed",
        },
      },
      fontFamily: {
        sans: ["Inter", "-apple-system", "BlinkMacSystemFont", "Segoe UI", "Roboto", "sans-serif"],
        mono: ["JetBrains Mono", "SFMono-Regular", "Menlo", "Monaco", "Consolas", "monospace"],
      },
      boxShadow: {
        "glow-cyan": "0 0 20px -3px rgba(0, 240, 255, 0.25)",
        "glow-cyan-sm": "0 0 10px -2px rgba(0, 240, 255, 0.2)",
        "glow-violet": "0 0 20px -3px rgba(139, 92, 246, 0.25)",
        "card-subtle": "0 4px 20px -2px rgba(0, 0, 0, 0.5)",
      },
      animation: {
        "pulse-slow": "pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite",
        "scan-line": "scanline 2.5s ease-in-out infinite",
        "spin-slow": "spin 8s linear infinite",
      },
      keyframes: {
        scanline: {
          "0%, 100%": { transform: "translateY(0%)" },
          "50%": { transform: "translateY(100%)" },
        }
      }
    },
  },
  plugins: [],
}
