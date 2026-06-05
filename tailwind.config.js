/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: "#09111f",
        panel: "#101b2f",
        panelAlt: "#13233d",
        accent: "#56f0c7",
        accentSoft: "#1f6f73",
        danger: "#ff5f6d",
        warn: "#f7c948",
        text: "#e7edf7",
        muted: "#8ba0bd"
      },
      fontFamily: {
        sans: ["Segoe UI", "system-ui", "sans-serif"],
      },
      boxShadow: {
        glow: "0 0 0 1px rgba(86, 240, 199, 0.12), 0 12px 40px rgba(5, 16, 31, 0.5)",
      }
    },
  },
  plugins: [],
};

