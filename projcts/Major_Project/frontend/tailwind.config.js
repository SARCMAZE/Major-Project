/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        ink: "#04131f",
        ocean: "#0f2740",
        cyan: "#3dd9d6",
        lime: "#a3e635",
        ember: "#fb7185",
        sand: "#f5e6c8",
      },
      fontFamily: {
        display: ["Space Grotesk", "ui-sans-serif", "system-ui"],
        body: ["DM Sans", "ui-sans-serif", "system-ui"],
      },
      boxShadow: {
        panel: "0 24px 80px rgba(0, 0, 0, 0.35)",
      },
    },
  },
  plugins: [],
};
