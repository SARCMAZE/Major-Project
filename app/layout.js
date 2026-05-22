import "./globals.css";

export const metadata = {
  title: "Aether SOC L2 Triage Terminal",
  description: "Real-Time Heuristic Correlation & GenAI Security Coprocessor",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
