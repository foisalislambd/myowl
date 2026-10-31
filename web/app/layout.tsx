import type { Metadata, Viewport } from "next";
import "@fontsource/inter/latin-400.css";
import "@fontsource/inter/latin-500.css";
import "@fontsource/inter/latin-600.css";
import "@fontsource/inter/latin-700.css";
import "@fontsource/jetbrains-mono/latin-400.css";
import "@fontsource/jetbrains-mono/latin-500.css";
import "@fontsource/jetbrains-mono/latin-700.css";
import "@fontsource/orbitron/latin-500.css";
import "@fontsource/orbitron/latin-700.css";
import "@fontsource/orbitron/latin-900.css";
import "./globals.css";
import { AppShell } from "@/components/shell";
import { FxProvider } from "@/lib/fx";
import { ThemeProvider, themeInitScript } from "@/lib/theme";

export const metadata: Metadata = {
  title: "myOwl // Command Center",
  description: "Everything about your server and its network in one place",
  robots: { index: false, follow: false },
  icons: { icon: "/favicon.svg" },
};
export const viewport: Viewport = { width: "device-width", initialScale: 1 };

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark" suppressHydrationWarning>
      <head>
        {/* Apply the saved colour theme before first paint (no flash of the default theme). */}
        <script dangerouslySetInnerHTML={{ __html: themeInitScript }} />
      </head>
      <body>
        <ThemeProvider>
          <FxProvider>
            <AppShell>{children}</AppShell>
          </FxProvider>
        </ThemeProvider>
      </body>
    </html>
  );
}
