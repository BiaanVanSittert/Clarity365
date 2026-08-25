import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Clarity365: Multi-Tenant M365 IRM & Security Suite",
  description: "Enterprise Information Rights Management (IRM) and Security Posture Dashboard for Microsoft 365 MSPs and IT Security Teams.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        {/* Applies the persisted/system theme before hydration to avoid a
            flash of the wrong theme on load. */}
        <script
          dangerouslySetInnerHTML={{
            __html: `(function(){try{var t=localStorage.getItem('clarity365_theme');var d=t?t==='dark':window.matchMedia('(prefers-color-scheme: dark)').matches;if(d)document.documentElement.classList.add('dark');}catch(e){}})();`,
          }}
        />
      </head>
      <body className="antialiased bg-background text-foreground selection:bg-slate-900 selection:text-white dark:selection:bg-slate-100 dark:selection:text-slate-900" suppressHydrationWarning>
        {children}
      </body>
    </html>
  );
}
