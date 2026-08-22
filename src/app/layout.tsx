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
    <html lang="en">
      <body className="antialiased bg-white text-slate-900 selection:bg-slate-900 selection:text-white">
        {children}
      </body>
    </html>
  );
}
