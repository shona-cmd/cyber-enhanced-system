import Link from 'next/link';          // ← This is the correct one
import './globals.css';              // if you have global styles

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>
        <div>
          <h1>App Router</h1>

          <nav>
            <ul style={{ listStyle: 'none', padding: 0 }}>
              <li>
                {/* ✅ Next.js Link – works perfectly */}
                <Link href="/">Dashboard</Link>
              </li>
              <li>
                <Link href="/settings">Settings</Link>
              </li>
            </ul>
          </nav>

          <main>{children}</main>
        </div>
      </body>
    </html>
  );
}
