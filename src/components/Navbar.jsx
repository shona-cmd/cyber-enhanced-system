export default function Navbar() {
  return (
    <nav className="bg-gray-800 border-b border-cyan-500 p-2 sm:p-4 sticky top-0 z-50"> {/* Sticky + responsive padding */}
      <div className="max-w-7xl mx-auto flex flex-col sm:flex-row justify-between items-center gap-2"> {/* Stack on mobile */}
        <h1 className="text-xl sm:text-2xl font-bold text-cyan-400 text-center">
          NaashonSecureIoT
        </h1>
        <p className="text-xs sm:text-sm text-gray-400 text-center sm:text-right">MTAC Uganda | NITA-U Certified</p>
      </div>
    </nav>
  );
}
