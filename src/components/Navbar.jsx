import { ShieldCheckIcon } from '@heroicons/react/24/outline';

export default function Navbar() {
  return (
    <nav className="bg-gray-900 border-b border-cyan-500 shadow-lg" role="banner" aria-label="Main navigation">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between items-center py-4 md:justify-start md:space-x-8">
          <div className="flex items-center space-x-3">
            <ShieldCheckIcon className="h-8 w-8 text-cyan-400" />
            <h1 className="text-2xl font-bold text-white tracking-tight">
              NaashonSecureIoT
            </h1>
          </div>
          <p className="hidden md:block text-sm text-gray-300 font-medium">
            MTAC Uganda | NITA-U Certified
          </p>
          <p className="md:hidden text-xs text-gray-400">
            MTAC Uganda | NITA-U Certified
          </p>
        </div>
      </div>
    </nav>
  );
}
