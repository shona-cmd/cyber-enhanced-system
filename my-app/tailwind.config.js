/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,jsx,ts,tsx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        orbitron: ['Orbitron', 'sans-serif'],
        roboto: ['"Roboto Mono"', 'monospace'],
      },
      colors: {
        cyan: {
          400: '#06b6d4',
          500: '#0891b2',
        }
      }
    },
  },
  plugins: [],
}
