/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        navy: {
          950: '#070B14',
          900: '#0B1120',
          850: '#0E1726',
          800: '#0F172A',
          750: '#152136',
          700: '#1E293B',
          600: '#334155',
          500: '#475569',
        },
        cyber: {
          cyan: '#06B6D4',
          blue: '#3B82F6',
          emerald: '#10B981',
          rose: '#EF4444',
          amber: '#F59E0B',
          violet: '#8B5CF6',
        }
      },
      fontFamily: {
        mono: ['Fira Code', 'JetBrains Mono', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
      }
    },
  },
  plugins: [],
}
