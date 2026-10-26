/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        background: '#0a0a0a', // Deep dark 
        surface: '#171717',    // Slightly lighter for cards
        primary: '#00ff9d',    // Neon green
        danger: '#ff003c',     // Neon red
      },
    },
  },
  plugins: [],
}