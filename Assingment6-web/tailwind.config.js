/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./views/**/*.ejs", // This will include all HTML files in the views directory and subdirectories
  ],
  theme: {
    extend: {},
    // Optionally, define a custom theme here if needed
  },
  plugins: [
    require('daisyui'), // Adds DaisyUI components
    require('@tailwindcss/typography'), // Adds typography enhancements
  ],
  daisyui: {
    themes: ["fantasy"], // This is an example; adjust the theme as needed
  },
}
