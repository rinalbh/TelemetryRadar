import { defineConfig } from 'vite';
import { sveltekit } from '@sveltejs/kit/vite';
import adapter from '@sveltejs/adapter-static';
import { paraglideVitePlugin } from '@inlang/paraglide-js';
import { paraglideOptions } from './paraglide.config.js';

export default defineConfig({
  plugins: [
    paraglideVitePlugin(paraglideOptions),
    sveltekit({ adapter: adapter({ fallback: 'index.html' }), paths: { relative: false } })
  ],
  server: { port: 5173, strictPort: true }
});
