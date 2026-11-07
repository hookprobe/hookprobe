// ADR 0001: Astro (shell) + SolidJS (islands/SPA).
// output: 'static' → built static assets served by Rust/Axum at runtime.
// No Node SSR adapter — the edge device (Pi5/N100/RK3588) runs only the
// Axum binary; Node has zero runtime presence there.

import { defineConfig } from 'astro/config';
import solidJs from '@astrojs/solid-js';

export default defineConfig({
  integrations: [solidJs()],
  output: 'static',
});
