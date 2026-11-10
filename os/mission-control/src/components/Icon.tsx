/**
 * Icon — the shell's bundled stroke icons (TR-03: no icon font or CDN; works air-gapped).
 * Decorative by default (aria-hidden); the label always sits next to it.
 */
import { type Component } from 'solid-js';

const PATHS: Record<string, string> = {
  home:      'M3 11l9-7 9 7v9a1 1 0 0 1-1 1h-5v-6h-6v6H4a1 1 0 0 1-1-1z',
  shield:    'M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z',
  network:   'M12 5a2 2 0 1 0 0-.01M5 19a2 2 0 1 0 0-.01M19 19a2 2 0 1 0 0-.01M12 7v4M12 11l-6 6M12 11l6 6',
  online:    'M7 4v14M3 14l4 4 4-4M17 20V6M13 10l4-4 4 4',
  timeline:  'M4 6h16M4 12h10M4 18h13',
  mission:   'M12 12m-8 0a8 8 0 1 0 16 0a8 8 0 1 0-16 0M12 12m-3 0a3 3 0 1 0 6 0a3 3 0 1 0-6 0',
  workspace: 'M4 4h7v7H4zM13 4h7v7h-7zM4 13h7v7H4zM13 13h7v7h-7z',
  observe:   'M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12zM12 12m-3 0a3 3 0 1 0 6 0a3 3 0 1 0-6 0',
  detect:    'M12 3l9 9-9 9-9-9zM12 8v5M12 16v.5',
  investigate: 'M11 11m-7 0a7 7 0 1 0 14 0a7 7 0 1 0-14 0M16 16l5 5',
  automate:  'M4 7h10M18 7h2M4 17h2M10 17h10M16 7m-2 0a2 2 0 1 0 4 0a2 2 0 1 0-4 0M8 17m-2 0a2 2 0 1 0 4 0a2 2 0 1 0-4 0',
  intel:     'M12 3l2.5 5.5L20 9l-4 4 1 6-5-3-5 3 1-6-4-4 5.5-.5z',
  customers: 'M9 8m-3 0a3 3 0 1 0 6 0a3 3 0 1 0-6 0M3 20c0-3 3-5 6-5s6 2 6 5M17 8a3 3 0 0 1 0 6M21 20c0-2-1.5-4-4-4.6',
  business:  'M3 7h18v12H3zM8 7V5h8v2M3 12h18',
  knowledge: 'M5 4h11l3 3v13H5zM9 9h6M9 13h6M9 17h4',
  admin:     'M12 15m-3 0a3 3 0 1 0 6 0a3 3 0 1 0-6 0M12 3v3M12 18v3M3 12h3M18 12h3M5.6 5.6l2.1 2.1M16.3 16.3l2.1 2.1M5.6 18.4l2.1-2.1M16.3 7.7l2.1-2.1',
  approvals: 'M4 12l5 5L20 6',
  more:      'M5 12h.01M12 12h.01M19 12h.01',
  pro:       'M14 4h6v6M20 4l-7 7M10 20H4v-6M4 20l7-7',
};

const Icon: Component<{ name: string; size?: number }> = (props) => (
  <svg width={props.size ?? 18} height={props.size ?? 18} viewBox="0 0 24 24" fill="none" stroke="currentColor"
       stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
    <path d={PATHS[props.name] ?? PATHS.more} />
  </svg>
);

export default Icon;
