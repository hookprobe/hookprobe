/**
 * sampleClock — one clock for every sample story (no device answering), so pages agree with each other and
 * never show an event in the future. Everything is relative to page load: the kitchen-camera incident is
 * about a minute old everywhere (Home, Mission, Observe, Detect, Investigate, the incident story, Protect).
 */
export const SAMPLE_NOW = Math.floor(Date.now() / 1000);

/** The kitchen-camera story (INC-0142), in order: DNS lookup → flagged by intel → TLS match → LAN scan → isolated 1 h. */
export const CAMERA = {
  dns: SAMPLE_NOW - 69,
  flagged: SAMPLE_NOW - 68,
  tls: SAMPLE_NOW - 67,
  scan: SAMPLE_NOW - 62,
  isolated: SAMPLE_NOW - 60,
  /** Seconds left of the 1-hour automatic isolation. */
  isolationLeft: 3600 - 60,
};

/** The other sample events, oldest last. */
export const SAMPLE_AT = {
  wifiChannel: SAMPLE_NOW - 25 * 60,
  unknownDevice: SAMPLE_NOW - 9000,
  trackers: SAMPLE_NOW - 6 * 3600,
  bruteForce: SAMPLE_NOW - 86400,
  update: SAMPLE_NOW - 86400 - 13 * 3600,
};

/** "14:32" today, "yesterday", or the date: a sample row's time label. */
export function sampleWhen(ts: number): string {
  const d = new Date(ts * 1000), today = new Date();
  const days = Math.round((new Date(today.toDateString()).getTime() - new Date(d.toDateString()).getTime()) / 86400000);
  if (days === 0) return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false });
  if (days === 1) return 'yesterday';
  return d.toLocaleDateString();
}
