import seed from './mock-traffic.json';
import { nextSnapshot, parseSnapshot, UPDATE_INTERVAL_MS } from './model.ts';
import type { TelemetrySource } from './types.ts';

export function createMockSource(): TelemetrySource {
  return {
    subscribe(listener) {
      const now = Date.now();
      const shift = now - seed.timestamp;
      let snapshot = parseSnapshot(JSON.stringify({
        ...seed, timestamp: now,
        history: seed.history.map((sample) => ({ ...sample, timestamp: sample.timestamp + shift }))
      }));
      listener(snapshot);
      const timer = setInterval(() => {
        // Round-trip JSON intentionally models the future agent transport boundary.
        snapshot = parseSnapshot(JSON.stringify(nextSnapshot(snapshot, Date.now())));
        listener(snapshot);
      }, UPDATE_INTERVAL_MS);
      return () => clearInterval(timer);
    }
  };
}
