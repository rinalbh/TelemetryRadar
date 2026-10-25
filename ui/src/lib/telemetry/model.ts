import type { TelemetrySnapshot, TrafficSample } from './types.ts';

export const UPDATE_INTERVAL_MS = 5_000;
export const HISTORY_POINTS = 61;
export const KB = 1024;
export const MB = KB * KB;

export function totals(applications: TelemetrySnapshot['applications']) {
  return applications.reduce((sum, app) => ({
    inputBytesPerSecond: sum.inputBytesPerSecond + app.inputBytesPerSecond,
    outputBytesPerSecond: sum.outputBytesPerSecond + app.outputBytesPerSecond
  }), { inputBytesPerSecond: 0, outputBytesPerSecond: 0 });
}

/** Pure update: one atomic snapshot drives the chart, rates and application bars. */
export function nextSnapshot(previous: TelemetrySnapshot, timestamp: number): TelemetrySnapshot {
  const elapsed = Math.max(0, (timestamp - previous.timestamp) / 1000);
  const sequence = previous.sequence + 1;
  const applications = previous.applications.map((app, index) => {
    const wave = 0.72 + 0.36 * (1 + Math.sin(sequence * 0.79 + index * 1.9)) / 2;
    const inputBytesPerSecond = Math.round((index === 6 ? 160 : 1400 + index * 1050) * wave);
    const outputBytesPerSecond = Math.round(inputBytesPerSecond * (0.25 + (1 + Math.cos(sequence * 0.61 + index)) * 0.18));
    return {
      ...app,
      inputBytesPerSecond,
      outputBytesPerSecond,
      inputBytes: app.inputBytes + Math.round(inputBytesPerSecond * elapsed),
      outputBytes: app.outputBytes + Math.round(outputBytesPerSecond * elapsed)
    };
  });
  const sample: TrafficSample = { timestamp, ...totals(applications) };
  return {
    schemaVersion: 1, sequence, timestamp, applications,
    history: [...previous.history, sample].slice(-HISTORY_POINTS)
  };
}

/** Reject invalid transport data before it reaches coordinates or CSS widths. */
export function parseSnapshot(json: string): TelemetrySnapshot {
  const value = JSON.parse(json) as TelemetrySnapshot;
  const positive = (n: unknown) => typeof n === 'number' && Number.isFinite(n) && n >= 0;
  if (!value || value.schemaVersion !== 1 || !Number.isInteger(value.sequence) || value.sequence < 0 || !positive(value.timestamp)
    || !Array.isArray(value.history) || value.history.length < 2 || value.history.length > HISTORY_POINTS
    || !Array.isArray(value.applications)) throw new Error('Invalid telemetry snapshot');
  const ids = new Set<string>();
  for (const app of value.applications) {
    if (!app || typeof app.id !== 'string' || !app.id || ids.has(app.id) || typeof app.name !== 'string'
      || typeof app.icon !== 'string' || ![app.inputBytes, app.outputBytes, app.inputBytesPerSecond, app.outputBytesPerSecond].every(positive)) {
      throw new Error('Invalid application traffic');
    }
    ids.add(app.id);
  }
  value.history.forEach((sample, index) => {
    if (!sample || ![sample.timestamp, sample.inputBytesPerSecond, sample.outputBytesPerSecond].every(positive)
      || (index > 0 && sample.timestamp <= value.history[index - 1].timestamp)) throw new Error('Invalid traffic history');
  });
  if (value.history.at(-1)?.timestamp !== value.timestamp) throw new Error('Snapshot timestamp does not match history');
  return value;
}
