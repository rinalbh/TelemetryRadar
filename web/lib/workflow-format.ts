import type { CapturedProcess } from './capture';

const integer = new Intl.NumberFormat(undefined, { maximumFractionDigits: 0 });

/** Frame lengths are traffic measurements, not application payload sizes. */
export function formatBytes(value: number | null | undefined): string {
  if (value == null || !Number.isFinite(value) || value < 0) return 'Unknown';
  if (value < 1000) return `${integer.format(value)} B`;
  const units = ['kB', 'MB', 'GB', 'TB', 'PB'];
  let amount = value / 1000;
  let index = 0;
  while (amount >= 1000 && index < units.length - 1) { amount /= 1000; index += 1; }
  return `${new Intl.NumberFormat(undefined, { maximumFractionDigits: amount < 10 ? 2 : 1 }).format(amount)} ${units[index]}`;
}

export function formatInteger(value: number | null | undefined): string {
  return value == null || !Number.isFinite(value) || value < 0 ? 'Unknown' : integer.format(value);
}

export function formatDuration(milliseconds: number): string {
  if (!Number.isFinite(milliseconds) || milliseconds < 0) return '0:00';
  const seconds = Math.floor(milliseconds / 1000);
  const minutes = Math.floor(seconds / 60);
  return minutes >= 60
    ? `${Math.floor(minutes / 60)}:${String(minutes % 60).padStart(2, '0')}:${String(seconds % 60).padStart(2, '0')}`
    : `${minutes}:${String(seconds % 60).padStart(2, '0')}`;
}

export function processName(process: CapturedProcess | null): string {
  if (!process) return 'Selected app';
  return process.name || process.path?.split(/[\\/]/).filter(Boolean).at(-1) || `Process ${process.pid}`;
}

export function formatRate(value: number | null | undefined, kind: 'packets' | 'bytes' = 'bytes'): string {
  if (value == null || !Number.isFinite(value) || value < 0) return 'Unknown';
  return kind === 'packets' ? `${formatInteger(value)} packets/s` : `${formatBytes(value)}/s`;
}
