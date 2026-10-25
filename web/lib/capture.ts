import { Channel, invoke } from '@tauri-apps/api/core';

export interface StartCaptureOptions {
  dumpcapPath?: string | null;
  interfaces?: string[];
  captureFilter?: string | null;
  durationMillis?: number | null;
  interception?: {
    mitmdumpPath?: string | null;
    automaticTrust?: boolean;
    domains?: string[] | null;
  } | null;
}

export type CapturePhase =
  | 'preparing'
  | 'startingProxy'
  | 'startingCapture'
  | 'recording'
  | 'finalizing'
  | 'embeddingTls'
  | 'completed'
  | 'cancelled'
  | 'failed';

export type CaptureStatsStatus = 'waiting' | 'provisional' | 'stale' | 'complete' | 'unavailable';

/** Identity is captured metadata, including exited processes. Never resolve this PID again. */
export interface CapturedProcess {
  key: string;
  pid: number;
  /** Normalized epoch nanoseconds, serialized losslessly rather than as a JS number. */
  startTime: string;
  name: string | null;
  path: string | null;
  packets: number;
  frameBytes: number;
  packetRate: number | null;
  byteRate: number | null;
  /** Captured packet timestamp, retained as decimal text. */
  lastSeen: string;
}

export interface CaptureSnapshot {
  captureId: string;
  sequence: number;
  phase: CapturePhase;
  elapsedMillis: number;
  packets: number;
  frameBytes: number;
  attributedPackets: number;
  unattributedPackets: number;
  statsStatus: CaptureStatsStatus;
  /** Epoch milliseconds of the latest decoded snapshot; null means no statistics yet. */
  statsAsOf: number | null;
  statsError: string | null;
  processes: CapturedProcess[];
  /** Each packet can belong to several distinct process rows. Never sum rows as a total. */
  processRowsOverlap: true;
  outputPath: string | null;
  recoveryDirectory: string;
  error: string | null;
  terminal: boolean;
  limitations: string[];
}

export interface CaptureInterface {
  index: number;
  description: string;
}

/** Snapshot events are replaceable; use status when a view reconnects or remounts. */
export const capture = {
  start: (options: StartCaptureOptions, receive: (snapshot: CaptureSnapshot) => void) => {
    const onEvent = new Channel<CaptureSnapshot>();
    onEvent.onmessage = receive;
    return invoke<string>('start_capture', { options, onEvent });
  },
  status: (captureId: string) => invoke<CaptureSnapshot>('capture_status', { captureId }),
  stop: (captureId: string) => invoke<void>('stop_capture', { captureId }),
  interfaces: (dumpcapPath?: string) =>
    invoke<CaptureInterface[]>('capture_interfaces', { dumpcapPath: dumpcapPath || null }),
};
