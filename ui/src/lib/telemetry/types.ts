export interface TrafficSample {
  timestamp: number;
  inputBytesPerSecond: number;
  outputBytesPerSecond: number;
}

export interface ApplicationTraffic {
  id: string;
  name: string;
  /** An agent can supply a local asset URL or a data:image URL. */
  icon: string;
  inputBytes: number;
  outputBytes: number;
  inputBytesPerSecond: number;
  outputBytesPerSecond: number;
}

export interface TelemetrySnapshot {
  schemaVersion: 1;
  sequence: number;
  timestamp: number;
  history: TrafficSample[];
  applications: ApplicationTraffic[];
}

/** Replace this implementation with Tauri events without changing the UI. */
export interface TelemetrySource {
  subscribe(listener: (snapshot: TelemetrySnapshot) => void): () => void;
}
