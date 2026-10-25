/** Model-owned findings. Only host-validated ReportV1 values may become results. */
export interface ReportV1 {
  schemaVersion: 1;
  summary: string;
  trafficKinds: TrafficKind[];
  evidence: Evidence[];
  limitations: string[];
}

export type AmountUnit = 'packets' | 'frame_bytes' | 'requests' | 'connections' | 'events';
export type AmountCoverage = 'complete' | 'partial' | 'unknown';
export type RiskLevel = 'low' | 'medium' | 'high' | 'unknown';

export interface TrafficKind {
  id: string;
  kind: string;
  description: string;
  amount: {
    /** null is unknown; zero is a verified measurement. */
    value: number | null;
    unit: AmountUnit;
    coverage: AmountCoverage;
    basis: string;
    evidenceRefs: string[];
  };
  risk: {
    level: RiskLevel;
    rationale: string;
    evidenceRefs: string[];
  };
  example: {
    text: string;
    redacted: boolean;
    evidenceRefs: string[];
  } | null;
  evidenceRefs: string[];
}

export interface Evidence {
  id: string;
  frames: number[];
  streams: { protocol: 'tcp' | 'udp'; id: number }[];
  displayFilter: string | null;
  note: string;
}

/** Authoritative totals count original frame lengths, not application payload. */
export interface TrafficTotals {
  packets: number;
  frameBytes: number;
}

/** Existence and quantity verification do not prove the model's interpretation. */
export interface ReportValidation {
  totals: TrafficTotals;
  evidenceLocatorsVerified: boolean;
  quantitiesVerified: boolean;
  interpretationsVerified: boolean;
}

/** Bounds match src/opencode/report.rs and the checked-in v1 JSON Schema.
 * String limits count Unicode code points (Array.from(text).length), not UTF-16 units.
 */
export const REPORT_LIMITS = {
  candidateBytes: 4 * 1024 * 1024,
  trafficKinds: 200,
  evidence: 2_000,
  locatorsPerEvidence: 100,
  referencesPerArray: 100,
  idCharacters: 64,
  kindCharacters: 80,
  exampleCharacters: 512,
  textCharacters: 2_048,
  summaryCharacters: 4_096,
  limitations: 200,
  integer: Number.MAX_SAFE_INTEGER,
} as const;

/** Guard saved host results before choosing a dashboard renderer. */
export function requireSupportedReportVersion(value: unknown): asserts value is { schemaVersion: 1 } {
  const version = value !== null && typeof value === 'object' && 'schemaVersion' in value
    ? value.schemaVersion
    : undefined;
  if (version !== 1) {
    throw new Error(`Unsupported traffic report schema version: ${String(version)}`);
  }
}
