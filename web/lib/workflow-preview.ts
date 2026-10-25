/** Explicitly labelled sample states for development-only visual verification.
 * The workspace loads these only behind import.meta.env.DEV + ?preview=...
 * They never invoke capture, ACP, or a provider.
 */
import type { CaptureSnapshot, CapturedProcess } from './capture';
import type { AnalysisDraft, AnalysisResult, AnalysisSnapshot } from './opencode';

export const previewStages = ['recording', 'selection', 'analyzing', 'results'] as const;
export type PreviewStage = typeof previewStages[number];

export function workflowPreview(variant?: string | null) {
  const selected: CapturedProcess = {
    key: 'sample-capture:4242:1761390000123456789', pid: 4242,
    startTime: '1761390000123456789', name: 'Example browser', path: null,
    packets: 1824, frameBytes: 2_920_000, packetRate: 16, byteRate: 28_400,
    lastSeen: '1761390042.123456789',
  };
  const capture: CaptureSnapshot = {
    captureId: 'sample-capture', sequence: 24, phase: 'recording', elapsedMillis: 84_000,
    packets: 3180, frameBytes: 5_210_000, attributedPackets: 3020, unattributedPackets: 160,
    statsStatus: 'provisional', statsAsOf: Date.now(), statsError: null,
    processes: [selected, {
      ...selected, key: 'sample-capture:5252:1761390000987654321', pid: 5252,
      startTime: '1761390000987654321', name: 'Example messenger', packets: 976,
      frameBytes: 1_840_000, packetRate: 9, byteRate: 14_600,
    }, {
      ...selected, key: 'sample-capture:6262:1761390000111111111', pid: 6262,
      startTime: '1761390000111111111', name: 'Example updater', packets: 220,
      frameBytes: 310_000, packetRate: 1, byteRate: 3200,
    }],
    processRowsOverlap: true, outputPath: null, recoveryDirectory: '', error: null,
    terminal: false, limitations: ['Sample data for layout verification. No traffic was recorded.'],
  };
  const draft: AnalysisDraft = {
    draftId: 'sample-draft', captureId: capture.captureId, processKey: selected.key,
    sessionId: 'sample-session', configOptions: [{
      id: 'sample-model-option', name: 'Model', category: 'model', type: 'select',
      currentValue: 'sample-model', options: [{group: 'sample-provider', name: 'Example provider', options: [
        {value: 'sample-model', name: 'Example model'},
      ]}],
    }],
  };
  const result: AnalysisResult = {
    analysisId: 'sample-analysis', sessionId: draft.sessionId, status: 'completed',
    stopReason: 'end_turn', reportPath: '', manifestPath: '',
    validation: {totals:{packets:1824,frameBytes:2_920_000},evidenceLocatorsVerified:true,quantitiesVerified:true,interpretationsVerified:false},
    report: {
      schemaVersion: 1,
      summary: 'Sample report for layout verification. Most traffic in this example is encrypted. Its purpose cannot be determined from packet metadata alone.',
      trafficKinds: [
        {id:'encrypted',kind:'Encrypted traffic',description:'TLS connections to remote services. The encrypted payload is not visible in this sample; no application purpose is asserted.',
          amount:{value:1670,unit:'packets',coverage:'complete',basis:'Frames matching the TLS display filter in the selected artifact.',evidenceRefs:['tls-frames']},
          risk:{level:'unknown',rationale:'Payload visibility is insufficient to assess the data being exchanged.',evidenceRefs:[]},example:null,evidenceRefs:['tls-frames']},
        {id:'dns',kind:'Name lookups',description:'Queries resolve example hostnames before connections are established.',
          amount:{value:92,unit:'packets',coverage:'complete',basis:'All matching DNS frames in the selected artifact.',evidenceRefs:['dns-frames']},
          risk:{level:'low',rationale:'The observed names in this sample contain no account or personal identifiers. This is an agent assessment.',evidenceRefs:['dns-frames']},
          example:{text:'Query: updates.example.invalid',redacted:false,evidenceRefs:['dns-frames']},evidenceRefs:['dns-frames']},
        {id:'unclear',kind:'Unclassified traffic',description:'Some packets lack enough context for a supported classification.',
          amount:{value:null,unit:'events',coverage:'unknown',basis:'Application events cannot be measured deterministically from this packet sample.',evidenceRefs:[]},
          risk:{level:'unknown',rationale:'No supported risk assessment is available for unclassified behavior.',evidenceRefs:[]},example:null,evidenceRefs:[]},
      ],
      evidence: [
        {id:'tls-frames',frames:[14,27],streams:[{protocol:'tcp',id:2}],displayFilter:'tls',note:'Sample TLS locators. This fixture is for layout verification only.'},
        {id:'dns-frames',frames:[3,4],streams:[{protocol:'udp',id:0}],displayFilter:'dns',note:'Sample DNS locators. No live evidence query is run in preview mode.'},
      ],
      limitations: ['Sample data, not a real investigation. Verification badges illustrate the layout.', 'Encrypted payloads were not available for inspection.', 'Traffic categories may overlap and must not be summed.'],
    },
  };
  const analysis: AnalysisSnapshot = {
    analysisId: result.analysisId, sequence: 8, status: 'running', stage: 'analyzing',
    directory: '', sessionId: draft.sessionId, error: null, result: null,
    pendingPermissions: [], latestPublicMessage: 'Inspecting protocols and destinations. Checking which findings can be supported by packet evidence.',
    activeToolTitle: 'Inspect packet metadata', cancellationRequested: false,
  };
  const history = [19_000, 27_000, 24_000, 34_000, 29_000, 21_000, 25_000, 36_000, 31_000, 24_000, 28_400]
    .map((rate, index) => ({time: Date.now() - (10 - index) * 1000, rate}));
  if (variant === 'empty') {
    result.report.trafficKinds = [];
    result.report.evidence = [];
    result.report.summary = 'Sample empty classification: packets were recorded, but there is not enough visible evidence to classify their purpose.';
    result.report.limitations = ['Sample data for empty-state layout verification.', 'Classification was unavailable; an empty findings table does not establish that telemetry is absent.'];
  } else if (variant === 'unsupported') {
    result.report = {schemaVersion: 2} as unknown as AnalysisResult['report'];
  }
  return {capture, selected, draft, analysis, result, history};
}
