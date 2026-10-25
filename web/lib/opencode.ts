import { Channel, invoke } from '@tauri-apps/api/core';
import type { Discovery } from './backend';
import type { ReportV1, ReportValidation } from './traffic-report';

export interface OpenCodeInstallation {
  executable: string;
  version: string;
}

export type OpenCodeConnection =
  | { status: 'disconnected'; message: string | null }
  | {
      status: 'connected';
      installation: OpenCodeInstallation;
      protocolVersion: string;
      agentName: string | null;
      agentVersion: string | null;
    };

export interface ToolCall {
  toolCallId: string;
  title?: string;
  status?: string;
  rawInput?: unknown;
  rawOutput?: unknown;
  content?: unknown[];
}

export interface PermissionRequest {
  requestId: number;
  request: {
    sessionId: string;
    toolCall: ToolCall;
    options: { optionId: string; name: string; kind: string }[];
  };
}

export type AnalysisEvent =
  | { type: 'started'; analysisId: string; sessionId: string; directory: string }
  | { type: 'stage'; stage: string }
  | { type: 'permission'; permission: PermissionRequest }
  | { type: 'update'; notification: { sessionId: string; update: Omit<ToolCall, 'toolCallId' | 'content'> & {
      sessionUpdate: string;
      toolCallId?: string;
      content?: { type: string; text?: string } | unknown[];
    } } };

export interface AnalysisResult {
  analysisId: string;
  sessionId: string;
  status: 'completed';
  stopReason: string;
  reportPath: string;
  manifestPath: string;
  report: ReportV1;
  validation: ReportValidation;
}

export interface ModelChoice {
  configId: string;
  value: string;
}

/** ACP supplies the option IDs and choices. Do not substitute a hardcoded list. */
export interface AnalysisDraft {
  draftId: string;
  captureId: string;
  processKey: string;
  sessionId: string;
  configOptions: unknown[];
}

export interface AnalysisSnapshot {
  analysisId: string;
  sequence: number;
  status: 'running' | 'completed' | 'cancelled' | 'failed';
  stage: string;
  directory: string;
  sessionId: string | null;
  error: string | null;
  result: AnalysisResult | null;
  pendingPermissions: PermissionRequest[];
  latestPublicMessage: string | null;
  activeToolTitle: string | null;
  cancellationRequested: boolean;
}

function events(receive: (event: AnalysisEvent) => void): Channel<AnalysisEvent> {
  const onEvent = new Channel<AnalysisEvent>();
  onEvent.onmessage = receive;
  return onEvent;
}

export const opencode = {
  discover: (path: string) => invoke<Discovery<OpenCodeInstallation>>('discover_opencode', { executablePath: path || null }),
  connect: (path: string) => invoke<OpenCodeConnection>('connect_opencode', { executablePath: path || null }),
  disconnect: () => invoke<OpenCodeConnection>('disconnect_opencode'),
  status: () => invoke<OpenCodeConnection>('opencode_status'),
  analyze: (capturePath: string, question: string, receive: (event: AnalysisEvent) => void) =>
    invoke<AnalysisResult>('analyze_capture', { capturePath, question, onEvent: events(receive) }),
  prepare: (captureId: string, processKey: string) =>
    invoke<AnalysisDraft>('prepare_analysis', { captureId, processKey }),
  discardDraft: (draftId: string) => invoke<void>('discard_analysis_draft', { draftId }),
  stopCaptureAndAnalyze: (draftId: string, modelChoice: ModelChoice | null, question: string, receive: (event: AnalysisEvent) => void) =>
    invoke<string>('stop_capture_and_analyze', { draftId, modelChoice, question, onEvent: events(receive) }),
  analysisStatus: (analysisId: string) => invoke<AnalysisSnapshot>('analysis_status', { analysisId }),
  cancel: () => invoke<void>('cancel_analysis'),
  respond: (requestId: number, optionId: string | null) =>
    invoke<void>('respond_opencode_permission', { requestId, optionId }),
};
