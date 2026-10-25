import { Channel, invoke } from '@tauri-apps/api/core';
import type { Discovery } from './backend';

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
  | { type: 'started'; sessionId: string; directory: string }
  | { type: 'permission'; permission: PermissionRequest }
  | { type: 'update'; notification: { sessionId: string; update: Omit<ToolCall, 'toolCallId' | 'content'> & {
      sessionUpdate: string;
      toolCallId?: string;
      content?: { type: string; text?: string } | unknown[];
    } } };

export interface AnalysisResult {
  stopReason: string;
  reportPath: string;
}

export const opencode = {
  discover: (path: string) => invoke<Discovery<OpenCodeInstallation>>('discover_opencode', { executablePath: path || null }),
  connect: (path: string) => invoke<OpenCodeConnection>('connect_opencode', { executablePath: path || null }),
  disconnect: () => invoke<OpenCodeConnection>('disconnect_opencode'),
  status: () => invoke<OpenCodeConnection>('opencode_status'),
  analyze: (capturePath: string, question: string, receive: (event: AnalysisEvent) => void) => {
    const onEvent = new Channel<AnalysisEvent>();
    onEvent.onmessage = receive;
    return invoke<AnalysisResult>('analyze_capture', { capturePath, question, onEvent });
  },
  cancel: () => invoke<void>('cancel_analysis'),
  respond: (requestId: number, optionId: string | null) =>
    invoke<void>('respond_opencode_permission', { requestId, optionId }),
};
