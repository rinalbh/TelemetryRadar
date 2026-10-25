import { invoke } from '@tauri-apps/api/core';
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

export const opencode = {
  discover: (path: string) => invoke<Discovery<OpenCodeInstallation>>('discover_opencode', { executablePath: path || null }),
  connect: (path: string) => invoke<OpenCodeConnection>('connect_opencode', { executablePath: path || null }),
  disconnect: () => invoke<OpenCodeConnection>('disconnect_opencode'),
  status: () => invoke<OpenCodeConnection>('opencode_status'),
};
