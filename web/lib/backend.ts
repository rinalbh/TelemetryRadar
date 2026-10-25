import { invoke, isTauri } from '@tauri-apps/api/core';

export interface WiresharkInstallation {
  version: string;
  dumpcap: string;
  tshark: string;
}

export interface MitmproxyInstallation {
  version: string;
  mitmdump: string;
}

/** Mirrors the serializable discovery DTO in src-tauri/src/discovery.rs. */
export type Discovery<T> =
  | { status: 'available'; installation: T }
  | { status: 'unavailable'; message: string };

export interface DiscoveryBackend {
  discoverWireshark(executablePath?: string): Promise<Discovery<WiresharkInstallation>>;
  discoverMitmproxy(executablePath?: string): Promise<Discovery<MitmproxyInstallation>>;
}

export function isDesktop(): boolean {
  return isTauri();
}

function discover<T>(command: string, executablePath?: string): Promise<Discovery<T>> {
  if (!isDesktop()) {
    return Promise.reject(new Error('Tool discovery requires the desktop app. Run npm run dev.'));
  }
  return invoke<Discovery<T>>(command, { executablePath: executablePath || null });
}

export const backend: DiscoveryBackend = {
  discoverWireshark: (path) => discover<WiresharkInstallation>('discover_wireshark', path),
  discoverMitmproxy: (path) => discover<MitmproxyInstallation>('discover_mitmproxy', path),
};

export type ToolId = 'wireshark' | 'mitmproxy';
export type Installation = WiresharkInstallation | MitmproxyInstallation;
export type ToolState =
  | { status: 'unchecked' }
  | { status: 'checking' }
  | { status: 'checked'; result: Discovery<Installation>; checkedAt: string }
  | { status: 'error'; message: string };

export interface ToolDescription {
  id: ToolId;
  name: string;
  purpose: string;
  requirement: string;
  executable: string;
  environmentVariable: string;
}

export const tools: readonly ToolDescription[] = [
  {
    id: 'wireshark', name: 'Wireshark', purpose: 'System traffic & process attribution',
    requirement: 'Wireshark 5.0rc or newer, with a matching TShark.',
    executable: 'dumpcap', environmentVariable: 'WIRESHARK_DUMPCAP',
  },
  {
    id: 'mitmproxy', name: 'mitmproxy', purpose: 'Optional local HTTPS interception',
    requirement: 'mitmproxy 11.1 or newer, including mitmdump.',
    executable: 'mitmdump', environmentVariable: 'MITMPROXY_MITMDUMP',
  },
];

export function discoverTool(id: ToolId, path?: string): Promise<Discovery<Installation>> {
  return id === 'wireshark' ? backend.discoverWireshark(path) : backend.discoverMitmproxy(path);
}
