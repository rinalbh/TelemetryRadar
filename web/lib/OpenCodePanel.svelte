<script lang="ts">
  import { onMount } from 'svelte';
  import { opencode, type OpenCodeConnection, type OpenCodeInstallation } from './opencode';
  import type { Discovery } from './backend';

  let { desktop }: { desktop: boolean } = $props();
  let path = $state('');
  let discovery = $state<Discovery<OpenCodeInstallation> | null>(null);
  let connection = $state<OpenCodeConnection>({ status: 'disconnected', message: null });
  let operation = $state<'check' | 'connect' | 'disconnect' | null>(null);
  let error = $state('');
  let revision = 0;
  let polling = false;

  async function perform(action: 'check' | 'connect' | 'disconnect'): Promise<void> {
    if (!desktop || operation) return;
    revision += 1;
    operation = action;
    error = '';
    try {
      if (action === 'check') discovery = await opencode.discover(path);
      else if (action === 'connect') connection = await opencode.connect(path);
      else connection = await opencode.disconnect();
    } catch (failure) {
      error = failure instanceof Error ? failure.message : String(failure);
    } finally {
      operation = null;
    }
  }

  // Observe an unexpected child exit without launching an agent on page load.
  onMount(() => {
    const timer = setInterval(async () => {
      if (!desktop || operation || polling || connection.status !== 'connected') return;
      polling = true;
      const currentRevision = revision;
      try {
        const status = await opencode.status();
        if (revision === currentRevision) connection = status;
      } catch (failure) {
        if (revision === currentRevision) error = String(failure);
      } finally {
        polling = false;
      }
    }, 2000);
    return () => { revision += 1; clearInterval(timer); };
  });
</script>

<article class="tool-card" aria-labelledby="opencode-title" aria-busy={operation !== null}>
  <div class="tool-heading">
    <div class="tool-symbol" aria-hidden="true">O</div>
    <div class="tool-name"><h3 id="opencode-title">OpenCode</h3><p>Agent Client Protocol connection</p></div>
    <span class="badge" class:positive={connection.status === 'connected'}>{connection.status === 'connected' ? 'Connected' : 'Disconnected'}</span>
  </div>
  <p class="requirement">Discover OpenCode, then connect to initialize ACP. No prompt or session is sent.</p>
  <div class="tool-result" aria-live="polite">
    {#if connection.status === 'connected'}
      <p class="result-title"><span class="success-dot" aria-hidden="true"></span>{connection.agentName ?? 'OpenCode'} · ACP {connection.protocolVersion}</p>
      <dl class="paths"><div><dt>Executable</dt><dd>{connection.installation.executable}</dd></div><div><dt>Version</dt><dd>{connection.installation.version}</dd></div></dl>
    {:else if operation === 'connect'}
      <p class="result-title">Initializing ACP…</p>
    {:else if discovery?.status === 'available'}
      <p class="result-title">OpenCode {discovery.installation.version} detected</p>
      <dl class="paths"><div><dt>Executable</dt><dd>{discovery.installation.executable}</dd></div></dl>
    {:else if discovery?.status === 'unavailable'}
      <p class="result-title">OpenCode unavailable</p><p class="result-hint">{discovery.message}</p>
    {:else}
      <p class="result-title">Not connected</p><p class="result-hint">Check the installation or connect directly.</p>
    {/if}
    {#if connection.status === 'disconnected' && connection.message}<p class="result-hint">{connection.message}</p>{/if}
    {#if error}<p class="result-hint" role="alert">{error}</p>{/if}
  </div>
  <label class="custom-path">Executable override (optional)<input bind:value={path} disabled={operation !== null || connection.status === 'connected'} placeholder="opencode executable path" /></label>
  <div class="opencode-actions">
    <button class="secondary" disabled={!desktop || operation !== null || connection.status === 'connected'} onclick={() => perform('check')}>{operation === 'check' ? 'Checking…' : 'Check installation'}</button>
    {#if connection.status === 'connected'}
      <button class="secondary" disabled={operation !== null} onclick={() => perform('disconnect')}>{operation === 'disconnect' ? 'Disconnecting…' : 'Disconnect'}</button>
    {:else}
      <button class="primary" disabled={!desktop || operation !== null} onclick={() => perform('connect')}>{operation === 'connect' ? 'Connecting…' : 'Connect'}</button>
    {/if}
  </div>
</article>
