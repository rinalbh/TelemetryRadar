<script lang="ts">
  import { onMount } from 'svelte';
  import { opencode, type AnalysisEvent, type OpenCodeConnection, type OpenCodeInstallation, type PermissionRequest, type ToolCall } from './opencode';
  import type { Discovery } from './backend';

  let { desktop }: { desktop: boolean } = $props();
  let path = $state('');
  let discovery = $state<Discovery<OpenCodeInstallation> | null>(null);
  let connection = $state<OpenCodeConnection>({ status: 'disconnected', message: null });
  let operation = $state<'check' | 'connect' | 'disconnect' | null>(null);
  let error = $state('');
  let capturePath = $state('');
  let question = $state('');
  let running = $state(false);
  let started = $state(false);
  let cancelling = $state(false);
  let response = $state('');
  let reportPath = $state('');
  let directory = $state('');
  let stopReason = $state('');
  let calls = $state<ToolCall[]>([]);
  let permissions = $state<PermissionRequest[]>([]);
  let answering = $state<number[]>([]);
  let revision = 0;
  let polling = false;

  function receive(event: AnalysisEvent): void {
    if (event.type === 'started') {
      started = true;
      directory = event.directory;
    } else if (event.type === 'permission') {
      permissions = [...permissions, event.permission];
    } else {
      const update = event.notification.update;
      if (update.sessionUpdate === 'agent_message_chunk' && update.content && !Array.isArray(update.content) && update.content.type === 'text') {
        response += update.content.text ?? '';
      } else if ((update.sessionUpdate === 'tool_call' || update.sessionUpdate === 'tool_call_update') && update.toolCallId) {
        const { content, ...fields } = update;
        const call: ToolCall = { ...fields, toolCallId: update.toolCallId, ...(Array.isArray(content) ? { content } : {}) };
        const index = calls.findIndex((call) => call.toolCallId === update.toolCallId);
        if (index < 0) calls = [...calls, call];
        else calls[index] = { ...calls[index], ...call };
      }
    }
  }

  async function analyze(): Promise<void> {
    if (running || !capturePath.trim()) return;
    running = true;
    started = false;
    cancelling = false;
    response = ''; reportPath = ''; directory = ''; stopReason = ''; error = '';
    calls = []; permissions = [];
    try {
      const result = await opencode.analyze(capturePath.trim(), question, receive);
      reportPath = result.reportPath;
      stopReason = result.stopReason;
    } catch (failure) {
      error = String(failure);
    } finally {
      running = false;
      permissions = [];
    }
  }

  async function cancel(): Promise<void> {
    cancelling = true;
    permissions = [];
    try { await opencode.cancel(); }
    catch (failure) { error = String(failure); cancelling = false; }
  }

  async function answer(permission: PermissionRequest, option: string): Promise<void> {
    answering = [...answering, permission.requestId];
    try {
      await opencode.respond(permission.requestId, option);
      permissions = permissions.filter((pending) => pending.requestId !== permission.requestId);
    } catch (failure) { error = String(failure); }
    finally { answering = answering.filter((id) => id !== permission.requestId); }
  }

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
  <p class="requirement">Connect OpenCode, then analyze an existing capture with its shell tools and host TShark. Uses your configured model and provider credentials.</p>
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
      <button class="secondary" disabled={operation !== null || running} onclick={() => perform('disconnect')}>{operation === 'disconnect' ? 'Disconnecting…' : 'Disconnect'}</button>
    {:else}
      <button class="primary" disabled={!desktop || operation !== null} onclick={() => perform('connect')}>{operation === 'connect' ? 'Connecting…' : 'Connect'}</button>
    {/if}
  </div>
  <form class="analysis-form" onsubmit={(event) => { event.preventDefault(); void analyze(); }}>
    <label class="custom-path">Capture path<input bind:value={capturePath} disabled={running} placeholder="C:\captures\system.pcapng" required /></label>
    <label class="custom-path">Question (optional)<textarea bind:value={question} disabled={running} rows="3" placeholder="What data is sent, and to which destinations?"></textarea></label>
    <div class="opencode-actions">
      <button class="primary" type="submit" disabled={!desktop || connection.status !== 'connected' || operation !== null || running || !capturePath.trim()}>Analyze capture</button>
      {#if running}<button class="secondary" type="button" disabled={!started || cancelling} onclick={cancel}>{cancelling ? 'Cancelling…' : 'Cancel'}</button>{/if}
      <span class="result-hint" role="status">{running ? (cancelling ? 'Stopping analysis…' : started ? 'Analyzing…' : 'Preparing session…') : stopReason ? `Finished: ${stopReason}` : ''}</span>
    </div>
  </form>
  {#each permissions as permission (permission.requestId)}
    <div class="permission-request">
      <p class="result-title">{permission.request.toolCall.title ?? 'OpenCode requests permission'}</p>
      <pre>{JSON.stringify(permission.request.toolCall, null, 2)}</pre>
      <div class="opencode-actions">
        {#each permission.request.options as option (option.optionId)}
          <button class="secondary" disabled={cancelling || answering.includes(permission.requestId)} onclick={() => answer(permission, option.optionId)}>{option.name}</button>
        {/each}
      </div>
    </div>
  {/each}
  {#if calls.length}
    <details class="analysis-tools" open={running}>
      <summary>Tool activity ({calls.length})</summary>
      {#each calls as call (call.toolCallId)}
        <details><summary>{call.title ?? call.toolCallId} — {call.status ?? 'pending'}</summary><pre>{JSON.stringify({ input: call.rawInput, output: call.rawOutput, content: call.content }, null, 2)}</pre></details>
      {/each}
    </details>
  {/if}
  {#if response}<pre class="analysis-response" aria-label="Analysis response">{response}</pre>{/if}
  {#if reportPath}<p class="result-hint">Report saved to {reportPath}</p>
  {:else if directory}<p class="result-hint">Analysis files: {directory}</p>{/if}
</article>
