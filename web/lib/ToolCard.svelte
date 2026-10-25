<script lang="ts">
  import type { ToolDescription, ToolState } from './backend';

  let { tool, state, desktop, executablePath = $bindable(''), oncheck, onpathchange }: {
    tool: ToolDescription;
    state: ToolState;
    desktop: boolean;
    executablePath?: string;
    oncheck: () => void;
    onpathchange: () => void;
  } = $props();

  const labels = {
    unchecked: 'Not checked', checking: 'Checking…', error: 'Check failed',
    available: 'Detected', unavailable: 'Unavailable',
  };
  let status = $derived(state.status === 'checked' ? state.result.status : state.status);
  let busy = $derived(state.status === 'checking');
</script>

<article class="tool-card" aria-labelledby={`${tool.id}-title`} aria-busy={busy}>
  <div class="tool-heading">
    <div class="tool-symbol" aria-hidden="true">{tool.id === 'wireshark' ? 'W' : 'm'}</div>
    <div class="tool-name"><h3 id={`${tool.id}-title`}>{tool.name}</h3><p>{tool.purpose}</p></div>
    <span class="badge" class:positive={status === 'available'} class:warning={status === 'unavailable' || status === 'error'}>{labels[status]}</span>
  </div>

  <p class="requirement">{tool.requirement}</p>
  <div class="tool-result" aria-live="polite">
    {#if state.status === 'checked' && state.result.status === 'available'}
      <p class="result-title"><span class="success-dot" aria-hidden="true"></span>Version {state.result.installation.version}</p>
      <dl class="paths">
        {#each Object.entries(state.result.installation).filter(([key]) => key !== 'version') as [name, path]}
          <div><dt>{name}</dt><dd>{path}</dd></div>
        {/each}
      </dl>
      <p class="checked-time">Checked at {state.checkedAt}</p>
    {:else if state.status === 'checked' && state.result.status === 'unavailable'}
      <p class="result-title">A compatible installation wasn't found.</p>
      <p class="result-hint">Install the required version or specify its executable below, then check again.</p>
      <details class="diagnostics"><summary>Discovery details</summary><pre>{state.result.message}</pre></details>
    {:else if state.status === 'error'}
      <p class="result-title">Discovery could not complete.</p>
      <p class="result-hint">{state.message}</p>
    {:else if busy}
      <p class="result-title">Looking for {tool.executable}…</p>
      <p class="result-hint">Reading executable version information.</p>
    {:else}
      <p class="result-title">Ready when you are.</p>
      <p class="result-hint">Check your installation to see its version and executable paths.</p>
    {/if}
  </div>

  <details class="custom-path">
    <summary>Use a custom executable</summary>
    <label for={`${tool.id}-path`}>Path to {tool.executable}</label>
    <input id={`${tool.id}-path`} type="text" bind:value={executablePath} oninput={onpathchange} disabled={busy}
      spellcheck="false" autocomplete="off" placeholder={`Full path to ${tool.executable}`} />
    <p>Leave blank for automatic discovery, including <code>{tool.environmentVariable}</code>. Paths are used for this session only.</p>
  </details>

  <div class="tool-footer"><span>Version probes only</span><button class="secondary" onclick={oncheck} disabled={!desktop || busy}>{busy ? 'Checking…' : 'Check installation'}<span aria-hidden="true">↗</span></button></div>
</article>
