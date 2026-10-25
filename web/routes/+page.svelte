<script lang="ts">
  import { onMount } from 'svelte';
  import ToolCard from '../lib/ToolCard.svelte';
  import { discoverTool, isDesktop, tools, type ToolId, type ToolState } from '../lib/backend';
  import OpenCodePanel from '../lib/OpenCodePanel.svelte';
  import '../app.css';

  let desktop = $state(false);
  let states = $state<Record<ToolId, ToolState>>({
    wireshark: { status: 'unchecked' }, mitmproxy: { status: 'unchecked' },
  });
  let paths = $state<Record<ToolId, string>>({ wireshark: '', mitmproxy: '' });
  let checking = $derived(Object.values(states).some((state) => state.status === 'checking'));
  let detected = $derived(Object.values(states).filter((state) =>
    state.status === 'checked' && state.result.status === 'available').length);

  onMount(() => { desktop = isDesktop(); });

  async function checkTool(id: ToolId): Promise<void> {
    if (!desktop || states[id].status === 'checking') return;
    states[id] = { status: 'checking' };
    try {
      const result = await discoverTool(id, paths[id]);
      states[id] = {
        status: 'checked', result,
        checkedAt: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      };
    } catch (error) {
      states[id] = { status: 'error', message: error instanceof Error ? error.message : String(error) };
    }
  }

  async function checkAll(): Promise<void> {
    await Promise.all(tools.map((tool) => checkTool(tool.id)));
  }

  function resetResult(id: ToolId): void {
    states[id] = { status: 'unchecked' };
  }
</script>

<svelte:head>
  <title>TelemetryRadar · Workspace</title>
  <meta name="description" content="Prepare your tools for system traffic investigation." />
</svelte:head>

<a class="skip-link" href="#main">Skip to workspace</a>
<div class="app-shell">
  <aside class="sidebar">
    <a class="brand" href="#overview" aria-label="TelemetryRadar home">
      <span class="brand-icon" aria-hidden="true"><span></span></span>
      <span>Telemetry<span class="brand-light">Radar</span></span>
    </a>
    <p class="nav-label">WORKSPACE</p>
    <nav aria-label="Workspace">
      <a class="nav-link" href="#overview"><span aria-hidden="true">◫</span>Overview</a>
      <a class="nav-link" href="#tools"><span aria-hidden="true">⌘</span>Tool setup</a>
      <a class="nav-link" href="#extensions"><span aria-hidden="true">◇</span>Extensions</a>
    </nav>
    <div class="sidebar-bottom">
      <div class="local-mark"><span class="success-dot" aria-hidden="true"></span>Local workspace</div>
      <p>TelemetryRadar <span>0.1.0</span></p>
    </div>
  </aside>

  <div class="workspace">
    <header class="topbar">
      <span>Workspace <span class="slash">/</span> <strong>Overview</strong></span>
      <span class="idle-indicator"><span aria-hidden="true"></span>Capture idle</span>
    </header>

    <main id="main">
      <section id="overview" class="intro">
        <p class="eyebrow">YOUR SYSTEM, IN FOCUS</p>
        <div class="intro-line">
          <div><h1>See where your apps connect.</h1><p class="intro-description">A workspace for understanding your system's network activity.<br />Start by checking the tools on this machine.</p></div>
          <span class="stage-badge">Initial setup</span>
        </div>
      </section>

      {#if !desktop}
        <div class="preview-notice" role="note"><strong>Browser preview</strong><span>Open the desktop app with <code>npm run dev</code> to check installed tools.</span></div>
      {/if}

      <section class="status-strip" aria-label="Workspace status">
        <div><span class="status-icon" aria-hidden="true">◎</span><div><span class="metric-label">CAPTURE STATUS</span><strong>Idle</strong><p>No session is running</p></div></div>
        <div><span class="status-icon" aria-hidden="true">⌁</span><div><span class="metric-label">TOOLS DETECTED</span><strong>{detected}<span class="metric-total"> / 2</span></strong><p>Check installations below</p></div></div>
        <div><span class="status-icon" aria-hidden="true">◇</span><div><span class="metric-label">WORKSPACE</span><strong>Local</strong><p>Ready to configure</p></div></div>
      </section>

      <section id="tools" class="tools-section">
        <div class="section-heading">
          <div><h2>Capture tools</h2><p>Discover the tools that power traffic investigation.</p></div>
          <button class="primary" onclick={checkAll} disabled={!desktop || checking}><span aria-hidden="true">↻</span>{checking ? 'Checking tools…' : 'Check all tools'}</button>
        </div>
        <div class="tools-grid">
          {#each tools as tool (tool.id)}
            <ToolCard {tool} state={states[tool.id]} {desktop} bind:executablePath={paths[tool.id]}
              oncheck={() => checkTool(tool.id)} onpathchange={() => resetResult(tool.id)} />
          {/each}
        </div>
        <div class="setup-note"><span aria-hidden="true">ⓘ</span><p>Checks read tool version information. Capture and HTTPS interception will require a separate, explicit action when those workflows are available.</p></div>
      </section>

      <section class="next-step">
        <div class="next-icon" aria-hidden="true">⌁</div>
        <div><span class="eyebrow">UP NEXT</span><h2>Your first capture</h2><p>Capture controls and traffic analysis are planned for a future update.<br />This initial workspace helps you prepare the required tools.</p></div>
        <span class="badge">Coming later</span>
      </section>

      <section id="extensions" class="extensions-section">
        <div class="section-heading"><div><h2>Extensions</h2><p>Room for connected investigation workflows.</p></div></div>
        <OpenCodePanel {desktop} />
      </section>
      <footer class="workspace-footer"><span class="success-dot" aria-hidden="true"></span>No capture has started. Certificate trust is unchanged.</footer>
    </main>
  </div>
</div>
