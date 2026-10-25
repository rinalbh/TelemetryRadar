<script lang="ts">
  import { onMount } from 'svelte';
  import TrafficChart from '../lib/components/TrafficChart.svelte';
  import { createMockSource } from '../lib/telemetry/mock-source';
  import { KB, MB, totals } from '../lib/telemetry/model';
  import type { TelemetrySnapshot } from '../lib/telemetry/types';
  import { m } from '../lib/paraglide/messages.js';
  import { getLocale } from '../lib/paraglide/runtime.js';

  let snapshot = $state<TelemetrySnapshot | null>(null);
  let paused = $state(false);
  let pending: TelemetrySnapshot | null = null;
  let rates = $derived(totals(snapshot?.applications ?? []));
  let sortedApplications = $derived(
    [...(snapshot?.applications ?? [])].sort((a, b) =>
      (b.inputBytes + b.outputBytes) - (a.inputBytes + a.outputBytes)
      || a.id.localeCompare(b.id, 'en')
    )
  );
  // A shared scale makes the cumulative application volumes comparable.
  let scale = $derived(Math.max(27 * MB, ...(snapshot?.applications.map(app => (app.inputBytes + app.outputBytes) * 1.12) ?? [])));
  const format = (value: number, maximumFractionDigits = 1) => new Intl.NumberFormat(getLocale(), { maximumFractionDigits }).format(value);
  const volume = (value: number) => value >= MB ? `${format(value / MB)} ${m.mb()}` : `${format(value / KB, 0)} ${m.kb()}`;
  const rate = (value: number) => m.rate({ value: format(value / KB) });
  const clock = (timestamp: number) => new Intl.DateTimeFormat(getLocale(), { timeZone: 'Europe/Moscow', hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23' }).format(timestamp);

  onMount(() => {
    document.documentElement.lang = getLocale();
    return createMockSource().subscribe((next) => {
      pending = next;
      if (!paused) snapshot = next;
    });
  });

  function togglePause() {
    paused = !paused;
    if (!paused && pending) snapshot = pending;
  }

  function safeIcon(icon: string) {
    return /^\/icons\/[a-z0-9_-]+\.svg$/i.test(icon) || /^data:image\/(png|webp|jpeg);base64,/i.test(icon)
      ? icon : '/icons/terminal.svg';
  }
</script>

<svelte:head>
  <title>TelemetryRadar · {m.analytics()}</title>
  <meta name="description" content="TelemetryRadar — desktop application network traffic analytics." />
</svelte:head>

<main>
  <header class="page-header">
    <div>
      <h1>{m.analytics()}</h1>
      <p class="subtitle">{m.subtitle()}</p>
    </div>
    <div class="toolbar">
      <span class="demo">{m.demo()}</span>
      <button class="update-button" onclick={togglePause} aria-label={paused ? m.resume() : m.pause()} title={paused ? m.resume() : m.pause()} aria-pressed={paused}>
        <span class:paused class="status-dot"></span>
        <span>{paused ? m.paused() : m.live()}</span>
        {#if paused}<svg viewBox="0 0 16 16" aria-hidden="true"><path d="m5 3 8 5-8 5Z" fill="currentColor"/></svg>
        {:else}<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M5 4v8m6-8v8" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>{/if}
      </button>
    </div>
  </header>

  <section class="panel traffic-panel" aria-labelledby="traffic-heading" data-sequence={snapshot?.sequence ?? 0}>
    <h2 id="traffic-heading">{m.traffic_rate()}</h2>
    <div class="chart-meta">
      <div class="rates">
        <span class="legend-item"><i class="dot input"></i>{m.input()} <strong data-testid="input-rate">{rate(rates.inputBytesPerSecond)}</strong></span>
        <span class="legend-item"><i class="dot output"></i>{m.output()} <strong data-testid="output-rate">{rate(rates.outputBytesPerSecond)}</strong></span>
      </div>
      <div class="chart-legend" aria-hidden="true">
        <span class="legend-item"><i class="dot input"></i>{m.input()}</span>
        <span class="legend-item"><i class="dot output"></i>{m.output()}</span>
      </div>
    </div>
    {#if snapshot}<TrafficChart history={snapshot.history}/>{/if}
  </section>

  <section class="panel programs-panel" aria-labelledby="program-heading" data-sequence={snapshot?.sequence ?? 0}>
    <div class="programs-heading">
      <h2 id="program-heading">{m.program()}</h2>
      <div class="program-legend" aria-hidden="true"><span class="legend-item"><i class="dot input"></i>{m.input()}</span><span class="legend-item"><i class="dot output"></i>{m.output()}</span></div>
    </div>
    <ul class="program-list">
      {#each sortedApplications as app (app.id)}
        {@const total = app.inputBytes + app.outputBytes}
        <li data-app-id={app.id}>
          <div class="app-identity"><img src={safeIcon(app.icon)} alt="" width="40" height="40"/><span>{app.name}</span></div>
          <div class="bar-track" role="img" aria-label={`${app.name}: ${m.input()} ${volume(app.inputBytes)}, ${m.output()} ${volume(app.outputBytes)}`} title={`${m.input()}: ${volume(app.inputBytes)} · ${m.output()}: ${volume(app.outputBytes)}`}>
            <div class="bar-total" style:width={`${total / scale * 100}%`}>
              <div class="bar-input" style:width={`${total ? app.inputBytes / total * 100 : 0}%`}></div>
              <div class="bar-output" style:width={`${total ? app.outputBytes / total * 100 : 0}%`}></div>
            </div>
          </div>
          <span class="app-volume" data-testid="app-volume">{volume(total)}</span>
        </li>
      {/each}
    </ul>
  </section>
  <footer><span class="brand"><svg viewBox="0 0 20 20" aria-hidden="true"><circle cx="10" cy="10" r="7.5"/><circle cx="10" cy="10" r="3.5"/><path d="m10 10 6-6"/></svg>TelemetryRadar</span><span data-testid="updated">{snapshot ? m.updated({ time: clock(snapshot.timestamp) }) : '—'}</span></footer>
</main>

<style>
  :global(*){box-sizing:border-box} :global(body){margin:0;min-width:960px;font-family:Arial,Helvetica,sans-serif;color:#535fc3;background:radial-gradient(ellipse at 50% -30%,#f3f9ff 0%,#d2e9ff 48%,#a8d0f7 100%);min-height:100vh;-webkit-font-smoothing:antialiased} :global(button){font:inherit} :global(button:focus-visible){outline:3px solid #1257f2;outline-offset:4px}
  main{max-width:1680px;margin:0 auto;padding:28px 3% 12px}.page-header{display:flex;justify-content:space-between;align-items:center;gap:24px;margin-bottom:20px}h1{font-size:46px;font-weight:750;letter-spacing:-1.9px;line-height:1.12;color:#08085e;margin:0 0 6px}.subtitle{font-size:23px;line-height:1.35;font-weight:600;color:#636cbc;margin:0;letter-spacing:-.5px}.toolbar{display:flex;align-items:center;gap:10px;align-self:flex-start;margin-top:12px;font-size:12px;white-space:nowrap}.demo{color:#606cb1}.update-button{display:flex;align-items:center;gap:7px;border:1px solid #ffffffa0;border-radius:20px;padding:7px 10px;background:#ffffff66;color:#4655ac;cursor:pointer}.update-button:hover{background:#ffffffb0}.update-button svg{width:13px;height:13px}.status-dot{width:6px;height:6px;flex-shrink:0;border-radius:50%;background:#00b9ae;box-shadow:0 0 0 3px #00ccbb14}.status-dot.paused{background:#b18b28;box-shadow:none}
  .panel{background:#ffffffef;border-radius:25px;padding:19px 27px 13px;box-shadow:0 1px 0 #ffffff60}.traffic-panel{margin-bottom:21px;min-height:360px}h2{font-size:25px;line-height:1.2;letter-spacing:-.7px;color:#090965;margin:0;font-weight:700}.chart-meta{display:flex;align-items:center;justify-content:space-between;margin-top:14px;padding-right:5px;font-size:17px}.rates,.chart-legend,.program-legend{display:flex;align-items:center;gap:28px}.legend-item{display:inline-flex;align-items:center;gap:9px;white-space:nowrap}.legend-item strong{font-weight:500;margin-left:-3px}.dot{display:inline-block;width:16px;height:16px;flex-shrink:0;border-radius:50%}.input{background:linear-gradient(140deg,#00f0ea,#00d4ec)}.output{background:linear-gradient(140deg,#0587ff,#003cff)}
  .programs-panel{padding-top:17px;padding-bottom:9px}.programs-heading{display:flex;align-items:center;gap:24px;margin-bottom:12px}.program-legend{gap:25px;font-size:16px}.program-legend .dot{width:14px;height:14px}.program-list{list-style:none;padding:0;margin:0}.program-list li{display:grid;grid-template-columns:29% minmax(0,1fr) 12%;align-items:center;min-height:46px;border-bottom:1px solid #dae6fb;gap:0}.program-list li:last-child{border-bottom:0}.app-identity{display:flex;align-items:center;gap:15px;min-width:0;padding-right:16px;font-size:18px;letter-spacing:-.3px}.app-identity img{width:38px;height:38px;flex-shrink:0}.app-identity span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.bar-track{height:11px;border-radius:10px;background:#e5edf5;overflow:hidden}.bar-total{height:100%;display:flex;overflow:hidden;border-radius:10px;transition:width .65s ease}.bar-input{background:linear-gradient(90deg,#00e9e9,#00dbe9);height:100%;transition:width .65s ease}.bar-output{background:linear-gradient(90deg,#007aff,#0060ff);height:100%;transition:width .65s ease}.app-volume{text-align:right;font-size:19px;letter-spacing:-.4px;font-variant-numeric:tabular-nums}footer{display:flex;justify-content:space-between;align-items:center;font-size:11px;padding:12px 4px 0;color:#5568ab}.brand{display:flex;align-items:center;gap:5px;letter-spacing:.2px}.brand svg{width:16px;height:16px;fill:none;stroke:currentColor;stroke-width:1.3}
  @media(min-width:1500px){main{padding-top:29px}.traffic-panel{padding-bottom:14px}.program-list li{min-height:46px}}
  @media(max-width:1100px){.page-header{align-items:flex-start}.toolbar{flex-wrap:wrap;justify-content:flex-end;max-width:190px}.demo{display:none}h1{font-size:40px}.subtitle{font-size:18px}.app-identity{font-size:15px;gap:10px}.app-volume{font-size:16px}.traffic-panel{min-height:0}}
  @media(prefers-reduced-motion:reduce){.bar-total,.bar-input,.bar-output{transition:none}}
</style>
