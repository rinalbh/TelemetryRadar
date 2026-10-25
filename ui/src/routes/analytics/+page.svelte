<script lang="ts">
  import { onMount } from 'svelte';
  import TrafficChart from '../../lib/components/TrafficChart.svelte';
  import AppIcon from '../../lib/components/AppIcon.svelte';
  import { createMockSource } from '../../lib/telemetry/mock-source';
  import { KB, MB, totals } from '../../lib/telemetry/model';
  import type { TelemetrySnapshot } from '../../lib/telemetry/types';
  import { m } from '../../lib/paraglide/messages.js';
  import { getLocale } from '../../lib/paraglide/runtime.js';

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
          <div class="app-identity"><AppIcon icon={app.icon} name={app.name}/><span>{app.name}</span></div>
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
  <footer><span class="brand"><span class="radar-icon" aria-hidden="true"></span>TelemetryRadar</span>    <div class="toolbar">
      <span class="demo">{m.demo()}</span>
      <button class="update-button" onclick={togglePause} aria-label={paused ? m.resume() : m.pause()} title={paused ? m.resume() : m.pause()} aria-pressed={paused}>
        <span class:paused class="status-dot"></span>
        <span>{paused ? m.paused() : m.live()}</span>
        <span class="playback-icon" class:play={paused} aria-hidden="true"></span>
      </button>
    </div><span data-testid="updated">{snapshot ? m.updated({ time: clock(snapshot.timestamp) }) : '—'}</span></footer>
</main>

<style>
  main { max-width: 1680px; margin: 0 auto; padding: 30px 3% 8px; animation: dashboard-enter 480ms cubic-bezier(.2,.7,.2,1) both; }
  .page-header { margin-bottom: 21px; }
  h1 { font-size: 44px; font-weight: 700; letter-spacing: -.5px; line-height: 53px; color: #151b36; margin: 0 0 6px 2px; }
  .subtitle { font-size: 21px; line-height: 25px; font-weight: 400; color: #7482a4; margin: 0 0 0 2px; }
  .panel { background: white; border-radius: 28px; padding: 17px 29px; }
  .traffic-panel { margin-bottom: 22px; height: 409px; }
  h2 { font-size: 24px; line-height: 29px; color: #151b36; margin: 0; font-weight: 700; }
  .chart-meta { display: flex; align-items: center; justify-content: space-between; margin-top: 14px; padding-right: 5px; font-size: 16px; line-height: 19px; color: #617193; }
  .rates, .chart-legend, .program-legend { display: flex; align-items: center; gap: 40px; }
  .chart-legend { gap: 34px; }
  .legend-item { display: inline-flex; align-items: center; gap: 10px; white-space: nowrap; }
  .legend-item strong { font-weight: 400; margin-left: -6px; }
  .dot { display: inline-block; width: 15px; height: 15px; flex-shrink: 0; border-radius: 50%; }
  .input { background: #00c5d7; } .output { background: #287dff; }
  .programs-panel { padding-top: 14px; padding-bottom: 9.5px; }
  .programs-heading { display: flex; align-items: center; gap: 25px; margin-bottom: 12px; }
  .program-legend { gap: 28px; font-size: 16px; color: #68799c; }
  .program-legend .dot { width: 14px; height: 14px; }
  .program-list { list-style: none; padding: 0; margin: 0; }
  .program-list li { display: grid; grid-template-columns: 28.87% 57.32% 13.81%; align-items: center; height: 46.5px; border-bottom: 1px solid #e3ecf8; }
  .program-list li:last-child { border-bottom: 0; }
  .app-identity { display: flex; align-items: center; gap: 15px; min-width: 0; padding-right: 16px; font-size: 17px; color: #455986; }
  .app-identity span { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .bar-track { height: 6px; border-radius: 3px; background: #e9f0fa; overflow: hidden; }
  .bar-total { height: 100%; display: flex; overflow: hidden; border-radius: 3px; transition: width .65s ease; }
  .bar-input { background: #00cdde; height: 100%; transition: width .65s ease; }
  .bar-output { background: #197fff; height: 100%; transition: width .65s ease; }
  .app-volume { text-align: right; padding-right: 6px; color: #455986; font-size: 18px; font-variant-numeric: tabular-nums; }
  footer { display: flex; justify-content: space-between; align-items: center; gap: 20px; font-size: 11px; padding: 4px 4px 0; color: #7c8fad; }
  .brand { display: flex; align-items: center; gap: 5px; letter-spacing: .2px; }
  .radar-icon { position: relative; width: 15px; height: 15px; border: 1px solid currentColor; border-radius: 50%; }
  .radar-icon::before { content: ''; position: absolute; inset: 3px; border: 1px solid currentColor; border-radius: 50%; }
  .radar-icon::after { content: ''; position: absolute; left: 50%; top: 50%; width: 7px; border-top: 1px solid currentColor; transform: rotate(-45deg); transform-origin: left; }
  .toolbar { display: flex; align-items: center; gap: 10px; font-size: 11px; white-space: nowrap; }
  .demo { color: #7c8fad; }
  .update-button { display: flex; align-items: center; gap: 7px; border: 1px solid #ffffff90; border-radius: 20px; padding: 4px 9px; background: #ffffff60; color: #617193; cursor: pointer; }
  .update-button:hover { background: #ffffffc0; }
  .playback-icon { width: 8px; height: 9px; border-left: 2px solid currentColor; border-right: 2px solid currentColor; margin-left: 3px; }
  .playback-icon.play { width: 0; height: 0; border: 4px solid transparent; border-left: 6px solid currentColor; border-right: 0; }
  .status-dot { width: 6px; height: 6px; border-radius: 50%; background: #00b9ae; }
  .status-dot.paused { background: #b18b28; }
  @keyframes dashboard-enter { from { opacity: 0; transform: translateY(15px); } to { opacity: 1; transform: translateY(0); } }
  @media (prefers-reduced-motion: reduce) { main { animation: none; } .bar-total, .bar-input, .bar-output { transition: none; } }
</style>
