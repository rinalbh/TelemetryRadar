<script lang="ts">
  import type { TrafficSample } from '../telemetry/types';
  import { m } from '../paraglide/messages.js';
  import { getLocale } from '../paraglide/runtime.js';
  import { KB } from '../telemetry/model';

  let { history }: { history: TrafficSample[] } = $props();
  const left = 86, right = 1370, top = 24, bottom = 226, zero = 158;
  let maxIn = $derived(Math.max(40, Math.ceil(Math.max(...history.map(p => p.inputBytesPerSecond / KB), 0) / 20) * 20));
  let maxOut = $derived(Math.max(20, Math.ceil(Math.max(...history.map(p => p.outputBytesPerSecond / KB), 0) / 20) * 20));
  const formatTime = (timestamp: number) => new Intl.DateTimeFormat(getLocale(), { timeZone: 'Europe/Moscow', hour: '2-digit', minute: '2-digit', hourCycle: 'h23' }).format(timestamp);
  function path(direction: 'input' | 'output') {
    const points = history.map((sample, i) => ({
      x: left + i / Math.max(1, history.length - 1) * (right - left),
      y: direction === 'input'
        ? zero - sample.inputBytesPerSecond / KB / maxIn * (zero - top)
        : zero + sample.outputBytesPerSecond / KB / maxOut * (bottom - zero)
    }));
    if (!points.length) return '';
    const slopes = points.slice(1).map((point, i) => (point.y - points[i].y) / (point.x - points[i].x));
    const tangents = points.map((_, i) => {
      if (i === 0) return slopes[0] ?? 0;
      if (i === points.length - 1) return slopes.at(-1) ?? 0;
      const a = slopes[i - 1], b = slopes[i];
      return a * b <= 0 ? 0 : 2 * a * b / (a + b);
    });
    let d = `M ${points[0].x} ${points[0].y}`;
    // Monotone Hermite interpolation avoids artificial peaks between samples.
    for (let i = 1; i < points.length; i++) {
      const a = points[i - 1], b = points[i], dx = (b.x - a.x) / 3;
      d += ` C ${a.x + dx} ${a.y + tangents[i - 1] * dx} ${b.x - dx} ${b.y - tangents[i] * dx} ${b.x} ${b.y}`;
    }
    return d;
  }
  let inputPath = $derived(path('input'));
  let outputPath = $derived(path('output'));
  let hovered = $state<number | null>(null);
  let selected = $derived(hovered === null ? null : history[hovered]);
  function inspect(event: PointerEvent) {
    const rect = event.currentTarget instanceof SVGElement ? event.currentTarget.getBoundingClientRect() : null;
    if (rect) hovered = Math.min(history.length - 1, Math.max(0, Math.round(((event.clientX - rect.left) / rect.width * 1400 - left) / (right - left) * (history.length - 1))));
  }
</script>

<div class="chart-wrap">
  <svg viewBox="0 0 1400 294" role="img" aria-label={m.chart_label()} onpointermove={inspect} onpointerleave={() => hovered = null}>
    <defs>
      <linearGradient id="input-fill" x1="0" y1="0" x2="0" y2="1"><stop stop-color="#00e8ee" stop-opacity=".35"/><stop offset="1" stop-color="#00e8ee" stop-opacity=".19"/></linearGradient>
      <linearGradient id="output-fill" x1="0" y1="0" x2="0" y2="1"><stop stop-color="#006aff" stop-opacity=".24"/><stop offset="1" stop-color="#006aff" stop-opacity=".12"/></linearGradient>
      <clipPath id="plot-clip"><rect x={left} y={top} width={right-left} height={bottom-top}/></clipPath>
    </defs>
    <g class="grid">
      {#each [top, (top + zero) / 2, zero, bottom] as y}<line x1={left} x2={right} y1={y} y2={y}/>{/each}
      {#each [0, 1, 2, 3, 4, 5] as i}
        {@const x = left + i / 5 * (right - left)}
        <line x1={x} x2={x} y1={top} y2={bottom}/>
      {/each}
    </g>
    <g clip-path="url(#plot-clip)">
      <path d={`${inputPath} L ${right} ${zero} L ${left} ${zero} Z`} fill="url(#input-fill)"/>
      <path d={`${outputPath} L ${right} ${zero} L ${left} ${zero} Z`} fill="url(#output-fill)"/>
      <path d={inputPath} fill="none" stroke="#00dce6" stroke-width="2.6"/>
      <path d={outputPath} fill="none" stroke="#0648ff" stroke-width="2.8"/>
    </g>
    <line x1={left} x2={right} y1={zero} y2={zero} stroke="#648fff" stroke-width="1"/>
    <g class="labels" text-anchor="end">
      <text x="72" y={top+6}>{maxIn} {m.kb()}</text>
      <text x="72" y={(top+zero)/2+6}>{maxIn/2} {m.kb()}</text>
      <text x="72" y={zero+6}>0 {m.kb()}</text>
      <text x="72" y={bottom+1}>{maxOut} {m.kb()}</text>
    </g>
    <g class="labels" text-anchor="middle">
      {#each [0, 1, 2, 3, 4, 5] as i}
        {@const x = left + i / 5 * (right-left)}
        <line x1={x} x2={x} y1={bottom} y2={bottom+14} stroke="#91b4ff"/>
        <text x={x} y="260">{history.length ? formatTime(history[Math.round(i/5*(history.length-1))].timestamp) : ''}</text>
      {/each}
      <text x="728" y="286">{m.time_axis()}</text>
      <text transform="translate(16 133) rotate(-90)">{m.traffic_axis()}</text>
    </g>
    {#if selected && hovered !== null}
      {@const x = left + hovered / Math.max(1, history.length-1) * (right-left)}
      <line x1={x} x2={x} y1={top} y2={bottom} stroke="#5b64b7" stroke-dasharray="4 4"/>
    {/if}
  </svg>
  {#if selected}
    <div class="tooltip"><strong>{formatTime(selected.timestamp)}</strong><span>{m.input()}: {m.rate({ value: (selected.inputBytesPerSecond/KB).toFixed(1) })}</span><span>{m.output()}: {m.rate({ value: (selected.outputBytesPerSecond/KB).toFixed(1) })}</span></div>
  {/if}
</div>

<style>
  .chart-wrap{position:relative;margin:12px 0 0}svg{width:100%;display:block;overflow:visible}.grid line{stroke:#8db5ff;stroke-width:1;stroke-dasharray:3 2}.labels{fill:#535fc3;font-size:16px;font-weight:500}.tooltip{position:absolute;right:34px;top:14px;display:grid;gap:5px;padding:12px 16px;border:1px solid #dce6ff;background:#ffffffed;border-radius:12px;font-size:13px;color:#283893;box-shadow:0 8px 24px #10286c10;pointer-events:none}
</style>
