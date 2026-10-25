<script lang="ts">
  import type { TrafficSample } from '../telemetry/types';
  import { m } from '../paraglide/messages.js';
  import { KB } from '../telemetry/model';

  let { history }: { history: TrafficSample[] } = $props();
  let canvas: HTMLCanvasElement;
  let width = $state(0);
  let height = $state(0);
  let hovered = $state<number | null>(null);
  let maxIn = $derived(Math.max(40, Math.ceil(Math.max(...history.map(p => p.inputBytesPerSecond / KB), 0) / 20) * 20));
  let maxOut = $derived(Math.max(20, Math.ceil(Math.max(...history.map(p => p.outputBytesPerSecond / KB), 0) / 20) * 20));
  let selected = $derived(hovered === null ? null : history[hovered]);
  const formatTime = (timestamp: number) => new Intl.DateTimeFormat('en', { timeZone: 'Europe/Moscow', hour: '2-digit', minute: '2-digit', hourCycle: 'h23' }).format(timestamp);

  function curve(ctx: CanvasRenderingContext2D, points: {x: number; y: number}[]) {
    if (!points.length) return;
    const slopes = points.slice(1).map((p, i) => (p.y - points[i].y) / (p.x - points[i].x));
    const tangents = points.map((_, i) => {
      if (i === 0) return slopes[0] ?? 0;
      if (i === points.length - 1) return slopes.at(-1) ?? 0;
      const a = slopes[i - 1], b = slopes[i];
      return a * b <= 0 ? 0 : 2 * a * b / (a + b);
    });
    ctx.moveTo(points[0].x, points[0].y);
    for (let i = 1; i < points.length; i++) {
      const a = points[i - 1], b = points[i], dx = (b.x - a.x) / 3;
      ctx.bezierCurveTo(a.x + dx, a.y + tangents[i - 1] * dx, b.x - dx, b.y - tangents[i] * dx, b.x, b.y);
    }
  }

  $effect(() => {
    if (!canvas || !width || !height) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    const dpr = window.devicePixelRatio || 1;
    canvas.width = Math.round(width * dpr);
    canvas.height = Math.round(height * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, width, height);
    const zero = height * 2 / 3;
    for (const direction of ['input', 'output'] as const) {
      const points = history.map((p, i) => ({
        x: i / Math.max(1, history.length - 1) * width,
        y: direction === 'input' ? zero - p.inputBytesPerSecond / KB / maxIn * zero
          : zero + p.outputBytesPerSecond / KB / maxOut * (height - zero)
      }));
      const fill = ctx.createLinearGradient(0, direction === 'input' ? 0 : zero, 0, direction === 'input' ? zero : height);
      fill.addColorStop(0, direction === 'input' ? '#00e8ee59' : '#006aff3d');
      fill.addColorStop(1, direction === 'input' ? '#00e8ee30' : '#006aff1f');
      ctx.beginPath(); curve(ctx, points);
      ctx.lineTo(width, zero); ctx.lineTo(0, zero); ctx.closePath();
      ctx.fillStyle = fill; ctx.fill();
      ctx.beginPath(); curve(ctx, points);
      ctx.strokeStyle = direction === 'input' ? '#00dce6' : '#0648ff';
      ctx.lineWidth = 2.6; ctx.stroke();
    }
    if (hovered !== null) {
      const x = hovered / Math.max(1, history.length - 1) * width;
      ctx.beginPath(); ctx.setLineDash([4, 4]); ctx.strokeStyle = '#5b64b7'; ctx.lineWidth = 1;
      ctx.moveTo(x, 0); ctx.lineTo(x, height); ctx.stroke();
    }
  });

  function inspect(event: PointerEvent) {
    const rect = canvas.getBoundingClientRect();
    hovered = Math.min(history.length - 1, Math.max(0, Math.round((event.clientX - rect.left) / rect.width * (history.length - 1))));
  }
  function navigate(event: KeyboardEvent) {
    if (event.key === 'Escape') hovered = null;
    if (event.key !== 'ArrowLeft' && event.key !== 'ArrowRight') return;
    event.preventDefault();
    hovered = Math.min(history.length - 1, Math.max(0, (hovered ?? history.length - 1) + (event.key === 'ArrowLeft' ? -1 : 1)));
  }
</script>

<div class="chart-wrap" role="group" aria-label={m.chart_label()}>
  <div class="plot" bind:clientWidth={width} bind:clientHeight={height}>
    <div class="grid" aria-hidden="true">
      {#each [0, 1/3, 2/3, 1] as y}<div class="horizontal" style:top={`${y * 100}%`}></div>{/each}
      {#each [0, 1, 2, 3, 4, 5] as i}<div class="vertical" style:left={`${i * 20}%`}></div>{/each}
    </div>
    <canvas bind:this={canvas} tabindex="0" onkeydown={navigate} onblur={() => hovered = null} aria-label={m.chart_label()} onpointermove={inspect} onpointerleave={() => hovered = null} data-sample-time={history.at(-1)?.timestamp}>
      {m.chart_label()}
    </canvas>
    <div class="zero-line" aria-hidden="true"></div>
    <div class="y-tick" style:top="0%">{maxIn} {m.kb()}</div>
    <div class="y-tick" style:top="33.333%">{maxIn / 2} {m.kb()}</div>
    <div class="y-tick" style:top="66.667%">0 {m.kb()}</div>
    <div class="y-tick" style:top="100%">{maxOut} {m.kb()}</div>
    {#each [0, 1, 2, 3, 4, 5] as i}
      <div class="x-tick" style:left={`${i * 20}%`}>{history.length ? formatTime(history[Math.round(i / 5 * (history.length - 1))].timestamp) : ''}</div>
    {/each}
  </div>
  <span class="y-title">{m.traffic_axis()}</span>
  <span class="x-title">{m.time_axis()}</span>
  {#if selected}
    <div class="tooltip"><strong>{formatTime(selected.timestamp)}</strong><span>{m.input()}: {m.rate({ value: (selected.inputBytesPerSecond / KB).toFixed(1) })}</span><span>{m.output()}: {m.rate({ value: (selected.outputBytesPerSecond / KB).toFixed(1) })}</span></div>
  {/if}
</div>

<style>
  .chart-wrap { position: relative; margin-top: 12px; height: clamp(240px, 22vw, 310px); color: #535fc3; font-size: 16px; }
  canvas:focus-visible { outline: 2px solid #648fff; outline-offset: 4px; border-radius: 8px; }
  .plot { position: absolute; inset: 24px 30px 66px 86px; }
  canvas, .grid { position: absolute; inset: 0; width: 100%; height: 100%; }
  .grid { pointer-events: none; }
  .horizontal { position: absolute; width: 100%; border-top: 1px dashed #8db5ff; }
  .vertical { position: absolute; height: 100%; border-left: 1px dashed #8db5ff; }
  .zero-line { position: absolute; top: 66.667%; width: 100%; border-top: 1px solid #648fff; pointer-events: none; }
  .y-tick { position: absolute; right: calc(100% + 14px); transform: translateY(-50%); white-space: nowrap; }
  .x-tick { position: absolute; top: calc(100% + 22px); transform: translateX(-50%); white-space: nowrap; }
  .x-tick::before { content: ''; position: absolute; height: 14px; border-left: 1px solid #91b4ff; bottom: calc(100% + 8px); left: 50%; }
  .y-title { position: absolute; left: 0; top: 47%; transform: translate(-37%, -50%) rotate(-90deg); white-space: nowrap; }
  .x-title { position: absolute; bottom: 0; left: 53%; transform: translateX(-50%); }
  .tooltip { position: absolute; right: 34px; top: 14px; display: grid; gap: 5px; padding: 12px 16px; border: 1px solid #dce6ff; background: #ffffffed; border-radius: 12px; font-size: 13px; color: #283893; box-shadow: 0 8px 24px #10286c10; pointer-events: none; }
</style>

