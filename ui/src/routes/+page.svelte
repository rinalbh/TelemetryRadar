<script lang="ts">
  import { goto } from '$app/navigation';
  import { onDestroy } from 'svelte';

  let leaving = $state(false);
  let transitionTimer: ReturnType<typeof setTimeout> | undefined;

  function startRecording() {
    if (leaving) return;
    leaving = true;
    const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    transitionTimer = setTimeout(() => {
      void goto('/analytics').catch(() => { leaving = false; });
    }, reducedMotion ? 0 : 320);
  }
  onDestroy(() => clearTimeout(transitionTimer));
</script>

<svelte:head>
  <title>TelemetryRadar · Ready to record</title>
  <meta name="description" content="Record desktop application network traffic and explore it with TelemetryRadar." />
</svelte:head>

<main class:leaving>
  <header>
    <h1>TelemetryRadar</h1>
    <p>Record the computer, pick one app, then let an agent explain it.</p>
  </header>
  <section class="welcome-card" aria-labelledby="ready-heading">
    <div class="record-indicator" aria-hidden="true"><span></span></div>
    <h2 id="ready-heading">Ready to record</h2>
    <p class="explanation">This captures upload and download for every desktop app.<br />You choose one app after the capture stops.</p>
    <button type="button" onclick={startRecording} disabled={leaving}>Start recording</button>
    <p class="hint">Stop the capture later from the traffic dashboard.</p>
  </section>
</main>

<style>
  main { max-width: 1680px; margin: 0 auto; padding: 30px 3% 48px; }
  header { transition: opacity 250ms ease; }
  h1 { margin: 0; font-size: 44px; line-height: 53px; letter-spacing: -.5px; color: #151b36; }
  header p { margin: 7px 0 0 2px; font-size: 21px; line-height: 25px; color: #52617b; }
  .welcome-card { width: 800px; height: 520px; margin: 73px auto 0; padding: 72px 36px 32px; border-radius: 28px; background: white; box-shadow: 0 12px 32px #4559860c; text-align: center; transition: transform 320ms cubic-bezier(.4, 0, .2, 1), opacity 280ms ease, filter 320ms ease; animation: welcome-enter 550ms cubic-bezier(.2, .7, .2, 1) both; }
  .record-indicator { display: grid; place-items: center; width: 116px; height: 116px; border: 2px solid #d6e6fa; border-radius: 50%; background: #f4f8ff; margin: 0 auto 24px; }
  .record-indicator span { width: 36px; height: 36px; background: #ff5a6c; border-radius: 50%; box-shadow: 0 0 0 0 #ff5a6c20; animation: record-breathe 3s ease-in-out infinite; }
  h2 { font-size: 32px; line-height: 38px; color: #151b36; margin: 0 0 16px; }
  .explanation { font-size: 18px; line-height: 28px; color: #52617b; margin: 0; }
  button { display: block; width: 360px; height: 56px; border: 0; border-radius: 28px; background: #3478ff; color: white; font-size: 18px; font-weight: 600; margin: 30px auto 0; cursor: pointer; transition: background 180ms ease, transform 180ms ease, box-shadow 180ms ease; }
  button:hover { background: #2469ef; transform: translateY(-2px); box-shadow: 0 8px 20px #3478ff25; }
  button:active { transform: translateY(0) scale(.985); }
  button:disabled { cursor: default; }
  .hint { margin: 52px 0 0; color: #8b98b0; font-size: 14px; line-height: 18px; }
  .leaving header { opacity: .3; }
  .leaving .welcome-card { animation: none; opacity: 0; transform: translateY(-18px) scale(.975); filter: blur(3px); }
  @keyframes welcome-enter { from { opacity: 0; transform: translateY(12px); } to { opacity: 1; transform: translateY(0); } }
  @keyframes record-breathe { 0%, 100% { box-shadow: 0 0 0 0 #ff5a6c18; } 50% { box-shadow: 0 0 0 10px #ff5a6c00; } }
  @media (prefers-reduced-motion: reduce) { header, .welcome-card, button { transition: none; } .welcome-card, .record-indicator span { animation: none; } .leaving .welcome-card { transform: none; filter: none; } }
</style>
