<script lang="ts">
  let { icon, name }: { icon: string; name: string } = $props();
  const mockIcons = new Set(['zoom', 'telegram', 'slack', 'chrome', 'terminal', 'bird', 'rapportd']);
  let kind = $derived(icon.startsWith('mock:') && mockIcons.has(icon.slice(5)) ? icon.slice(5) : 'fallback');
  let raster = $derived(/^\/icons\/[a-z0-9_-]+\.(png|webp|jpe?g)$/i.test(icon) || /^data:image\/(png|webp|jpeg);base64,/i.test(icon));
</script>

{#if raster}
  <img src={icon} alt="" width="38" height="38" />
{:else}
  <span class="app-icon {kind}" aria-hidden="true">
    {#if kind === 'zoom'}<b>zoom</b>
    {:else if kind === 'telegram'}<i class="paper-plane"></i>
    {:else if kind === 'slack'}<i></i><i></i><i></i><i></i>
    {:else if kind === 'chrome'}<i></i>
    {:else if kind === 'bird'}<i class="envelope"></i>
    {:else if kind === 'terminal' || kind === 'rapportd'}<b>&gt;{kind === 'terminal' ? '_' : '›'}</b>
    {:else}<b>{name.slice(0, 2).toUpperCase()}</b>{/if}
  </span>
{/if}

<style>
  img, .app-icon { width: 38px; height: 38px; flex: 0 0 38px; }
  .app-icon { position: relative; display: inline-flex; align-items: center; justify-content: center; overflow: hidden; border-radius: 9px; background: #e7edff; color: #4655ac; font: 700 14px Arial, sans-serif; }
  .zoom { background: linear-gradient(140deg, #02cafa, #052bff); color: white; }
  .zoom b { font-size: 10px; letter-spacing: -.5px; }
  .telegram { background: #06b8f2; border-radius: 50%; }
  .paper-plane { width: 25px; height: 24px; background: white; clip-path: polygon(0 40%, 100% 0, 77% 100%, 48% 72%, 29% 90%, 33% 59%, 80% 18%, 24% 54%); }
  .slack { background: transparent; }
  .slack i { position: absolute; width: 8px; height: 22px; border-radius: 5px; }
  .slack i:nth-child(1) { background: #35c5f0; left: 11px; top: 1px; }
  .slack i:nth-child(2) { background: #24b67c; transform: rotate(90deg); left: 23px; top: 4px; }
  .slack i:nth-child(3) { background: #eab12e; left: 20px; top: 16px; }
  .slack i:nth-child(4) { background: #e71d5b; transform: rotate(90deg); left: 7px; top: 13px; }
  .chrome { border-radius: 50%; background: conic-gradient(#fa4246 0deg 118deg, #ffcc3c 118deg 238deg, #13c96d 238deg 360deg); }
  .chrome i { width: 19px; height: 19px; border: 2px solid white; border-radius: 50%; background: #1689fa; }
  .terminal, .rapportd { background: linear-gradient(135deg, #3b4048, #080a0d); color: white; justify-content: flex-start; align-items: flex-start; padding: 7px; }
  .rapportd { background: #101612; color: #31ad38; }
  .bird { border-radius: 50%; background: radial-gradient(circle at 70% 25%, #00ceff, #0575ff 65%); }
  .envelope { width: 23px; height: 17px; border-radius: 3px; background: #e9f8ff; position: relative; overflow: hidden; }
  .envelope::after { content: ''; position: absolute; width: 16px; height: 16px; border: 2px solid #a7d8ed; transform: rotate(45deg); top: -10px; left: 2px; }
</style>
