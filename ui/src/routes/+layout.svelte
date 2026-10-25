<script lang="ts">
  import type { Snippet } from 'svelte';
  let { children }: { children: Snippet } = $props();
</script>

{@render children()}

<style>
  :global(*) { box-sizing: border-box; }
  :global(html) { min-width: 960px; min-height: 100%; }
  :global(body) { margin: 0; min-width: 960px; min-height: 100vh; font-family: Arial, Helvetica, sans-serif; color: #455986; background: linear-gradient(180deg, #edf6ff 0%, #aaccee 100%); -webkit-font-smoothing: antialiased; }
  :global(button), :global(a) { -webkit-tap-highlight-color: transparent; }
  :global(button) { font: inherit; }
  :global(button:focus-visible), :global(a:focus-visible) { outline: 3px solid #3478ff; outline-offset: 5px; }
</style>
