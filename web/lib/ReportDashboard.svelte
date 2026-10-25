<script lang="ts">
  import type { AnalysisResult } from './opencode';
  import type { CapturedProcess } from './capture';
  import { requireSupportedReportVersion, type RiskLevel, type TrafficKind, type Evidence, type ReportV1 } from './traffic-report';
  import { formatBytes, formatInteger, processName } from './workflow-format';

  let { result, process = null, modelLabel, onNewCapture }: {
    result: AnalysisResult;
    process: CapturedProcess | null;
    modelLabel: string;
    onNewCapture: () => void;
  } = $props();

  let search = $state('');
  let riskFilter = $state<'all' | RiskLevel>('all');
  let sort = $state<'kind' | 'risk' | 'amount'>('kind');
  let expanded = $state<string[]>([]);
  const riskOrder: Record<RiskLevel, number> = { high: 3, medium: 2, low: 1, unknown: 0 };
  const unitLabels = { packets: 'packets', frame_bytes: 'frame bytes', requests: 'requests', connections: 'connections', events: 'events' };
  const emptyReport: ReportV1 = { schemaVersion: 1, summary: '', trafficKinds: [], evidence: [], limitations: [] };

  let versionError = $derived.by(() => {
    try { requireSupportedReportVersion(result.report); return ''; }
    catch (error) { return String(error instanceof Error ? error.message : error); }
  });
  // Unsupported future versions may have an entirely different object shape.
  // Keep every downstream derivation safe while the version error is displayed.
  let report = $derived(versionError ? emptyReport : result.report);
  let evidenceById = $derived(new Map(report.evidence.map((evidence) => [evidence.id, evidence])));
  let rows = $derived.by(() => {
    const query = search.trim().toLocaleLowerCase();
    const filtered = report.trafficKinds.filter((row) =>
      (riskFilter === 'all' || row.risk.level === riskFilter)
      && (!query || `${row.kind} ${row.description} ${row.example?.text ?? ''}`.toLocaleLowerCase().includes(query)));
    return filtered.toSorted((a, b) => {
      if (sort === 'risk') return riskOrder[b.risk.level] - riskOrder[a.risk.level] || a.kind.localeCompare(b.kind);
      if (sort === 'amount') {
        // Different units have no common denominator. Keep them in separate groups.
        return a.amount.unit.localeCompare(b.amount.unit)
          || (b.amount.value ?? -1) - (a.amount.value ?? -1)
          || a.kind.localeCompare(b.kind);
      }
      return a.kind.localeCompare(b.kind);
    });
  });

  function amount(row: TrafficKind): string {
    if (row.amount.value === null) return 'Unknown';
    return row.amount.unit === 'frame_bytes'
      ? formatBytes(row.amount.value)
      : `${formatInteger(row.amount.value)} ${unitLabels[row.amount.unit]}`;
  }
  function toggle(id: string): void {
    expanded = expanded.includes(id) ? expanded.filter((entry) => entry !== id) : [...expanded, id];
  }
  function detailId(id: string): string { return `finding-details-${report.trafficKinds.findIndex((row) => row.id === id)}`; }
  function relatedEvidence(row: TrafficKind): { id: string; evidence: Evidence | undefined }[] {
    return [...new Set([...row.evidenceRefs, ...row.amount.evidenceRefs, ...row.risk.evidenceRefs, ...(row.example?.evidenceRefs ?? [])])]
      .map((id) => ({ id, evidence: evidenceById.get(id) }));
  }
</script>

{#if versionError}
  <section class="report-error" role="alert">
    <span class="report-eyebrow">REPORT UNAVAILABLE</span>
    <h1>This report needs a newer reader.</h1>
    <p>{versionError}</p>
    <button class="report-button" onclick={onNewCapture}>Start a new recording</button>
  </section>
{:else}
  <section class="report-dashboard" aria-label="Traffic analysis results">
    <header class="report-heading">
      <div>
        <div class="report-heading-meta"><span class="report-complete"><span></span>Analysis complete</span><span>Report 1</span></div>
        <h1>{processName(process)} <span>traffic report</span></h1>
        <p>{process ? `Process ${process.pid} · ` : ''}{modelLabel || 'Configured OpenCode model'}</p>
      </div>
      <button class="report-button report-button-secondary" onclick={onNewCapture}><span aria-hidden="true">+</span> New recording</button>
    </header>

    <div class="report-overview">
      <section class="report-card report-summary" aria-labelledby="report-overview-title">
        <div class="report-section-top"><h2 id="report-overview-title">What we found</h2><span class="report-small-chip">Selected app</span></div>
        <p class="report-summary-text">{report.summary}</p>
        <p class="report-quiet">Findings describe the recorded traffic. Encrypted or missing data can limit what is visible.</p>
      </section>
      <section class="report-card report-measurements" aria-labelledby="report-measurements-title">
        <h2 id="report-measurements-title">Recorded traffic</h2>
        <div class="report-totals">
          <div><strong>{formatBytes(result.validation.totals.frameBytes)}</strong><span>original frame lengths</span></div>
          <div><strong>{formatInteger(result.validation.totals.packets)}</strong><span>packets in this app's recording</span></div>
        </div>
        <p class="report-verification"><span aria-hidden="true">✓</span> {result.validation.quantitiesVerified ? 'Amounts checked against the recording' : 'Quantity verification unavailable'}</p>
      </section>
    </div>

    <section class="report-card report-findings" aria-labelledby="report-findings-title">
      <div class="report-section-top report-findings-heading">
        <div><h2 id="report-findings-title">Traffic, explained</h2><p>Explore what the app communicated and the evidence behind each finding.</p></div>
        <span class="report-count">{report.trafficKinds.length} {report.trafficKinds.length === 1 ? 'finding' : 'findings'}</span>
      </div>
      <div class="report-filters">
        <label class="report-search"><span aria-hidden="true">⌕</span><span class="report-sr-only">Search findings</span><input type="search" bind:value={search} placeholder="Search traffic…" /></label>
        <label class="report-select"><span>Risk</span><select bind:value={riskFilter}><option value="all">All risks</option><option value="low">Low</option><option value="medium">Medium</option><option value="high">High</option><option value="unknown">Unknown</option></select></label>
        <label class="report-select"><span>Sort</span><select bind:value={sort}><option value="kind">Kind</option><option value="risk">Risk</option><option value="amount">Amount, by unit</option></select></label>
      </div>

      {#if report.trafficKinds.length === 0}
        <div class="report-empty"><span aria-hidden="true">◎</span><h3>No traffic categories are available.</h3><p>The summary and visibility notes explain whether the recording is empty or traffic could not be classified.</p></div>
      {:else if rows.length === 0}
        <div class="report-empty" role="status"><h3>No matching findings.</h3><p>Try another search or risk level.</p><button class="report-text-button" onclick={() => { search = ''; riskFilter = 'all'; }}>Clear filters</button></div>
      {:else}
        <!-- svelte-ignore a11y_no_noninteractive_tabindex (The overflow region needs keyboard focus for horizontal scrolling.) -->
        <div class="report-table-wrap" tabindex="0" role="region" aria-label="Traffic findings table; scroll horizontally on smaller screens">
          <table>
            <thead><tr><th scope="col">Kind</th><th scope="col">Description</th><th scope="col">Amount</th><th scope="col">Risk</th><th scope="col">Example</th></tr></thead>
            <tbody>
              {#each rows as row (row.id)}
                <tr class:report-row-open={expanded.includes(row.id)}>
                  <th scope="row"><div class="report-kind"><span class="report-kind-dot" aria-hidden="true"></span><strong>{row.kind}</strong></div><button class="report-details-button" aria-expanded={expanded.includes(row.id)} aria-controls={detailId(row.id)} onclick={() => toggle(row.id)}>{expanded.includes(row.id) ? 'Hide details' : 'View details'}<span aria-hidden="true">{expanded.includes(row.id) ? '−' : '+'}</span></button></th>
                  <td class="report-description">{row.description}</td>
                  <td class="report-amount"><strong>{amount(row)}</strong><span>{row.amount.coverage} coverage</span>{#if row.amount.unit === 'frame_bytes'}<span>frame bytes</span>{/if}</td>
                  <td><span class="report-risk" class:report-risk-low={row.risk.level === 'low'} class:report-risk-medium={row.risk.level === 'medium'} class:report-risk-high={row.risk.level === 'high'}>{row.risk.level}</span></td>
                  <td class="report-example">{#if row.example}<q>{row.example.text}</q>{#if row.example.redacted}<span class="report-redacted">Agent marked as redacted</span>{/if}{:else}<span class="report-unavailable">No suitable example</span>{/if}</td>
                </tr>
                <tr class="report-detail-row" hidden={!expanded.includes(row.id)} id={detailId(row.id)}><td colspan="5">
                  {#if expanded.includes(row.id)}
                    <div class="report-row-details">
                      <div class="report-basis-grid">
                        <div><h3>How the amount was measured</h3><p>{row.amount.basis}</p><span class="report-detail-caption">{row.amount.value === null ? 'Unknown amount' : `${formatInteger(row.amount.value)} ${unitLabels[row.amount.unit]}`} · {row.amount.coverage} coverage</span></div>
                        <div><h3>Why this risk level</h3><p>{row.risk.rationale}</p><span class="report-detail-caption">{row.risk.level === 'unknown' || row.risk.evidenceRefs.length === 0 ? 'No supported risk assessment is available.' : 'An agent assessment. Referenced traffic was checked; the interpretation remains unverified.'}</span></div>
                      </div>
                      <div class="report-evidence-heading"><h3>Supporting evidence</h3><span>{result.validation.evidenceLocatorsVerified ? 'Locators checked' : 'Locator verification unavailable'}</span></div>
                      {#each relatedEvidence(row) as entry (entry.id)}
                        {#if entry.evidence}
                          {@const evidence = entry.evidence}
                          <details class="report-evidence"><summary><span class="report-evidence-id">{evidence.id}</span><span>{evidence.note}</span></summary><div class="report-evidence-body">
                            {#if evidence.frames.length}<div><span class="report-detail-caption">Frames in this recording</span><p>{evidence.frames.map(formatInteger).join(', ')}</p></div>{/if}
                            {#if evidence.streams.length}<div><span class="report-detail-caption">Streams in this recording</span><p>{evidence.streams.map((stream) => `${stream.protocol.toUpperCase()} ${stream.id}`).join(', ')}</p></div>{/if}
                            {#if evidence.displayFilter}<div><span class="report-detail-caption">Display filter</span><code>{evidence.displayFilter}</code></div>{/if}
                          </div></details>
                        {:else}<p class="report-quiet">Evidence {entry.id} is unavailable.</p>{/if}
                      {:else}<p class="report-quiet">No quantitative or qualitative evidence was available for this finding.</p>{/each}
                      <p class="report-evidence-note">Checking a frame, stream or filter confirms that the traffic exists. It does not prove the agent's interpretation or privacy assessment.</p>
                    </div>
                  {/if}
                </td></tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
      <footer class="report-table-footer"><span aria-live="polite">{rows.length} of {report.trafficKinds.length} findings</span><p>Categories can overlap. Their amounts should not be added together.</p></footer>
    </section>

    <section class="report-card report-limitations" aria-labelledby="report-limitations-title">
      <div class="report-limitations-symbol" aria-hidden="true">i</div>
      <div><h2 id="report-limitations-title">Visibility &amp; limitations</h2>
        <ul>{#each report.limitations as limitation}<li>{limitation}</li>{/each}<li>This recording is filtered to the selected app's packets. Retained metadata and TLS secrets can include other processes; the recording is not sanitized.</li></ul>
        <p class="report-quiet">Traffic amounts use original frame lengths, not application payload size. Risk levels and purpose descriptions are agent assessments.</p>
      </div>
    </section>
  </section>
{/if}

<style>
  .report-dashboard { display: grid; gap: 24px; color: #182344; }
  .report-heading { display: flex; align-items: center; justify-content: space-between; gap: 24px; }
  .report-heading > div { min-width: 0; }
  .report-heading-meta { display: flex; align-items: center; gap: 16px; font-size: 12px; color: #7e90ae; margin-bottom: 13px; }
  .report-complete { display: inline-flex; align-items: center; gap: 7px; color: #038b82; font-weight: 650; }
  .report-complete > span { width: 7px; height: 7px; border-radius: 50%; background: #04b9b7; }
  .report-heading h1 { font-size: clamp(25px, 3vw, 36px); line-height: 1.2; letter-spacing: -.9px; font-weight: 720; margin: 0; overflow-wrap: anywhere; }
  .report-heading h1 > span { font-weight: 450; color: #64789d; }
  .report-heading p { margin-top: 9px; color: #63799d; font-size: 13px; overflow-wrap: anywhere; }
  .report-button { display: inline-flex; justify-content: center; align-items: center; gap: 8px; border: 0; border-radius: 100px; color: #fff; background: #3478ff; padding: 12px 21px; font: inherit; font-size: 13px; font-weight: 650; cursor: pointer; flex-shrink: 0; }
  .report-button:hover { background: #2665e6; }
  .report-button-secondary { color: #2963ca; background: #fff; border: 1px solid #d2e0f4; }
  .report-button-secondary:hover { background: #f4f8ff; }
  .report-button-secondary > span { font-size: 19px; font-weight: 400; line-height: .8; }
  .report-card { min-width: 0; border-radius: 23px; background: #fff; border: 1px solid #e3ebf6; box-shadow: 0 7px 24px #376aa707; }
  .report-overview { display: grid; grid-template-columns: minmax(0, 1.25fr) minmax(320px, 1fr); gap: 22px; }
  .report-summary, .report-measurements { padding: 26px 29px; }
  .report-section-top { display: flex; align-items: flex-start; gap: 16px; justify-content: space-between; }
  h2 { margin: 0; font-size: 18px; letter-spacing: -.3px; font-weight: 690; }
  .report-small-chip { font-size: 10px; background: #eff3ff; color: #5b77d3; padding: 5px 9px; border-radius: 30px; white-space: nowrap; }
  .report-summary-text { margin: 19px 0 15px; line-height: 1.75; color: #3f557a; font-size: 14px; white-space: pre-wrap; overflow-wrap: anywhere; }
  .report-quiet { font-size: 12px; color: #7184a5; line-height: 1.65; margin: 0; }
  .report-totals { display: grid; grid-template-columns: 1fr 1fr; gap: 22px; margin: 27px 0 22px; }
  .report-totals > div + div { border-left: 1px solid #e7edf7; padding-left: 24px; }
  .report-totals strong { display: block; font-size: 31px; letter-spacing: -.9px; font-weight: 650; }
  .report-totals span { display: block; font-size: 11px; color: #7b8dad; margin-top: 9px; line-height: 1.45; }
  .report-verification { display: flex; align-items: center; gap: 7px; font-size: 11px; color: #638598; margin: 0; }
  .report-verification > span { display: grid; place-items: center; width: 17px; height: 17px; background: #e6f7f4; color: #079a87; border-radius: 50%; font-size: 10px; }
  .report-findings { overflow: hidden; }
  .report-findings-heading { padding: 28px 29px 0; }
  .report-findings-heading p { font-size: 12px; color: #7184a5; margin: 8px 0 0; line-height: 1.6; }
  .report-count { font-size: 11px; color: #6a80a2; padding-top: 5px; white-space: nowrap; }
  .report-filters { display: flex; gap: 12px; padding: 22px 29px; align-items: center; }
  .report-search { display: flex; align-items: center; gap: 8px; background: #f7f9fd; border: 1px solid #e0e8f5; border-radius: 10px; padding: 0 12px; flex: 1; color: #8a9cba; min-width: 120px; }
  .report-search > span:first-child { font-size: 21px; }
  .report-search input { border: 0; width: 100%; min-width: 0; background: transparent; padding: 11px 0; color: #334969; outline-offset: 3px; font: inherit; font-size: 12px; }
  .report-search input::placeholder { color: #8b9db9; }
  .report-select { display: inline-flex; align-items: center; gap: 7px; font-size: 11px; color: #7c8fae; }
  .report-select select { border: 1px solid #e0e8f5; background: #fff; padding: 10px 25px 10px 10px; border-radius: 9px; color: #425a7d; font: inherit; font-size: 12px; cursor: pointer; }
  .report-table-wrap { overflow-x: auto; }
  table { width: 100%; border-collapse: collapse; min-width: 850px; font-size: 12px; table-layout: fixed; }
  thead { background: #f7f9fd; color: #7a8cac; }
  th, td { text-align: left; vertical-align: top; }
  thead th { padding: 13px 15px; font-size: 10px; letter-spacing: .5px; font-weight: 550; }
  thead th:first-child { width: 19%; padding-left: 29px; }
  thead th:nth-child(2) { width: 29%; }
  thead th:nth-child(3) { width: 15%; }
  thead th:nth-child(4) { width: 11%; }
  thead th:nth-child(5) { width: 26%; padding-right: 29px; }
  tbody tr:not(.report-detail-row) { border-bottom: 1px solid #edf1f8; }
  tbody th, tbody td { padding: 23px 15px; overflow-wrap: anywhere; line-height: 1.7; }
  tbody th { padding-left: 29px; }
  tbody td:last-child { padding-right: 29px; }
  .report-kind { display: flex; align-items: baseline; gap: 9px; line-height: 1.5; }
  .report-kind strong { font-weight: 650; color: #27375b; }
  .report-kind-dot { display: inline-block; background: #3478ff; border-radius: 50%; width: 8px; height: 8px; flex-shrink: 0; }
  tbody tr:nth-child(4n + 3) .report-kind-dot { background: #00bdc8; }
  .report-description { color: #5e7397; white-space: pre-wrap; }
  .report-amount strong { display: block; color: #3b5278; font-weight: 600; }
  .report-amount > span { display: block; font-size: 10px; line-height: 1.5; color: #8292ae; margin-top: 4px; }
  .report-risk { display: inline-flex; align-items: center; justify-content: center; min-width: 63px; background: #edf1f7; color: #7484a0; border-radius: 99px; padding: 3px 10px; font-size: 10px; text-transform: capitalize; }
  .report-risk-low { color: #008f83; background: #e5f7f4; }
  .report-risk-medium { color: #b57821; background: #fff3e0; }
  .report-risk-high { color: #ce4b63; background: #ffedf0; }
  .report-example { color: #627897; font-size: 11px; }
  .report-example q { quotes: none; white-space: pre-wrap; font-family: Consolas, monospace; }
  .report-redacted { display: block; font-size: 9px; color: #8b9ab0; margin-top: 6px; }
  .report-unavailable { color: #91a0b7; }
  .report-details-button, .report-text-button { display: inline-flex; align-items: center; gap: 8px; color: #4778c5; background: transparent; border: 0; padding: 7px 0 0; font: inherit; font-size: 10px; cursor: pointer; font-weight: 550; }
  .report-details-button { margin-left: 17px; }
  .report-details-button:hover, .report-text-button:hover { color: #1e60d0; }
  .report-details-button > span { font-size: 15px; line-height: 1; }
  .report-row-open { background: #fcfdff; }
  .report-detail-row > td { padding: 0; }
  .report-row-details { background: #f8faff; border-bottom: 1px solid #e5edf8; padding: 25px 29px; }
  .report-basis-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 28px; }
  .report-row-details h3 { font-size: 12px; font-weight: 650; color: #3c5378; margin: 0 0 8px; }
  .report-basis-grid p { font-size: 12px; line-height: 1.75; color: #647a9a; margin: 0; white-space: pre-wrap; }
  .report-detail-caption { display: block; font-size: 10px; color: #8294b0; margin-top: 9px; line-height: 1.65; }
  .report-evidence-heading { display: flex; align-items: center; gap: 13px; margin: 24px 0 10px; }
  .report-evidence-heading h3 { margin: 0; }
  .report-evidence-heading > span { font-size: 9px; border: 1px solid #d9e8e6; color: #55968c; padding: 2px 7px; border-radius: 20px; }
  .report-evidence { border: 1px solid #dfe8f4; background: #fff; border-radius: 9px; margin-top: 8px; padding: 11px 13px; }
  .report-evidence summary { color: #617696; cursor: pointer; font-size: 11px; line-height: 1.65; overflow-wrap: anywhere; }
  .report-evidence-id { font-family: Consolas, monospace; color: #3975c8; margin-right: 12px; }
  .report-evidence-body { display: grid; gap: 12px; padding: 6px 0 2px 13px; }
  .report-evidence-body p { margin: 3px 0 0; color: #556e92; font-size: 11px; }
  .report-evidence-body code { display: block; white-space: pre-wrap; overflow-wrap: anywhere; color: #496998; font-size: 11px; margin-top: 5px; user-select: text; }
  .report-evidence-note { color: #8293ad; margin: 15px 0 0; font-size: 10px; line-height: 1.7; }
  .report-table-footer { padding: 17px 29px; display: flex; align-items: center; justify-content: space-between; gap: 15px; color: #8b9bb3; font-size: 10px; }
  .report-table-footer p { margin: 0; line-height: 1.6; text-align: right; }
  .report-table-footer > span { white-space: nowrap; }
  .report-limitations { display: flex; align-items: flex-start; gap: 18px; padding: 25px 29px; }
  .report-limitations-symbol { display: grid; place-items: center; width: 27px; height: 27px; flex-shrink: 0; border-radius: 50%; background: #edf3ff; color: #6794de; font-family: Georgia, serif; font-size: 17px; }
  .report-limitations h2 { font-size: 16px; margin-top: 3px; }
  .report-limitations ul { padding-left: 17px; margin: 14px 0; color: #667d9e; font-size: 12px; line-height: 1.8; }
  .report-limitations li + li { margin-top: 5px; }
  .report-empty { text-align: center; padding: 52px 24px; color: #6c81a2; }
  .report-empty > span { color: #b4c9ee; font-size: 30px; }
  .report-empty h3 { font-size: 15px; color: #4d6487; margin: 12px 0 9px; }
  .report-empty p { max-width: 460px; margin: 0 auto; font-size: 12px; line-height: 1.75; }
  .report-empty .report-text-button { margin-top: 12px; }
  .report-error { background: #fff; border-radius: 23px; padding: 42px; color: #334969; }
  .report-eyebrow { font-size: 10px; letter-spacing: 1.5px; color: #8b9db9; }
  .report-error h1 { font-size: 26px; margin-top: 15px; }
  .report-error p { margin: 15px 0 24px; line-height: 1.7; color: #7b89a0; }
  .report-sr-only { position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px; overflow: hidden; clip: rect(0, 0, 0, 0); white-space: nowrap; border: 0; }
  button:focus-visible, input:focus-visible, select:focus-visible, summary:focus-visible, .report-table-wrap:focus-visible { outline: 3px solid #9ebeff; outline-offset: 3px; }
  @media (max-width: 1000px) { .report-overview { grid-template-columns: 1fr; } .report-totals { margin-top: 20px; } }
  @media (max-width: 760px) { .report-heading { align-items: flex-start; flex-direction: column; gap: 17px; } .report-heading h1 { font-size: 29px; } .report-card { border-radius: 18px; } .report-summary, .report-measurements, .report-limitations { padding: 23px; } .report-findings-heading { padding: 23px 23px 0; } .report-filters { padding: 20px 23px; flex-wrap: wrap; } .report-search { flex-basis: 100%; } .report-select { flex: 1; } .report-select select { flex: 1; min-width: 0; } .report-table-footer { padding: 16px 23px; align-items: flex-start; } .report-table-footer p { max-width: 210px; } .report-basis-grid { grid-template-columns: 1fr; gap: 20px; } }
  @media (prefers-reduced-motion: reduce) { * { scroll-behavior: auto; } }
</style>
