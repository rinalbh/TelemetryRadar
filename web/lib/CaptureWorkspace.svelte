<script lang="ts">
  import { onMount } from 'svelte';
  import { backend, isDesktop } from './backend';
  import { capture, type CapturedProcess, type CaptureSnapshot } from './capture';
  import { opencode, type AnalysisDraft, type AnalysisEvent, type AnalysisResult, type AnalysisSnapshot, type PermissionRequest } from './opencode';
  import { advertisedModels, selectedModel } from './workflow-models';
  import { formatBytes, formatDuration, formatInteger, processName, formatRate } from './workflow-format';
  import ReportDashboard from './ReportDashboard.svelte';

  interface Activity { id: string; time: number; kind: 'stage' | 'message' | 'tool'; text: string; status?: string }
  interface RatePoint { time: number; rate: number }
  interface Remembered { captureId: string | null; analysisId: string | null; draftId: string | null; selected: CapturedProcess | null; modelLabel: string }
  const STORAGE_KEY = 'telemetryradar.workflow.v1';
  const STAGES: Record<string, string> = {
    preparing: 'Getting ready', stopping: 'Stopping recording', finalizing: 'Finishing recording',
    extracting: 'Preparing app traffic', starting: 'Starting analysis', analyzing: 'Analyzing traffic',
    validating: 'Checking the report', repairing: 'Refining the report', completed: 'Analysis complete',
    cancelling: 'Cancelling analysis', cancelled: 'Analysis cancelled', failed: 'Analysis stopped',
  };

  let desktop = $state(false);
  let restoring = $state(true);
  let readiness = $state<'checking' | 'ready' | 'missing'>('checking');
  let readinessError = $state('');
  let captureId = $state<string | null>(null);
  let recording = $state<CaptureSnapshot | null>(null);
  let selected = $state<CapturedProcess | null>(null);
  let draft = $state<AnalysisDraft | null>(null);
  let rememberedDraftId: string | null = null;
  let modelValue = $state('');
  let retainedModelLabel = $state('OpenCode default');
  let starting = $state(false);
  let stopping = $state(false);
  let preparing = $state(false);
  let preparationError = $state('');
  let handingOff = $state(false);
  let analysisId = $state<string | null>(null);
  let analysis = $state<AnalysisSnapshot | null>(null);
  let result = $state<AnalysisResult | null>(null);
  let stage = $state('preparing');
  let permissions = $state<PermissionRequest[]>([]);
  let answering = $state<number[]>([]);
  let activity = $state<Activity[]>([]);
  let history = $state<RatePoint[]>([]);
  let query = $state('');
  let error = $state('');
  let statusError = $state('');
  let now = $state(Date.now());
  let lastCaptureObservedAt = $state(Date.now());
  let analysisStartedAt = $state<number | null>(null);
  let currentCaptureGeneration = 0;
  let selectionGeneration = 0;
  let preparationQueue: Promise<void> = Promise.resolve();
  let disposed = false;
  let polling = false;
  let mounted = false;
  let activityId = 0;
  let analysisGeneration = 0;
  const answeredPermissions = new Set<number>();
  let lastRateSnapshot: CaptureSnapshot | null = null;
  let layoutPreview = $state(false);

  const picker = $derived(advertisedModels(draft?.configOptions ?? []));
  const model = $derived(selectedModel(picker, modelValue));
  const selectedLive = $derived(recording?.processes.find((row) => row.key === selected?.key) ?? selected);
  const recordingActive = $derived(recording !== null && !recording.terminal);
  const capturePhaseLabel = $derived(recording?.phase === 'finalizing' || recording?.phase === 'embeddingTls'
    ? 'Finishing recording' : stopping ? 'Stopping recording' : recording?.phase === 'recording' ? 'Recording' : 'Starting recording');
  const analysisActive = $derived(handingOff || (analysisId !== null && (!analysis || analysis.status === 'running')));
  const showAnalysis = $derived(handingOff || analysisId !== null);
  const rows = $derived((recording?.processes ?? []).filter((row) => `${processName(row)} ${row.pid}`.toLowerCase().includes(query.toLowerCase())).toSorted((a, b) => b.frameBytes - a.frameBytes));
  const maxProcessBytes = $derived(Math.max(1, ...(recording?.processes ?? []).map((row) => row.frameBytes)));
  const latestRate = $derived(history.length && recording?.statsStatus !== 'stale' && recording?.statsStatus !== 'unavailable' ? history[history.length - 1].rate : null);
  const statsKnown = $derived(recording?.statsAsOf !== null && recording?.statsAsOf !== undefined);
  const chartMaximum = $derived(Math.max(1, ...history.map((point) => point.rate)));
  const chartLine = $derived(history.map((point, index) => `${index === 0 ? 'M' : 'L'}${history.length === 1 ? 0 : index / (history.length - 1) * 1000},${148 - point.rate / chartMaximum * 124}`).join(' '));
  const chartArea = $derived(history.length > 1 ? `${chartLine} L1000,160 L0,160 Z` : '');
  const elapsed = $derived(recording ? recording.elapsedMillis + (recordingActive ? Math.max(0, Math.min(3000, now - lastCaptureObservedAt)) : 0) : 0);
  const analysisElapsed = $derived(analysisStartedAt ? Math.max(0, now - analysisStartedAt) : 0);

  function restoreProcess(value: unknown): CapturedProcess | null {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
    const row = value as Record<string, unknown>;
    if (typeof row.key !== 'string' || typeof row.startTime !== 'string' || typeof row.pid !== 'number'
      || !Number.isSafeInteger(row.pid) || row.pid <= 0 || typeof row.packets !== 'number'
      || !Number.isSafeInteger(row.packets) || row.packets < 0 || typeof row.frameBytes !== 'number'
      || !Number.isSafeInteger(row.frameBytes) || row.frameBytes < 0) return null;
    const rate = (value: unknown): number | null => typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : null;
    return {
      key: row.key, startTime: row.startTime, pid: row.pid, packets: row.packets, frameBytes: row.frameBytes,
      name: typeof row.name === 'string' ? row.name : null, path: typeof row.path === 'string' ? row.path : null,
      packetRate: rate(row.packetRate), byteRate: rate(row.byteRate), lastSeen: typeof row.lastSeen === 'string' ? row.lastSeen : '',
    };
  }

  function remember(): void {
    if (!mounted || layoutPreview) return;
    const value: Remembered = { captureId, analysisId, draftId: draft?.draftId ?? rememberedDraftId, selected, modelLabel: retainedModelLabel };
    try { localStorage.setItem(STORAGE_KEY, JSON.stringify(value)); } catch { /* A blocked storage area must not interrupt capture. */ }
  }

  function addActivity(kind: Activity['kind'], text: string, id?: string, status?: string): void {
    if (!text.trim()) return;
    if (id) {
      const previous = activity.findIndex((entry) => entry.id === id);
      if (previous >= 0) {
        activity = activity.map((entry, index) => index === previous ? { ...entry, text: text.slice(0, 4096), status } : entry);
        return;
      }
    }
    activity = [...activity.slice(-119), { id: id ?? `activity-${++activityId}`, time: Date.now(), kind, text: text.slice(0, 4096), status }];
  }

  function receiveCapture(snapshot: CaptureSnapshot, generation = currentCaptureGeneration): void {
    if (disposed || generation !== currentCaptureGeneration || (captureId && snapshot.captureId !== captureId)) return;
    if (recording && snapshot.captureId === recording.captureId && snapshot.sequence < recording.sequence) return;
    if (snapshot.statsAsOf !== null && snapshot.statsStatus !== 'stale' && snapshot.statsStatus !== 'unavailable') {
      const previous = lastRateSnapshot;
      if (previous && previous.statsAsOf !== null && snapshot.statsAsOf > previous.statsAsOf && snapshot.frameBytes >= previous.frameBytes) {
        const seconds = (snapshot.statsAsOf - previous.statsAsOf) / 1000;
        if (seconds <= 30) history = [...history.slice(-59), { time: snapshot.statsAsOf, rate: (snapshot.frameBytes - previous.frameBytes) / seconds }];
      }
      if (!previous || snapshot.statsAsOf > (previous.statsAsOf ?? 0)) lastRateSnapshot = snapshot;
    }
    if (recording?.sequence === snapshot.sequence) snapshot = { ...snapshot, elapsedMillis: Math.max(recording.elapsedMillis, snapshot.elapsedMillis) };
    recording = snapshot;
    lastCaptureObservedAt = Date.now();
    captureId = snapshot.captureId;
    if (snapshot.terminal) stopping = false;
    remember();
  }

  function receiveAnalysis(event: AnalysisEvent, generation = analysisGeneration): void {
    if (disposed || generation !== analysisGeneration) return;
    if (event.type === 'started') {
      analysisId = event.analysisId;
      remember();
    } else if (event.type === 'stage') {
      stage = event.stage;
      if (activity[activity.length - 1]?.text !== (STAGES[stage] ?? stage)) addActivity('stage', STAGES[stage] ?? stage);
    } else if (event.type === 'permission') {
      if (!answeredPermissions.has(event.permission.requestId) && !permissions.some((pending) => pending.requestId === event.permission.requestId)) permissions = [...permissions, event.permission];
    } else {
      const update = event.notification.update;
      if (update.sessionUpdate === 'agent_message_chunk' && update.content && !Array.isArray(update.content) && update.content.type === 'text') {
        const text = update.content.text ?? '';
        const previous = activity[activity.length - 1];
        if (previous?.kind === 'message') activity = [...activity.slice(0, -1), { ...previous, text: (previous.text + text).slice(-8192) }];
        else addActivity('message', text);
      } else if ((update.sessionUpdate === 'tool_call' || update.sessionUpdate === 'tool_call_update') && update.toolCallId) {
        const existing = activity.find((entry) => entry.id === `tool-${update.toolCallId}`);
        addActivity('tool', update.title ?? existing?.text ?? 'Inspecting traffic', `tool-${update.toolCallId}`, update.status);
      }
    }
  }

  function receiveAnalysisSnapshot(snapshot: AnalysisSnapshot): void {
    if (disposed || snapshot.analysisId !== analysisId || (analysis && snapshot.sequence < analysis.sequence)) return;
    const first = analysis === null;
    analysis = snapshot;
    stage = snapshot.stage;
    permissions = snapshot.status === 'running' ? snapshot.pendingPermissions.filter((permission) => !answeredPermissions.has(permission.requestId)) : [];
    if (first && snapshot.latestPublicMessage) addActivity('message', snapshot.latestPublicMessage);
    if (snapshot.activeToolTitle && !activity.some((entry) => entry.kind === 'tool' && entry.text === snapshot.activeToolTitle)) addActivity('tool', snapshot.activeToolTitle);
    if (snapshot.status === 'completed' && snapshot.result) result = snapshot.result;
  }

  async function checkReadiness(): Promise<void> {
    readiness = 'checking'; readinessError = '';
    if (!desktop) { readiness = 'missing'; readinessError = 'Open the desktop app to record your apps’ traffic.'; return; }
    try {
      const found = await backend.discoverWireshark();
      if (disposed) return;
      readiness = found.status === 'available' ? 'ready' : 'missing';
      readinessError = found.status === 'unavailable' ? found.message : '';
    } catch (failure) { if (!disposed) { readiness = 'missing'; readinessError = String(failure); } }
  }

  async function startRecording(): Promise<void> {
    if (layoutPreview || restoring || starting || readiness !== 'ready') return;
    starting = true; error = ''; statusError = '';
    const generation = ++currentCaptureGeneration;
    try {
      const id = await capture.start({}, (snapshot) => receiveCapture(snapshot, generation));
      if (disposed || generation !== currentCaptureGeneration) return;
      captureId = id;
      remember();
      receiveCapture(await capture.status(id), generation);
    } catch (failure) { error = String(failure); }
    finally { starting = false; }
  }

  async function stopRecording(): Promise<void> {
    if (layoutPreview || restoring || !captureId || stopping) return;
    stopping = true; error = '';
    try { await capture.stop(captureId); }
    catch (failure) { error = String(failure); stopping = false; }
  }

  async function discardPreparedDraft(id: string): Promise<void> {
    try { await opencode.discardDraft(id); }
    catch (failure) {
      if (!/unknown|stale/i.test(String(failure))) {
        await opencode.disconnect().catch(() => {});
        throw failure;
      }
    } finally {
      if (draft?.draftId === id) draft = null;
      if (rememberedDraftId === id) rememberedDraftId = null;
      remember();
    }
  }

  function chooseProcess(process: CapturedProcess, force = false): void {
    if (layoutPreview || restoring || analysisActive || handingOff || (!force && selected?.key === process.key && (preparing || draft))) return;
    const generation = ++selectionGeneration;
    selected = { ...process };
    preparing = true; error = ''; preparationError = ''; modelValue = '';
    if (draft && (draft.processKey !== process.key || force)) { rememberedDraftId = draft.draftId; draft = null; }
    remember();
    preparationQueue = preparationQueue.then(async () => {
      if (generation !== selectionGeneration || disposed || !captureId) return;
      const oldDraftId = draft?.draftId ?? rememberedDraftId;
      if (oldDraftId && draft?.processKey !== process.key) {
        await discardPreparedDraft(oldDraftId);
      }
      await opencode.connect('');
      if (generation !== selectionGeneration || disposed) return;
      const prepared = await opencode.prepare(captureId, process.key);
      // A remounted view may already have reused this same backend draft.
      // Only an in-view selection change should abandon it.
      if (disposed) return;
      if (generation !== selectionGeneration) {
        await discardPreparedDraft(prepared.draftId);
        return;
      }
      draft = prepared; rememberedDraftId = prepared.draftId;
      const advertised = advertisedModels(prepared.configOptions);
      modelValue = advertised?.currentValue ?? '';
      retainedModelLabel = selectedModel(advertised, modelValue).label;
      remember();
    }).catch((failure) => {
      if (generation === selectionGeneration && !disposed) { preparationError = 'The analyst could not connect. Your recording is still available.'; error = String(failure); }
    }).finally(() => { if (generation === selectionGeneration && !disposed) preparing = false; });
  }

  async function analyzeSelection(): Promise<void> {
    if (layoutPreview || restoring || !draft || draft.processKey !== selected?.key || draft.captureId !== captureId || preparing || handingOff || !selected) return;
    const generation = ++analysisGeneration;
    answeredPermissions.clear();
    handingOff = true; error = ''; statusError = ''; activity = []; permissions = []; analysis = null;
    retainedModelLabel = model.label;
    stage = 'stopping'; analysisStartedAt = Date.now();
    addActivity('stage', STAGES.stopping);
    try {
      const id = await opencode.stopCaptureAndAnalyze(draft.draftId, model.choice, '', (event) => receiveAnalysis(event, generation));
      if (disposed || generation !== analysisGeneration) return;
      analysisId = id;
      draft = null; rememberedDraftId = null;
      remember();
      receiveAnalysisSnapshot(await opencode.analysisStatus(id));
    } catch (failure) {
      error = String(failure);
      if (!analysisId) preparationError = 'The analyst needs to reconnect before continuing.';
    } finally { handingOff = false; }
  }

  async function cancelAnalysis(): Promise<void> {
    if (layoutPreview || !analysisActive || analysis?.cancellationRequested) return;
    try { await opencode.cancel(); stage = 'cancelling'; }
    catch (failure) { error = String(failure); }
  }

  async function answerPermission(permission: PermissionRequest, optionId: string): Promise<void> {
    if (layoutPreview || answering.includes(permission.requestId)) return;
    answering = [...answering, permission.requestId];
    try {
      await opencode.respond(permission.requestId, optionId);
      answeredPermissions.add(permission.requestId);
      permissions = permissions.filter((pending) => pending.requestId !== permission.requestId);
    } catch (failure) { error = String(failure); }
    finally { answering = answering.filter((id) => id !== permission.requestId); }
  }

  async function newRecording(): Promise<void> {
    if (layoutPreview || restoring || analysisActive) return;
    if (recordingActive && captureId) {
      try { receiveCapture(await capture.status(captureId)); }
      catch (failure) { error = String(failure); return; }
      if (recordingActive) return;
    }
    ++selectionGeneration;
    await preparationQueue;
    const old = draft?.draftId ?? rememberedDraftId;
    if (old) {
      try { await discardPreparedDraft(old); }
      catch (failure) { error = String(failure); return; }
    }
    ++currentCaptureGeneration;
    ++analysisGeneration;
    answeredPermissions.clear();
    captureId = null; recording = null; selected = null; draft = null; rememberedDraftId = null;
    analysisId = null; analysis = null; result = null; history = []; lastRateSnapshot = null;
    activity = []; permissions = []; error = ''; statusError = ''; query = ''; analysisStartedAt = null; preparing = false; preparationError = '';
    remember();
  }

  async function poll(): Promise<void> {
    if (layoutPreview || restoring || result || !desktop || disposed || polling) return;
    polling = true;
    const currentCapture = recording?.terminal ? null : captureId;
    const currentAnalysis = analysis && analysis.status !== 'running' ? null : analysisId;
    const generation = currentCaptureGeneration;
    try {
      const responses = await Promise.allSettled([
        currentCapture ? capture.status(currentCapture) : Promise.resolve(null),
        currentAnalysis ? opencode.analysisStatus(currentAnalysis) : Promise.resolve(null),
      ] as const);
      if (disposed) return;
      const captureResponse = responses[0];
      if (captureResponse.status === 'fulfilled' && captureResponse.value && captureId === currentCapture) receiveCapture(captureResponse.value, generation);
      const analysisResponse = responses[1];
      if (analysisResponse.status === 'fulfilled' && analysisResponse.value && analysisId === currentAnalysis) receiveAnalysisSnapshot(analysisResponse.value);
      if (captureResponse.status === 'rejected' || analysisResponse.status === 'rejected') statusError = 'Reconnecting to the current activity…';
      else statusError = '';
    } finally { polling = false; }
  }

  onMount(() => {
    mounted = true; disposed = false; desktop = isDesktop();
    if (import.meta.env.DEV) {
      const preview = new URLSearchParams(location.search).get('preview');
      if (preview === 'recording' || preview === 'selection' || preview === 'analyzing' || preview === 'results') {
        layoutPreview = true;
        restoring = false;
        void import('./workflow-preview').then(({ workflowPreview }) => {
          if (disposed) return;
          const fixture = workflowPreview(new URLSearchParams(location.search).get('variant'));
          recording = fixture.capture; captureId = fixture.capture.captureId;
          readiness = 'ready';
          history = fixture.history;
          if (preview !== 'recording') selected = fixture.selected;
          if (preview === 'selection') { draft = fixture.draft; modelValue = advertisedModels(fixture.draft.configOptions)?.currentValue ?? ''; }
          if (preview === 'analyzing') { analysisId = fixture.analysis.analysisId; analysis = fixture.analysis; stage = fixture.analysis.stage; addActivity('message', fixture.analysis.latestPublicMessage ?? ''); }
          if (preview === 'results') result = fixture.result;
          retainedModelLabel = 'Sample analyst';
        });
        return () => { disposed = true; mounted = false; };
      }
    }
    void checkReadiness();
    const restore = async (): Promise<void> => {
      if (!desktop) return;
      let remembered: Remembered | null = null;
      try { remembered = JSON.parse(localStorage.getItem(STORAGE_KEY) ?? 'null') as Remembered | null; } catch { /* Start fresh if local state is malformed. */ }
      if (!remembered || typeof remembered !== 'object') return;
      selected = restoreProcess(remembered.selected);
      retainedModelLabel = typeof remembered.modelLabel === 'string' ? remembered.modelLabel : 'OpenCode default';
      rememberedDraftId = typeof remembered.draftId === 'string' ? remembered.draftId : null;
      if (typeof remembered.analysisId === 'string') {
        analysisId = remembered.analysisId;
        try {
          const snapshot = await opencode.analysisStatus(analysisId);
          if (disposed) return;
          receiveAnalysisSnapshot(snapshot);
        }
        catch { if (!disposed) { analysisId = null; statusError = 'The previous analysis is unavailable. You can start a new recording.'; } }
      }
      if (typeof remembered.captureId === 'string') {
        captureId = remembered.captureId;
        try {
          const snapshot = await capture.status(captureId);
          if (disposed) return;
          receiveCapture(snapshot);
        } catch { if (!disposed) { captureId = null; recording = null; if (!result) selected = null; rememberedDraftId = null; } }
      }
      remember();
    };
    void restore().finally(() => {
      if (disposed) return;
      restoring = false;
      if (captureId && !analysisId && selected) chooseProcess(selected);
    });
    const timer = setInterval(() => { now = Date.now(); void poll(); }, 1000);
    return () => { disposed = true; mounted = false; ++selectionGeneration; clearInterval(timer); };
  });
</script>

<a class="skip-link" href="#main">Skip to content</a>
<div class="radar-app">
  <header class="app-topbar">
    <div class="wordmark"><span class="radar-mark" aria-hidden="true"><i></i></span><span>TelemetryRadar</span></div>
    {#if layoutPreview}<span class="preview-label" role="note">Sample data · layout preview</span>{/if}
    {#if recordingActive && !showAnalysis}<span class="pill recording-pill"><span class="status-dot"></span>{capturePhaseLabel}</span>
    {:else if showAnalysis && !result}<span class="pill">{analysisActive ? 'Analysis in progress' : analysis?.status === 'cancelled' ? 'Cancelled' : 'Recording saved'}</span>
    {:else if result}<span class="pill complete-pill">Report ready</span>{/if}
  </header>

  <main id="main" class:landing={!captureId && !showAnalysis && !result}>
    {#if result}
      <ReportDashboard {result} process={selectedLive} modelLabel={retainedModelLabel} onNewCapture={() => { void newRecording(); }} />
    {:else if showAnalysis}
      <section class="page-heading">
        <div><p class="eyebrow">MAKING SENSE OF YOUR TRAFFIC</p><h1>{processName(selectedLive)} analysis</h1><p>{STAGES[stage] ?? 'Analyzing traffic'}. Your recording is kept for this report.</p></div>
        {#if analysisActive}<button class="text-button" onclick={cancelAnalysis} disabled={analysis?.cancellationRequested || stage === 'cancelling'}>{stage === 'cancelling' ? 'Cancelling…' : 'Cancel analysis'}</button>{/if}
      </section>
      <div class="analysis-grid">
        <section class="card activity-card" aria-labelledby="activity-title">
          <div class="card-heading"><h2 id="activity-title">Analysis activity</h2><span class="pill" class:recording-pill={analysisActive}>{analysisActive ? 'Working' : analysis?.status === 'cancelled' ? 'Cancelled' : 'Stopped'}</span></div>
          <div class="analysis-stage" role="status">{#if analysisActive}<span class="spinner" aria-hidden="true"></span>{/if}<div><strong>{permissions.length ? 'Waiting for tool permission' : STAGES[stage] ?? stage}</strong><p>{analysisStartedAt ? `${formatDuration(analysisElapsed)} elapsed` : 'Activity restored'}</p></div></div>
          {#each permissions as permission (permission.requestId)}
            <div class="permission-card">
              <strong>{permission.request.toolCall.title ?? 'The analyst needs permission to continue'}</strong>
              <p>Choose one of the permissions requested by your analyst.</p>
              <div class="button-row">{#each permission.request.options as option (option.optionId)}<button class="secondary" disabled={answering.includes(permission.requestId) || stage === 'cancelling'} onclick={() => answerPermission(permission, option.optionId)}>{option.name}</button>{/each}</div>
            </div>
          {/each}
          <div class="activity-list" aria-label="Public analysis activity">
            {#each activity as entry (entry.id)}
              <div class="activity-entry" class:tool-entry={entry.kind === 'tool'}><time>{new Date(entry.time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}</time><p>{entry.text}{#if entry.kind === 'tool' && entry.status}<span class="tool-status">{entry.status.replaceAll('_', ' ')}</span>{/if}</p></div>
            {:else}<p class="empty-state">The analyst’s progress will appear here.</p>{/each}
          </div>
          {#if analysisActive}<div class="indeterminate-track" aria-hidden="true"><span></span></div><p class="subtle">The report appears after its evidence has been checked.</p>{/if}
          {#if analysis?.status === 'failed' || analysis?.status === 'cancelled'}
            <div class="inline-error" role="alert"><strong>{analysis.status === 'cancelled' ? 'Analysis cancelled' : 'The report could not be completed'}</strong><p>Your recording is retained. Start a new recording when you’re ready.</p>{#if analysis.error}<details><summary>Details</summary><p>{analysis.error}</p></details>{/if}</div>
            <button class="primary" onclick={() => { void newRecording(); }}>New recording</button>
          {/if}
        </section>
        <aside class="card selected-card"><p class="eyebrow">SELECTED APP</p><div class="app-avatar large" aria-hidden="true">{processName(selectedLive).slice(0, 1).toUpperCase()}</div><h2>{processName(selectedLive)}</h2><p>{formatBytes(selectedLive?.frameBytes)} observed in this recording</p><div class="summary-divider"></div><p class="eyebrow">ANALYZING WITH</p><strong class="model-summary">{retainedModelLabel}</strong><p>Findings, amounts, and supporting evidence will appear together in the report.</p></aside>
      </div>
    {:else if captureId}
      <section class="page-heading"><div><p class="eyebrow">YOUR APPS, IN FOCUS</p><h1>{recordingActive ? recording?.phase === 'recording' && !stopping ? 'Recording your traffic' : capturePhaseLabel : recording?.phase === 'failed' ? 'Recording stopped' : 'Your recorded traffic'}</h1><p>{recordingActive ? 'Choose an app to understand what it communicates.' : 'Choose an app and run its analysis.'}</p></div><div class="recording-actions"><span class="elapsed-time">{formatDuration(elapsed)}</span>{#if recordingActive}<button class="secondary" onclick={stopRecording} disabled={stopping}>{stopping ? 'Stopping…' : 'Stop recording'}</button>{:else}<button class="text-button" onclick={() => { void newRecording(); }} disabled={preparing}>New recording</button>{/if}</div></section>
      <section class="card traffic-card" aria-labelledby="traffic-title">
        <div class="card-heading"><div><h2 id="traffic-title">Traffic rate</h2><p>All recorded traffic</p></div><div class="traffic-stats"><div><span>Observed</span><strong>{formatBytes(statsKnown ? recording?.frameBytes : null)}</strong></div><div><span>Current rate</span><strong>{formatRate(latestRate)}</strong></div><div><span>Packets</span><strong>{formatInteger(statsKnown ? recording?.packets : null)}</strong></div></div></div>
        <div class="traffic-chart">
          <div class="chart-scale"><span>{history.length > 1 ? formatRate(chartMaximum) : '—'}</span><span>{history.length > 1 ? formatRate(chartMaximum / 2) : '—'}</span><span>{history.length > 1 ? '0 B/s' : '—'}</span></div>
          <div class="chart-canvas"><div class="chart-grid"></div>{#if history.length > 1}<svg viewBox="0 0 1000 160" preserveAspectRatio="none" role="img" aria-label="Recorded traffic rate over recent snapshots"><defs><linearGradient id="traffic-fill" x1="0" x2="0" y1="0" y2="1"><stop offset="0%" stop-color="#00becf" stop-opacity=".25" /><stop offset="100%" stop-color="#00becf" stop-opacity=".02" /></linearGradient></defs><path d={chartArea} fill="url(#traffic-fill)"/><path d={chartLine} fill="none" stroke="#00b8ca" stroke-width="3" vector-effect="non-scaling-stroke"/></svg>{:else}<p class="chart-placeholder">{recording?.terminal ? 'Recording finished' : recording?.phase === 'recording' ? 'Listening for network activity…' : 'Starting the recording…'}</p>{/if}</div>
        </div>
        <div class="chart-footer"><span><i class="legend-dot"></i>Total traffic · original frame bytes</span><span>Recent snapshots</span></div>
      </section>
      <div class="capture-grid" class:with-selection={selected !== null}>
        <section class="card processes-card" aria-labelledby="apps-title">
          <div class="card-heading"><div><h2 id="apps-title">Apps</h2><p>{recording?.phase === 'recording' && !stopping ? 'Select an app while recording continues.' : 'Select an app from this recording.'}</p></div><label class="search-field"><span class="sr-only">Find an app</span><input type="search" placeholder="Find an app" bind:value={query}/></label></div>
          <div class="process-list">
            {#each rows as process (process.key)}
              <button class="process-row" class:selected={selected?.key === process.key} aria-pressed={selected?.key === process.key} onclick={() => chooseProcess(process)} disabled={handingOff}>
                <span class="app-avatar" aria-hidden="true">{processName(process).slice(0, 1).toUpperCase()}</span><span class="process-name"><strong>{processName(process)}</strong><span>PID {process.pid} · {formatInteger(process.packets)} packets</span></span><span class="process-meter" aria-hidden="true"><i style:width={`${process.frameBytes / maxProcessBytes * 100}%`}></i></span><span class="process-amount">{formatBytes(process.frameBytes)}<span>{formatRate(process.byteRate)}</span></span><span class="row-arrow" aria-hidden="true">{selected?.key === process.key ? '✓' : '→'}</span>
              </button>
            {:else}<div class="empty-state"><strong>{query ? 'No matching apps' : 'Waiting for apps'}</strong><p>{query ? 'Try another app name or process ID.' : 'Use an app to generate some traffic. Apps appear when their packets can be attributed.'}</p></div>{/each}
          </div>
          <div class="process-footer"><span>Unattributed traffic <strong>{statsKnown ? `${formatInteger(recording?.unattributedPackets)} packets` : 'Waiting for statistics'}</strong></span><span class="health-badge" class:health-warning={recording?.statsStatus === 'stale' || recording?.statsStatus === 'unavailable'}>{recording?.statsStatus === 'complete' ? 'Final statistics' : recording?.statsStatus === 'stale' ? 'Statistics delayed' : recording?.statsStatus === 'unavailable' ? 'Statistics unavailable' : 'Live snapshots · provisional'}</span></div>
          <p class="subtle">One packet can belong to several apps. App totals may overlap.</p>
          {#if recording?.statsError}<details class="technical-details"><summary>Statistics details</summary><p>{recording.statsError}</p></details>{/if}
        </section>
        {#if selectedLive}
          <aside class="card selected-card">
            <p class="eyebrow">SELECTED APP</p><div class="app-avatar large" aria-hidden="true">{processName(selectedLive).slice(0, 1).toUpperCase()}</div><h2>{processName(selectedLive)}</h2><p>{formatBytes(selectedLive.frameBytes)} observed · {formatInteger(selectedLive.packets)} packets</p><div class="summary-divider"></div><p class="eyebrow">YOUR ANALYST</p><h3>Understand this app’s traffic</h3><p>See what it communicates, what’s visible, and what may affect your privacy.</p>
            {#if preparing}<div class="preparation-status" role="status"><span class="spinner" aria-hidden="true"></span>Getting your analyst ready…</div>
            {:else if draft && draft.processKey === selectedLive.key && draft.captureId === captureId && !preparationError}
              {#if picker && picker.choices.length}<label class="model-field"><span>Model</span><select bind:value={modelValue}>{#if !picker.choices.some((choice) => choice.value === picker.currentValue)}<option value={picker.currentValue}>Current model ({picker.currentValue})</option>{/if}{#each picker.choices as choice (choice.value)}<option value={choice.value}>{choice.group ? `${choice.group} · ` : ''}{choice.label}</option>{/each}</select></label>
              {:else}<div class="default-model"><span>Model</span><strong>{model.label}</strong><p>This analyst did not advertise a model picker.</p></div>{/if}
              <p class="provider-note">{model.label} will analyze the selected traffic. It may be sent to the model’s configured provider.</p>
              <button class="primary analyze-button" onclick={analyzeSelection} disabled={handingOff}>{recordingActive ? 'Stop & analyze this app' : 'Analyze this app'}<span aria-hidden="true">→</span></button>
            {:else}{#if preparationError}<p class="preparation-error">{preparationError}</p>{/if}<button class="secondary" onclick={() => chooseProcess(selectedLive, true)}>Retry analyst setup</button>{/if}
          </aside>
        {/if}
      </div>
      {#if recording?.error}<div class="inline-error" role="alert"><strong>Recording could not finish</strong><details><summary>Details</summary><p>{recording.error}</p></details></div>{/if}
    {:else}
      <section class="ready-card card" aria-labelledby="ready-title">
        <div class="radar-mark hero-radar" aria-hidden="true"><i></i></div><h1 id="ready-title">TelemetryRadar</h1><h2>{starting ? 'Starting your recording' : 'Ready to record'}</h2><p>See what your apps are saying.</p>
        <button class="primary start-button" onclick={startRecording} disabled={starting || restoring || readiness !== 'ready'}>{#if starting || restoring || readiness === 'checking'}<span class="spinner" aria-hidden="true"></span>{/if}{starting ? 'Starting…' : restoring || readiness === 'checking' ? 'Getting ready…' : 'Start recording'}</button>
        {#if readiness === 'missing'}<div class="setup-blocker" role="alert"><strong>{desktop ? 'Wireshark is needed to record' : 'Open TelemetryRadar on your desktop'}</strong><p>{desktop ? 'Install Wireshark 5.0 or newer, then try again.' : readinessError}</p>{#if desktop}<button class="text-button" onclick={checkReadiness}>Check again</button><details><summary>Details</summary><p>{readinessError}</p></details>{/if}</div>
        {:else}<p class="ready-note">Record locally. Choose an app. Understand its traffic.</p>{/if}
      </section>
    {/if}
    {#if error}<div class="inline-error workflow-error" role="alert"><strong>We couldn’t complete that step</strong><p>{preparationError || 'Your recording and any saved analysis remain available.'}</p><details><summary>Details</summary><p>{error}</p></details></div>{/if}
    {#if statusError}<p class="status-note" role="status">{statusError}</p>{/if}
  </main>
</div>
