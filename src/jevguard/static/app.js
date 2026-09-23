const state = { events: [], initialized: false, newestId: 0 };
const $ = id => document.getElementById(id);
const esc = value => String(value ?? "—").replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
const label = value => String(value ?? "pending").replaceAll('_', ' ');

async function load() {
  const severity = $('severity').value;
  const query = severity ? `?severity=${encodeURIComponent(severity)}` : '';
  try {
    const [healthResponse, summaryResponse, eventsResponse] = await Promise.all([
      fetch('/api/health'), fetch('/api/summary'), fetch(`/api/events${query}`)
    ]);
    const [health, summary, events] = await Promise.all([
      healthResponse.json(), summaryResponse.json(), eventsResponse.json()
    ]);
    state.events = events;
    $('provider').textContent = `Decisiones: ${health.decision_provider}`;
    $('total').textContent = summary.total_events;
    $('review').textContent = summary.requires_review;
    $('monitored').textContent = summary.monitored;
    $('high').textContent = (summary.by_severity.high || 0) + (summary.by_severity.critical || 0);
    $('sources').textContent = Object.keys(summary.by_category).length;
    const usage = summary.ai_usage_24h || {};
    const unmetered = (usage.calls || 0) - (usage.metered_calls || 0);
    $('ai-usage').textContent = usage.calls || 0;
    $('ai-usage-detail').textContent = unmetered
      ? `${unmetered} sin medición de coste`
      : `$${Number(usage.cost_usd || 0).toFixed(4)} acumulado`;
    $('error').classList.toggle('hidden', !health.collector_error);
    $('error').textContent = health.collector_error ? `Telemetría parcial: ${health.collector_error}` : '';
    announce(events);
    render(events);
  } catch (error) {
    $('error').classList.remove('hidden');
    $('error').textContent = `No se pudo actualizar el panel: ${error.message}`;
  }
}

function render(events) {
  $('events').innerHTML = events.length ? events.map((event, index) => `
    <tr data-index="${index}">
      <td>${esc(new Date(event.observed_at).toLocaleTimeString())}</td>
      <td class="signal">${esc(event.summary)}<small>${esc(event.category)} · ${esc(event.source)}${event.process ? ` · ${esc(event.process)}` : ''}</small></td>
      <td><span class="badge ${esc(event.severity)}">${esc(label(event.severity))}</span></td>
      <td><span class="badge status-${esc(event.status)}">${esc(label(event.status))}</span></td>
      <td><span class="badge ${esc(event.classification)}">${esc(label(event.classification))}</span></td>
      <td>${event.confidence == null ? '—' : `${Math.round(event.confidence * 100)}%`}</td>
      <td>${esc(label(event.recommended_action))}</td>
    </tr>`).join('') : '<tr><td colspan="7" class="muted">No hay eventos para este filtro.</td></tr>';
  document.querySelectorAll('tbody tr[data-index]').forEach(row => row.addEventListener('click', () => show(Number(row.dataset.index))));
}

function show(index) {
  const event = state.events[index];
  $('detail-title').textContent = event.summary;
  $('detail-body').innerHTML = `
    <dl class="detail-grid">
      <dt>Tipo</dt><dd>${esc(event.event_type)}</dd>
      <dt>Equipo</dt><dd>${esc(event.host)}</dd>
      <dt>Clasificación</dt><dd>${esc(label(event.classification))}</dd>
      <dt>Proveedor</dt><dd>${esc(event.provider)}</dd>
      <dt>Tokens IA</dt><dd>${esc((event.input_tokens || 0) + (event.output_tokens || 0))}</dd>
      <dt>Coste IA</dt><dd>$${Number(event.cost_usd || 0).toFixed(6)}</dd>
      <dt>Acción</dt><dd>${esc(label(event.recommended_action))}</dd>
      <dt>Estado</dt><dd>${esc(label(event.status))}</dd>
      <dt>Revisión humana</dt><dd>${event.requires_human_review ? 'Sí' : 'No'}</dd>
      <dt>Motivo</dt><dd>${esc(event.rationale)}</dd>
    </dl>
    <p class="eyebrow">EVIDENCIA ORIGINAL</p>
    <pre>${esc(JSON.stringify(event.evidence, null, 2))}</pre>
    <p class="eyebrow">PROBABILIDADES</p>
    <pre>${esc(JSON.stringify(event.probabilities, null, 2))}</pre>
    <div class="status-actions">
      <button data-status="investigating">Investigar</button>
      <button data-status="resolved">Resolver</button>
      <button data-status="false_positive">Falso positivo</button>
    </div>`;
  document.querySelectorAll('.status-actions button').forEach(button => {
    button.addEventListener('click', () => setStatus(event.id, button.dataset.status));
  });
  $('details').showModal();
}

async function setStatus(id, status) {
  const response = await fetch(`/api/events/${id}/status`, {
    method: 'PATCH', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({status})
  });
  if (!response.ok) throw new Error('No se pudo actualizar el estado');
  $('details').close();
  await load();
}

function announce(events) {
  const newest = events.reduce((value, event) => Math.max(value, event.id || 0), 0);
  if (!state.initialized) {
    state.initialized = true;
    state.newestId = newest;
    return;
  }
  const alerts = events.filter(event =>
    event.id > state.newestId && ['high', 'critical'].includes(event.severity)
  );
  state.newestId = Math.max(state.newestId, newest);
  for (const event of alerts) {
    const node = document.createElement('button');
    node.className = `alert-toast ${event.severity}`;
    node.textContent = `${event.severity.toUpperCase()}: ${event.summary}`;
    node.addEventListener('click', () => {
      const index = state.events.findIndex(item => item.id === event.id);
      if (index >= 0) show(index);
    });
    $('alert-feed').appendChild(node);
    setTimeout(() => node.remove(), 15000);
  }
}

$('refresh').addEventListener('click', load);
$('severity').addEventListener('change', load);
document.querySelector('.close').addEventListener('click', () => $('details').close());
load();
setInterval(load, 10000);
