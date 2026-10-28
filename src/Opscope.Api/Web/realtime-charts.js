(() => {
  'use strict';
  const LIMIT = 720;
  const MAX_SNAPSHOT_POINTS = 120;
  const validPercent = value => value === null || (typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 100);
  const dateValue = value => typeof value === 'string' && value.length <= 64 ? Date.parse(value) : NaN;
  function normalize(value) {
    if (!value || typeof value !== 'object') return null;
    const metric = value.source === 'local-lightweight';
    if (metric && (value.schemaVersion !== 1 || !Number.isSafeInteger(value.sequence) || value.sequence < 1 || !Number.isSafeInteger(value.elapsedMilliseconds) || value.elapsedMilliseconds < 0 || !Number.isFinite(value.sampleIntervalSeconds) || value.sampleIntervalSeconds < 1 || value.sampleIntervalSeconds > 86400)) return null;
    const time = dateValue(metric ? value.sampledAtUtc : value.collectedAtUtc);
    const cpu = metric ? value.cpuPercent : value.cpuUsedPercent;
    const memory = metric ? value.memoryPercent : (value.memory?.usedPercent ?? value.memoryUsedPercent);
    if (!Number.isFinite(time) || !validPercent(cpu ?? null) || !validPercent(memory ?? null)) return null;
    return { time, cpu: cpu ?? null, memory: memory ?? null, sequence: metric ? value.sequence : null,
      elapsed: metric ? value.elapsedMilliseconds : null, clockAdjusted: metric && value.clockAdjusted === true,
      memoryEstimated: metric && memory != null && value.coverage?.memory === 'estimated',
      interval: metric ? value.sampleIntervalSeconds * 1000 : null, source: metric ? 'local-lightweight' : 'snapshot' };
  }
  class SeriesBuffer {
    constructor(capacity = LIMIT) { this.capacity = Math.min(LIMIT, Math.max(1, capacity)); this.points = []; this.dropped = 0; }
    push(point) {
      if (!point) return false;
      const last = this.points[this.points.length - 1];
      if (last && (point.sequence !== null ? point.sequence <= last.sequence || point.elapsed <= last.elapsed : point.time <= last.time)) return false;
      if (last && point.sequence !== null && last.sequence !== null && point.sequence > last.sequence + 1) this.dropped += point.sequence - last.sequence - 1;
      this.points.push(point);
      if (this.points.length > this.capacity) this.points.splice(0, this.points.length - this.capacity);
      return true;
    }
    clear() { this.points.length = 0; this.dropped = 0; }
  }
  // Keep the first/last and each bucket's extrema, in their original temporal order.
  function decimate(points, key, buckets = 80) {
    if (points.length <= buckets * 4 || points.length < 2) return points;
    const result = new Set([0, points.length - 1]);
    const width = Math.ceil(points.length / buckets);
    for (let start = 0; start < points.length; start += width) {
      const end = Math.min(points.length, start + width);
      let low = -1, high = -1;
      result.add(start); result.add(end - 1);
      for (let i = start; i < end; i++) {
        if (points[i][key] === null) { result.add(i); if (i > 0) result.add(i - 1); if (i + 1 < points.length) result.add(i + 1); continue; }
        if (low === -1 || points[i][key] < points[low][key]) low = i;
        if (high === -1 || points[i][key] > points[high][key]) high = i;
      }
      if (low >= 0) result.add(low);
      if (high >= 0) result.add(high);
    }
    return [...result].sort((a, b) => a - b).map(index => points[index]);
  }
  if (typeof module !== 'undefined' && module.exports) module.exports = { normalize, SeriesBuffer, decimate };
  if (typeof window === 'undefined' || typeof document === 'undefined') return;
  const snapshotBuffer = new SeriesBuffer(MAX_SNAPSHOT_POINTS), metricBuffer = new SeriesBuffer(LIMIT);
  const mounts = new Map();
  let connection = 'connecting', timer = null, nextId = 0;
  const words = {
    en: { title: 'CPU and memory', description: 'Observed aggregate host percentages. Gaps indicate missing observations; cloud measurements use separate sources.', window: 'Time window', minutes: 'min', pause: 'Pause chart', resume: 'Resume chart', paused: 'Chart paused', cpu: 'CPU', memory: 'Memory', noData: 'No samples received yet.', unavailable: 'Unavailable', stale: 'Stale', latest: 'Last sample', samples: 'samples', table: 'Sample data table', time: 'Time (local)', source: 'Source', snapshot: 'Host snapshots', fast: 'Lightweight host metrics', shown: 'Most recent observations shown', lost: 'Missing sequence samples', connecting: 'Connecting', connected: 'Connected', recovering: 'Recovering', disconnected: 'Disconnected', empty: 'No observations in this window.', partial: 'Partial coverage', elapsed: 'Elapsed sample time', adjusted: 'System clock adjusted' },
    es: { title: 'CPU y memoria', description: 'Porcentajes agregados observados del host. Los huecos indican ausencia de muestras; las mediciones cloud utilizan fuentes separadas.', window: 'Ventana temporal', minutes: 'min', pause: 'Pausar gráfica', resume: 'Reanudar gráfica', paused: 'Gráfica pausada', cpu: 'CPU', memory: 'Memoria', noData: 'Todavía no se han recibido muestras.', unavailable: 'No disponible', stale: 'Obsoleto', latest: 'Última muestra', samples: 'muestras', table: 'Tabla de muestras', time: 'Hora (local)', source: 'Fuente', snapshot: 'Snapshots del host', fast: 'Métricas ligeras del host', shown: 'Se muestran las observaciones más recientes', lost: 'Muestras de secuencia ausentes', connecting: 'Conectando', connected: 'Conectado', recovering: 'Recuperando', disconnected: 'Desconectado', empty: 'Sin observaciones en esta ventana.', partial: 'Cobertura parcial', elapsed: 'Tiempo transcurrido de muestra', adjusted: 'Reloj del sistema ajustado' }
  };
  Object.assign(words.en, { estimatedMemory: 'Memory includes estimates', estimateNote: 'Marked macOS memory values estimate physical use by treating free and inactive pages as reclaimable. They do not measure memory pressure.' });
  Object.assign(words.es, { estimatedMemory: 'La memoria incluye estimaciones', estimateNote: 'Los valores de memoria macOS marcados estiman el uso físico considerando recuperables las páginas libres e inactivas. No miden la presión de memoria.' });
  const make = (tag, text, className) => { const node = document.createElement(tag); if (text !== undefined) node.textContent = text; if (className) node.className = className; return node; };
  const svgNode = (tag, attrs = {}, text) => { const node = document.createElementNS('http://www.w3.org/2000/svg', tag); Object.entries(attrs).forEach(([key, value]) => node.setAttribute(key, String(value))); if (text !== undefined) node.textContent = text; return node; };
  function currentBuffer(source) { return source === 'snapshots' ? snapshotBuffer : source === 'metrics' ? metricBuffer : metricBuffer.points.length ? metricBuffer : snapshotBuffer; }
  function prune() {
    for (const [container, view] of mounts) if (!container.isConnected) view.dispose();
    if (!mounts.size && timer) { clearInterval(timer); timer = null; }
  }
  function update() { prune(); if (document.hidden) return; for (const view of mounts.values()) view.render(); }
  function mount(container, options = {}) {
    if (!container || typeof container.replaceChildren !== 'function') return null;
    if (mounts.has(container)) return mounts.get(container).api;
    const language = options.language === 'es' || (!options.language && document.documentElement.lang === 'es') ? 'es' : 'en';
    const t = words[language];
    const id = 'ops-chart-' + (++nextId);
    const root = make('section', undefined, 'ops-chart');
    const heading = make('h3', t.title); heading.id = id + '-title';
    const description = make('p', t.description, 'muted'); description.id = id + '-description';
    const controls = make('div', undefined, 'ops-chart__controls');
    const label = make('label', t.window + ' '), select = make('select'); select.setAttribute('aria-label', t.window);
    for (const minutes of [5, 15, 30]) { const option = make('option', minutes + ' ' + t.minutes); option.value = String(minutes); select.append(option); }
    select.value = '15'; label.append(select);
    const pause = make('button', t.pause); pause.type = 'button'; pause.setAttribute('aria-pressed', 'false');
    const metadata = make('p', '', 'ops-chart__meta'); metadata.setAttribute('role', 'status'); metadata.setAttribute('aria-live', 'off');
    const svg = svgNode('svg', { viewBox: '0 0 800 230', role: 'img', 'aria-labelledby': id + '-title ' + id + '-description', class: 'ops-chart__svg' });
    const graph = svgNode('g'); svg.append(graph);
    const legend = make('p', undefined, 'ops-chart__legend'), memoryLegend = make('span', t.memory + ' ┄', 'ops-chart__memory'); legend.append(make('span', t.cpu + ' — ', 'ops-chart__cpu'), memoryLegend);
    const estimateNote = make('p', '* ' + t.estimateNote, 'ops-chart__estimate muted'); estimateNote.id = id + '-estimate'; estimateNote.hidden = true;
    const details = make('details'), summary = make('summary', t.table), tableWrap = make('div', undefined, 'table-wrap'), table = make('table', undefined, 'ops-chart__table');
    const caption = make('caption', ''), head = make('thead'), row = make('tr'), body = make('tbody');
    for (const text of [t.time, t.cpu + ' (%)', t.memory + ' (%)']) { const th = make('th', text); th.scope = 'col'; row.append(th); }
    head.append(row); table.append(caption, head, body); tableWrap.append(table); details.append(summary, tableWrap);
    controls.append(label, pause); root.append(heading, description, controls, metadata, svg, legend, estimateNote, details); container.replaceChildren(root);
    let paused = false, frozen = null, viewConnection = null;
    const view = {
      render() {
        const buffer = currentBuffer(options.source);
        const all = frozen || buffer.points;
        const now = Date.now();
        const duration = Number(select.value) * 60000;
        const latest = all[all.length - 1];
        const monotonic = latest?.source === 'local-lightweight';
        const coordinate = point => monotonic ? point.elapsed : point.time;
        const end = monotonic ? latest.elapsed : all.length ? Math.max(latest.time, now) : now;
        const start = end - duration;
        const points = all.filter(point => coordinate(point) >= start && coordinate(point) <= end);
        const interval = latest?.interval || (all.length > 1 ? all[all.length - 1].time - all[all.length - 2].time : 30000);
        const stale = latest && now - latest.time > Math.max(interval * 3, 30000);
        const state = viewConnection || connection;
        const hasEstimate = points.some(point => point.memoryEstimated);
        estimateNote.hidden = !hasEstimate;
        if (hasEstimate) svg.setAttribute('aria-describedby', estimateNote.id); else svg.removeAttribute('aria-describedby');
        memoryLegend.textContent = t.memory + (hasEstimate ? ' *' : '') + ' ┄';
        metadata.textContent = (t[state] || t.disconnected) + ' · ' + (latest?.source === 'local-lightweight' ? t.fast : t.snapshot) + ' · ' +
          (latest ? t.latest + ': ' + new Date(latest.time).toLocaleString(language) + ' · ' + Math.max(0, Math.floor((now - latest.time) / 1000)) + ' s · ' + points.length + ' ' + t.samples + (stale ? ' · ' + t.stale : '') + (latest.cpu === null || latest.memory === null ? ' · ' + t.partial : '') : t.noData) +
          (latest?.memoryEstimated ? ' · ' + t.estimatedMemory : '') + (buffer.dropped ? ' · ' + t.lost + ': ' + buffer.dropped : '') + (monotonic ? ' · ' + t.elapsed : '') + (points.some(point => point.clockAdjusted) ? ' · ' + t.adjusted : '') + (paused ? ' · ' + t.paused : '');
        graph.replaceChildren();
        // Match SVG coordinates to CSS pixels so axis labels stay readable on small screens.
        const viewport = Math.max(160, Math.min(2400, Math.round(svg.getBoundingClientRect().width || container.clientWidth || 800)));
        svg.setAttribute('viewBox', `0 0 ${viewport} 230`);
        const left = 45, top = 16, width = viewport - 65, height = 170;
        for (const value of [0, 25, 50, 75, 100]) {
          const y = top + height * (1 - value / 100);
          graph.append(svgNode('line', { x1: left, x2: left + width, y1: y, y2: y, class: 'ops-chart__grid', stroke: 'currentColor', opacity: '.2' }));
          graph.append(svgNode('text', { x: left - 8, y: y + 4, 'text-anchor': 'end', fill: 'currentColor', 'font-size': '12' }, value + '%'));
        }
        for (const ratio of [0, .5, 1]) graph.append(svgNode('text', { x: left + width * ratio, y: 212, 'text-anchor': ratio === 0 ? 'start' : ratio === 1 ? 'end' : 'middle', fill: 'currentColor', 'font-size': '12' }, monotonic ? '−' + Math.round(duration * (1 - ratio) / 60000) + ' ' + t.minutes : new Date(start + duration * ratio).toLocaleTimeString(language, { hour: '2-digit', minute: '2-digit' })));
        if (!points.length) graph.append(svgNode('text', { x: left + width / 2, y: 100, 'text-anchor': 'middle', fill: 'currentColor', 'font-size': '14' }, all.length ? t.empty : t.noData));
        for (const [key, color] of [['cpu', '#3676d9'], ['memory', '#ae6600']]) {
          let path = '', previous = null, segment = 0, originalPrevious = null;
          const segmented = points.map(point => {
            if (point[key] === null || !originalPrevious || point.clockAdjusted || coordinate(point) - coordinate(originalPrevious) > Math.max(point.interval || interval, originalPrevious.interval || interval) * 2.5) segment++;
            originalPrevious = point[key] === null ? null : point;
            return { ...point, segment };
          });
          for (const point of decimate(segmented, key)) {
            if (point[key] === null) { previous = null; continue; }
            const x = left + (coordinate(point) - start) / duration * width, y = top + height * (1 - point[key] / 100);
            const continuous = previous && point.segment === previous.segment;
            path += (continuous ? ' L ' : ' M ') + x.toFixed(2) + ' ' + y.toFixed(2);
            if (!continuous) graph.append(svgNode('circle', { cx: x, cy: y, r: '2.5', fill: color, class: 'ops-chart__' + key }));
            previous = point;
          }
          graph.append(svgNode('path', { d: path, fill: 'none', stroke: color, 'stroke-width': '2.5', 'stroke-dasharray': key === 'memory' ? '7 4' : 'none', class: 'ops-chart__' + key }));
        }
        const selected = points.slice(-50).reverse();
        caption.textContent = t.shown + ': ' + selected.length + ' / ' + points.length + '. ' + t.source + ': ' + (latest?.source === 'local-lightweight' ? t.fast : t.snapshot) + (selected.some(point => point.memoryEstimated) ? '. ' + t.estimatedMemory + ' *' : '');
        {
          const rows = selected.map(point => { const tr = make('tr'); tr.append(make('td', new Date(point.time).toLocaleString(language)), make('td', point.cpu === null ? t.unavailable : point.cpu.toFixed(1)), make('td', point.memory === null ? t.unavailable : point.memory.toFixed(1) + (point.memoryEstimated ? ' *' : ''))); return tr; });
          body.replaceChildren(...rows);
        }
      },
      dispose() { mounts.delete(container); observer?.disconnect(); if (!mounts.size && timer) { clearInterval(timer); timer = null; } },
      api: null
    };
    view.api = { dispose: () => view.dispose(), setConnection: status => { viewConnection = status; view.render(); } };
    select.addEventListener('change', () => { if (paused) { paused = false; frozen = null; pause.textContent = t.pause; pause.setAttribute('aria-pressed', 'false'); } view.render(); });
    pause.addEventListener('click', () => { paused = !paused; frozen = paused ? currentBuffer(options.source).points.slice() : null; pause.textContent = paused ? t.resume : t.pause; pause.setAttribute('aria-pressed', String(paused)); if (paused) metadata.textContent += ' · ' + t.paused; else view.render(); });
    details.addEventListener('toggle', () => { if (!paused) view.render(); });
    const observer = typeof ResizeObserver === 'function' ? new ResizeObserver(() => { if (!document.hidden) view.render(); }) : null;
    observer?.observe(container); mounts.set(container, view);
    if (!timer) timer = setInterval(update, 5000);
    view.render(); return view.api;
  }
  window.OpscopeCharts = Object.freeze({
    mount,
    push(value) { const point = normalize(value); if (!point) return false; const accepted = (point.source === 'local-lightweight' ? metricBuffer : snapshotBuffer).push(point); if (accepted) update(); return accepted; },
    setConnection(status) { connection = String(status).slice(0, 32); update(); },
    reset() { snapshotBuffer.clear(); metricBuffer.clear(); update(); }
  });
  document.addEventListener('visibilitychange', () => { if (!document.hidden) update(); });
})();
