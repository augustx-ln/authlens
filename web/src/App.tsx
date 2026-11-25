import { useMemo, useRef, useState } from 'react'
import demoLog from './assets/demo-auth.log?raw'
import './App.css'

type AuthEvent = {
  timestamp: string
  sourceIp: string
  username: string
  outcome: 'failed' | 'success'
  platform: 'Linux' | 'Windows'
  eventId: number | null
}

type Alert = {
  id: string
  title: string
  severity: 'High' | 'Medium'
  description: string
  sourceIp: string
  username: string | null
  count: number
  firstSeen: string
  lastSeen: string
  technique: string
  techniqueName: string
}

type Report = {
  events: AuthEvent[]
  alerts: Alert[]
  parsedLines: number
  skippedLines: number
  truncated: boolean
}

type View = 'overview' | 'events'

const MAX_FILE_BYTES = 25 * 1024 * 1024

function formatTime(value: string) {
  if (!value || value === 'Unknown time') return 'Unknown time'
  const date = new Date(value)
  return Number.isNaN(date.getTime())
    ? value
    : new Intl.DateTimeFormat('en', { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' }).format(date)
}

function Icon({ name, size = 18 }: { name: 'shield' | 'upload' | 'spark' | 'download' | 'search' | 'arrow' | 'check' | 'close' | 'file' | 'lock' | 'external'; size?: number }) {
  const common = { width: size, height: size, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', strokeWidth: 1.8, strokeLinecap: 'round' as const, strokeLinejoin: 'round' as const, 'aria-hidden': true as const }
  const paths = {
    shield: <><path d="M12 3 20 6v5c0 5-3.4 8.4-8 10-4.6-1.6-8-5-8-10V6l8-3Z" /><path d="m9 12 2 2 4-4" /></>,
    upload: <><path d="M12 16V4m0 0L7 9m5-5 5 5" /><path d="M5 14v5h14v-5" /></>,
    spark: <><path d="m12 3 1.6 5.4L19 10l-5.4 1.6L12 17l-1.6-5.4L5 10l5.4-1.6L12 3Z" /><path d="m19 15 .8 2.2L22 18l-2.2.8L19 21l-.8-2.2L16 18l2.2-.8L19 15Z" /></>,
    download: <><path d="M12 4v11m0 0 4-4m-4 4-4-4" /><path d="M5 17v3h14v-3" /></>,
    search: <><circle cx="10.8" cy="10.8" r="6.8" /><path d="m16 16 4.5 4.5" /></>,
    arrow: <><path d="M4 12h15m-6-6 6 6-6 6" /></>,
    check: <path d="m5 12 4 4L19 6" />,
    close: <path d="m6 6 12 12M18 6 6 18" />,
    file: <><path d="M13 3H6v18h12V8Z" /><path d="M13 3v5h5M9 13h6m-6 4h6" /></>,
    lock: <><rect x="4" y="10" width="16" height="11" rx="2" /><path d="M8 10V7a4 4 0 0 1 8 0v3m-4 4v3" /></>,
    external: <><path d="M14 4h6v6m-1-5-8 8" /><path d="M18 13v6a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h6" /></>,
  }
  return <svg {...common}>{paths[name]}</svg>
}

async function loadAnalyzer() {
  const wasm = await import('./wasm/pkg/authlens_analyzer.js')
  await wasm.default()
  return wasm
}

function App() {
  const fileInput = useRef<HTMLInputElement>(null)
  const [report, setReport] = useState<Report | null>(null)
  const [fileName, setFileName] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [view, setView] = useState<View>('overview')
  const [query, setQuery] = useState('')
  const [outcomeFilter, setOutcomeFilter] = useState('all')
  const [activeAlert, setActiveAlert] = useState<Alert | null>(null)

  const failedCount = report?.events.filter((event) => event.outcome === 'failed').length ?? 0
  const sourceCount = new Set(report?.events.map((event) => event.sourceIp).filter((ip) => ip !== 'Unknown') ?? []).size
  const filteredEvents = useMemo(() => report?.events.filter((event) => {
    const matchesQuery = `${event.username} ${event.sourceIp} ${event.platform} ${event.eventId ?? ''}`.toLowerCase().includes(query.toLowerCase())
    const matchesOutcome = outcomeFilter === 'all' || event.outcome === outcomeFilter
    return matchesQuery && matchesOutcome
  }) ?? [], [report, query, outcomeFilter])

  async function analyzeText(text: string, name: string) {
    setBusy(true)
    setError('')
    try {
      const wasm = await loadAnalyzer()
      setReport(wasm.analyze_auth_log(text, new Date().getFullYear()) as Report)
      setFileName(name)
      setView('overview')
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'The log could not be analyzed. Check the file and try again.')
    } finally {
      setBusy(false)
    }
  }

  async function analyzeFile(file: File) {
    if (file.size > MAX_FILE_BYTES) {
      setError('This file is larger than 25 MB. Choose a smaller log file.')
      return
    }
    setBusy(true)
    setError('')
    try {
      const wasm = await loadAnalyzer()
      const result = file.name.toLowerCase().endsWith('.evtx')
        ? wasm.analyze_evtx(new Uint8Array(await file.arrayBuffer())) as Report
        : wasm.analyze_auth_log(await file.text(), new Date().getFullYear()) as Report
      setReport(result)
      setFileName(file.name)
      setView('overview')
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'The log could not be analyzed. Check the file and try again.')
    } finally {
      setBusy(false)
    }
  }

  function download(name: string, body: string, type: string) {
    const url = URL.createObjectURL(new Blob([body], { type }))
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = name
    document.body.append(anchor)
    anchor.click()
    anchor.remove()
    window.setTimeout(() => URL.revokeObjectURL(url), 0)
  }

  function exportJson() {
    if (report) download('authlens-investigation.json', JSON.stringify(report, null, 2), 'application/json')
  }

  function exportCsv() {
    if (!report) return
    const rows = [['timestamp', 'platform', 'event_id', 'outcome', 'username', 'source_ip'], ...report.events.map((event) => [event.timestamp, event.platform, event.eventId ?? '', event.outcome, event.username, event.sourceIp])]
    const csv = rows.map((row) => row.map((value) => {
      const text = String(value)
      const first = text.trimStart().charAt(0)
      const safe = ['=', '+', '-', '@'].includes(first) ? `'${text}` : text
      return `"${safe.replaceAll('"', '""')}"`
    }).join(',')).join('\r\n')
    download('authlens-events.csv', csv, 'text/csv;charset=utf-8')
  }

  function reset() {
    setReport(null)
    setFileName('')
    setQuery('')
    setOutcomeFilter('all')
    setError('')
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <a className="brand" href="#top" aria-label="AuthLens home" onClick={reset}>
          <span className="brand-mark"><Icon name="shield" size={21} /></span>
          <span>auth<span>lens</span></span>
          <span className="brand-tag">BETA</span>
        </a>
        <div className="topbar-right">
          <span className="privacy-chip"><span className="status-dot" /><Icon name="lock" size={14} /> Private analysis</span>
          <a className="github-link" href="https://github.com/augustx-ln/authlens" target="_blank" rel="noreferrer">GitHub <Icon name="external" size={14} /></a>
        </div>
      </header>

      <main id="top">
        <section className="hero-row">
          <div>
            <div className="eyebrow"><span className="eyebrow-line" /> SECURITY LOG WORKSPACE <span className="eyebrow-divider">/</span> AUTHENTICATION</div>
            <h1>See the story behind<br /><span>every sign-in.</span></h1>
            <p className="hero-copy">Spot brute-force attempts and suspicious login patterns in Windows and Linux authentication logs.</p>
          </div>
          <div className="hero-aside">
            <div className="orbit orbit-one" /><div className="orbit orbit-two" /><div className="orbit-core"><Icon name="shield" size={32} /></div>
            <span className="orbit-label label-top">LOCAL PARSING</span><span className="orbit-label label-bottom">RUST ENGINE</span>
          </div>
        </section>

        <section className="workspace-card" aria-label="Authentication log analysis">
          {!report ? (
            <div className="welcome-panel">
              <div className="welcome-head">
                <div><span className="section-kicker">START AN INVESTIGATION</span><h2>Bring in an authentication log</h2><p>Choose a Windows Security event log or a Linux OpenSSH authentication log.</p></div>
                <div className="format-badges"><span><i className="win-icon">W</i> Windows <small>.evtx</small></span><span><i className="linux-icon">L</i> Linux <small>.log / .txt</small></span></div>
              </div>
              <button className={`dropzone ${busy ? 'is-busy' : ''}`} onClick={() => fileInput.current?.click()} onDragOver={(event) => event.preventDefault()} onDrop={(event) => { event.preventDefault(); const file = event.dataTransfer.files[0]; if (file) void analyzeFile(file) }} disabled={busy}>
                <span className="upload-icon"><Icon name={busy ? 'spark' : 'upload'} size={24} /></span>
                <strong>{busy ? 'Analyzing locally…' : 'Drop a log file here, or browse'}</strong>
                <span className="drop-caption">Maximum file size 25 MB <span>·</span> No upload required</span>
                {busy && <span className="progress-track"><i /></span>}
              </button>
              <input ref={fileInput} type="file" accept=".evtx,.log,.txt,.authlog" hidden onChange={(event) => { const file = event.currentTarget.files?.[0]; if (file) void analyzeFile(file); event.currentTarget.value = '' }} />
              {error && <div className="error-message" role="alert"><Icon name="close" size={16} /> {error}</div>}
              <div className="welcome-foot"><span className="safe-note"><Icon name="lock" size={15} /> Your logs stay in this browser and are never sent to a server.</span><button className="demo-button" onClick={() => void analyzeText(demoLog, 'synthetic-auth-demo.log')} disabled={busy}><Icon name="spark" size={16} /> Try a sample investigation <Icon name="arrow" size={15} /></button></div>
              <div className="detection-strip"><span>DETECTION COVERAGE</span><b>Repeated login failures</b><i /><b>Password spray</b><i /><b>Success after failures</b><a href="https://attack.mitre.org/techniques/T1110/" target="_blank" rel="noreferrer">MITRE ATT&amp;CK <Icon name="external" size={12} /></a></div>
            </div>
          ) : (
            <>
              <div className="report-header">
                <div className="report-title-group"><span className="report-icon"><Icon name="file" size={18} /></span><div><div className="section-kicker">INVESTIGATION REPORT</div><h2>{fileName}</h2></div><span className="loaded-chip"><Icon name="check" size={13} /> ANALYZED</span></div>
                <div className="report-actions"><button className="quiet-button" onClick={exportCsv}><Icon name="download" size={15} /> CSV</button><button className="quiet-button" onClick={exportJson}><Icon name="download" size={15} /> JSON</button><button className="primary-button small" onClick={() => fileInput.current?.click()}><Icon name="upload" size={15} /> New file</button><button className="icon-button" onClick={reset} aria-label="Clear investigation"><Icon name="close" size={17} /></button><input ref={fileInput} type="file" accept=".evtx,.log,.txt,.authlog" hidden onChange={(event) => { const file = event.currentTarget.files?.[0]; if (file) void analyzeFile(file); event.currentTarget.value = '' }} /></div>
              </div>
              <div className="privacy-line"><Icon name="lock" size={14} /> Parsed locally in your browser <span /> {report.parsedLines.toLocaleString()} authentication events <span />{report.truncated ? 'Analysis capped at 100,000 events' : 'Source file is not stored'}{report.skippedLines > 0 && <><span /> {report.skippedLines.toLocaleString()} records skipped</>}</div>
              {report.parsedLines === 0 && <div className="info-message"><Icon name="file" size={15} /> No supported authentication events were found. AuthLens reads common OpenSSH auth logs and Windows Security event IDs 4624/4625.</div>}
              {error && <div className="error-message" role="alert"><Icon name="close" size={16} /> {error}</div>}
              <div className="metric-grid">
                <Metric label="AUTH EVENTS" value={report.parsedLines.toLocaleString()} note="Parsed from source" tone="neutral" />
                <Metric label="DETECTIONS" value={String(report.alerts.length).padStart(2, '0')} note={report.alerts.length ? 'Needs analyst review' : 'No matched patterns'} tone={report.alerts.length ? 'amber' : 'green'} />
                <Metric label="FAILED SIGN-INS" value={failedCount.toLocaleString()} note="Across all accounts" tone="red" />
                <Metric label="SOURCE ADDRESSES" value={String(sourceCount).padStart(2, '0')} note="Unique remote IPs" tone="blue" />
              </div>
              <nav className="report-tabs" aria-label="Report views"><button className={view === 'overview' ? 'active' : ''} onClick={() => setView('overview')}>Overview <span>{report.alerts.length}</span></button><button className={view === 'events' ? 'active' : ''} onClick={() => setView('events')}>Event stream <span>{report.events.length.toLocaleString()}</span></button></nav>
              {view === 'overview' ? <Overview report={report} onSelectAlert={setActiveAlert} onViewEvents={() => setView('events')} /> : <EventTable events={filteredEvents} query={query} setQuery={setQuery} outcomeFilter={outcomeFilter} setOutcomeFilter={setOutcomeFilter} />}
            </>
          )}
        </section>

        <footer className="page-footer"><span>AUTHLENS <b>·</b> OPEN-SOURCE AUTHENTICATION TRIAGE</span><span>BUILT FOR DEFENDERS <b>·</b> NO SERVER. NO LOG UPLOADS.</span></footer>
      </main>

      {activeAlert && <div className="modal-backdrop" role="presentation" onClick={() => setActiveAlert(null)}><section className="alert-modal" role="dialog" aria-modal="true" aria-labelledby="alert-title" onClick={(event) => event.stopPropagation()}><button className="icon-button modal-close" onClick={() => setActiveAlert(null)} aria-label="Close finding details"><Icon name="close" /></button><span className={`severity-pill ${activeAlert.severity.toLowerCase()}`}>{activeAlert.severity} PRIORITY</span><h2 id="alert-title">{activeAlert.title}</h2><p>{activeAlert.description}</p><div className="modal-details"><div><span>SOURCE ADDRESS</span><b>{activeAlert.sourceIp}</b></div><div><span>ACCOUNT</span><b>{activeAlert.username ?? 'Multiple accounts'}</b></div><div><span>OBSERVED</span><b>{activeAlert.count} events</b></div><div><span>TIME WINDOW</span><b>{formatTime(activeAlert.firstSeen)} — {formatTime(activeAlert.lastSeen)}</b></div></div><a className="mitre-link" href={`https://attack.mitre.org/techniques/${activeAlert.technique.replace('.', '/')}/`} target="_blank" rel="noreferrer"><span><small>MITRE ATT&amp;CK</small><b>{activeAlert.technique} · {activeAlert.techniqueName}</b></span><Icon name="external" /></a><button className="primary-button modal-done" onClick={() => setActiveAlert(null)}>Back to investigation</button></section></div>}
    </div>
  )
}

function Metric({ label, value, note, tone }: { label: string; value: string; note: string; tone: string }) {
  return <div className={`metric-card tone-${tone}`}><div className="metric-top"><span>{label}</span><i /></div><strong>{value}</strong><small>{note}</small></div>
}

function Overview({ report, onSelectAlert, onViewEvents }: { report: Report; onSelectAlert: (alert: Alert) => void; onViewEvents: () => void }) {
  const buckets = useMemo(() => {
    const values = Array.from({ length: 12 }, (_, index) => ({ label: `${String(index * 2).padStart(2, '0')}:00`, failed: 0, success: 0 }))
    const timed = report.events.map((event) => ({ event, date: new Date(event.timestamp) })).filter((item) => !Number.isNaN(item.date.getTime()))
    for (const { event, date } of timed) {
      const bucket = values[Math.min(11, Math.floor(date.getHours() / 2))]
      bucket[event.outcome] += 1
    }
    const peak = Math.max(1, ...values.map((item) => item.failed + item.success))
    return values.map((item) => ({ ...item, height: (item.failed + item.success) / peak * 100, failedHeight: item.failed / Math.max(1, item.failed + item.success) * 100 }))
  }, [report.events])

  return <div className="overview-grid">
    <section className="chart-panel"><div className="panel-heading"><div><span className="section-kicker">EVENT DISTRIBUTION</span><h3>Authentication activity</h3></div><div className="chart-legend"><span><i className="legend-fail" /> Failed</span><span><i className="legend-success" /> Successful</span></div></div><div className="chart-area"><div className="chart-y"><span>100%</span><span>75%</span><span>50%</span><span>25%</span><span>0%</span></div><div className="bars-area"><div className="chart-guides"><i /><i /><i /><i /><i /></div>{buckets.map((bucket) => <div className="bar-column" key={bucket.label} title={`${bucket.label} · ${bucket.failed} failed, ${bucket.success} successful`}><div className="bar-stack" style={{ height: `${Math.max(bucket.height, bucket.height ? 5 : 0)}%` }}><i className="bar-success" style={{ height: `${100 - bucket.failedHeight}%` }} /><i className="bar-failed" style={{ height: `${bucket.failedHeight}%` }} /></div><span>{bucket.label}</span></div>)}</div></div><div className="chart-foot"><span><i className="pulse-dot" /> {report.events.length ? `${report.events.length.toLocaleString()} events plotted by local time` : 'No events to plot'}</span><span>2 HOUR INTERVALS</span></div></section>
    <section className="findings-panel"><div className="panel-heading"><div><span className="section-kicker">RULE MATCHES</span><h3>Priority findings</h3></div><span className="findings-count">{String(report.alerts.length).padStart(2, '0')}</span></div>{report.alerts.length ? <div className="findings-list">{report.alerts.map((alert) => <button className="finding-row" key={alert.id} onClick={() => onSelectAlert(alert)}><span className={`finding-indicator ${alert.severity.toLowerCase()}`} /><span className="finding-content"><b>{alert.title}</b><small>{alert.sourceIp} <i>·</i> {alert.username ?? 'Multiple accounts'}</small></span><span className="finding-meta"><b>{alert.count}</b><small>{formatTime(alert.firstSeen)}</small></span><Icon name="arrow" size={16} /></button>)}</div> : <div className="no-findings"><span><Icon name="check" size={20} /></span><b>No matching patterns found</b><small>Review the event stream for context.</small></div>}<button className="panel-link" onClick={onViewEvents}>Review all events <Icon name="arrow" size={15} /></button></section>
    <section className="events-panel"><div className="panel-heading"><div><span className="section-kicker">LATEST ACTIVITY</span><h3>Authentication events</h3></div><button className="text-link" onClick={onViewEvents}>View all <Icon name="arrow" size={14} /></button></div><EventTable events={report.events.slice(-6).reverse()} compact query="" setQuery={() => undefined} outcomeFilter="all" setOutcomeFilter={() => undefined} /></section>
    <div className="coverage-note"><span className="coverage-icon"><Icon name="shield" size={17} /></span><span><b>Detection coverage</b><small>Repeated login failures · Password spray · Success after failures</small></span><a href="https://attack.mitre.org/techniques/T1110/" target="_blank" rel="noreferrer">MITRE ATT&amp;CK <Icon name="external" size={12} /></a></div>
  </div>
}

function EventTable({ events, query, setQuery, outcomeFilter, setOutcomeFilter, compact = false }: { events: AuthEvent[]; query: string; setQuery: (value: string) => void; outcomeFilter: string; setOutcomeFilter: (value: string) => void; compact?: boolean }) {
  return <div className={`event-section ${compact ? 'compact' : ''}`}>
    {!compact && <div className="table-tools"><label className="search-box"><Icon name="search" size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search user, IP, platform…" /></label><select aria-label="Filter by outcome" value={outcomeFilter} onChange={(event) => setOutcomeFilter(event.target.value)}><option value="all">All outcomes</option><option value="failed">Failed</option><option value="success">Successful</option></select><span className="row-count">{events.length.toLocaleString()} EVENTS</span></div>}
    <div className="table-scroll"><table><thead><tr><th>TIME</th><th>RESULT</th><th>ACCOUNT</th><th>SOURCE ADDRESS</th><th>PLATFORM</th>{!compact && <th>EVENT ID</th>}</tr></thead><tbody>{events.length ? events.map((event, index) => <tr key={`${event.timestamp}-${event.sourceIp}-${event.username}-${index}`}><td className="time-cell">{formatTime(event.timestamp)}</td><td><span className={`outcome-tag ${event.outcome}`}><i />{event.outcome === 'failed' ? 'Failed' : 'Success'}</span></td><td className="account-cell">{event.username}</td><td className="ip-cell">{event.sourceIp}</td><td><span className={`platform-tag ${event.platform.toLowerCase()}`}>{event.platform === 'Windows' ? 'W' : 'L'}</span> {event.platform}</td>{!compact && <td className="event-id-cell">{event.eventId ?? '—'}</td>}</tr>) : <tr><td colSpan={compact ? 5 : 6} className="empty-row">No events match this search.</td></tr>}</tbody></table></div>
  </div>
}

export default App
