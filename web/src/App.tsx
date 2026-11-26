import { useMemo, useRef, useState } from 'react'
import demoLog from './assets/demo-auth.log?raw'
import demoActivityLog from './assets/demo-activity.log?raw'
import './App.css'

type Outcome = 'failed' | 'success' | 'activity'
type Category = 'authentication' | 'privilege' | 'account_change'

type AuthEvent = {
  timestamp: string
  sourceIp: string
  username: string
  actor: string | null
  outcome: Outcome
  category: Category
  action: string
  platform: 'Linux' | 'Windows'
  sourceFile: string
  eventId: number | null
}

type Alert = {
  id: string
  title: string
  severity: 'High' | 'Medium' | 'Info'
  description: string
  sourceIp: string
  username: string | null
  actor: string | null
  sourceFiles: string[]
  count: number
  firstSeen: string
  lastSeen: string
  technique: string
  techniqueName: string
}

type Report = {
  events: AuthEvent[]
  alerts: Alert[]
  sourceFiles: string[]
  parsedLines: number
  skippedLines: number
  truncated: boolean
  findingsTruncated: boolean
}

type AnalysisInput = { name: string; content: string | Uint8Array }
type View = 'overview' | 'events'

const MAX_CASE_BYTES = 25 * 1024 * 1024

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
  const [caseName, setCaseName] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [view, setView] = useState<View>('overview')
  const [query, setQuery] = useState('')
  const [outcomeFilter, setOutcomeFilter] = useState('all')
  const [activeAlert, setActiveAlert] = useState<Alert | null>(null)

  const failedCount = report?.events.filter((event) => event.category === 'authentication' && event.outcome === 'failed').length ?? 0
  const accountChangeCount = report?.events.filter((event) => event.category === 'account_change').length ?? 0
  const privilegeCount = report?.events.filter((event) => event.category === 'privilege').length ?? 0
  const filteredEvents = useMemo(() => report?.events.filter((event) => {
    const matchesQuery = `${event.username} ${event.actor ?? ''} ${event.sourceIp} ${event.platform} ${event.eventId ?? ''} ${event.action} ${event.category} ${event.sourceFile}`.toLowerCase().includes(query.toLowerCase())
    const matchesOutcome = outcomeFilter === 'all' || event.outcome === outcomeFilter
    return matchesQuery && matchesOutcome
  }) ?? [], [report, query, outcomeFilter])

  async function analyze(loadInputs: () => Promise<AnalysisInput[]>) {
    setBusy(true)
    setError('')
    try {
      const inputs = await loadInputs()
      const wasm = await loadAnalyzer()
      setReport(wasm.analyze_case(inputs, new Date().getFullYear()) as Report)
      setCaseName(inputs.length === 1 ? inputs[0].name : `Case with ${inputs.length} log files`)
      setView('overview')
      setQuery('')
      setOutcomeFilter('all')
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'The selected logs could not be analyzed. Check the files and try again.')
    } finally {
      setBusy(false)
    }
  }

  function analyzeFiles(fileList: FileList | File[]) {
    const files = Array.from(fileList)
    if (!files.length) return
    if (files.reduce((sum, file) => sum + file.size, 0) > MAX_CASE_BYTES) {
      setError('These files exceed the 25 MB total case limit. Choose a smaller set of logs.')
      return
    }
    void analyze(() => Promise.all(files.map(async (file) => ({
      name: file.name,
      content: file.name.toLowerCase().endsWith('.evtx')
        ? new Uint8Array(await file.arrayBuffer())
        : await file.text(),
    }))))
  }

  function analyzeDemo() {
    void analyze(async () => [
      { name: 'synthetic-auth-demo.log', content: demoLog },
      { name: 'synthetic-activity-demo.log', content: demoActivityLog },
    ])
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
    const rows = [['timestamp', 'category', 'action', 'outcome', 'username', 'actor', 'source_ip', 'platform', 'source_file', 'event_id'], ...report.events.map((event) => [event.timestamp, event.category, event.action, event.outcome, event.username, event.actor ?? '', event.sourceIp, event.platform, event.sourceFile, event.eventId ?? ''])]
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
    setCaseName('')
    setQuery('')
    setOutcomeFilter('all')
    setError('')
    setActiveAlert(null)
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <a className="brand" href="#top" aria-label="AuthLens home" onClick={reset}>
          <span className="brand-mark"><Icon name="shield" size={21} /></span>
          <span>auth<span>lens</span></span>
        </a>
        <div className="topbar-right">
          <a className="github-link" href="https://github.com/augustx-ln/authlens" target="_blank" rel="noreferrer">GitHub <Icon name="external" size={14} /></a>
        </div>
      </header>

      <main id="top" className={report ? 'report-layout' : undefined}>
        {!report && <section className="hero-row">
          <div>
            <p className="eyebrow">AUTHLENS · SECURITY LOG ANALYSIS</p>
            <h1>Find suspicious activity in <span>Windows and Linux logs.</span></h1>
            <p className="hero-copy">Review sign-in attempts, privileged commands, and account changes together. Your files are analyzed locally in this browser.</p>
          </div>
        </section>}

        <section className="workspace-card" aria-label="Security log analysis">
          {!report ? (
            <div className="welcome-panel">
              <div className="welcome-head">
                <div><span className="section-kicker">START HERE</span><h2>Analyze a set of security logs</h2><p>Add Windows Security or Linux authentication and audit files to build a searchable investigation.</p></div>
              </div>
              <div className="welcome-layout">
                <div className="upload-column">
                  <button className={`dropzone ${busy ? 'is-busy' : ''}`} onClick={() => fileInput.current?.click()} onDragOver={(event) => event.preventDefault()} onDrop={(event) => { event.preventDefault(); analyzeFiles(event.dataTransfer.files) }} disabled={busy} aria-busy={busy}>
                    <span className="upload-icon"><Icon name={busy ? 'spark' : 'upload'} size={24} /></span>
                    <strong aria-live="polite">{busy ? 'Analyzing your logs locally…' : 'Drop log files here'}</strong>
                    <span className="drop-action">{busy ? 'This usually takes a few seconds' : 'Choose files'} {!busy && <Icon name="arrow" size={15} />}</span>
                    <span className="drop-caption">.evtx, .log, .txt, .authlog, .audit · 25 MB total</span>
                    {busy && <span className="progress-track"><i /></span>}
                  </button>
                  <input ref={fileInput} type="file" multiple accept=".evtx,.log,.txt,.authlog,.audit" hidden onChange={(event) => { if (event.currentTarget.files) analyzeFiles(event.currentTarget.files); event.currentTarget.value = '' }} />
                  {error && <div className="error-message" role="alert"><Icon name="close" size={16} /> {error}</div>}
                  <div className="upload-footer">
                    <span className="safe-note"><Icon name="lock" size={15} /> Files stay in this browser.</span>
                    <button className="demo-button" onClick={analyzeDemo} disabled={busy}>Open sample report <Icon name="arrow" size={15} /></button>
                  </div>
                  <p className="coverage-copy">Covers sign-ins, privilege use, and account or group changes.</p>
                </div>
                <aside className="product-preview" aria-label="Example AuthLens report using synthetic data">
                  <div className="preview-heading"><div><span className="section-kicker">PRODUCT PREVIEW</span><h3>Investigation overview</h3></div><span className="synthetic-label">Synthetic data</span></div>
                  <div className="preview-metrics"><div><b>20</b><span>Events</span></div><div><b>6</b><span>Findings</span></div><div><b>2</b><span>Log files</span></div></div>
                  <div className="preview-activity" aria-hidden="true"><span /><span /><span /><span /><span /><span /><span /><span /><span /><span /><span /><span /></div>
                  <div className="preview-list">
                    <div><i className="preview-dot high" /><span><b>Possible password spray</b><small>198.51.100.42 · multiple accounts</small></span><b className="preview-count">9</b></div>
                    <div><i className="preview-dot info" /><span><b>Linux user account created</b><small>Linux audit · backupsvc</small></span><b className="preview-count">1</b></div>
                  </div>
                  <p className="preview-note">Example output from the included logs. Open the sample report to explore the interactive dashboard.</p>
                </aside>
              </div>
            </div>
          ) : (
            <>
              <div className="report-header">
                <div className="report-title-group"><span className="report-icon"><Icon name="file" size={18} /></span><div><div className="section-kicker">INVESTIGATION</div><h2>{caseName}</h2></div></div>
                <div className="report-actions">{busy && <span className="loading-status" role="status"><i /> Analyzing locally…</span>}<button className="quiet-button" onClick={exportCsv}><Icon name="download" size={15} /> CSV</button><button className="quiet-button" onClick={exportJson}><Icon name="download" size={15} /> JSON</button><button className="primary-button small" onClick={() => fileInput.current?.click()} disabled={busy}><Icon name="upload" size={15} /> New case</button><button className="icon-button" onClick={reset} aria-label="Clear investigation"><Icon name="close" size={17} /></button><input ref={fileInput} type="file" multiple accept=".evtx,.log,.txt,.authlog,.audit" hidden onChange={(event) => { if (event.currentTarget.files) analyzeFiles(event.currentTarget.files); event.currentTarget.value = '' }} /></div>
              </div>
              <div className="privacy-line">{report.parsedLines.toLocaleString()} events <span />{report.truncated ? 'Analysis capped at 100,000 events' : `${report.sourceFiles.length} source file${report.sourceFiles.length === 1 ? '' : 's'}`}{report.skippedLines > 0 && <><span /> {report.skippedLines.toLocaleString()} records skipped</>}</div>
              {report.sourceFiles.length > 1 && <div className="source-files">Files in this case: {report.sourceFiles.join(' · ')}</div>}
              {report.parsedLines === 0 && <div className="info-message"><Icon name="file" size={15} /> No supported events were found. AuthLens reads OpenSSH sign-ins, sudo commands, selected Linux auditd account records, and Windows Security event IDs 4624/4625/4672/4720/4722/4724/4725/4728/4732/4756.</div>}
              {report.findingsTruncated && <div className="info-message"><Icon name="file" size={15} /> Findings are limited to the 500 highest-priority items; the event stream still includes every parsed event.</div>}
              {error && <div className="error-message" role="alert"><Icon name="close" size={16} /> {error}</div>}
              <div className="metric-grid">
                <Metric label="Events" value={report.parsedLines.toLocaleString()} note="Across selected files" tone="neutral" />
                <Metric label="Findings" value={String(report.alerts.length)} note={report.findingsTruncated ? '500 item limit' : report.alerts.length ? 'Matched patterns' : 'No matches'} tone={report.alerts.length ? 'amber' : 'green'} />
                <Metric label="Failed sign-ins" value={failedCount.toLocaleString()} note="Authentication" tone="red" />
                <Metric label="Account changes" value={accountChangeCount.toLocaleString()} note="Audit activity" tone="blue" />
                <Metric label="Privilege use" value={privilegeCount.toLocaleString()} note="Elevated activity" tone="amber" />
              </div>
              <nav className="report-tabs" aria-label="Report views"><button className={view === 'overview' ? 'active' : ''} onClick={() => setView('overview')}>Overview <span>{report.alerts.length}</span></button><button className={view === 'events' ? 'active' : ''} onClick={() => setView('events')}>Event stream <span>{report.events.length.toLocaleString()}</span></button></nav>
              {view === 'overview' ? <Overview report={report} onSelectAlert={setActiveAlert} onViewEvents={() => setView('events')} /> : <EventTable events={filteredEvents} query={query} setQuery={setQuery} outcomeFilter={outcomeFilter} setOutcomeFilter={setOutcomeFilter} showSource={report.sourceFiles.length > 1} />}
            </>
          )}
        </section>

      <footer className="page-footer"><span>AuthLens · Open-source security log analysis</span><span>Local browser analysis · No log uploads</span></footer>
      </main>

      {activeAlert && <div className="modal-backdrop" role="presentation" onClick={() => setActiveAlert(null)}><section className="alert-modal" role="dialog" aria-modal="true" aria-labelledby="alert-title" onClick={(event) => event.stopPropagation()}><button className="icon-button modal-close" onClick={() => setActiveAlert(null)} aria-label="Close finding details"><Icon name="close" /></button><span className={`severity-pill ${activeAlert.severity.toLowerCase()}`}>{activeAlert.severity === 'Info' ? 'ACTIVITY' : `${activeAlert.severity} PRIORITY`}</span><h2 id="alert-title">{activeAlert.title}</h2><p>{activeAlert.description}</p><div className="modal-details"><div><span>SOURCE ADDRESS</span><b>{activeAlert.sourceIp}</b></div><div><span>ACCOUNT / TARGET</span><b>{activeAlert.username ?? 'Multiple accounts'}</b></div><div><span>ACTOR</span><b>{activeAlert.actor ?? '—'}</b></div><div><span>SOURCE FILES</span><b>{activeAlert.sourceFiles.join(' · ')}</b></div><div><span>OBSERVED</span><b>{activeAlert.count} event{activeAlert.count === 1 ? '' : 's'}</b></div><div><span>TIME WINDOW</span><b>{formatTime(activeAlert.firstSeen)} — {formatTime(activeAlert.lastSeen)}</b></div></div>{activeAlert.technique ? <a className="mitre-link" href={`https://attack.mitre.org/techniques/${activeAlert.technique.replace('.', '/')}/`} target="_blank" rel="noreferrer"><span><small>MITRE ATT&amp;CK</small><b>{activeAlert.technique} · {activeAlert.techniqueName}</b></span><Icon name="external" /></a> : <div className="mitre-link"><span><small>ACTIVITY CONTEXT</small><b>{activeAlert.techniqueName}</b></span></div>}<button className="primary-button modal-done" onClick={() => setActiveAlert(null)}>Back to investigation</button></section></div>}
    </div>
  )
}

function Metric({ label, value, note, tone }: { label: string; value: string; note: string; tone: string }) {
  return <div className={`metric-card tone-${tone}`}><div className="metric-top"><span>{label}</span><i /></div><strong>{value}</strong><small>{note}</small></div>
}

function Overview({ report, onSelectAlert, onViewEvents }: { report: Report; onSelectAlert: (alert: Alert) => void; onViewEvents: () => void }) {
  const buckets = useMemo(() => {
    const values = Array.from({ length: 12 }, (_, index) => ({ label: `${String(index * 2).padStart(2, '0')}:00`, failed: 0, success: 0, activity: 0 }))
    const timed = report.events.map((event) => ({ event, date: new Date(event.timestamp) })).filter((item) => !Number.isNaN(item.date.getTime()))
    for (const { event, date } of timed) values[Math.min(11, Math.floor(date.getHours() / 2))][event.outcome] += 1
    const peak = Math.max(1, ...values.map((item) => item.failed + item.success + item.activity))
    return values.map((item) => {
      const total = item.failed + item.success + item.activity
      return { ...item, height: total / peak * 100, failedHeight: item.failed / Math.max(1, total) * 100, successHeight: item.success / Math.max(1, total) * 100, activityHeight: item.activity / Math.max(1, total) * 100 }
    })
  }, [report.events])

  return <div className="overview-grid">
    <section className="chart-panel"><div className="panel-heading"><div><span className="section-kicker">EVENT DISTRIBUTION</span><h3>System activity</h3></div><div className="chart-legend"><span><i className="legend-fail" /> Failed</span><span><i className="legend-success" /> Successful</span><span><i className="legend-activity" /> Activity</span></div></div><div className="chart-area"><div className="chart-y"><span>100%</span><span>75%</span><span>50%</span><span>25%</span><span>0%</span></div><div className="bars-area"><div className="chart-guides"><i /><i /><i /><i /><i /></div>{buckets.map((bucket) => <div className="bar-column" key={bucket.label} title={`${bucket.label} · ${bucket.failed} failed, ${bucket.success} successful, ${bucket.activity} activity`}><div className="bar-stack" style={{ height: `${Math.max(bucket.height, bucket.height ? 5 : 0)}%` }}><i className="bar-activity" style={{ height: `${bucket.activityHeight}%` }} /><i className="bar-success" style={{ height: `${bucket.successHeight}%` }} /><i className="bar-failed" style={{ height: `${bucket.failedHeight}%` }} /></div><span>{bucket.label}</span></div>)}</div></div><div className="chart-foot"><span>{report.events.length ? `${report.events.length.toLocaleString()} events · local time` : 'No events to plot'}</span><span>2 hour intervals</span></div></section>
    <section className="findings-panel"><div className="panel-heading"><div><span className="section-kicker">MATCHED PATTERNS</span><h3>Findings to review</h3></div><span className="findings-count">{report.alerts.length}</span></div>{report.alerts.length ? <div className="findings-list">{report.alerts.slice(0, 12).map((alert) => <button className="finding-row" key={alert.id} onClick={() => onSelectAlert(alert)}><span className={`finding-indicator ${alert.severity.toLowerCase()}`} /><span className="finding-content"><b>{alert.title}</b><small>{alert.sourceFiles.join(' · ')} <i>·</i> {alert.username ?? 'Multiple accounts'}</small></span><span className="finding-meta"><b>{alert.count}</b><small>{formatTime(alert.firstSeen)}</small></span><Icon name="arrow" size={16} /></button>)}</div> : <div className="no-findings"><span><Icon name="check" size={20} /></span><b>No matching patterns found</b><small>Review the event stream for context.</small></div>}{report.alerts.length > 12 && <small className="more-findings">Showing 12 of {report.alerts.length} findings</small>}<button className="panel-link" onClick={onViewEvents}>Review all events <Icon name="arrow" size={15} /></button></section>
    <section className="events-panel"><div className="panel-heading"><div><span className="section-kicker">LATEST ACTIVITY</span><h3>Recent security events</h3></div><button className="text-link" onClick={onViewEvents}>View all <Icon name="arrow" size={14} /></button></div><EventTable events={report.events.slice(-6).reverse()} compact query="" setQuery={() => undefined} outcomeFilter="all" setOutcomeFilter={() => undefined} showSource={report.sourceFiles.length > 1} /></section>
  </div>
}

function EventTable({ events, query, setQuery, outcomeFilter, setOutcomeFilter, compact = false, showSource = false }: { events: AuthEvent[]; query: string; setQuery: (value: string) => void; outcomeFilter: string; setOutcomeFilter: (value: string) => void; compact?: boolean; showSource?: boolean }) {
  const columns = (compact ? 7 : 8) + Number(showSource)
  return <div className={`event-section${compact ? ' compact' : ''}${showSource ? ' with-source' : ''}`}>
    {!compact && <div className="table-tools"><label className="search-box"><Icon name="search" size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search accounts, events, IPs, files" /></label><select aria-label="Filter by outcome" value={outcomeFilter} onChange={(event) => setOutcomeFilter(event.target.value)}><option value="all">All outcomes</option><option value="failed">Failed</option><option value="success">Successful</option><option value="activity">Activity</option></select><span className="row-count">{events.length.toLocaleString()} events</span></div>}
    <div className="table-scroll"><table><thead><tr><th>Time</th><th>Event</th><th>Result</th><th>Account / target</th><th>Actor</th><th>Source address</th><th>Platform</th>{showSource && <th>Source file</th>}{!compact && <th>Event ID</th>}</tr></thead><tbody>{events.length ? events.map((event, index) => <tr key={`${event.timestamp}-${event.sourceFile}-${event.sourceIp}-${event.username}-${index}`}><td className="time-cell">{formatTime(event.timestamp)}</td><td className="event-action-cell"><b>{event.action}</b><small>{event.category.replace('_', ' ')}</small></td><td><span className={`outcome-text ${event.outcome}`}><i />{event.outcome === 'failed' ? 'Failed' : event.outcome === 'success' ? 'Success' : 'Activity'}</span></td><td className="account-cell">{event.username}</td><td className="actor-cell">{event.actor ?? '—'}</td><td className="ip-cell">{event.sourceIp}</td><td>{event.platform}</td>{showSource && <td className="source-file-cell">{event.sourceFile}</td>}{!compact && <td className="event-id-cell">{event.eventId ?? '—'}</td>}</tr>) : <tr><td colSpan={columns} className="empty-row">No events match this search.</td></tr>}</tbody></table></div>
  </div>
}

export default App
