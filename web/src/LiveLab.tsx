import { useEffect, useRef, useState } from 'react'
import { activityBuckets } from './liveActivity.ts'
import './LiveLab.css'

type LiveEvent = {
  atMs: number
  source: string
  kind: 'connection' | 'http'
  detail: string
  port: number
  status: number | null
  action?: string
  actor?: string
  target?: string
  outcome?: string
  reason?: string
  userAgent?: string
  sourceSensor?: string
}

type Finding = {
  id: string
  title: string
  severity: 'High' | 'Medium' | 'Info'
  source: string
  evidence: string
  firstMs: number
  lastMs: number
  count: number
  eventIds: number[]
}

type Snapshot = {
  events: LiveEvent[]
  findings: Finding[]
  totalEvents: number
  targetUrl: string
}

type Detail = { type: 'event'; value: LiveEvent } | { type: 'finding'; value: Finding }

const timeFormat = new Intl.DateTimeFormat('en', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
const shortTimeFormat = new Intl.DateTimeFormat('en', { hour: '2-digit', minute: '2-digit' })
const formatTime = (value: number) => timeFormat.format(value)
const actionLabels: Record<string, string> = {
  login_page_view: 'Sign-in page viewed', login_failed: 'Failed sign-in', login_success: 'Successful sign-in',
  authentication_required: 'Sign-in required', account_overview_redirect: 'Account overview opened',
  account_lookup_failed: 'Account lookup failed', statement_view: 'Statement viewed',
  cross_account_read: 'Cross-account statement read', admin_dashboard_view: 'Admin workspace viewed',
  authorization_denied: 'Access denied', page_not_found: 'Unknown page requested',
  admin_export: 'Customer accounts exported', logout: 'Signed out',
  unsupported_method: 'Unsupported method rejected', invalid_request: 'Invalid request rejected',
}
const activityLabel = (event: LiveEvent) => event.action ? actionLabels[event.action] ?? event.action : event.detail
const resultLabel = (event: LiveEvent) => event.outcome ? event.outcome + (event.status ? ' · ' + event.status : '') : event.status ?? 'Accepted'
const searchFields: Record<string, (event: LiveEvent) => string> = {
  source: event => event.source, actor: event => event.actor ?? '', action: event => event.action ?? '',
  target: event => event.target ?? '', status: event => String(event.status ?? ''),
  outcome: event => event.outcome ?? '', reason: event => event.reason ?? '',
  sensor: event => event.sourceSensor ?? '',
}
function matchesQuery(event: LiveEvent, query: string) {
  return query.split(/\s+/).every(term => {
    const colon = term.indexOf(':')
    if (colon > 0 && searchFields[term.slice(0, colon)]) {
      return searchFields[term.slice(0, colon)](event).toLowerCase().includes(term.slice(colon + 1))
    }
    return [event.source, event.detail, event.port, event.status, event.action, event.actor, event.target, event.outcome, event.reason, event.userAgent, event.sourceSensor].join(' ').toLowerCase().includes(term)
  })
}

function Icon({ name, size = 18 }: { name: 'download' | 'external' | 'search' | 'pause' | 'play' | 'close'; size?: number }) {
  const common = { width: size, height: size, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', strokeWidth: 1.8, strokeLinecap: 'round' as const, strokeLinejoin: 'round' as const, 'aria-hidden': true as const }
  const paths = {
    download: <><path d="M12 4v11m0 0 4-4m-4 4-4-4" /><path d="M5 17v3h14v-3" /></>,
    external: <><path d="M14 4h6v6m-1-5-8 8" /><path d="M18 13v6a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h6" /></>,
    search: <><circle cx="10.8" cy="10.8" r="6.8" /><path d="m16 16 4.5 4.5" /></>,
    pause: <path d="M8 5v14M16 5v14" />,
    play: <path d="m8 5 11 7-11 7V5Z" />,
    close: <path d="m6 6 12 12M18 6 6 18" />,
  }
  return <svg {...common}>{paths[name]}</svg>
}

function ActivityChart({ events, findings, now, minutes }: { events: LiveEvent[]; findings: Finding[]; now: number; minutes: number }) {
  const buckets = activityBuckets(events, findings, now, minutes)
  const max = Math.max(1, ...buckets.map(bucket => bucket.http + bucket.tcp))
  const total = buckets.reduce((sum, bucket) => sum + bucket.http + bucket.tcp, 0)
  const baseline = 140
  const chartHeight = 104
  const firstX = 46
  const step = 43
  const chartWidth = minutes === 8 ? 400 : 730
  const chartEnd = firstX + (minutes - 1) * step + 34

  return <div className="live-chart-wrap">
    <div className="live-chart-summary"><strong>{total.toLocaleString()}</strong><span>events in view · latest 500 retained</span></div>
    <svg className="live-chart" viewBox={'0 0 ' + chartWidth + ' 184'} role="img" aria-label={'Traffic in the last ' + minutes + ' minutes: ' + total + ' retained events. Mint bars show HTTP, blue bars show TCP, amber markers show findings.'}>
      <line x1="38" x2={chartEnd} y1="36" y2="36" className="live-chart-grid" />
      <line x1="38" x2={chartEnd} y1="88" y2="88" className="live-chart-grid" />
      <line x1="38" x2={chartEnd} y1={baseline} y2={baseline} className="live-chart-axis" />
      <text x="28" y="40" textAnchor="end" className="live-chart-label">{max}</text>
      <text x="28" y="144" textAnchor="end" className="live-chart-label">0</text>
      {buckets.map((bucket, index) => {
        const x = firstX + index * step
        const httpHeight = bucket.http / max * chartHeight
        const tcpHeight = bucket.tcp / max * chartHeight
        return <g key={bucket.atMs}>
          <title>{shortTimeFormat.format(bucket.atMs) + ' · ' + bucket.http + ' HTTP · ' + bucket.tcp + ' TCP · ' + bucket.findings + ' findings'}</title>
          <rect x={x} y={baseline - httpHeight} width="23" height={httpHeight} rx="2" className="live-chart-http" />
          <rect x={x} y={baseline - httpHeight - tcpHeight} width="23" height={tcpHeight} rx="2" className="live-chart-tcp" />
          {bucket.findings > 0 && <circle cx={x + 11.5} cy={Math.max(19, baseline - httpHeight - tcpHeight - 9)} r="4.5" className="live-chart-finding" />}
        </g>
      })}
      {[0, Math.floor((minutes - 1) / 2), minutes - 1].map(index => <text key={index} x={firstX + index * step + 11.5} y="169" textAnchor="middle" className="live-chart-label">{shortTimeFormat.format(buckets[index].atMs)}</text>)}
    </svg>
    <div className="live-chart-legend"><span><i className="is-http" />HTTP</span><span><i className="is-tcp" />TCP</span><span><i className="is-finding" />Finding</span></div>
  </div>
}

export default function LiveLab() {
  const [data, setData] = useState<Snapshot | null>(null)
  const [connected, setConnected] = useState(false)
  const [updatedAt, setUpdatedAt] = useState<number | null>(null)
  const [frozen, setFrozen] = useState<{ snapshot: Snapshot; atMs: number } | null>(null)
  const [query, setQuery] = useState('')
  const [kindFilter, setKindFilter] = useState('all')
  const [resultFilter, setResultFilter] = useState('all')
  const [focusedFindingId, setFocusedFindingId] = useState<string | null>(null)
  const [detail, setDetail] = useState<Detail | null>(null)
  const [activityPulse, setActivityPulse] = useState(0)
  const [findingPulse, setFindingPulse] = useState(0)
  const [recentBatch, setRecentBatch] = useState<{ first: number; last: number; count: number } | null>(null)
  const [recentFindings, setRecentFindings] = useState<Record<string, 'New' | 'Updated'>>({})
  const [motionEnabled, setMotionEnabled] = useState(() => !window.matchMedia('(prefers-reduced-motion: reduce)').matches)
  const [exporting, setExporting] = useState(false)
  const [exportStatus, setExportStatus] = useState('')
  const previous = useRef<{ total: number; findings: Map<string, string> } | null>(null)
  const closeButton = useRef<HTMLButtonElement>(null)
  const streamPanel = useRef<HTMLElement>(null)

  useEffect(() => {
    const previousTitle = document.title
    document.title = 'AuthLens — Live Monitor'
    return () => { document.title = previousTitle }
  }, [])

  useEffect(() => {
    let active = true
    let batchTimer: number | undefined
    let findingTimer: number | undefined
    const refresh = async () => {
      try {
        const response = await fetch('/api/live', { cache: 'no-store' })
        if (!response.ok) throw new Error('Monitor returned ' + response.status)
        const next = await response.json() as Snapshot
        if (!active) return
        const prior = previous.current
        if (prior && next.totalEvents > prior.total) {
          setActivityPulse(value => value + 1)
          setRecentBatch({ first: prior.total + 1, last: next.totalEvents, count: next.totalEvents - prior.total })
          window.clearTimeout(batchTimer)
          batchTimer = window.setTimeout(() => setRecentBatch(null), 5000)
        }
        if (prior) {
          const changed: Record<string, 'New' | 'Updated'> = {}
          for (const finding of next.findings) {
            const signature = finding.lastMs + ':' + finding.count
            const before = prior.findings.get(finding.id)
            if (before !== signature) changed[finding.id] = before === undefined ? 'New' : 'Updated'
          }
          if (Object.keys(changed).length) {
            setFindingPulse(value => value + 1)
            setRecentFindings(changed)
            window.clearTimeout(findingTimer)
            findingTimer = window.setTimeout(() => setRecentFindings({}), 5000)
          }
        }
        if (prior && next.totalEvents < prior.total) {
          setFrozen(null)
          setRecentBatch(null)
          setRecentFindings({})
        }
        previous.current = { total: next.totalEvents, findings: new Map(next.findings.map(finding => [finding.id, finding.lastMs + ':' + finding.count])) }
        setData(next)
        setConnected(true)
        setUpdatedAt(Date.now())
      } catch {
        if (active) setConnected(false)
      }
    }
    void refresh()
    const timer = window.setInterval(() => void refresh(), 1500)
    return () => { active = false; window.clearInterval(timer); window.clearTimeout(batchTimer); window.clearTimeout(findingTimer) }
  }, [])

  useEffect(() => {
    if (!detail) return
    const priorFocus = document.activeElement as HTMLElement | null
    const priorOverflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    closeButton.current?.focus()
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setDetail(null)
      if (event.key === 'Tab') { event.preventDefault(); closeButton.current?.focus() }
    }
    window.addEventListener('keydown', onKeyDown)
    return () => { window.removeEventListener('keydown', onKeyDown); document.body.style.overflow = priorOverflow; priorFocus?.focus() }
  }, [detail])

  const visible = frozen?.snapshot ?? data
  const targetUrl = data?.targetUrl ?? 'Waiting for target address…'
  const latestEvent = visible?.events[0]
  const sources = new Set(visible?.events.map(event => event.source)).size
  const httpErrors = visible?.events.filter(event => event.kind === 'http' && (event.status ?? 0) >= 400).length ?? 0
  const unseen = frozen && data ? Math.max(0, data.totalEvents - frozen.snapshot.totalEvents) : 0
  const normalizedQuery = query.trim().toLowerCase()
  const focusedFinding = visible?.findings.find(finding => finding.id === focusedFindingId)
  const focusedEventIds = focusedFinding ? new Set(focusedFinding.eventIds) : null
  const shown = visible?.events.map((event, index) => ({ event, sequence: visible.totalEvents - index })).filter(({ event, sequence }) => {
    if (focusedEventIds && !focusedEventIds.has(sequence)) return false
    if (kindFilter !== 'all' && event.kind !== kindFilter) return false
    if (resultFilter === 'ok' && (event.status === null || event.status >= 400)) return false
    if (resultFilter === 'error' && (event.status === null || event.status < 400)) return false
    if (resultFilter === 'accepted' && event.status !== null) return false
    return !normalizedQuery || matchesQuery(event, normalizedQuery)
  }) ?? []

  async function downloadEvents() {
    if (!data?.events.length || exporting) return
    setExporting(true)
    setExportStatus('')
    try {
      const wasm = await import('./wasm/pkg/authlens_analyzer.js')
      await wasm.default()
      const bytes = wasm.export_live_evtx(data.events)
      if (new TextDecoder().decode(bytes.slice(0, 8)) !== 'ElfFile\0') throw new Error('Invalid EVTX header')
      const blob = new Blob([new Uint8Array(bytes).buffer as ArrayBuffer], { type: 'application/octet-stream' })
      const url = URL.createObjectURL(blob)
      const anchor = document.createElement('a')
      anchor.href = url
      anchor.download = 'authlens-live-events-' + new Date().toISOString().replace(/[:.]/g, '-') + '.evtx'
      document.body.append(anchor)
      anchor.click()
      anchor.remove()
      window.setTimeout(() => URL.revokeObjectURL(url), 0)
      setExportStatus('Downloaded ' + data.events.length.toLocaleString() + ' retained events.')
    } catch {
      setExportStatus('EVTX download failed. Check the live monitor connection.')
    } finally {
      setExporting(false)
    }
  }

  return <div className={'live-shell ' + (motionEnabled ? 'motion-on' : 'motion-off')}>
    <header className="live-topbar">
      <div className="live-brand"><span className="live-brand-mark">◇</span><strong>auth<span>lens</span></strong><span className="live-tag">DOCKER LAB</span></div>
      <a href="https://augustx-ln.github.io/authlens/" target="_blank" rel="noreferrer">File analysis <Icon name="external" size={14} /></a>
    </header>
    <main className="live-main">
      <div className="live-heading">
        <div><p className="live-kicker">LIVE MONITOR</p><h1>Lab activity at a glance</h1><p>Watch connections, web requests, and detection findings as they arrive.</p></div>
        <div className="live-heading-actions">
          <span className={'live-status ' + (connected ? frozen ? 'is-frozen' : 'is-connected' : 'is-disconnected')} role="status"><i />{connected ? frozen ? 'View frozen' : 'Monitoring live' : data ? 'Reconnecting…' : 'Connecting…'}</span>
          <button className="live-download" type="button" onClick={downloadEvents} disabled={!data?.events.length || exporting}><Icon name="download" size={16} />{exporting ? 'Creating EVTX…' : 'Download .evtx'}</button>
        </div>
      </div>
      <div className="live-target">
        <div><span>LAB TARGET</span><strong>{targetUrl}</strong><small>HTTP target on 8080 · TCP probe ports 8081–8087</small></div>
        <div className="live-target-end"><span>{updatedAt ? 'Last updated ' + formatTime(updatedAt) : 'Waiting for connection'}</span>{data && <a href={targetUrl} target="_blank" rel="noreferrer">Open target <Icon name="external" size={14} /></a>}</div>
      </div>
      <div className="live-metrics">
        <div><span>Events observed</span><strong>{(visible?.totalEvents ?? 0).toLocaleString()}</strong><small>Since container start</small></div>
        <div><span>Findings</span><strong>{visible?.findings.length ?? 0}</strong><small>Patterns to review</small></div>
        <div><span>Observed sources</span><strong>{sources}</strong><small>In retained events</small></div>
        <div><span>HTTP errors</span><strong>{httpErrors}</strong><small>4xx / 5xx in retained events</small></div>
      </div>
      <div className="live-overview-grid">
        <section className="live-panel live-activity-panel" aria-labelledby="activity-title">
          <div className="live-panel-heading"><div><span className="live-kicker">ACTIVITY</span><h2 id="activity-title">Traffic over the last <span className="live-desktop-only">15</span><span className="live-mobile-only">8</span> minutes</h2></div><span>Retained events only</span></div>
          <div className="live-flow-heading"><strong>Live detection</strong><div className="live-flow-controls"><span className={'live-flow-state ' + (connected && !frozen ? 'is-listening' : '')}><i />{frozen ? 'View frozen' : !connected ? 'Reconnecting' : recentBatch ? '+' + recentBatch.count + (recentBatch.count === 1 ? ' new event' : ' new events') : 'Listening for traffic'}</span><button className="live-motion-toggle" type="button" aria-pressed={motionEnabled} onClick={() => setMotionEnabled(value => !value)}>{motionEnabled ? 'Motion on' : 'Motion off'}</button></div></div>
          <div className="live-flow">
            <div className="live-flow-node"><span>OBSERVED SOURCE</span><strong>{latestEvent?.source ?? '—'}</strong></div>
            <div className={'live-flow-route ' + (connected && !frozen ? 'is-listening' : '')}><span className="live-flow-line" />{activityPulse > 0 && !frozen && connected && <span key={activityPulse} className="live-flow-pulse" />}</div>
            <div className={'live-flow-node is-target ' + (findingPulse > 0 && !frozen && connected ? 'has-finding' : '')} key={findingPulse}><span>LAB TARGET</span><strong>{':' + (latestEvent?.port ?? '8080–8087')}</strong></div>
          </div>
          <p className="live-flow-caption">{latestEvent ? 'Last observed ' + formatTime(latestEvent.atMs) + ' · ' + (latestEvent.kind === 'http' ? 'HTTP ' : 'TCP ') + latestEvent.detail : 'Send traffic to the lab target to see activity here.'}</p>
          {visible && updatedAt ? <><div className="live-chart-desktop"><ActivityChart events={visible.events} findings={visible.findings} now={frozen?.atMs ?? updatedAt} minutes={15} /></div><div className="live-chart-mobile"><ActivityChart events={visible.events} findings={visible.findings} now={frozen?.atMs ?? updatedAt} minutes={8} /></div></> : <div className="live-chart-loading">Connecting to the lab monitor…</div>}
        </section>
        <section className="live-panel live-findings-panel" aria-labelledby="findings-title">
          <div className="live-panel-heading"><div><span className="live-kicker">DETECTION RESULTS</span><h2 id="findings-title">Findings to investigate</h2></div><span>{visible?.findings.length ?? 0}</span></div>
          {visible?.findings.length ? <div className="live-findings">{visible.findings.map(finding => <button className={'live-finding ' + (!frozen && recentFindings[finding.id] ? 'is-recent' : '')} key={finding.id + ':' + finding.lastMs + ':' + finding.count} type="button" onClick={() => setDetail({ type: 'finding', value: finding })}><span className="live-finding-top"><span className={'live-severity ' + finding.severity.toLowerCase()}>{finding.severity}</span>{!frozen && recentFindings[finding.id] && <span className="live-finding-new">{recentFindings[finding.id]}</span>}</span><strong>{finding.title}</strong><small>{finding.source + ' · ' + finding.count + (finding.count === 1 ? ' occurrence' : ' occurrences')}</small><span className="live-finding-time">Latest {formatTime(finding.lastMs)}</span></button>)}</div> : <div className="live-empty">No findings yet. Detection results will appear here when lab traffic matches a rule.</div>}
        </section>
      </div>
      <section ref={streamPanel} className="live-panel live-stream-panel" aria-labelledby="stream-title">
        <div className="live-panel-heading"><div><span className="live-kicker">EVENT STREAM</span><h2 id="stream-title">Latest activity</h2></div><div className="live-stream-meta"><span>{shown.length.toLocaleString() + ' shown · ' + (visible?.events.length.toLocaleString() ?? 0) + ' retained'}</span>{!frozen && recentBatch && <strong role="status">{'+' + recentBatch.count + ' new'}</strong>}</div></div>
        <div className="live-stream-toolbar">
          <label className="live-search"><Icon name="search" size={17} /><input value={query} onChange={event => setQuery(event.target.value)} placeholder="Search or filter source:, actor:, action:, status:" aria-label="Search events" /></label>
          <select value={kindFilter} onChange={event => setKindFilter(event.target.value)} aria-label="Filter event type"><option value="all">All types</option><option value="http">HTTP</option><option value="connection">TCP</option></select>
          <select value={resultFilter} onChange={event => setResultFilter(event.target.value)} aria-label="Filter result"><option value="all">All results</option><option value="ok">HTTP below 400</option><option value="error">HTTP 4xx / 5xx</option><option value="accepted">TCP accepted</option></select>
          <button className={'live-freeze ' + (frozen ? 'is-frozen' : '')} type="button" onClick={() => setFrozen(frozen ? null : data ? { snapshot: data, atMs: Date.now() } : null)} disabled={!data}><Icon name={frozen ? 'play' : 'pause'} size={16} />{frozen ? 'Resume live' + (unseen ? ' · ' + unseen + ' new' : '') : 'Freeze view'}</button>
        </div>
        {focusedFinding && <div className="live-evidence-filter" role="status"><span>Related events for <strong>{focusedFinding.title}</strong> · {shown.length} retained</span><button type="button" onClick={() => setFocusedFindingId(null)}>Show all events</button></div>}
        <div className="live-table-scroll" role="region" aria-label="Latest live events" tabIndex={0}><table><thead><tr><th>Time</th><th>Observed source</th><th>Activity</th><th>Account / actor</th><th>Target</th><th>Result</th></tr></thead><tbody>{shown.length ? shown.map(({ event, sequence }, index) => <tr key={sequence} className={!frozen && recentBatch && sequence >= recentBatch.first && sequence <= recentBatch.last ? 'live-row-new' : ''} style={{ animationDelay: Math.min(index, 6) * 55 + 'ms' }} onClick={() => setDetail({ type: 'event', value: event })} onKeyDown={key => { if (key.key === 'Enter' || key.key === ' ') { key.preventDefault(); setDetail({ type: 'event', value: event }) } }} tabIndex={0} aria-label={'View ' + activityLabel(event) + ' from ' + event.source}><td>{formatTime(event.atMs)}</td><td>{event.source}</td><td><strong className="live-activity-name">{activityLabel(event)}</strong>{event.action && <small className="live-activity-request">{event.detail}</small>}</td><td>{event.actor || '—'}</td><td>{event.target || '—'}</td><td><span className={'live-result ' + ((event.status ?? 0) >= 400 ? 'is-error' : '')}>{resultLabel(event)}</span></td></tr>) : <tr><td colSpan={6} className="live-empty-cell">{visible?.events.length ? 'No events match these filters.' : 'Waiting for traffic to the lab target.'}</td></tr>}</tbody></table></div>
        {exportStatus && <p className="live-export-status" role="status">{exportStatus}</p>}
      </section>
      <p className="live-footnote">The local VMnet8 listener captures peer IPs before Docker forwarding. Container-only events may still show a gateway. Events and findings stay in monitor memory and clear on restart. The EVTX export contains up to 500 AuthLens lab events, not a Windows Security log.</p>
    </main>
    {detail && <div className="live-detail-backdrop" onClick={() => setDetail(null)}>
      <aside className="live-detail" role="dialog" aria-modal="true" aria-label={detail.type === 'event' ? 'Event details' : 'Finding details'} onClick={event => event.stopPropagation()}>
        <div className="live-detail-heading"><div><span className="live-kicker">{detail.type === 'event' ? 'EVENT DETAILS' : 'FINDING DETAILS'}</span><h2>{detail.type === 'event' ? activityLabel(detail.value) : detail.value.title}</h2></div><button ref={closeButton} type="button" onClick={() => setDetail(null)} aria-label="Close details"><Icon name="close" /></button></div>
        {detail.type === 'event' ? <dl><dt>Observed at</dt><dd>{new Date(detail.value.atMs).toLocaleString()}</dd><dt>Observed source</dt><dd>{detail.value.source}</dd><dt>Captured by</dt><dd>{detail.value.sourceSensor || 'Docker container'}</dd><dt>Account / actor</dt><dd>{detail.value.actor || 'Unknown'}</dd><dt>Event code</dt><dd>{detail.value.action || '—'}</dd><dt>Target</dt><dd>{detail.value.target || '—'}</dd><dt>Outcome</dt><dd>{detail.value.outcome || '—'}</dd><dt>Reason</dt><dd>{detail.value.reason || '—'}</dd><dt>HTTP / TCP</dt><dd>{detail.value.kind === 'http' ? 'HTTP' : 'TCP connection'}</dd><dt>Request / connection</dt><dd>{detail.value.detail}</dd><dt>Destination port</dt><dd>{detail.value.port}</dd><dt>HTTP status</dt><dd>{detail.value.status ?? '—'}</dd><dt>User-Agent</dt><dd>{detail.value.userAgent || '—'}</dd></dl> : <><span className={'live-severity ' + detail.value.severity.toLowerCase()}>{detail.value.severity}</span><p className="live-detail-evidence">{detail.value.evidence}</p><dl><dt>Observed source</dt><dd>{detail.value.source}</dd><dt>Occurrences</dt><dd>{detail.value.count}</dd><dt>First observed</dt><dd>{new Date(detail.value.firstMs).toLocaleString()}</dd><dt>Latest observed</dt><dd>{new Date(detail.value.lastMs).toLocaleString()}</dd></dl></>}
        {detail.type === 'finding' && <button className="live-evidence-action" type="button" onClick={() => { setFocusedFindingId(detail.value.id); setQuery(''); setKindFilter('all'); setResultFilter('all'); setDetail(null); window.setTimeout(() => streamPanel.current?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 0) }}>View related events ({detail.value.eventIds.length})</button>}
        <p className="live-detail-note">{detail.type === 'event' && detail.value.sourceSensor ? 'The observed source was captured by the local listener.' : 'Container-only observations may show a Docker gateway address.'}</p>
      </aside>
    </div>}
  </div>
}
