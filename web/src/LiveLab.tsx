import { useEffect, useState } from 'react'
import './LiveLab.css'

type LiveEvent = {
  atMs: number
  source: string
  kind: 'connection' | 'http'
  detail: string
  port: number
  status: number | null
}

type Finding = {
  id: string
  title: string
  severity: 'Medium' | 'Info'
  source: string
  evidence: string
  firstMs: number
  lastMs: number
  count: number
}

type Snapshot = {
  events: LiveEvent[]
  findings: Finding[]
  totalEvents: number
  targetUrl: string
}

const formatTime = (value: number) => new Intl.DateTimeFormat('en', {
  hour: '2-digit', minute: '2-digit', second: '2-digit',
}).format(value)

export default function LiveLab() {
  const [data, setData] = useState<Snapshot | null>(null)
  const [connected, setConnected] = useState(false)

  useEffect(() => {
    let active = true
    const refresh = async () => {
      try {
        const response = await fetch('/api/live', { cache: 'no-store' })
        if (!response.ok) throw new Error(`Monitor returned ${response.status}`)
        const next = await response.json() as Snapshot
        if (active) {
          setData(next)
          setConnected(true)
        }
      } catch {
        if (active) setConnected(false)
      }
    }
    void refresh()
    const timer = window.setInterval(() => void refresh(), 1500)
    return () => { active = false; window.clearInterval(timer) }
  }, [])

  const targetUrl = data?.targetUrl ?? 'Waiting for target address…'
  const latest = data?.events.slice(0, 100) ?? []

  return <div className="live-shell">
    <header className="live-topbar">
      <div className="live-brand"><span className="live-brand-mark">◇</span><strong>auth<span>lens</span></strong><span className="live-tag">DOCKER LAB</span></div>
      <a href="https://augustx-ln.github.io/authlens/" target="_blank" rel="noreferrer">File analysis ↗</a>
    </header>
    <main className="live-main">
      <div className="live-heading">
        <div><p className="live-kicker">LIVE DETECTION</p><h1>Watch the lab target</h1><p>Connections and web requests from your Kali VM appear here as they arrive.</p></div>
        <span className={`live-status ${connected ? 'is-connected' : ''}`} role="status"><i />{connected ? 'Monitoring live' : 'Connecting…'}</span>
      </div>
      <div className="live-target"><div><span>TARGET</span><strong>{targetUrl}</strong><small>Ports 8080–8087 · TCP connect scans and HTTP probes</small></div>{data && <a href={targetUrl} target="_blank" rel="noreferrer">Open target ↗</a>}</div>
      <div className="live-metrics">
        <div><span>Observed activity</span><strong>{(data?.totalEvents ?? 0).toLocaleString()}</strong><small>Since container start</small></div>
        <div><span>Findings</span><strong>{data?.findings.length ?? 0}</strong><small>Patterns to review</small></div>
        <div><span>Recent sources</span><strong>{new Set(data?.events.map(event => event.source)).size}</strong><small>Up to 500 latest events</small></div>
      </div>
      <section className="live-panel">
        <div className="live-panel-heading"><div><span className="live-kicker">DETECTION RESULTS</span><h2>Findings</h2></div><span>{data?.findings.length ?? 0}</span></div>
        {data?.findings.length ? <div className="live-findings">{data.findings.map(finding => <article key={finding.id}><div><span className={`live-severity ${finding.severity.toLowerCase()}`}>{finding.severity}</span><h3>{finding.title}</h3><p>{finding.evidence}</p></div><div className="live-finding-meta"><strong>{finding.source}</strong><span>First {formatTime(finding.firstMs)} · Latest {formatTime(finding.lastMs)}</span></div></article>)}</div> : <div className="live-empty">No scan patterns yet. Open the target or run the lab commands from Kali to see activity.</div>}
      </section>
      <section className="live-panel">
        <div className="live-panel-heading"><div><span className="live-kicker">EVENT STREAM</span><h2>Latest activity</h2></div><span>{latest.length.toLocaleString()} shown</span></div>
        <div className="live-table-scroll" role="region" aria-label="Latest live events" tabIndex={0}><table><thead><tr><th>Time</th><th>Source</th><th>Type</th><th>Request / connection</th><th>Result</th></tr></thead><tbody>{latest.length ? latest.map((event, index) => <tr key={`${event.atMs}-${event.source}-${index}`}><td>{formatTime(event.atMs)}</td><td>{event.source}</td><td>{event.kind === 'http' ? 'HTTP' : 'TCP'}</td><td>{event.detail}</td><td>{event.status ?? 'Accepted'}</td></tr>) : <tr><td colSpan={5} className="live-empty-cell">Waiting for traffic to the lab target.</td></tr>}</tbody></table></div>
      </section>
      <p className="live-footnote">Findings indicate patterns to investigate, not proof of a specific tool. Monitor data stays in container memory and clears when the container restarts.</p>
    </main>
  </div>
}
