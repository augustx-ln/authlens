use axum::{
    Json, Router,
    extract::{ConnectInfo, State},
    http::{HeaderMap, HeaderValue, Request, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashSet, VecDeque},
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::net::TcpListener;
use tower_http::services::{ServeDir, ServeFile};

type Shared = Arc<Mutex<LabState>>;
const PORTS: std::ops::RangeInclusive<u16> = 8081..=8087;
const MAX_EVENTS: usize = 500;
const MAX_FINDINGS: usize = 100;

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Event {
    at_ms: u64,
    source: String,
    kind: &'static str,
    detail: String,
    port: u16,
    status: Option<u16>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Finding {
    id: String,
    title: &'static str,
    severity: &'static str,
    source: String,
    evidence: String,
    first_ms: u64,
    last_ms: u64,
    count: usize,
}

#[derive(Default)]
struct LabState {
    events: VecDeque<Event>,
    findings: VecDeque<Finding>,
    total_events: u64,
    started_ms: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Snapshot {
    events: Vec<Event>,
    findings: Vec<Finding>,
    total_events: u64,
    target_url: String,
}

#[derive(Deserialize)]
struct IngestEvent {
    source: String,
    method: String,
    path: String,
    status: u16,
    action: Option<String>,
}

async fn ingest(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(input): Json<IngestEvent>,
) -> StatusCode {
    let Ok(token) = std::env::var("LAB_INGEST_TOKEN") else {
        return StatusCode::SERVICE_UNAVAILABLE;
    };
    if token.len() < 32
        || headers.get("x-lab-token").and_then(|v| v.to_str().ok()) != Some(token.as_str())
    {
        return StatusCode::UNAUTHORIZED;
    }
    if input.source.parse::<IpAddr>().is_err()
        || input.method.len() > 12
        || input.path.len() > 180
        || !input.path.starts_with('/')
        || input.status < 100
        || input.status > 599
        || !input.method.bytes().all(|c| c.is_ascii_uppercase())
        || input.path.chars().any(char::is_control)
    {
        return StatusCode::BAD_REQUEST;
    }
    let event = Event {
        at_ms: now_ms(),
        source: input.source,
        kind: "http",
        detail: format!("{} {}", input.method, input.path),
        port: 8080,
        status: Some(input.status),
    };
    let mut lab = state.lock().expect("lab state mutex poisoned");
    lab.record(event.clone());
    if matches!(
        input.action.as_deref(),
        Some("login_failed" | "login_success")
    ) {
        let failures = lab
            .events
            .iter()
            .filter(|item| {
                item.source == event.source
                    && item.detail == "POST /login"
                    && item.status == Some(401)
                    && event.at_ms.saturating_sub(item.at_ms) <= 600_000
            })
            .count();
        if failures >= 5 {
            if input.action.as_deref() == Some("login_failed") {
                lab.upsert(
                    format!("bank-login:{}", event.source),
                    "Repeated bank sign-in failures",
                    "Medium",
                    &event,
                    format!("{failures} failed sign-ins from this observed source in 10 minutes"),
                    failures,
                );
            } else {
                lab.upsert(
                    format!("bank-followup:{}", event.source),
                    "Bank sign-in after repeated failures",
                    "High",
                    &event,
                    format!(
                        "A sign-in succeeded after {failures} failures from this observed source"
                    ),
                    failures + 1,
                );
            }
        }
    }
    if input.action.as_deref() == Some("cross_account_read") {
        lab.upsert(
            format!("bank-access:{}", event.source),
            "Cross-account statement access",
            "High",
            &event,
            "A customer session read another synthetic customer's statement".to_owned(),
            1,
        );
    }
    StatusCode::NO_CONTENT
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before 1970")
        .as_millis() as u64
}

impl LabState {
    fn record(&mut self, event: Event) {
        // shortcut: Docker Desktop probes published TCP ports at startup; ignore the first ten seconds.
        if event.kind == "connection"
            && self.started_ms != 0
            && event.at_ms.saturating_sub(self.started_ms) < 10_000
        {
            return;
        }
        self.total_events += 1;
        self.events.push_front(event.clone());
        self.events.truncate(MAX_EVENTS);

        if event.kind == "connection" {
            let recent: Vec<_> = self
                .events
                .iter()
                .filter(|item| {
                    item.source == event.source
                        && item.kind == "connection"
                        && event.at_ms.saturating_sub(item.at_ms) <= 30_000
                })
                .collect();
            let mut ports: Vec<_> = recent.iter().map(|item| item.port).collect();
            ports.sort_unstable();
            ports.dedup();
            if ports.len() >= 4 {
                self.upsert(
                    format!("ports:{}", event.source),
                    "Possible TCP connect scan",
                    "Medium",
                    &event,
                    format!(
                        "{} distinct lab ports in 30 seconds: {ports:?}",
                        ports.len()
                    ),
                    ports.len(),
                );
            }
        } else if event.kind == "http" {
            let recent: Vec<_> = self
                .events
                .iter()
                .filter(|item| {
                    item.source == event.source
                        && item.kind == "http"
                        && event.at_ms.saturating_sub(item.at_ms) <= 10_000
                })
                .collect();
            let requests = recent.len();
            let missing_paths: HashSet<_> = recent
                .iter()
                .filter(|item| item.status == Some(404))
                .filter_map(|item| item.detail.split_once(' ').map(|(_, path)| path.to_owned()))
                .collect();
            let unusual_methods: HashSet<_> = recent
                .iter()
                .filter(|item| item.status == Some(405))
                .filter_map(|item| {
                    item.detail
                        .split_once(' ')
                        .map(|(method, _)| method.to_owned())
                })
                .collect();
            drop(recent);
            if requests >= 12 {
                self.upsert(
                    format!("http-burst:{}", event.source),
                    "Rapid web probing",
                    "Medium",
                    &event,
                    format!("{requests} HTTP requests in 10 seconds"),
                    requests,
                );

                if missing_paths.len() >= 6 || unusual_methods.len() >= 2 {
                    self.upsert(
                        format!("web-recon:{}", event.source),
                        "Possible web reconnaissance burst",
                        "High",
                        &event,
                        format!(
                            "{requests} requests in 10 seconds; {} distinct missing paths; methods rejected with 405: {}",
                            missing_paths.len(),
                            if unusual_methods.is_empty() { "none".to_owned() } else { unusual_methods.into_iter().collect::<Vec<_>>().join(", ") },
                        ),
                        requests,
                    );
                }
            }

            let paths: HashSet<_> = self
                .events
                .iter()
                .filter(|item| {
                    item.source == event.source
                        && item.kind == "http"
                        && item.status == Some(404)
                        && event.at_ms.saturating_sub(item.at_ms) <= 60_000
                })
                .filter_map(|item| item.detail.split_once(' ').map(|(_, path)| path))
                .collect();
            if paths.len() >= 6 {
                self.upsert(
                    format!("paths:{}", event.source),
                    "Possible web path enumeration",
                    "Medium",
                    &event,
                    format!("{} distinct missing paths in 60 seconds", paths.len()),
                    paths.len(),
                );
            }
        }
    }

    fn fingerprint(&mut self, event: &Event, reason: &str) {
        self.upsert(
            format!("fingerprint:{}", event.source),
            "Possible web fingerprinting",
            "Info",
            event,
            reason.to_owned(),
            1,
        );
    }

    fn upsert(
        &mut self,
        id: String,
        title: &'static str,
        severity: &'static str,
        event: &Event,
        evidence: String,
        count: usize,
    ) {
        if let Some(index) = self.findings.iter().position(|item| item.id == id) {
            let mut finding = self.findings.remove(index).expect("finding exists");
            finding.last_ms = event.at_ms;
            finding.evidence = evidence;
            finding.count = count;
            self.findings.push_front(finding);
        } else {
            self.findings.push_front(Finding {
                id,
                title,
                severity,
                source: event.source.clone(),
                evidence,
                first_ms: event.at_ms,
                last_ms: event.at_ms,
                count,
            });
            self.findings.truncate(MAX_FINDINGS);
        }
    }

    fn snapshot(&self) -> Snapshot {
        Snapshot {
            events: self.events.iter().cloned().collect(),
            findings: self.findings.iter().cloned().collect(),
            total_events: self.total_events,
            target_url: std::env::var("LAB_TARGET_URL").unwrap_or_else(|_| {
                format!(
                    "http://{}:8080/",
                    std::env::var("LAB_BIND_IP").unwrap_or_else(|_| "localhost".to_owned())
                )
            }),
        }
    }
}

async fn snapshot(State(state): State<Shared>) -> impl IntoResponse {
    let data = state.lock().expect("lab state mutex poisoned").snapshot();
    (
        [(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))],
        Json(data),
    )
}

async fn track_http(
    State(state): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let path = request.uri().path().chars().take(180).collect::<String>();
    let method = request.method().as_str().to_ascii_uppercase();
    let user_agent = request
        .headers()
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .chars()
        .take(180)
        .collect::<String>();
    let response = next.run(request).await;
    let event = Event {
        at_ms: now_ms(),
        source: peer.ip().to_string(),
        kind: "http",
        detail: format!("{method} {path}"),
        port: 8080,
        status: Some(response.status().as_u16()),
    };
    let mut lab = state.lock().expect("lab state mutex poisoned");
    lab.record(event.clone());
    let agent = user_agent.to_ascii_lowercase();
    let path_lower = path.to_ascii_lowercase();
    let known_tool = [
        "nmap",
        "nikto",
        "whatweb",
        "nuclei",
        "gobuster",
        "dirbuster",
        "ffuf",
    ]
    .iter()
    .find(|tool| agent.contains(**tool));
    let known_path = [
        "/.git/",
        "/.env",
        "/wp-admin",
        "/wp-login.php",
        "/xmlrpc.php",
        "/server-status",
        "/phpinfo.php",
        "/actuator/",
        "/swagger",
        "/openapi.json",
        "/graphql",
        "/vendor/phpunit",
        "/config.json",
        "/backup.zip",
        "/api-docs",
        "/.aws/",
        "/.htaccess",
        "/server-status",
        "/admin.php",
        "/credentials",
    ]
    .iter()
    .find(|probe| path_lower.starts_with(**probe));
    let traversal = path_lower.contains("../")
        || path_lower.contains("..%2f")
        || path_lower.contains("%2e%2e")
        || path_lower.contains("%252e%252e");
    if let Some(tool) = known_tool {
        lab.fingerprint(&event, &format!("Tool signature in User-Agent: {tool}"));
    } else if let Some(probe) = known_path {
        lab.fingerprint(
            &event,
            &format!("Common fingerprint path requested: {probe}"),
        );
    } else if traversal {
        lab.fingerprint(&event, "Path contains a directory traversal pattern");
    } else if matches!(
        method.as_str(),
        "OPTIONS" | "TRACE" | "CONNECT" | "DEBUG" | "PUT" | "DELETE" | "PATCH"
    ) {
        lab.fingerprint(&event, &format!("Uncommon HTTP method requested: {method}"));
    }
    response
}

async fn target_home() -> Html<&'static str> {
    Html(include_str!("target.html"))
}

async fn target_missing() -> StatusCode {
    StatusCode::NOT_FOUND
}

async fn listen_probe(listener: TcpListener, port: u16, state: Shared) -> std::io::Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        state
            .lock()
            .expect("lab state mutex poisoned")
            .record(Event {
                at_ms: now_ms(),
                source: peer.ip().to_string(),
                kind: "connection",
                detail: format!("TCP connection to lab port {port}"),
                port,
                status: None,
            });
        drop(stream);
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let state = Arc::new(Mutex::new(LabState {
        started_ms: now_ms(),
        ..LabState::default()
    }));
    for port in PORTS {
        let listener = TcpListener::bind(("0.0.0.0", port)).await?;
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(error) = listen_probe(listener, port, state).await {
                eprintln!("Lab port {port} stopped: {error}");
            }
        });
    }

    let target = Router::new()
        .route("/", get(target_home))
        .route(
            "/robots.txt",
            get(|| async { "User-agent: *\nDisallow: /admin\n" }),
        )
        .route(
            "/api/health",
            get(|| async { Json(serde_json::json!({"status":"ok"})) }),
        )
        .fallback(target_missing)
        .layer(middleware::from_fn_with_state(state.clone(), track_http))
        .with_state(state.clone());
    let target_listener = TcpListener::bind("0.0.0.0:8080").await?;
    tokio::spawn(async move {
        if let Err(error) = axum::serve(
            target_listener,
            target.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        {
            eprintln!("Target web server stopped: {error}");
        }
    });

    let dist = std::env::var("AUTHLENS_WEB_DIST").unwrap_or_else(|_| "web/dist".to_owned());
    let monitor = Router::new()
        .route("/api/live", get(snapshot))
        .route("/api/lab-event", post(ingest))
        .route_service("/monitor", ServeFile::new(format!("{dist}/index.html")))
        .route_service(
            "/favicon.svg",
            ServeFile::new(format!("{dist}/favicon.svg")),
        )
        .nest_service("/assets", ServeDir::new(format!("{dist}/assets")))
        .with_state(state);
    let monitor_listener = TcpListener::bind("0.0.0.0:3000").await?;
    println!("AuthLens lab monitor: http://localhost:3000/monitor");
    axum::serve(monitor_listener, monitor).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(
        at_ms: u64,
        source: &str,
        kind: &'static str,
        detail: &str,
        port: u16,
        status: Option<u16>,
    ) -> Event {
        Event {
            at_ms,
            source: source.into(),
            kind,
            detail: detail.into(),
            port,
            status,
        }
    }

    #[test]
    fn scan_requires_four_distinct_ports_from_one_source_in_window() {
        let mut lab = LabState::default();
        for port in 8081..=8083 {
            lab.record(event(1_000, "192.0.2.1", "connection", "", port, None));
        }
        lab.record(event(1_000, "192.0.2.2", "connection", "", 8084, None));
        lab.record(event(1_000, "192.0.2.1", "connection", "", 8081, None));
        assert!(lab.findings.is_empty());
        lab.record(event(2_000, "192.0.2.1", "connection", "", 8084, None));
        assert_eq!(lab.findings[0].count, 4);
        lab.record(event(40_000, "192.0.2.3", "connection", "", 8085, None));
        assert_eq!(lab.findings.len(), 1);
    }

    #[test]
    fn path_enumeration_counts_distinct_missing_paths_only() {
        let mut lab = LabState::default();
        for n in 0..5 {
            lab.record(event(
                1_000,
                "192.0.2.1",
                "http",
                &format!("GET /bad/{n}"),
                8080,
                Some(404),
            ));
        }
        lab.record(event(
            1_000,
            "192.0.2.1",
            "http",
            "GET /bad/0",
            8080,
            Some(404),
        ));
        lab.record(event(
            1_000,
            "192.0.2.2",
            "http",
            "GET /bad/5",
            8080,
            Some(404),
        ));
        assert!(lab.findings.is_empty());
        lab.record(event(
            2_000,
            "192.0.2.1",
            "http",
            "GET /bad/5",
            8080,
            Some(404),
        ));
        assert_eq!(lab.findings[0].title, "Possible web path enumeration");
    }

    #[test]
    fn startup_probe_connections_are_ignored() {
        let mut lab = LabState {
            started_ms: 1_000,
            ..LabState::default()
        };
        for port in 8081..=8087 {
            lab.record(event(2_000, "192.0.2.1", "connection", "", port, None));
        }
        assert!(lab.findings.is_empty());
        assert!(lab.events.is_empty());
        for port in 8081..=8084 {
            lab.record(event(11_001, "192.0.2.1", "connection", "", port, None));
        }
        assert_eq!(lab.findings[0].title, "Possible TCP connect scan");
    }
}
