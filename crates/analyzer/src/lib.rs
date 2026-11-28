use std::collections::{BTreeMap, HashMap, HashSet};

mod live_evtx;

use evtx::EvtxParser;
use js_sys::{Array, Reflect, Uint8Array};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

const MAX_CASE_BYTES: usize = 25 * 1024 * 1024;
const MAX_EVENTS: usize = 100_000;
const MAX_FINDINGS: usize = 500;
const BRUTE_FORCE_COUNT: usize = 5;
const SPRAY_ACCOUNTS: usize = 5;
const SPRAY_FAILURES: usize = 8;
const TEN_MINUTES: i64 = 10 * 60;
const THIRTY_MINUTES: i64 = 30 * 60;
const MAX_LIVE_EVENTS: usize = 500;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LiveEvent {
    at_ms: u64,
    source: String,
    kind: String,
    detail: String,
    port: u16,
    status: Option<u16>,
    action: Option<String>,
    actor: Option<String>,
    target: Option<String>,
    outcome: Option<String>,
    reason: Option<String>,
    user_agent: Option<String>,
    source_sensor: Option<String>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthEvent {
    timestamp: String,
    source_ip: String,
    username: String,
    actor: Option<String>,
    outcome: String,
    category: String,
    action: String,
    platform: String,
    source_file: String,
    event_id: Option<u32>,
    #[serde(skip)]
    lab: Option<LabObservation>,
    #[serde(skip_serializing)]
    epoch: Option<i64>,
}

#[derive(Clone)]
struct LabObservation {
    at_ms: Option<i64>,
    kind: String,
    detail: String,
    port: Option<u16>,
    status: Option<u16>,
    action: Option<String>,
    actor: Option<String>,
    target: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Alert {
    id: String,
    title: String,
    severity: String,
    description: String,
    source_ip: String,
    username: Option<String>,
    actor: Option<String>,
    source_files: Vec<String>,
    count: usize,
    first_seen: String,
    last_seen: String,
    technique: String,
    technique_name: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Report {
    events: Vec<AuthEvent>,
    alerts: Vec<Alert>,
    source_files: Vec<String>,
    parsed_lines: usize,
    skipped_lines: usize,
    truncated: bool,
    findings_truncated: bool,
}

#[wasm_bindgen]
pub fn export_live_evtx(events: JsValue) -> Result<Vec<u8>, JsValue> {
    let events: Vec<LiveEvent> = serde_wasm_bindgen::from_value(events)
        .map_err(|_| JsValue::from_str("Invalid live event data."))?;
    if events.len() > MAX_LIVE_EVENTS {
        return Err(JsValue::from_str(
            "The live export contains too many events.",
        ));
    }
    live_evtx::encode(&events).map_err(|_| JsValue::from_str("Could not create the EVTX file."))
}

struct InputFile {
    name: String,
    content: FileContent,
}

enum FileContent {
    Text(String),
    Bytes(Vec<u8>),
}

#[wasm_bindgen]
pub fn analyze_case(files: JsValue, year: i32) -> Result<JsValue, JsValue> {
    if !Array::is_array(&files) {
        return Err(JsValue::from_str("Choose one or more log files."));
    }
    let files = Array::from(&files);
    if files.length() == 0 {
        return Err(JsValue::from_str("Choose one or more log files."));
    }

    let mut inputs = Vec::with_capacity(files.length() as usize);
    let mut total_bytes = 0usize;
    for value in files.iter() {
        let name = Reflect::get(&value, &JsValue::from_str("name"))?
            .as_string()
            .filter(|name| !name.is_empty())
            .ok_or_else(|| JsValue::from_str("Each log file needs a name."))?;
        let content = Reflect::get(&value, &JsValue::from_str("content"))?;
        let is_evtx = name.to_ascii_lowercase().ends_with(".evtx");
        let content = if is_evtx {
            if content.is_string() || content.is_null() || content.is_undefined() {
                return Err(JsValue::from_str(
                    "Windows EVTX files must be read as binary data.",
                ));
            }
            let bytes = Uint8Array::new(&content).to_vec();
            total_bytes = total_bytes.saturating_add(bytes.len());
            FileContent::Bytes(bytes)
        } else {
            let text = content
                .as_string()
                .ok_or_else(|| JsValue::from_str("Linux log files must be read as text."))?;
            total_bytes = total_bytes.saturating_add(text.len());
            FileContent::Text(text)
        };
        if total_bytes > MAX_CASE_BYTES {
            return Err(JsValue::from_str(
                "The selected files exceed the 25 MB total case limit.",
            ));
        }
        inputs.push(InputFile { name, content });
    }

    let source_files = inputs.iter().map(|file| file.name.clone()).collect();
    let mut events = Vec::new();
    let mut skipped_lines = 0;
    let mut truncated = false;

    'files: for file in inputs {
        match file.content {
            FileContent::Text(input) => {
                for line in input.lines() {
                    if events.len() >= MAX_EVENTS {
                        truncated = true;
                        break 'files;
                    }
                    if let Some(event) = parse_linux_line(line, year, &file.name) {
                        events.push(event);
                    } else if looks_like_supported_linux_event(line) {
                        skipped_lines += 1;
                    }
                }
            }
            FileContent::Bytes(input) => {
                let mut parser = EvtxParser::from_buffer(input).map_err(|error| {
                    JsValue::from_str(&format!("Could not read {}: {error}", file.name))
                })?;
                for record in parser.records() {
                    if events.len() >= MAX_EVENTS {
                        truncated = true;
                        break 'files;
                    }
                    let Ok(record) = record else {
                        skipped_lines += 1;
                        continue;
                    };
                    match parse_evtx_record(&record.data, &file.name) {
                        Ok(Some(event)) => events.push(event),
                        Ok(None) => {}
                        Err(()) => skipped_lines += 1,
                    }
                }
            }
        }
    }

    make_report(events, source_files, skipped_lines, truncated)
}

fn parse_linux_line(line: &str, year: i32, source_file: &str) -> Option<AuthEvent> {
    parse_ssh_line(line, year, source_file)
        .or_else(|| parse_sudo_line(line, year, source_file))
        .or_else(|| parse_audit_line(line, source_file))
}

fn parse_ssh_line(line: &str, year: i32, source_file: &str) -> Option<AuthEvent> {
    let (outcome, action, rest) = if let Some(rest) = line.split_once("Failed password for ") {
        ("failed", "Failed sign-in", rest.1)
    } else if let Some(rest) = line.split_once("Accepted password for ") {
        ("success", "Successful password sign-in", rest.1)
    } else if let Some(rest) = line.split_once("Accepted publickey for ") {
        ("success", "Successful public-key sign-in", rest.1)
    } else {
        return None;
    };
    let (identity, address_part) = rest.split_once(" from ")?;
    let username = identity
        .strip_prefix("invalid user ")
        .unwrap_or(identity)
        .trim();
    let source_ip = address_part
        .split_whitespace()
        .next()?
        .trim_matches(['[', ']']);
    if username.is_empty() || source_ip.is_empty() || source_ip == "-" {
        return None;
    }
    let (timestamp, epoch) = parse_syslog_time(line, year)
        .map(|(stamp, value)| (stamp, Some(value)))
        .unwrap_or_else(|| ("Unknown time".to_string(), None));

    Some(AuthEvent {
        timestamp,
        source_ip: source_ip.to_string(),
        username: username.to_string(),
        actor: None,
        outcome: outcome.to_string(),
        category: "authentication".to_string(),
        action: action.to_string(),
        platform: "Linux".to_string(),
        source_file: source_file.to_string(),
        event_id: None,
        lab: None,
        epoch,
    })
}

fn parse_sudo_line(line: &str, year: i32, source_file: &str) -> Option<AuthEvent> {
    let (prefix, details) = line.split_once("sudo:")?;
    let (actor, details) = details.split_once(':')?;
    let actor = actor.trim();
    let target = details
        .split(';')
        .find_map(|part| part.trim().strip_prefix("USER="))?
        .trim();
    let command = details
        .split(';')
        .find_map(|part| part.trim().strip_prefix("COMMAND="))?
        .trim();
    if actor.is_empty() || command.is_empty() {
        return None;
    }
    let (timestamp, epoch) = parse_syslog_time(prefix.trim(), year)
        .map(|(stamp, value)| (stamp, Some(value)))
        .unwrap_or_else(|| ("Unknown time".to_string(), None));
    Some(AuthEvent {
        timestamp,
        source_ip: "Unknown".to_string(),
        username: target.to_string(),
        actor: Some(actor.to_string()),
        outcome: "activity".to_string(),
        category: "privilege".to_string(),
        action: format!("Sudo command as {target}: {command}"),
        platform: "Linux".to_string(),
        source_file: source_file.to_string(),
        event_id: None,
        lab: None,
        epoch,
    })
}

fn parse_audit_line(line: &str, source_file: &str) -> Option<AuthEvent> {
    let fields = parse_key_values(line);
    let record_type = fields.get("type")?;
    let (category, action, account_field) = match record_type.as_str() {
        "ADD_USER" => ("account_change", "Linux user account created", "acct"),
        "DEL_USER" => ("account_change", "Linux user account deleted", "acct"),
        "ADD_GROUP" => ("account_change", "Linux group created", "acct"),
        "DEL_GROUP" => ("account_change", "Linux group deleted", "acct"),
        "USER_CHAUTHTOK" => ("account_change", "Linux user password changed", "acct"),
        _ => return None,
    };
    let epoch = parse_audit_epoch(line)?;
    let target = fields
        .get(account_field)
        .or_else(|| fields.get("name"))
        .or_else(|| fields.get("id"))
        .map(String::as_str)
        .unwrap_or("Unknown");
    let result = fields.get("res").map(String::as_str).unwrap_or("success");
    let action = if matches!(result, "failed" | "no") {
        format!("Attempted: {action}")
    } else {
        action.to_string()
    };
    let actor = fields
        .get("auid")
        .or_else(|| fields.get("uid"))
        .filter(|value| value.as_str() != "4294967295" && value.as_str() != "-1")
        .map(|value| format!("UID {value}"));
    let source_ip = fields
        .get("addr")
        .filter(|value| !value.is_empty() && value.as_str() != "?" && value.as_str() != "-")
        .cloned()
        .unwrap_or_else(|| "Unknown".to_string());
    Some(AuthEvent {
        timestamp: format_epoch(epoch),
        source_ip,
        username: target.to_string(),
        actor,
        outcome: "activity".to_string(),
        category: category.to_string(),
        action,
        platform: "Linux".to_string(),
        source_file: source_file.to_string(),
        event_id: None,
        lab: None,
        epoch: Some(epoch),
    })
}

fn parse_key_values(input: &str) -> HashMap<String, String> {
    let mut values = parse_key_values_flat(input);
    if let Some(message) = values.get("msg") {
        if message.contains('=') && !message.starts_with("audit(") {
            values.extend(parse_key_values_flat(message));
        }
    }
    values
}

fn parse_key_values_flat(input: &str) -> HashMap<String, String> {
    let mut values = HashMap::new();
    let mut chars = input.chars().peekable();
    while chars.peek().is_some() {
        while chars.peek().is_some_and(|ch| ch.is_whitespace()) {
            chars.next();
        }
        let mut key = String::new();
        while let Some(character) = chars.peek().copied() {
            if character == '=' || character.is_whitespace() {
                break;
            }
            key.push(chars.next().unwrap_or_default());
        }
        if key.is_empty() {
            chars.next();
            continue;
        }
        if chars.peek() != Some(&'=') {
            continue;
        }
        chars.next();
        let value: String = if matches!(chars.peek(), Some('\'') | Some('"')) {
            let quote = chars.next().unwrap_or_default();
            chars.by_ref().take_while(|ch| *ch != quote).collect()
        } else {
            chars
                .by_ref()
                .take_while(|ch| !ch.is_whitespace())
                .collect()
        };
        values.insert(key, value);
    }

    values
}

fn parse_audit_epoch(line: &str) -> Option<i64> {
    let start = line.find("audit(")? + "audit(".len();
    let timestamp = line[start..].split(')').next()?;
    timestamp.split(':').next()?.split('.').next()?.parse().ok()
}

fn looks_like_supported_linux_event(line: &str) -> bool {
    line.contains("Failed password for ")
        || line.contains("Accepted password for ")
        || line.contains("Accepted publickey for ")
        || line.contains("sudo:") && line.contains("COMMAND=")
        || [
            "ADD_USER",
            "DEL_USER",
            "ADD_GROUP",
            "DEL_GROUP",
            "USER_CHAUTHTOK",
        ]
        .iter()
        .any(|kind| line.contains(&format!("type={kind}")))
}

fn parse_syslog_time(line: &str, year: i32) -> Option<(String, i64)> {
    let mut parts = line.split_whitespace();
    let month = month_number(parts.next()?)?;
    let day: u32 = parts.next()?.parse().ok()?;
    let time = parts.next()?;
    let mut clock = time.split(':');
    let hour: u32 = clock.next()?.parse().ok()?;
    let minute: u32 = clock.next()?.parse().ok()?;
    let second: u32 = clock.next()?.parse().ok()?;
    if day == 0 || day > days_in_month(year, month)? || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    Some((
        format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}"),
        civil_to_days(year, month, day) * 86_400 + (hour * 3600 + minute * 60 + second) as i64,
    ))
}

fn parse_evtx_record(xml: &str, source_file: &str) -> Result<Option<AuthEvent>, ()> {
    let document = roxmltree::Document::parse(xml).map_err(|_| ())?;
    let event_id = document
        .descendants()
        .find(|node| node.is_element() && node.tag_name().name() == "EventID")
        .and_then(|node| node.text())
        .and_then(|value| value.parse::<u32>().ok());
    let provider = document
        .descendants()
        .find(|node| node.is_element() && node.tag_name().name() == "Provider")
        .and_then(|node| node.attribute("Name"))
        .unwrap_or("");
    let authlens_live = provider == "AuthLens-LiveLab";
    let Some(event_id) = event_id.filter(|id| {
        matches!(
            *id,
            4624 | 4625 | 4672 | 4720 | 4722 | 4724 | 4725 | 4728 | 4732 | 4756
        ) || (authlens_live && matches!(*id, 1000 | 1001 | 1002))
    }) else {
        return Ok(None);
    };

    let fields: HashMap<&str, &str> = document
        .descendants()
        .filter(|node| node.is_element() && node.tag_name().name() == "Data")
        .filter_map(|node| Some((node.attribute("Name")?, node.text()?)))
        .collect();
    let get = |keys: &[&str]| {
        keys.iter()
            .find_map(|key| fields.get(key).copied())
            .filter(|value| !value.trim().is_empty() && *value != "-")
    };
    let timestamp = document
        .descendants()
        .find(|node| node.is_element() && node.tag_name().name() == "TimeCreated")
        .and_then(|node| node.attribute("SystemTime"))
        .unwrap_or("Unknown time");
    let epoch = parse_iso_time(timestamp);
    let source_ip = get(&["IpAddress", "SourceAddress"]).unwrap_or("Unknown");
    let (category, action, target, actor, outcome) = match event_id {
        1000 if authlens_live => (
            "network_activity",
            "TCP connection observed",
            get(&["DestinationPort"]),
            None,
            "activity",
        ),
        1001 if authlens_live => {
            let event_action = get(&["Action"]).unwrap_or("");
            let category = if matches!(event_action, "login_failed" | "login_success") {
                "authentication"
            } else {
                "network_activity"
            };
            let outcome = match event_action {
                "login_failed" => "failed",
                "login_success" => "success",
                _ => "activity",
            };
            (
                category,
                "HTTP request observed",
                get(&["Target"]),
                get(&["Actor"]),
                outcome,
            )
        }
        1002 if authlens_live => (
            "network_activity",
            "ICMP packet observed",
            get(&["Target"]),
            None,
            "activity",
        ),
        4624 => (
            "authentication",
            "Successful sign-in",
            get(&["TargetUserName", "SubjectUserName"]),
            None,
            "success",
        ),
        4625 => (
            "authentication",
            "Failed sign-in",
            get(&["TargetUserName", "SubjectUserName"]),
            None,
            "failed",
        ),
        4672 => (
            "privilege",
            "Special privileges assigned to logon",
            get(&["SubjectUserName"]),
            get(&["SubjectUserName"]),
            "activity",
        ),
        4720 => (
            "account_change",
            "Windows user account created",
            get(&["TargetUserName"]),
            get(&["SubjectUserName"]),
            "activity",
        ),
        4722 => (
            "account_change",
            "Windows user account enabled",
            get(&["TargetUserName"]),
            get(&["SubjectUserName"]),
            "activity",
        ),
        4724 => (
            "account_change",
            "Windows password reset attempted",
            get(&["TargetUserName"]),
            get(&["SubjectUserName"]),
            "activity",
        ),
        4725 => (
            "account_change",
            "Windows user account disabled",
            get(&["TargetUserName"]),
            get(&["SubjectUserName"]),
            "activity",
        ),
        4728 => (
            "account_change",
            "Member added to Windows global group",
            get(&["MemberName", "TargetUserName", "MemberSid"]),
            get(&["SubjectUserName"]),
            "activity",
        ),
        4732 => (
            "account_change",
            "Member added to Windows local group",
            get(&["MemberName", "TargetUserName", "MemberSid"]),
            get(&["SubjectUserName"]),
            "activity",
        ),
        4756 => (
            "account_change",
            "Member added to Windows universal group",
            get(&["MemberName", "TargetUserName", "MemberSid"]),
            get(&["SubjectUserName"]),
            "activity",
        ),
        _ => return Ok(None),
    };
    let action = match event_id {
        1000 if authlens_live => {
            format!("TCP connection: {}", get(&["Detail"]).unwrap_or("Unknown"))
        }
        1001 if authlens_live => {
            let kind = get(&["Action"]).unwrap_or("request").replace('_', " ");
            let reason = get(&["Reason"])
                .map(|reason| format!(" — {reason}"))
                .unwrap_or_default();
            format!(
                "HTTP {kind}: {} ({}){reason}",
                get(&["Detail"]).unwrap_or("Unknown"),
                get(&["ResponseStatus"]).unwrap_or("unknown status")
            )
        }
        1002 if authlens_live => format!(
            "ICMP {}: {} ({})",
            get(&["Outcome"]).unwrap_or("observed"),
            get(&["Detail"]).unwrap_or("Unknown"),
            get(&["Reason"]).unwrap_or("unknown result")
        ),
        4672 => format!(
            "Special privileges assigned: {}",
            get(&["PrivilegeList"]).unwrap_or("Unknown")
        ),
        4728 => format!(
            "Member added to global group {}",
            get(&["TargetUserName"]).unwrap_or("Unknown")
        ),
        4732 => format!(
            "Member added to local group {}",
            get(&["TargetUserName"]).unwrap_or("Unknown")
        ),
        4756 => format!(
            "Member added to universal group {}",
            get(&["TargetUserName"]).unwrap_or("Unknown")
        ),
        _ => action.to_string(),
    };
    let lab = authlens_live.then(|| LabObservation {
        at_ms: parse_iso_millis(timestamp),
        kind: match event_id {
            1000 => "connection",
            1001 => "http",
            1002 => "icmp",
            _ => "unknown",
        }
        .to_string(),
        detail: get(&["Detail"]).unwrap_or("").to_string(),
        port: get(&["DestinationPort"]).and_then(|value| value.parse().ok()),
        status: get(&["ResponseStatus"]).and_then(|value| value.parse().ok()),
        action: get(&["Action"]).map(str::to_string),
        actor: get(&["Actor"]).map(str::to_string),
        target: get(&["Target"]).map(str::to_string),
    });
    Ok(Some(AuthEvent {
        timestamp: timestamp.to_string(),
        source_ip: source_ip.to_string(),
        username: target.unwrap_or("Unknown").to_string(),
        actor: actor.map(str::to_string),
        outcome: outcome.to_string(),
        category: category.to_string(),
        action,
        platform: "Windows".to_string(),
        source_file: source_file.to_string(),
        event_id: Some(event_id),
        lab,
        epoch,
    }))
}

fn make_report(
    mut events: Vec<AuthEvent>,
    source_files: Vec<String>,
    skipped_lines: usize,
    truncated: bool,
) -> Result<JsValue, JsValue> {
    events.sort_by(|a, b| {
        a.epoch
            .cmp(&b.epoch)
            .then_with(|| a.timestamp.cmp(&b.timestamp))
    });
    let parsed_lines = events.len();
    let mut alerts = detect(&events);
    alerts.extend(detect_live_lab(&events));
    let severity_rank = |severity: &str| match severity {
        "High" => 0,
        "Medium" => 1,
        _ => 2,
    };
    alerts.sort_by(|a, b| {
        severity_rank(&a.severity)
            .cmp(&severity_rank(&b.severity))
            .then_with(|| a.first_seen.cmp(&b.first_seen))
    });
    let findings_truncated = alerts.len() > MAX_FINDINGS;
    alerts.truncate(MAX_FINDINGS);
    serde_wasm_bindgen::to_value(&Report {
        events,
        alerts,
        source_files,
        parsed_lines,
        skipped_lines,
        truncated,
        findings_truncated,
    })
    .map_err(|error| JsValue::from_str(&format!("Could not format analysis results: {error}")))
}

fn detect(events: &[AuthEvent]) -> Vec<Alert> {
    let mut by_account: BTreeMap<(&str, &str), Vec<&AuthEvent>> = BTreeMap::new();
    let mut by_source: BTreeMap<&str, Vec<&AuthEvent>> = BTreeMap::new();
    for event in events {
        if event.category == "authentication"
            && event.lab.is_none()
            && event.outcome == "failed"
            && event.source_ip != "Unknown"
            && event.epoch.is_some()
        {
            by_account
                .entry((&event.source_ip, &event.username))
                .or_default()
                .push(event);
            by_source.entry(&event.source_ip).or_default().push(event);
        }
    }

    let mut alerts = Vec::new();
    for ((source_ip, username), failures) in &by_account {
        if let Some(window) = first_window(failures, BRUTE_FORCE_COUNT, TEN_MINUTES) {
            alerts.push(Alert {
                id: format!("brute-{source_ip}-{username}"),
                title: "Repeated login failures".to_string(),
                severity: "High".to_string(),
                description: format!(
                    "{} failed sign-ins targeted {username} from {source_ip} within 10 minutes.",
                    window.len()
                ),
                source_ip: (*source_ip).to_string(),
                username: Some((*username).to_string()),
                actor: None,
                source_files: source_files_for(window.iter().copied()),
                count: window.len(),
                first_seen: window
                    .first()
                    .map(|event| event.timestamp.clone())
                    .unwrap_or_default(),
                last_seen: window
                    .last()
                    .map(|event| event.timestamp.clone())
                    .unwrap_or_default(),
                technique: "T1110".to_string(),
                technique_name: "Brute Force".to_string(),
            });
        }
    }

    for (source_ip, failures) in &by_source {
        if let Some(window) = first_spray_window(failures) {
            let accounts: HashSet<&str> =
                window.iter().map(|event| event.username.as_str()).collect();
            alerts.push(Alert {
                id: format!("spray-{source_ip}"),
                title: "Possible password spray".to_string(),
                severity: "High".to_string(),
                description: format!(
                    "{} failed sign-ins touched {} accounts from {source_ip} within 10 minutes.",
                    window.len(),
                    accounts.len()
                ),
                source_ip: (*source_ip).to_string(),
                username: None,
                actor: None,
                source_files: source_files_for(window.iter().copied()),
                count: window.len(),
                first_seen: window
                    .first()
                    .map(|event| event.timestamp.clone())
                    .unwrap_or_default(),
                last_seen: window
                    .last()
                    .map(|event| event.timestamp.clone())
                    .unwrap_or_default(),
                technique: "T1110.003".to_string(),
                technique_name: "Password Spraying".to_string(),
            });
        }
    }

    for ((source_ip, username), failures) in &by_account {
        let success = events.iter().find(|event| {
            event.category == "authentication"
                && event.lab.is_none()
                && event.outcome == "success"
                && event.source_ip == *source_ip
                && event.username == *username
                && event.epoch.is_some_and(|success_time| {
                    failures.iter().any(|failure| {
                        failure.epoch.is_some_and(|failed_time| {
                            failed_time <= success_time
                                && success_time - failed_time <= THIRTY_MINUTES
                        })
                    })
                })
        });
        if let Some(success) = success {
            let related_failures: Vec<_> = failures
                .iter()
                .filter(|failure| {
                    failure.epoch.is_some_and(|failed_time| {
                        success.epoch.is_some_and(|success_time| {
                            failed_time <= success_time
                                && success_time - failed_time <= THIRTY_MINUTES
                        })
                    })
                })
                .collect();
            alerts.push(Alert {
                id: format!("success-after-failures-{source_ip}-{username}"),
                title: "Successful login after failures".to_string(),
                severity: "Medium".to_string(),
                description: format!("A successful sign-in for {username} from {source_ip} followed one or more failures within 30 minutes."),
                source_ip: (*source_ip).to_string(),
                username: Some((*username).to_string()),
                actor: None,
                source_files: source_files_for(
                    related_failures
                        .iter()
                        .map(|event| **event)
                        .chain(std::iter::once(success)),
                ),
                count: related_failures.len(),
                first_seen: related_failures.first().map(|event| event.timestamp.clone()).unwrap_or_default(),
                last_seen: success.timestamp.clone(),
                technique: "T1110".to_string(),
                technique_name: "Brute Force".to_string(),
            });
        }
    }

    for (index, event) in events.iter().enumerate().filter(|(_, event)| {
        event.category == "account_change"
            && event.outcome == "activity"
            && !event.action.starts_with("Attempted:")
            && (event.action.ends_with("user account created")
                || event.action.ends_with("group created")
                || event.action.starts_with("Member added to "))
    }) {
        let (technique, technique_name) = if event.action.starts_with("Member added to ") {
            ("T1098.007", "Additional Local or Domain Groups")
        } else if event.action.ends_with("user account created") {
            ("T1136", "Create Account")
        } else {
            ("", "Account management activity")
        };
        let actor_text = event
            .actor
            .as_deref()
            .map(|actor| format!(" by {actor}"))
            .unwrap_or_default();
        alerts.push(Alert {
            id: format!("account-change-{index}"),
            title: event.action.clone(),
            severity: "Info".to_string(),
            description: format!(
                "{}{} was observed in {}.",
                event.action, actor_text, event.source_file
            ),
            source_ip: event.source_ip.clone(),
            username: Some(event.username.clone()),
            actor: event.actor.clone(),
            source_files: vec![event.source_file.clone()],
            count: 1,
            first_seen: event.timestamp.clone(),
            last_seen: event.timestamp.clone(),
            technique: technique.to_string(),
            technique_name: technique_name.to_string(),
        });
    }
    alerts
}

fn detect_live_lab(events: &[AuthEvent]) -> Vec<Alert> {
    let mut by_source: BTreeMap<&str, Vec<&AuthEvent>> = BTreeMap::new();
    for event in events {
        if event.lab.is_some() && event.epoch.is_some() {
            by_source
                .entry(event.source_ip.as_str())
                .or_default()
                .push(event);
        }
    }

    let mut alerts = Vec::new();
    for (source, source_events) in by_source {
        if source == "Unknown" {
            continue;
        }

        let mut scan: Option<(i64, Vec<&AuthEvent>, Vec<u16>)> = None;
        for anchor in source_events.iter().copied().filter(|event| {
            event
                .lab
                .as_ref()
                .is_some_and(|lab| lab.kind == "connection")
        }) {
            let Some(at_ms) = anchor.lab.as_ref().and_then(|lab| lab.at_ms) else {
                continue;
            };
            let window: Vec<_> = source_events
                .iter()
                .copied()
                .filter(|event| {
                    let Some(lab) = event.lab.as_ref() else {
                        return false;
                    };
                    lab.kind == "connection"
                        && lab
                            .at_ms
                            .is_some_and(|time| time <= at_ms && at_ms - time <= 30_000)
                })
                .collect();
            let mut ports: Vec<_> = window
                .iter()
                .filter_map(|event| event.lab.as_ref()?.port)
                .collect();
            ports.sort_unstable();
            ports.dedup();
            if ports.len() >= 4
                && scan
                    .as_ref()
                    .is_none_or(|(seen_at, _, _)| at_ms >= *seen_at)
            {
                scan = Some((at_ms, window, ports));
            }
        }
        if let Some((_, window, ports)) = scan {
            let count = ports.len();
            alerts.push(live_alert(
                format!("live-scan-{source}"),
                "Possible TCP connect scan",
                "Medium",
                format!("{count} distinct lab ports in 30 seconds: {ports:?}"),
                source,
                None,
                None,
                &window,
                count,
                "T1046",
                "Network Service Discovery",
            ));
        }

        let mut blocked_echoes: Option<(i64, Vec<&AuthEvent>)> = None;
        for anchor in source_events.iter().copied().filter(|event| {
            event.lab.as_ref().is_some_and(|lab| {
                lab.kind == "icmp" && lab.action.as_deref() == Some("icmp_echo_request_blocked")
            })
        }) {
            let Some(at_ms) = anchor.lab.as_ref().and_then(|lab| lab.at_ms) else {
                continue;
            };
            let window: Vec<_> = source_events
                .iter()
                .copied()
                .filter(|event| {
                    let Some(lab) = event.lab.as_ref() else {
                        return false;
                    };
                    lab.kind == "icmp"
                        && lab.action.as_deref() == Some("icmp_echo_request_blocked")
                        && lab
                            .at_ms
                            .is_some_and(|time| time <= at_ms && at_ms - time <= 10_000)
                })
                .collect();
            if window.len() >= 5
                && blocked_echoes
                    .as_ref()
                    .is_none_or(|(seen_at, _)| at_ms >= *seen_at)
            {
                blocked_echoes = Some((at_ms, window));
            }
        }
        if let Some((_, window)) = blocked_echoes {
            let count = window.len();
            alerts.push(live_alert(
                format!("live-icmp-{source}"),
                "Repeated blocked ICMP echo requests",
                "Medium",
                format!("{count} echo requests dropped by Windows Firewall in 10 seconds"),
                source,
                None,
                None,
                &window,
                count,
                "T1018",
                "Remote System Discovery",
            ));
        }

        let http_events: Vec<_> = source_events
            .iter()
            .copied()
            .filter(|event| event.lab.as_ref().is_some_and(|lab| lab.kind == "http"))
            .collect();
        let mut rapid: Option<(i64, Vec<&AuthEvent>)> = None;
        let mut recon: Option<(i64, Vec<&AuthEvent>, usize, Vec<String>)> = None;
        let mut enumeration: Option<(i64, Vec<&AuthEvent>, HashSet<String>)> = None;
        for anchor in http_events.iter().copied() {
            let Some(at_ms) = anchor.lab.as_ref().and_then(|lab| lab.at_ms) else {
                continue;
            };
            let recent: Vec<_> = http_events
                .iter()
                .copied()
                .filter(|event| {
                    event
                        .lab
                        .as_ref()
                        .and_then(|lab| lab.at_ms)
                        .is_some_and(|time| time <= at_ms && at_ms - time <= 10_000)
                })
                .collect();
            if recent.len() >= 12 && rapid.as_ref().is_none_or(|(seen_at, _)| at_ms >= *seen_at) {
                rapid = Some((at_ms, recent.clone()));
            }

            if recent.len() >= 12 {
                let paths = probe_paths(&recent);
                let methods: HashSet<_> = recent
                    .iter()
                    .filter_map(|event| {
                        let lab = event.lab.as_ref()?;
                        (lab.status == Some(405))
                            .then(|| {
                                lab.detail
                                    .split_once(' ')
                                    .map(|(method, _)| method.to_string())
                            })
                            .flatten()
                    })
                    .collect();
                if (paths.len() >= 6 || methods.len() >= 2)
                    && recon.as_ref().is_none_or(|(seen_at, ..)| at_ms >= *seen_at)
                {
                    recon = Some((at_ms, recent, paths.len(), methods.into_iter().collect()));
                }
            }

            let minute_window: Vec<_> = http_events
                .iter()
                .copied()
                .filter(|event| {
                    event
                        .lab
                        .as_ref()
                        .and_then(|lab| lab.at_ms)
                        .is_some_and(|time| time <= at_ms && at_ms - time <= 60_000)
                })
                .collect();
            let paths = probe_paths(&minute_window);
            if paths.len() >= 6
                && enumeration
                    .as_ref()
                    .is_none_or(|(seen_at, ..)| at_ms >= *seen_at)
            {
                enumeration = Some((at_ms, minute_window, paths));
            }
        }

        if let Some((_, window)) = rapid {
            let count = window.len();
            alerts.push(live_alert(
                format!("live-http-burst-{source}"),
                "Rapid web probing",
                "Medium",
                format!("{count} HTTP requests in 10 seconds"),
                source,
                None,
                None,
                &window,
                count,
                "T1595",
                "Active Scanning",
            ));
        }
        if let Some((_, window, path_count, methods)) = recon {
            let count = window.len();
            alerts.push(live_alert(
                format!("live-web-recon-{source}"),
                "Possible web reconnaissance burst",
                "High",
                format!(
                    "{count} requests in 10 seconds; {path_count} distinct missing or login-gated paths; methods rejected with 405: {}",
                    if methods.is_empty() { "none".to_string() } else { methods.join(", ") }
                ),
                source,
                None,
                None,
                &window,
                count,
                "T1595.003",
                "Wordlist Scanning",
            ));
        }
        if let Some((_, window, paths)) = enumeration {
            let count = paths.len();
            alerts.push(live_alert(
                format!("live-path-enum-{source}"),
                "Possible web path enumeration",
                "Medium",
                format!("{count} distinct missing or login-gated paths in 60 seconds"),
                source,
                None,
                None,
                &window,
                count,
                "T1595.003",
                "Wordlist Scanning",
            ));
        }

        let mut login_failure_finding: Option<(i64, Vec<&AuthEvent>, &str)> = None;
        let mut login_followup: Option<(i64, Vec<&AuthEvent>, &str)> = None;
        for anchor in http_events.iter().copied().filter(|event| {
            event.lab.as_ref().is_some_and(|lab| {
                matches!(
                    lab.action.as_deref(),
                    Some("login_failed" | "login_success")
                )
            })
        }) {
            let Some(at_ms) = anchor.lab.as_ref().and_then(|lab| lab.at_ms) else {
                continue;
            };
            let failures: Vec<_> = http_events
                .iter()
                .copied()
                .filter(|event| {
                    let Some(lab) = event.lab.as_ref() else {
                        return false;
                    };
                    lab.detail == "POST /login"
                        && lab.status == Some(401)
                        && lab.action.as_deref() == Some("login_failed")
                        && lab
                            .at_ms
                            .is_some_and(|time| time <= at_ms && at_ms - time <= 600_000)
                })
                .collect();
            if failures.len() < 5 {
                continue;
            }
            let action = anchor
                .lab
                .as_ref()
                .and_then(|lab| lab.action.as_deref())
                .unwrap_or("");
            if action == "login_failed"
                && login_failure_finding
                    .as_ref()
                    .is_none_or(|(seen_at, ..)| at_ms >= *seen_at)
            {
                let account = anchor
                    .lab
                    .as_ref()
                    .and_then(|lab| lab.actor.as_deref())
                    .unwrap_or("unknown");
                login_failure_finding = Some((at_ms, failures, account));
            } else if action == "login_success"
                && login_followup
                    .as_ref()
                    .is_none_or(|(seen_at, ..)| at_ms >= *seen_at)
            {
                let mut related = failures;
                related.push(anchor);
                let account = anchor
                    .lab
                    .as_ref()
                    .and_then(|lab| lab.actor.as_deref())
                    .unwrap_or("unknown");
                login_followup = Some((at_ms, related, account));
            }
        }
        if let Some((_, window, latest_account)) = login_failure_finding {
            let count = window.len();
            alerts.push(live_alert(
                format!("live-bank-login-{source}"),
                "Repeated bank sign-in failures",
                "Medium",
                format!("{count} failed sign-ins from this observed source in 10 minutes; latest attempted account: {latest_account}"),
                source,
                None,
                Some(latest_account.to_string()),
                &window,
                count,
                "T1110.001",
                "Password Guessing",
            ));
        }
        if let Some((_, window, account)) = login_followup {
            let count = window.len();
            alerts.push(live_alert(
                format!("live-bank-followup-{source}"),
                "Bank sign-in after repeated failures",
                "High",
                format!(
                    "Account {account} signed in after {} failures from this observed source",
                    count.saturating_sub(1)
                ),
                source,
                Some(account.to_string()),
                Some(account.to_string()),
                &window,
                count,
                "T1078",
                "Valid Accounts",
            ));
        }

        let mut seen_access = HashSet::new();
        for event in http_events.iter().copied().filter(|event| {
            event
                .lab
                .as_ref()
                .is_some_and(|lab| lab.action.as_deref() == Some("cross_account_read"))
        }) {
            let lab = event.lab.as_ref().expect("filtered live event");
            let actor = lab.actor.as_deref().unwrap_or("unknown");
            let target = lab.target.as_deref().unwrap_or("unknown");
            let key = format!("{actor}:{target}");
            if seen_access.insert(key) {
                alerts.push(live_alert(
                    format!("live-cross-account-{source}-{actor}-{target}"),
                    "Cross-account statement access",
                    "High",
                    format!("{actor} read {target} despite different account ownership"),
                    source,
                    None,
                    Some(actor.to_string()),
                    &[event],
                    1,
                    "",
                    "Access-control activity",
                ));
            }
        }
    }
    alerts
}

fn probe_paths(events: &[&AuthEvent]) -> HashSet<String> {
    events
        .iter()
        .filter_map(|event| {
            let lab = event.lab.as_ref()?;
            let is_probe = lab.status == Some(404)
                || (lab.status == Some(302)
                    && lab.action.as_deref() == Some("authentication_required"));
            is_probe
                .then(|| lab.detail.split_once(' ').map(|(_, path)| path.to_string()))
                .flatten()
        })
        .collect()
}

fn live_alert(
    id: String,
    title: &str,
    severity: &str,
    description: String,
    source: &str,
    username: Option<String>,
    actor: Option<String>,
    events: &[&AuthEvent],
    count: usize,
    technique: &str,
    technique_name: &str,
) -> Alert {
    Alert {
        id,
        title: title.to_string(),
        severity: severity.to_string(),
        description,
        source_ip: source.to_string(),
        username,
        actor,
        source_files: source_files_for(events.iter().copied()),
        count,
        first_seen: events
            .first()
            .map_or_else(String::new, |event| event.timestamp.clone()),
        last_seen: events
            .last()
            .map_or_else(String::new, |event| event.timestamp.clone()),
        technique: technique.to_string(),
        technique_name: technique_name.to_string(),
    }
}

fn source_files_for<'a>(events: impl IntoIterator<Item = &'a AuthEvent>) -> Vec<String> {
    let mut seen = HashSet::new();
    events
        .into_iter()
        .filter_map(|event| {
            seen.insert(event.source_file.clone())
                .then(|| event.source_file.clone())
        })
        .collect()
}

fn first_window<'a>(
    events: &[&'a AuthEvent],
    minimum: usize,
    seconds: i64,
) -> Option<Vec<&'a AuthEvent>> {
    events.windows(minimum).find_map(|candidate| {
        let first = candidate.first()?.epoch?;
        let last = candidate.last()?.epoch?;
        (last - first <= seconds).then(|| candidate.to_vec())
    })
}

fn first_spray_window<'a>(events: &[&'a AuthEvent]) -> Option<Vec<&'a AuthEvent>> {
    for start in 0..events.len() {
        let first = events[start].epoch?;
        let mut accounts = HashSet::new();
        for end in start..events.len() {
            let event = events[end];
            if event.epoch? - first > TEN_MINUTES {
                break;
            }
            accounts.insert(event.username.as_str());
            if end - start + 1 >= SPRAY_FAILURES && accounts.len() >= SPRAY_ACCOUNTS {
                return Some(events[start..=end].to_vec());
            }
        }
    }
    None
}

fn month_number(month: &str) -> Option<u32> {
    [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ]
    .iter()
    .position(|name| *name == month)
    .map(|index| index as u32 + 1)
}

fn days_in_month(year: i32, month: u32) -> Option<u32> {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => Some(31),
        4 | 6 | 9 | 11 => Some(30),
        2 if year % 400 == 0 || year % 4 == 0 && year % 100 != 0 => Some(29),
        2 => Some(28),
        _ => None,
    }
}

fn parse_iso_time(value: &str) -> Option<i64> {
    let date_time = value.split_once('T')?;
    let mut date = date_time.0.split('-');
    let year: i32 = date.next()?.parse().ok()?;
    let month: u32 = date.next()?.parse().ok()?;
    let day: u32 = date.next()?.parse().ok()?;
    if day == 0 || day > days_in_month(year, month)? {
        return None;
    }
    let time = date_time.1;
    let digits: String = time
        .chars()
        .take_while(|ch| ch.is_ascii_digit() || *ch == ':')
        .collect();
    let mut clock = digits.split(':');
    let hour: u32 = clock.next()?.parse().ok()?;
    let minute: u32 = clock.next()?.parse().ok()?;
    let second: u32 = clock.next()?.parse().ok()?;
    let offset_start = time.find(|character| character == '+' || character == '-');
    let offset = offset_start
        .and_then(|index| {
            let sign = if time.as_bytes()[index] == b'+' {
                1
            } else {
                -1
            };
            let mut parts = time[index + 1..].split(':');
            Some(
                sign * (parts.next()?.parse::<i64>().ok()? * 3600
                    + parts.next()?.get(..2)?.parse::<i64>().ok()? * 60),
            )
        })
        .unwrap_or(0);
    Some(
        civil_to_days(year, month, day) * 86_400 + (hour * 3600 + minute * 60 + second) as i64
            - offset,
    )
}

fn parse_iso_millis(value: &str) -> Option<i64> {
    let seconds = parse_iso_time(value)?;
    let fraction = if let Some((_, fraction)) = value.split_once('.') {
        let digits: String = fraction
            .chars()
            .take_while(|character| character.is_ascii_digit())
            .take(3)
            .collect();
        if digits.is_empty() {
            0
        } else {
            digits.parse::<i64>().ok()? * 10_i64.pow((3 - digits.len()) as u32)
        }
    } else {
        0
    };
    Some(seconds * 1_000 + fraction)
}

fn format_epoch(epoch: i64) -> String {
    let days = epoch.div_euclid(86_400) + 719_468;
    let seconds = epoch.rem_euclid(86_400);
    let era = days.div_euclid(146_097);
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_part = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_part + 2) / 5 + 1;
    let month = month_part + if month_part < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        seconds / 3_600,
        seconds % 3_600 / 60,
        seconds % 60
    )
}

fn civil_to_days(year: i32, month: u32, day: u32) -> i64 {
    let year = year - i32::from(month <= 2);
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let adjusted_month = month as i32 + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * adjusted_month + 2) / 5 + day as i32 - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    (era * 146_097 + day_of_era - 719_468) as i64
}
