use std::collections::{BTreeMap, HashMap, HashSet};

use evtx::EvtxParser;
use serde::Serialize;
use wasm_bindgen::prelude::*;

const MAX_INPUT_BYTES: usize = 25 * 1024 * 1024;
const MAX_EVENTS: usize = 100_000;
const BRUTE_FORCE_COUNT: usize = 5;
const SPRAY_ACCOUNTS: usize = 5;
const SPRAY_FAILURES: usize = 8;
const TEN_MINUTES: i64 = 10 * 60;
const THIRTY_MINUTES: i64 = 30 * 60;

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthEvent {
    timestamp: String,
    source_ip: String,
    username: String,
    outcome: String,
    platform: String,
    event_id: Option<u32>,
    #[serde(skip_serializing)]
    epoch: Option<i64>,
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
    parsed_lines: usize,
    skipped_lines: usize,
    truncated: bool,
}

#[wasm_bindgen]
pub fn analyze_auth_log(input: &str, year: i32) -> Result<JsValue, JsValue> {
    check_size(input.len())?;
    let mut events = Vec::new();
    let mut skipped_lines = 0;
    let mut truncated = false;

    for line in input.lines() {
        if events.len() >= MAX_EVENTS {
            truncated = true;
            break;
        }
        if let Some(event) = parse_ssh_line(line, year) {
            events.push(event);
        } else if line.contains("sshd[")
            && (line.contains("Failed password")
                || line.contains("Accepted password")
                || line.contains("Accepted publickey"))
        {
            skipped_lines += 1;
        }
    }

    make_report(events, skipped_lines, truncated)
}

#[wasm_bindgen]
pub fn analyze_evtx(input: &[u8]) -> Result<JsValue, JsValue> {
    check_size(input.len())?;
    let mut parser = EvtxParser::from_buffer(input.to_vec())
        .map_err(|error| JsValue::from_str(&format!("Could not read this EVTX file: {error}")))?;
    let mut events = Vec::new();
    let mut skipped_lines = 0;
    let mut truncated = false;

    for record in parser.records() {
        if events.len() >= MAX_EVENTS {
            truncated = true;
            break;
        }
        let Ok(record) = record else {
            skipped_lines += 1;
            continue;
        };
        match parse_evtx_record(&record.data) {
            Ok(Some(event)) => events.push(event),
            Ok(None) => {}
            Err(()) => skipped_lines += 1,
        }
    }

    make_report(events, skipped_lines, truncated)
}

fn check_size(size: usize) -> Result<(), JsValue> {
    if size > MAX_INPUT_BYTES {
        Err(JsValue::from_str(
            "File is larger than the 25 MB per-file limit.",
        ))
    } else {
        Ok(())
    }
}

fn parse_ssh_line(line: &str, year: i32) -> Option<AuthEvent> {
    let (outcome, rest) = if let Some(rest) = line.split_once("Failed password for ") {
        ("failed", rest.1)
    } else if let Some(rest) = line.split_once("Accepted password for ") {
        ("success", rest.1)
    } else if let Some(rest) = line.split_once("Accepted publickey for ") {
        ("success", rest.1)
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
        outcome: outcome.to_string(),
        platform: "Linux".to_string(),
        event_id: None,
        epoch,
    })
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

fn parse_evtx_record(xml: &str) -> Result<Option<AuthEvent>, ()> {
    let document = roxmltree::Document::parse(xml).map_err(|_| ())?;
    let event_id = document
        .descendants()
        .find(|node| node.is_element() && node.tag_name().name() == "EventID")
        .and_then(|node| node.text())
        .and_then(|value| value.parse::<u32>().ok());
    let Some(event_id @ (4624 | 4625)) = event_id else {
        return Ok(None);
    };

    let fields: HashMap<&str, &str> = document
        .descendants()
        .filter(|node| node.is_element() && node.tag_name().name() == "Data")
        .filter_map(|node| Some((node.attribute("Name")?, node.text()?)))
        .collect();
    let username = fields
        .get("TargetUserName")
        .or_else(|| fields.get("SubjectUserName"))
        .copied()
        .unwrap_or("Unknown")
        .trim();
    let source_ip = fields.get("IpAddress").copied().unwrap_or("Unknown").trim();
    let timestamp = document
        .descendants()
        .find(|node| node.is_element() && node.tag_name().name() == "TimeCreated")
        .and_then(|node| node.attribute("SystemTime"))
        .unwrap_or("Unknown time");
    let epoch = parse_iso_time(timestamp);

    Ok(Some(AuthEvent {
        timestamp: timestamp.to_string(),
        source_ip: if source_ip.is_empty() || source_ip == "-" {
            "Unknown".to_string()
        } else {
            source_ip.to_string()
        },
        username: if username.is_empty() || username == "-" {
            "Unknown".to_string()
        } else {
            username.to_string()
        },
        outcome: if event_id == 4625 {
            "failed"
        } else {
            "success"
        }
        .to_string(),
        platform: "Windows".to_string(),
        event_id: Some(event_id),
        epoch,
    }))
}

fn make_report(
    mut events: Vec<AuthEvent>,
    skipped_lines: usize,
    truncated: bool,
) -> Result<JsValue, JsValue> {
    events.sort_by(|a, b| {
        a.epoch
            .cmp(&b.epoch)
            .then_with(|| a.timestamp.cmp(&b.timestamp))
    });
    let parsed_lines = events.len();
    let alerts = detect(&events);
    serde_wasm_bindgen::to_value(&Report {
        events,
        alerts,
        parsed_lines,
        skipped_lines,
        truncated,
    })
    .map_err(|error| JsValue::from_str(&format!("Could not format analysis results: {error}")))
}

fn detect(events: &[AuthEvent]) -> Vec<Alert> {
    let mut by_account: BTreeMap<(&str, &str), Vec<&AuthEvent>> = BTreeMap::new();
    let mut by_source: BTreeMap<&str, Vec<&AuthEvent>> = BTreeMap::new();
    for event in events {
        if event.outcome == "failed" && event.source_ip != "Unknown" && event.epoch.is_some() {
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
            event.outcome == "success"
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
                count: related_failures.len(),
                first_seen: related_failures
                    .first()
                    .map(|event| event.timestamp.clone())
                    .unwrap_or_default(),
                last_seen: success.timestamp.clone(),
                technique: "T1110".to_string(),
                technique_name: "Brute Force".to_string(),
            });
        }
    }
    alerts.sort_by(|a, b| a.first_seen.cmp(&b.first_seen));
    alerts
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

fn civil_to_days(year: i32, month: u32, day: u32) -> i64 {
    let year = year - i32::from(month <= 2);
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let adjusted_month = month as i32 + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * adjusted_month + 2) / 5 + day as i32 - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    (era * 146097 + day_of_era - 719468) as i64
}
