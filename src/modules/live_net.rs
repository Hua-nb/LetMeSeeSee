//! 网络现场模块：当前 TCP/UDP 连接（含 PID→进程名）、DNS 解析缓存、hosts 文件。
//! 应急判断"是否有异常外联仍在进行"的第一手数据；hosts 非 localhost 映射
//! 常见于流量劫持/免杀域名固定解析（R-022）。

use crate::model::{ActivityEvent, Collector, ModuleResult, ModuleStatus, RawTable, Sev, Tag};
use serde_json::Value;
use std::time::Instant;

pub const MODULE: &str = "网络现场（连接/DNS/hosts）";

const RAW_COLS: &[&str] = &["协议", "本地", "远程", "状态", "PID", "进程"];

const HOSTS_PATH: &str = r"C:\Windows\System32\drivers\etc\hosts";

/// hosts 中默认无害条目（注释/空行/localhost 族之外都值得看一眼）
fn is_default_hosts_entry(names: &[&str]) -> bool {
    names.iter().all(|n| {
        let l = n.to_ascii_lowercase();
        l == "localhost" || l == "localhost.localdomain" || l.ends_with(".localdomain")
    })
}

/// 解析 hosts 文本 → (ip, names, 行号) 列表，排除注释与默认条目
pub fn parse_hosts_nondefault(text: &str) -> Vec<(String, Vec<String>, usize)> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let mut parts = t.split_whitespace();
        let Some(ip) = parts.next() else { continue };
        let names: Vec<String> = parts.map(|s| s.to_string()).collect();
        let refs: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
        if is_default_hosts_entry(&refs) {
            continue;
        }
        out.push((ip.to_string(), names, i + 1));
    }
    out
}

#[derive(Debug, Clone)]
pub struct ConnInfo {
    pub proto: String,
    pub local: String,
    pub remote: String,
    pub state: String,
    pub pid: u32,
}

pub fn parse_conns(json: &Value) -> Vec<ConnInfo> {
    json.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|o| {
                    Some(ConnInfo {
                        proto: o.get("Proto").and_then(|v| v.as_str()).unwrap_or("").into(),
                        local: o.get("Local").and_then(|v| v.as_str()).unwrap_or("").into(),
                        remote: o.get("Remote").and_then(|v| v.as_str()).unwrap_or("").into(),
                        state: o.get("State").and_then(|v| v.as_str()).unwrap_or("").into(),
                        pid: o.get("Pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// 值得进时间线/原表的连接：ESTABLISHED 与 LISTEN（UDP 全收，量小且无状态）
pub fn conn_worth_listing(c: &ConnInfo) -> bool {
    if c.proto.eq_ignore_ascii_case("UDP") {
        return true;
    }
    let s = c.state.to_ascii_uppercase();
    s == "ESTABLISHED" || s == "LISTEN"
}

/// 解析"协议\t本地\t远程\t状态\tPID"行（避开 PS 5.1 ConvertTo-Json 的性能坑）
pub fn parse_conn_lines(text: &str) -> Vec<ConnInfo> {
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            if f.len() < 5 {
                return None;
            }
            Some(ConnInfo {
                proto: f[0].into(),
                local: f[1].into(),
                remote: f[2].into(),
                state: f[3].into(),
                pid: f[4].parse().ok()?,
            })
        })
        .collect()
}

fn query_conns(logs: &mut Vec<String>) -> Vec<ConnInfo> {
    // Win32 API 直调（GetExtendedTcpTable + GetExtendedUdpTable）：零子进程
    match crate::winapi::enumerate_connections() {
        Ok(c) => c,
        Err(e) => {
            logs.push(format!("连接表查询失败：{e}"));
            Vec::new()
        }
    }
}

fn query_pid_names(_logs: &mut Vec<String>) -> Vec<(u32, String)> {
    // 复用 winapi 进程枚举（同一数据源，无需再起进程）
    match crate::winapi::enumerate_processes() {
        Ok(procs) => procs.into_iter().map(|p| (p.pid, p.name)).collect(),
        Err(_) => Vec::new(),
    }
}

fn query_dns_count(_logs: &mut Vec<String>) -> usize {
    crate::winapi::dns_cache_count()
}

pub struct LiveNetCollector;

impl Default for LiveNetCollector {
    fn default() -> Self {
        Self
    }
}

impl Collector for LiveNetCollector {
    fn id(&self) -> &'static str {
        MODULE
    }

    fn group(&self) -> &'static str {
        "现场快照（进程/网络）"
    }

    fn run(&self) -> ModuleResult {
        let t0 = Instant::now();
        let mut logs = Vec::new();
        let mut events = Vec::new();
        let mut rows: Vec<Vec<String>> = Vec::new();
        let mut hosts_hits = 0usize;

        // ---- hosts 文件（普通权限可读，优先级最高）----
        match std::fs::read(HOSTS_PATH) {
            Ok(b) => {
                let text = String::from_utf8_lossy(&b).into_owned();
                let entries = parse_hosts_nondefault(&text);
                let mtime = std::fs::metadata(HOSTS_PATH)
                    .ok()
                    .and_then(|m| m.modified().ok())
                    .map(|t| {
                        chrono::DateTime::<chrono::Local>::from(t)
                            .format("%Y-%m-%d %H:%M:%S.000")
                            .to_string()
                    })
                    .unwrap_or_else(|| "（无时间戳）".into());
                for (ip, names, lineno) in &entries {
                    hosts_hits += 1;
                    events.push(ActivityEvent {
                        time: mtime.clone(),
                        kind: "hosts 条目".into(),
                        desc: format!("{} {}", ip, names.join(" ")),
                        info: format!(
                            "{HOSTS_PATH} 第 {lineno} 行 · 文件修改时间 · 非 localhost 映射（劫持/免杀常见手法）"
                        ),
                        module: MODULE.into(),
                        sev: Sev::Yellow,
                        tags: vec![Tag {
                            sev: Sev::Yellow,
                            text: "R-022 hosts 文件异常条目".into(),
                        }],
                    });
                }
                logs.push(format!(
                    "hosts 非 localhost 映射 {} 条（文件修改时间 {mtime}）",
                    entries.len()
                ));
            }
            Err(e) => logs.push(format!("读取 hosts 失败：{e}")),
        }

        // ---- 连接表 + DNS 缓存（PowerShell）----
        let conns = query_conns(&mut logs);
        // 一次查询建 PID→进程名映射（逐条查询会为每条连接起一次 PowerShell，不可接受）
        let pid_names = query_pid_names(&mut logs);
        let listed = conns.iter().filter(|c| conn_worth_listing(c)).count();
        let mut established = 0usize;
        for c in conns.iter().filter(|c| conn_worth_listing(c)) {
            if c.state.eq_ignore_ascii_case("ESTABLISHED") {
                established += 1;
            }
            let name = pid_names
                .iter()
                .find(|(p, _)| *p == c.pid)
                .map(|(_, n)| n.clone())
                .unwrap_or_default();
            let target = if c.remote.is_empty() { "（任意）" } else { &c.remote };
            rows.push(vec![
                c.proto.clone(),
                c.local.clone(),
                c.remote.clone(),
                c.state.clone(),
                c.pid.to_string(),
                name.clone(),
            ]);
            // LISTEN/UDP 不进时间线（量大且多为正常服务）；ESTABLISHED 全进（外联排查核心）
            if c.state.eq_ignore_ascii_case("ESTABLISHED") {
                events.push(ActivityEvent {
                    time: "（无时间戳）".into(),
                    kind: "网络连接现场".into(),
                    desc: format!("{} → {}", c.local, target),
                    info: format!("PID {}（{}）· ESTABLISHED · 采集时刻现场", c.pid, name),
                    module: MODULE.into(),
                    sev: Sev::None,
                    tags: vec![],
                });
            }
        }
        let dns_n = query_dns_count(&mut logs);
        logs.push(format!(
            "连接 {} 条（ESTABLISHED {established}、LISTEN/UDP 其余）；DNS 缓存 {dns_n} 条（仅计数，详细用 ipconfig /displaydns 查看）",
            listed
        ));
        ModuleResult {
            module: self.id().into(),
            status: if conns.is_empty() && hosts_hits == 0 {
                ModuleStatus::Warn
            } else {
                ModuleStatus::Ok
            },
            count: events.len(),
            duration_ms: t0.elapsed().as_millis(),
            logs,
            events,
            raw: Some(RawTable {
                columns: RAW_COLS.iter().map(|s| s.to_string()).collect(),
                rows,
                refs: Vec::new(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn hosts_parsing_filters_defaults_and_comments() {
        let text = "\
# 注释
127.0.0.1 localhost
::1 localhost
1.2.3.4 update.microsoft.com edge.microsoft.com
0.0.0.0 telemetry.example.com
";
        let v = parse_hosts_nondefault(text);
        assert_eq!(v.len(), 2, "{v:?}");
        assert_eq!(v[0].0, "1.2.3.4");
        assert_eq!(v[0].1, vec!["update.microsoft.com", "edge.microsoft.com"]);
        assert_eq!(v[1].0, "0.0.0.0");
        assert_eq!(v[1].2, 5); // 行号
    }

    #[test]
    fn conns_parsed_and_filtered() {
        let v = json!([
            {"Proto":"TCP","Local":"0.0.0.0:80","Remote":"0.0.0.0:0","State":"LISTEN","Pid":4},
            {"Proto":"TCP","Local":"10.0.0.5:52100","Remote":"1.2.3.4:443","State":"ESTABLISHED","Pid":100},
            {"Proto":"TCP","Local":"10.0.0.5:52101","Remote":"5.6.7.8:80","State":"TIME_WAIT","Pid":100},
            {"Proto":"UDP","Local":"10.0.0.5:53","Remote":"","State":"","Pid":8}
        ]);
        let c = parse_conns(&v);
        assert_eq!(c.len(), 4);
        let listed: Vec<_> = c.iter().filter(|x| conn_worth_listing(x)).collect();
        assert_eq!(listed.len(), 3); // TIME_WAIT 被排除
    }

    #[test]
    fn collector_runs_gracefully() {
        let r = LiveNetCollector::default().run();
        assert!(!r.logs.is_empty());
    }
}
