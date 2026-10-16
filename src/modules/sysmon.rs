//! Sysmon 日志模块（demo）：检测并解析 Microsoft-Windows-Sysmon/Operational。
//! 事件 1=进程创建（命令行/父进程/哈希——IOC 哈希比对的最佳数据源）、
//! 3=网络连接（目标 IP:端口 + 发起进程映像）。
//! 未安装 Sysmon 属常态 → 如实说明并正常返回（非错误）；
//! LMSS_SYSMON_EVTX 环境变量可指向导出的样本 evtx（离线/演示用）。

use crate::evtxdata::{data_get, event_data, event_id, event_time_raw};
use crate::model::{ActivityEvent, Collector, ModuleResult, ModuleStatus};
use crate::timeutil::evtx_time_to_local;
use evtx::EvtxParser;
use serde_json::Value;
use std::time::Instant;

pub const MODULE: &str = "Sysmon 日志";

const CHANNEL: &str = "Microsoft-Windows-Sysmon/Operational";
const LIVE_PATH: &str =
    r"C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx";

/// 解析条数上限（Sysmon 日志可能数百万条；demo 先到量为止，后续可做时间窗口）
const MAX_EVENTS: usize = 20000;

/// 单条 Sysmon 记录 → 事件（时间取记录的 TimeCreated，非 UtcTime 字段——同源且已含毫秒）
pub fn map_sysmon_event(record: &Value) -> Option<ActivityEvent> {
    let id = event_id(record)?;
    let time = evtx_time_to_local(event_time_raw(record)?)?;
    let data = event_data(record);
    match id {
        1 => {
            let image = data_get(&data, "Image").unwrap_or("?");
            let cmdline = data_get(&data, "CommandLine").unwrap_or("");
            let parent = data_get(&data, "ParentImage").unwrap_or("");
            let hashes = data_get(&data, "Hashes").unwrap_or("");
            let user = data_get(&data, "User").unwrap_or("");
            Some(ActivityEvent::plain(
                time,
                "Sysmon 进程创建",
                image.to_string(),
                format!(
                    "命令行 {cmdline} · 父 {parent}{}{hashes} · Sysmon 1",
                    if user.is_empty() {
                        String::new()
                    } else {
                        format!(" · 用户 {user}")
                    },
                )
                .trim_start_matches("命令行  · ")
                .to_string(),
                MODULE,
            ))
        }
        3 => {
            let image = data_get(&data, "Image").unwrap_or("?");
            let ip = data_get(&data, "DestinationIp").unwrap_or("?");
            let port = data_get(&data, "DestinationPort").unwrap_or("?");
            let proto = data_get(&data, "Protocol").unwrap_or("tcp");
            Some(ActivityEvent::plain(
                time,
                "Sysmon 网络连接",
                image.to_string(),
                format!("连接 {ip}:{port}（{proto}） · Sysmon 3"),
                MODULE,
            ))
        }
        _ => None,
    }
}

pub struct SysmonCollector;

impl Default for SysmonCollector {
    fn default() -> Self {
        Self
    }
}

impl Collector for SysmonCollector {
    fn id(&self) -> &'static str {
        MODULE
    }

    fn group(&self) -> &'static str {
        "Sysmon 日志"
    }

    fn run(&self) -> ModuleResult {
        let t0 = Instant::now();
        let mut logs = Vec::new();
        let mut events = Vec::new();
        let mut status = ModuleStatus::Ok;

        let path = std::env::var("LMSS_SYSMON_EVTX")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| std::path::PathBuf::from(LIVE_PATH));

        let mut parser_owned: Option<EvtxParser<std::fs::File>> = None;
        let mut tmp_copy: Option<std::path::PathBuf> = None;

        match EvtxParser::from_path(&path) {
            Ok(p) => {
                logs.push(if path != std::path::Path::new(LIVE_PATH) {
                    format!("读取样本文件 {}（LMSS_SYSMON_EVTX）", path.display())
                } else {
                    "检测到 Sysmon 日志，直接读取成功".into()
                });
                parser_owned = Some(p);
            }
            Err(_) => {
                // 活动文件不存在（未装 Sysmon）或被锁：尝试 Win32 API 导出
                let tmp = std::env::temp_dir().join("LetMeSeeSee-Sysmon.evtx");
                match crate::winapi::export_event_log(CHANNEL,
                    Some("*[System[(EventID=1 or EventID=3)]]"),
                    tmp.to_string_lossy().as_ref()) {
                    Ok(()) => match EvtxParser::from_path(&tmp) {
                        Ok(p) => {
                            logs.push("已通过 Win32 API 导出副本解析".into());
                            parser_owned = Some(p);
                            tmp_copy = Some(tmp);
                        }
                        Err(e) => logs.push(format!("副本解析失败：{e}")),
                    },
                    _ => {
                        logs.push(
                            "未检测到 Sysmon（通道不存在）——本模块无数据。安装 Sysmon 可获得带命令行与哈希的进程创建/网络连接日志，质量远超默认审计"
                                .into(),
                        );
                    }
                }
            }
        }

        if let Some(mut parser) = parser_owned {
            let mut total = 0usize;
            let mut truncated = false;
            for r in parser.records_json_value() {
                match r {
                    Ok(rec) => {
                        total += 1;
                        if events.len() >= MAX_EVENTS {
                            truncated = true;
                            break;
                        }
                        // 注：Sysmon 事件 1 曾投递进程树种子；进程树已定稿为
                        // "仅当前存活进程"现场视图（2026-09-28 用户反馈），
                        // 历史创建事件只进时间线
                        if let Some(ev) = map_sysmon_event(&rec.data) {
                            events.push(ev);
                        }
                    }
                    Err(e) => logs.push(format!("记录解析失败（已跳过）：{e}")),
                }
            }
            drop(parser);
            if let Some(p) = tmp_copy {
                let _ = std::fs::remove_file(p);
            }
            logs.push(format!(
                "共解析 {total} 条记录（事件 1/3 命中 {} 条{}）",
                events.len(),
                if truncated {
                    format!("，已达 {MAX_EVENTS} 条上限，更早记录未解析")
                } else {
                    String::new()
                }
            ));
            if events.is_empty() {
                status = ModuleStatus::Warn;
            }
        }
        ModuleResult {
            module: self.id().into(),
            status,
            count: events.len(),
            duration_ms: t0.elapsed().as_millis(),
            logs,
            events,
            raw: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn rec(id: i64, fields: &[(&str, &str)]) -> Value {
        let mut m = serde_json::Map::new();
        for (k, v) in fields {
            m.insert(k.to_string(), json!(v));
        }
        json!({"Event":{
            "System":{
                "EventID": id,
                "TimeCreated":{"#attributes":{"SystemTime":"2026-09-28T02:31:36.944Z"}}
            },
            "EventData": m
        }})
    }

    #[test]
    fn maps_process_create_with_hash_and_parent() {
        let v = rec(1, &[
            ("Image", r"C:\Users\Public\svc.exe"),
            ("CommandLine", r"svc.exe -k"),
            ("ParentImage", r"C:\Windows\explorer.exe"),
            ("Hashes", "SHA1=AABBCC,MD5=1122"),
            ("User", r"WS\alice"),
        ]);
        let e = map_sysmon_event(&v).unwrap();
        assert_eq!(e.kind, "Sysmon 进程创建");
        assert_eq!(e.desc, r"C:\Users\Public\svc.exe");
        assert!(e.info.contains("svc.exe -k") && e.info.contains("AABBCC") && e.info.contains("explorer.exe"));
        assert_eq!(e.time, "2026-09-28 10:31:36.944"); // UTC+8 本机
    }

    #[test]
    fn maps_network_connect() {
        let v = rec(3, &[
            ("Image", r"C:\Windows\System32\curl.exe"),
            ("DestinationIp", "1.2.3.4"),
            ("DestinationPort", "443"),
            ("Protocol", "tcp"),
        ]);
        let e = map_sysmon_event(&v).unwrap();
        assert_eq!(e.kind, "Sysmon 网络连接");
        assert_eq!(e.desc, r"C:\Windows\System32\curl.exe");
        assert!(e.info.contains("1.2.3.4:443"));
    }

    #[test]
    fn other_ids_ignored() {
        assert!(map_sysmon_event(&rec(5, &[("Image", "x.exe")])).is_none());
    }

    #[test]
    fn collector_absent_sysmon_is_ok() {
        let r = SysmonCollector::default().run();
        assert!(!r.logs.is_empty());
        matches!(r.status, ModuleStatus::Ok | ModuleStatus::Warn);
    }
}
