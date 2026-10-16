//! PowerShell 操作日志模块：Microsoft-Windows-PowerShell/Operational 4104
//! 脚本块编译事件——每个脚本块一条记录，含脚本文本（攻击命令回放的核心证据）。
//! 非管理员可读（本机实测导出 15.8MB）。

use crate::evtxdata::{data_get, event_data, event_id, event_time_raw};
use crate::model::{ActivityEvent, Collector, ModuleResult, ModuleStatus};
use crate::timeutil::evtx_time_to_local;
use evtx::EvtxParser;
use serde_json::Value;
use std::time::Instant;

pub const MODULE: &str = "PowerShell 日志（4104）";

const CHANNEL: &str = "Microsoft-Windows-PowerShell/Operational";
const LIVE_PATH: &str =
    r"C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx";

/// 4104 的 ScriptBlockText 最长 4000 字符，展示截断
const INFO_TEXT_LIMIT: usize = 400;

pub fn map_ps_event(record: &Value) -> Option<ActivityEvent> {
    if event_id(record)? != 4104 {
        return None;
    }
    let time = evtx_time_to_local(event_time_raw(record)?)?;
    let data = event_data(record);
    let path = data_get(&data, "Path").unwrap_or("");
    let block_id = data_get(&data, "ScriptBlockId").unwrap_or("?");
    let text = data_get(&data, "ScriptBlockText").unwrap_or("");
    let desc = if path.is_empty() || path == "<No File>" {
        "交互式 PowerShell 命令".to_string()
    } else {
        path.to_string()
    };
    let mut info = format!("ScriptBlockId {block_id}");
    if !text.is_empty() {
        let shown: String = if text.len() > INFO_TEXT_LIMIT {
            let cut = text
                .char_indices()
                .nth(INFO_TEXT_LIMIT)
                .map(|(i, _)| i)
                .unwrap_or(text.len());
            format!("{}…（截断）", &text[..cut])
        } else {
            text.to_string()
        };
        info = format!("{shown} · {info}");
    }
    Some(ActivityEvent::plain(time, "脚本块执行（逐次）", desc, info, MODULE))
}

pub struct PowerShellCollector;

impl Default for PowerShellCollector {
    fn default() -> Self {
        Self
    }
}

impl Collector for PowerShellCollector {
    fn id(&self) -> &'static str {
        MODULE
    }

    fn group(&self) -> &'static str {
        "PowerShell 日志（4104）"
    }

    fn run(&self) -> ModuleResult {
        let t0 = Instant::now();
        let mut logs = Vec::new();
        let mut events = Vec::new();
        let mut status = ModuleStatus::Ok;

        let mut parser_owned: Option<EvtxParser<std::fs::File>> = None;
        let mut tmp_copy: Option<std::path::PathBuf> = None;

        if let Ok(p) = EvtxParser::from_path(LIVE_PATH) {
            logs.push("直接读取 PowerShell 日志成功".into());
            parser_owned = Some(p);
        } else {
            logs.push("直接读取失败，尝试 Win32 API 导出…".into());
            let tmp = std::env::temp_dir().join("LetMeSeeSee-PowerShell.evtx");
            match crate::winapi::export_event_log(CHANNEL, Some("*[System[(EventID=4104)]]"),
                tmp.to_string_lossy().as_ref()) {
                Ok(()) => match EvtxParser::from_path(&tmp) {
                    Ok(p) => {
                        logs.push("已通过 Win32 API 导出副本解析".into());
                        parser_owned = Some(p);
                        tmp_copy = Some(tmp);
                    }
                    Err(e) => logs.push(format!("副本解析失败：{e}")),
                },
                Err(e) => logs.push(format!("事件日志导出失败：{e}")),
            }
        }

        match parser_owned {
            Some(mut parser) => {
                let mut total = 0usize;
                for r in parser.records_json_value() {
                    match r {
                        Ok(rec) => {
                            total += 1;
                            if let Some(ev) = map_ps_event(&rec.data) {
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
                logs.push(format!("共解析 {total} 条，脚本块事件 {} 条", events.len()));
                if events.is_empty() {
                    status = ModuleStatus::Warn;
                    logs.push("无 4104 事件（脚本块日志记录可能未开启）".into());
                }
            }
            None => status = ModuleStatus::Err,
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

    #[test]
    fn maps_4104_with_script_text() {
        let v = json!({"Event":{
            "System":{
                "EventID": 4104,
                "TimeCreated":{"#attributes":{"SystemTime":"2026-09-22T10:00:00.000Z"}}
            },
            "EventData":{
                "Path": "C:\\scripts\\collect.ps1",
                "ScriptBlockId": "abc123",
                "ScriptBlockText": "Get-Process | Sort-Object CPU"
            }
        }});
        let e = map_ps_event(&v).unwrap();
        assert_eq!(e.kind, "脚本块执行（逐次）");
        assert_eq!(e.desc, "C:\\scripts\\collect.ps1");
        assert!(e.info.contains("Get-Process"));
        assert!(e.info.contains("abc123"));
    }

    #[test]
    fn interactive_when_no_file() {
        let v = json!({"Event":{
            "System":{
                "EventID": 4104,
                "TimeCreated":{"#attributes":{"SystemTime":"2026-09-22T10:00:00.000Z"}}
            },
            "EventData":{"Path":"<No File>","ScriptBlockId":"x","ScriptBlockText":"whoami"}
        }});
        let e = map_ps_event(&v).unwrap();
        assert_eq!(e.desc, "交互式 PowerShell 命令");
        assert!(e.info.contains("whoami"));
    }

    #[test]
    fn other_ids_ignored() {
        let v = json!({"Event":{
            "System":{
                "EventID": 400,
                "TimeCreated":{"#attributes":{"SystemTime":"2026-09-22T10:00:00.000Z"}}
            }
        }});
        assert!(map_ps_event(&v).is_none());
    }

    #[test]
    #[ignore = "真实日志；本机 cargo test -- --ignored"]
    fn collector_reads_real_powershell_log() {
        let r = PowerShellCollector::default().run();
        assert!(r.count >= 1, "{:?}", r.logs);
    }
}
