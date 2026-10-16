//! Defender 防护与检出模块：
//! - 注册表现状：排除项（Paths/Processes/Extensions，本机+策略两处）、实时保护关闭
//! - 事件日志 Microsoft-Windows-Windows Defender/Operational：
//!   1116 检出 / 1117 处置 / 5001 实时保护被关闭 / 5013 排除项增删
//! 命中 → R-018。Defender 日志是存量最大、成本最低的检出数据源。

use crate::evtxdata::{data_get, event_data, event_id, event_time_raw};
use crate::model::{ActivityEvent, Collector, ModuleResult, ModuleStatus, RawTable, Sev, Tag};
use crate::timeutil::evtx_time_to_local;
use evtx::EvtxParser;
use serde_json::Value;
use std::time::Instant;

pub const MODULE: &str = "Defender 防护与检出";

const CHANNEL: &str = "Microsoft-Windows-Windows Defender/Operational";
const LIVE_PATH: &str =
    r"C:\Windows\System32\winevt\Logs\Microsoft-Windows-Windows Defender%4Operational.evtx";

const RAW_COLS: &[&str] = &["时间", "类别", "对象", "详情", "来源"];

/// 5007 配置变更是否安全相关：引擎/签名版本更新类（UpdateSignatureLastUpdated、
/// ServiceStartStates 等）是常态噪声只计数；含防护开关/排除/防篡改关键词的才进事件
pub fn is_security_relevant_config(new_val: &str) -> bool {
    let l = new_val.to_ascii_lowercase();
    ["disable", "exclusion", "realtime", "real-time", "tamper", "unload", "removal", "allow"]
        .iter()
        .any(|k| l.contains(k))
}

fn tag18(sev: Sev) -> Vec<Tag> {
    vec![Tag {
        sev,
        text: "R-018 Defender 防护异常".into(),
    }]
}

/// 单条 Defender 日志记录 → 事件（纯函数便于测试）
pub fn map_defender_event(record: &Value) -> Option<ActivityEvent> {
    let id = event_id(record)?;
    let time = evtx_time_to_local(event_time_raw(record)?)?;
    let data = event_data(record);
    match id {
        1116 | 1117 => {
            let threat = data_get(&data, "Threat Name")
                .or_else(|| data_get(&data, "ThreatName"))
                .unwrap_or("未知威胁");
            let path = data_get(&data, "Path").unwrap_or("-");
            let action = data_get(&data, "Action Name")
                .or_else(|| data_get(&data, "ActionName"))
                .unwrap_or("-");
            let severity = data_get(&data, "Severity ID").unwrap_or("-");
            Some(ActivityEvent {
                time,
                kind: if id == 1116 { "Defender 检出" } else { "Defender 处置" }.into(),
                desc: format!("检出威胁：{threat}"),
                info: format!("对象 {path} · 动作 {action} · 严重度 {severity} · Defender {id}"),
                module: MODULE.into(),
                sev: Sev::Red,
                tags: tag18(Sev::Red),
            })
        }
        5001 => Some(ActivityEvent {
            time,
            kind: "Defender 防护异常".into(),
            desc: "实时保护被关闭".into(),
            info: format!("Defender 5001 · 关闭时段内恶意文件不会被扫描 · 产品 {product}",
                product = data_get(&data, "Product Name").unwrap_or("-")),
            module: MODULE.into(),
            sev: Sev::Red,
            tags: tag18(Sev::Red),
        }),
        5013 => {
            let path = data_get(&data, "Path").or_else(|| data_get(&data, "Excluded Path")).unwrap_or("-");
            Some(ActivityEvent {
                time,
                kind: "Defender 防护异常".into(),
                desc: format!("排除项被添加：{path}"),
                info: "Defender 5013 · 排除目录内的文件不查——免杀与持久化常用动作".into(),
                module: MODULE.into(),
                sev: Sev::Red,
                tags: tag18(Sev::Red),
            })
        }
        5007 => {
            // 配置变更（如被策略/命令改动）——附 ID 以便溯源
            let new_val = data_get(&data, "New Value").unwrap_or("-");
            Some(ActivityEvent {
                time,
                kind: "Defender 防护异常".into(),
                desc: "Defender 配置被更改".into(),
                info: format!("新值 {new_val} · Defender 5007"),
                module: MODULE.into(),
                sev: Sev::Yellow,
                tags: tag18(Sev::Yellow),
            })
        }
        _ => None,
    }
}

pub struct DefenderCollector;

impl Default for DefenderCollector {
    fn default() -> Self {
        Self
    }
}

impl Collector for DefenderCollector {
    fn id(&self) -> &'static str {
        MODULE
    }

    fn group(&self) -> &'static str {
        "入侵痕迹排查"
    }

    fn run(&self) -> ModuleResult {
        let t0 = Instant::now();
        let mut logs = Vec::new();
        let mut events = Vec::new();
        let mut rows: Vec<Vec<String>> = Vec::new();

        // ---- 注册表现状：排除项（本机配置 + 策略两处；需管理员/SYSTEM 可读）----
        let mut exclusions = 0usize;
        for (root, label) in [
            (r"SOFTWARE\Microsoft\Windows Defender\Exclusions", "本机配置"),
            (r"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions", "策略（组策略下发）"),
        ] {
            for (sub, kind) in [("Paths", "路径"), ("Processes", "进程名"), ("Extensions", "扩展名")] {
                let key = format!(r"{root}\{sub}");
                if let Ok(names) = crate::regutil::value_names(
                    crate::regutil::HKEY::local_machine(),
                    &key,
                ) {
                    for n in names {
                        if n.is_empty() {
                            continue;
                        }
                        exclusions += 1;
                        let t = crate::regutil::key_last_write(
                            crate::regutil::HKEY::local_machine(),
                            &key,
                        )
                        .unwrap_or_else(|| "（无时间戳）".into());
                        events.push(ActivityEvent {
                            time: t.clone(),
                            kind: "Defender 排除项".into(),
                            desc: format!("排除{kind}：{n}"),
                            info: format!(
                                "{label} · 当前仍生效 · 排除范围内的文件不会被扫描（免杀/持久化常见）"
                            ),
                            module: MODULE.into(),
                            sev: Sev::Yellow,
                            tags: tag18(Sev::Yellow),
                        });
                        rows.push(vec![
                            t,
                            format!("排除{kind}"),
                            n,
                            "当前仍生效（排除范围内不扫描）".into(),
                            label.into(),
                        ]);
                    }
                }
            }
        }
        // 实时保护被策略关闭
        let rtp = r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection";
        if let Ok((b, _)) = crate::regutil::read_value(
            crate::regutil::HKEY::local_machine(),
            rtp,
            "DisableRealtimeMonitoring",
        ) {
            if b.len() >= 4 && u32::from_le_bytes(b[..4].try_into().unwrap()) == 1 {
                let t = crate::regutil::key_last_write(
                    crate::regutil::HKEY::local_machine(),
                    rtp,
                )
                .unwrap_or_else(|| "（无时间戳）".into());
                events.push(ActivityEvent {
                    time: t.clone(),
                    kind: "Defender 防护异常".into(),
                    desc: "实时保护被策略禁用（DisableRealtimeMonitoring=1）".into(),
                    info: "当前状态 · 该键非零即实时保护关闭".into(),
                    module: MODULE.into(),
                    sev: Sev::Red,
                    tags: tag18(Sev::Red),
                });
                rows.push(vec![
                    t,
                    "实时保护".into(),
                    "已禁用（策略）".into(),
                    "DisableRealtimeMonitoring=1".into(),
                    "当前状态".into(),
                ]);
            }
        }

        // ---- 事件日志：检出/关闭/排除项历史 ----
        let mut detections = 0usize;
        let mut parser_owned: Option<EvtxParser<std::fs::File>> = None;
        let mut tmp_copy: Option<std::path::PathBuf> = None;
        match EvtxParser::from_path(LIVE_PATH) {
            Ok(p) => {
                logs.push("直接读取 Defender 日志成功".into());
                parser_owned = Some(p);
            }
            Err(_) => {
                logs.push("直接读取失败，尝试 Win32 API 导出…".into());
                let tmp = std::env::temp_dir().join("LetMeSeeSee-Defender.evtx");
                match crate::winapi::export_event_log(CHANNEL,
                    Some("*[System[(EventID=1116 or EventID=1117 or EventID=5001 or EventID=5013 or EventID=5007)]]"),
                    tmp.to_string_lossy().as_ref()) {
                    Ok(()) => match EvtxParser::from_path(&tmp) {
                        Ok(p) => {
                            parser_owned = Some(p);
                            tmp_copy = Some(tmp);
                        }
                        Err(e) => logs.push(format!("副本解析失败：{e}")),
                    },
                    Err(e) => logs.push(format!("事件日志导出失败：{e}")),
                }
            }
        }
        if let Some(mut parser) = parser_owned {
            // 检出/处置按（威胁名, 对象路径）聚合：同一威胁反复检出（实时监控每次
            // 触碰都记一条）会产生数千条刷屏——聚合成"N 次 · 首末时间"单条；
            // 5007 配置变更按新值聚合（首选项频繁变动会产生海量记录）
            use std::collections::HashMap;
            let mut agg: HashMap<(String, String), (String, String, usize, String, String)> =
                HashMap::new(); // (first, last, count, action, severity)
            let mut cfg_agg: HashMap<String, (String, String, usize)> = HashMap::new();
            for r in parser.records_json_value() {
                match r {
                    Ok(rec) => {
                        if let Some(ev) = map_defender_event(&rec.data) {
                            if ev.kind == "Defender 检出" || ev.kind == "Defender 处置" {
                                let threat = ev
                                    .desc
                                    .strip_prefix("检出威胁：")
                                    .unwrap_or(&ev.desc)
                                    .to_string();
                                let path = ev
                                    .info
                                    .split(" · ")
                                    .next()
                                    .and_then(|s| s.strip_prefix("对象 "))
                                    .unwrap_or("-")
                                    .to_string();
                                let e = agg
                                    .entry((threat, path))
                                    .or_insert((ev.time.clone(), ev.time.clone(), 0, String::new(), String::new()));
                                e.1 = ev.time.clone();
                                e.2 += 1;
                                if ev.kind == "Defender 处置" {
                                    e.3 = "已处置".into();
                                }
                                if e.4.is_empty() {
                                    e.4 = ev
                                        .info
                                        .split(" · ")
                                        .find(|s| s.starts_with("严重度 "))
                                        .unwrap_or("")
                                        .to_string();
                                }
                                detections += 1;
                            } else if ev.desc == "Defender 配置被更改" {
                                let new_val = ev
                                    .info
                                    .strip_prefix("新值 ")
                                    .and_then(|s| s.split(" · ").next())
                                    .unwrap_or("?")
                                    .to_string();
                                let e = cfg_agg
                                    .entry(new_val)
                                    .or_insert((ev.time.clone(), ev.time.clone(), 0));
                                e.1 = ev.time.clone();
                                e.2 += 1;
                            } else {
                                events.push(ev.clone());
                                rows.push(vec![
                                    ev.time,
                                    "防护事件".into(),
                                    ev.desc,
                                    ev.info,
                                    "Defender 日志".into(),
                                ]);
                            }
                        }
                    }
                    Err(e) => logs.push(format!("记录解析失败（已跳过）：{e}")),
                }
            }
            drop(parser);
            if let Some(p) = tmp_copy {
                let _ = std::fs::remove_file(p);
            }
            let mut groups: Vec<_> = agg.into_iter().collect();
            groups.sort_by(|a, b| b.1 .2.cmp(&a.1 .2));
            for ((threat, path), (first, last, count, action, sevtxt)) in groups {
                let mut info = format!(
                    "{path} · {} 次检出（{first} ~ {last}）",
                    if count == 1 { "1".into() } else { count.to_string() }
                );
                if !action.is_empty() {
                    info.push_str(&format!(" · {action}"));
                }
                if !sevtxt.is_empty() {
                    info.push_str(&format!(" · {sevtxt}"));
                }
                info.push_str(" · Defender 1116/1117 聚合");
                events.push(ActivityEvent {
                    time: last.clone(),
                    kind: "Defender 检出".into(),
                    desc: format!("检出威胁：{threat}"),
                    info,
                    module: MODULE.into(),
                    sev: Sev::Red,
                    tags: tag18(Sev::Red),
                });
                rows.push(vec![
                    last.clone(),
                    "检出".into(),
                    path.clone(),
                    format!(
                        "{threat} · {} 次检出（{first} ~ {last}）",
                        if count == 1 { "1".into() } else { count.to_string() }
                    ),
                    "Defender 1116/1117 聚合".into(),
                ]);
            }
            let mut cfgs: Vec<_> = cfg_agg.into_iter().collect();
            cfgs.sort_by(|a, b| b.1 .2.cmp(&a.1 .2));
            // 常规配置变更（引擎/签名更新）不进事件只计数；安全相关变更保留
            let routine: usize = cfgs
                .iter()
                .filter(|(v, _)| !is_security_relevant_config(v))
                .map(|(_, c)| c.2)
                .sum();
            cfgs.retain(|(v, _)| is_security_relevant_config(v));
            if routine > 0 {
                logs.push(format!(
                    "常规配置变更（引擎/签名更新类）共 {routine} 次，未列入事件（如需全量查 Defender 日志）"
                ));
            }
            // 配置变更组上限：引擎/签名更新会产生海量唯一值，全列会淹没真正的人工改动
            const MAX_CFG_GROUPS: usize = 100;
            let cfg_total = cfgs.len();
            cfgs.truncate(MAX_CFG_GROUPS);
            if cfg_total > MAX_CFG_GROUPS {
                logs.push(format!(
                    "安全相关配置变更共 {cfg_total} 组，仅列前 {MAX_CFG_GROUPS} 组（按次数排序；全量见 Defender 日志）"
                ));
            }
            for (new_val, (first, last, count)) in cfgs {
                events.push(ActivityEvent {
                    time: last.clone(),
                    kind: "Defender 防护异常".into(),
                    desc: format!("Defender 配置被更改：{new_val}"),
                    info: format!(
                        "{count} 次变更（{first} ~ {last}） · Defender 5007 聚合 · 频繁变更需关注篡改"
                    ),
                    module: MODULE.into(),
                    sev: Sev::Yellow,
                    tags: tag18(Sev::Yellow),
                });
                rows.push(vec![
                    last.clone(),
                    "配置变更".into(),
                    new_val,
                    format!("{count} 次变更（{first} ~ {last}）"),
                    "Defender 5007 聚合".into(),
                ]);
            }
        } else {
            logs.push("Defender 日志不可读（第三方杀软接管或日志被清也会如此——结合 1102/104 判断）".into());
        }

        logs.push(format!(
            "排除项 {exclusions} 条、实时保护状态已查；日志原始检出/处置 {detections} 条 → 聚合为 {} 组；配置变更/防护事件 {} 条",
            events.iter().filter(|e| e.kind == "Defender 检出").count(),
            events.iter().filter(|e| e.kind == "Defender 防护异常").count()
        ));
        ModuleResult {
            module: self.id().into(),
            status: if events.is_empty() {
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

    fn rec(id: i64, fields: &[(&str, &str)]) -> Value {
        let mut m = serde_json::Map::new();
        for (k, v) in fields {
            m.insert(k.to_string(), json!(v));
        }
        json!({"Event":{
            "System":{
                "EventID": id,
                "TimeCreated":{"#attributes":{"SystemTime":"2026-09-22T10:00:00.000Z"}}
            },
            "EventData": m
        }})
    }

    #[test]
    fn maps_detection_1116() {
        let v = rec(1116, &[
            ("Threat Name", "Trojan:Win32/Wacatac.B!ml"),
            ("Path", r"C:\Users\Public\tool.exe"),
            ("Action Name", "隔离"),
            ("Severity ID", "5"),
        ]);
        let e = map_defender_event(&v).unwrap();
        assert_eq!(e.kind, "Defender 检出");
        assert!(e.desc.contains("Wacatac") && e.info.contains("Public"));
        assert!(e.tags.iter().any(|t| t.text.contains("R-018")));
    }

    #[test]
    fn maps_rtp_disabled_5001() {
        let v = rec(5001, &[("Product Name", "Microsoft Defender")]);
        let e = map_defender_event(&v).unwrap();
        assert_eq!(e.kind, "Defender 防护异常");
        assert!(e.desc.contains("实时保护被关闭"));
    }

    #[test]
    fn maps_exclusion_added_5013() {
        let v = rec(5013, &[("Path", r"C:\ProgramData\svc")]);
        let e = map_defender_event(&v).unwrap();
        assert!(e.desc.contains("排除项被添加") && e.desc.contains("ProgramData"));
    }

    #[test]
    fn other_ids_ignored() {
        let v = rec(2000, &[]);
        assert!(map_defender_event(&v).is_none());
    }

    #[test]
    fn config_change_classification() {
        // 常规引擎/签名更新类：不进事件
        assert!(!is_security_relevant_config("Default\\ServiceStartStates = 0x0"));
        assert!(!is_security_relevant_config("UpdateSignatureLastUpdated = 2026-09-28"));
        assert!(!is_security_relevant_config("Signature-AV = 1.405.123.0"));
        // 安全相关：保留
        assert!(is_security_relevant_config("DisableAntiSpyware = 1"));
        assert!(is_security_relevant_config("Real-Time Protection = off"));
        assert!(is_security_relevant_config("Exclusions\\Paths added"));
        assert!(is_security_relevant_config("TamperProtectionSource = 2"));
    }

    #[test]
    fn collector_degrades_gracefully() {
        let r = DefenderCollector::default().run();
        assert!(!r.logs.is_empty());
    }
}
