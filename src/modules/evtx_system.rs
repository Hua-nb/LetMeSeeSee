use crate::evtxdata::{data_get, event_data, event_id, event_time_raw, provider_name};
use crate::model::ActivityEvent;
use crate::model::{Collector, ModuleResult, ModuleStatus};
use crate::timeutil::evtx_time_to_local;
use evtx::EvtxParser;
use serde_json::Value;
use std::path::PathBuf;
use std::time::Instant;

pub const MODULE: &str = "事件日志（系统/应用/网络）";

/// 采集通道清单：System + 无线 + 网络配置（睡眠/唤醒在 System 通道内）
pub struct ChannelDesc {
    pub name: &'static str,
    pub path: &'static str,
    /// wevtutil 导出时的事件 ID 过滤（XPath）：只导需要的事件，量缩几十倍
    pub query: Option<&'static str>,
}

pub const CHANNELS: &[ChannelDesc] = &[
    ChannelDesc {
        name: "System",
        path: r"C:\Windows\System32\winevt\Logs\System.evtx",
        query: Some("*[System[(EventID=6005 or EventID=6006 or EventID=6008 or EventID=42 or EventID=107 or EventID=104 or EventID=7045)]]"),
    },
    ChannelDesc {
        name: "Microsoft-Windows-WLAN-AutoConfig/Operational",
        path: r"C:\Windows\System32\winevt\Logs\Microsoft-Windows-WLAN-AutoConfig%4Operational.evtx",
        query: Some("*[System[(EventID=8001 or EventID=8003)]]"),
    },
    ChannelDesc {
        name: "Microsoft-Windows-NetworkProfile/Operational",
        path: r"C:\Windows\System32\winevt\Logs\Microsoft-Windows-NetworkProfile%4Operational.evtx",
        query: Some("*[System[(EventID=10000 or EventID=10001)]]"),
    },
    ChannelDesc {
        name: "Application",
        path: r"C:\Windows\System32\winevt\Logs\Application.evtx",
        query: Some("*[System[(EventID=1000 or EventID=1001 or EventID=1002 or EventID=1033 or EventID=1035 or EventID=11707 or EventID=11724)]]"),
    },
    ChannelDesc {
        name: "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
        path: r"C:\Windows\System32\winevt\Logs\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx",
        query: Some("*[System[(EventID=21 or EventID=23 or EventID=24 or EventID=25)]]"),
    },
    ChannelDesc {
        // TaskScheduler 运行日志：任务文件可被攻击者删除，注册/触发留痕在此
        name: "Microsoft-Windows-TaskScheduler/Operational",
        path: r"C:\Windows\System32\winevt\Logs\Microsoft-Windows-TaskScheduler%4Operational.evtx",
        query: Some("*[System[(EventID=106 or EventID=107 or EventID=141 or EventID=201)]]"),
    },
];

pub struct EvtxSystemCollector {
    pub path: PathBuf,
    /// 测试环境变量覆盖仅作用于 System 通道
    pub channel: &'static str,
}

impl Default for EvtxSystemCollector {
    fn default() -> Self {
        let path = std::env::var("LMSS_SYSTEM_EVTX")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(r"C:\Windows\System32\winevt\Logs\System.evtx"));
        Self {
            path,
            channel: "System",
        }
    }
}

/// 打开解析器：优先直接读活动文件；被权限拒绝时降级为 wevtutil 导出副本
/// 返回 (解析器, 副本路径)——副本路径非 None 时调用方用完需清理
fn open_parser(
    path: &PathBuf,
    channel: &str,
    query: Option<&str>,
    logs: &mut Vec<String>,
) -> Option<(EvtxParser<std::fs::File>, Option<PathBuf>)> {
    match EvtxParser::from_path(path) {
        Ok(p) => {
            logs.push("直接读取活动日志成功".into());
            return Some((p, None));
        }
        Err(e) => logs.push(format!("直接读取失败（{e}），尝试 wevtutil 导出副本…")),
    }
    let tmp = std::env::temp_dir().join(format!(
        "LetMeSeeSee-{}.evtx",
        channel.replace('/', "_")
    ));
    match crate::winapi::export_event_log(
        channel,
        query,
        tmp.to_string_lossy().as_ref(),
    ) {
        Ok(()) => match EvtxParser::from_path(&tmp) {
            Ok(p) => {
                logs.push(format!(
                    "已按事件ID过滤导出并解析（{}）",
                    byte_size(tmp.metadata().map(|m| m.len()).unwrap_or(0))
                ));
                return Some((p, Some(tmp)));
            }
            Err(e) => logs.push(format!("副本打开失败：{e}")),
        },
        Err(e) => logs.push(format!("事件日志导出失败：{e}")),
    }
    None
}

fn byte_size(n: u64) -> String {
    if n >= 1024 * 1024 {
        format!("{:.1} MB", n as f64 / 1048576.0)
    } else {
        format!("{n} B")
    }
}

impl Collector for EvtxSystemCollector {
    fn id(&self) -> &'static str {
        MODULE
    }

    fn group(&self) -> &'static str {
        "系统与软件事件"
    }

    fn run(&self) -> ModuleResult {
        let t0 = Instant::now();
        let mut logs = Vec::new();
        let mut events = Vec::new();
        let mut status = ModuleStatus::Ok;
        let mut any_channel_ok = false;

        for ch in CHANNELS {
            // 测试覆盖：LMSS_SYSTEM_EVTX 仅替换 System 通道的路径
            let path: PathBuf = if ch.name == "System" && std::env::var_os("LMSS_SYSTEM_EVTX").is_some() {
                self.path.clone()
            } else {
                PathBuf::from(ch.path)
            };
            let mut ch_events = 0usize;
            if !path.exists() {
                logs.push(format!("[{}] 日志文件不存在，尝试 wevtutil 导出…", ch.name));
            }
            if let Some((mut parser, tmp_copy)) = open_parser(&path, ch.name, ch.query, &mut logs) {
                any_channel_ok = true;
                let mut total = 0usize;
                for r in parser.records_json_value() {
                    match r {
                        Ok(rec) => {
                            total += 1;
                            if let Some(ev) = map_event(&rec.data) {
                                events.push(ev);
                                ch_events += 1;
                            }
                        }
                        Err(e) => logs.push(format!("[{}] 记录解析失败（已跳过）：{e}", ch.name)),
                    }
                }
                drop(parser);
                if let Some(p) = tmp_copy {
                    let _ = std::fs::remove_file(p);
                }
                logs.push(format!("[{}] 共解析 {total} 条，命中 {ch_events} 条", ch.name));
            }
        }
        if !any_channel_ok {
            status = ModuleStatus::Err;
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

/// 单条 evtx 记录 → 时间线事件（纯函数，不碰文件）。按 Provider+EventID 分派。
pub fn map_event(record: &Value) -> Option<ActivityEvent> {
    let id = event_id(record)?;
    let raw_time = event_time_raw(record)?;
    let time = evtx_time_to_local(raw_time)?;
    let data = event_data(record);
    let provider = provider_name(record).unwrap_or("");
    // 无线与网络通道按提供者优先判定
    if provider.contains("WLAN-AutoConfig") {
        let ssid = data_get(&data, "Name")
            .or_else(|| data_get(&data, "SSID"))
            .unwrap_or("未知");
        return match id {
            8001 => Some(ActivityEvent::plain(
                time,
                "无线网络连接",
                format!("无线网络已连接 \"{ssid}\""),
                "WLAN-AutoConfig 8001".into(),
                MODULE,
            )),
            8003 => Some(ActivityEvent::plain(
                time,
                "无线网络断开",
                format!("无线网络已断开 \"{ssid}\""),
                "WLAN-AutoConfig 8003".into(),
                MODULE,
            )),
            _ => None,
        };
    }
    if provider.contains("NetworkProfile") {
        let name = data_get(&data, "Name").unwrap_or("未知");
        let desc = data_get(&data, "Description").unwrap_or("");
        return match id {
            10000 => Some(ActivityEvent::plain(
                time,
                "网络连接",
                format!("网络已连接 \"{name}\""),
                format!("NetworkProfile 10000 · {desc}"),
                MODULE,
            )),
            10001 => Some(ActivityEvent::plain(
                time,
                "网络断开",
                format!("网络已断开 \"{name}\""),
                "NetworkProfile 10001".into(),
                MODULE,
            )),
            _ => None,
        };
    }
    // Application 通道：应用崩溃（1000）、挂起（1002）、Windows Installer
    if provider.contains("Application Error")
        || provider.contains("Windows Error Reporting")
        || provider.contains("Application Hang")
    {
        if id == 1000 || id == 1001 {
            let app = data_get(&data, "AppName")
                .or_else(|| data_get(&data, "param1"))
                .unwrap_or("未知程序");
            let module_file = data_get(&data, "AppPath")
                .or_else(|| data_get(&data, "param2"))
                .unwrap_or("");
            let code = data_get(&data, "ExceptionCode")
                .or_else(|| data_get(&data, "param5"))
                .unwrap_or("");
            return Some(ActivityEvent::plain(
                time,
                "应用崩溃",
                format!("崩溃：{app}"),
                format!("Application 1000 · 异常 {code} · {module_file}"),
                MODULE,
            ));
        }
        if id == 1002 {
            let app = data_get(&data, "AppName")
                .or_else(|| data_get(&data, "param1"))
                .unwrap_or("未知程序");
            return Some(ActivityEvent::plain(
                time,
                "程序挂起",
                format!("无响应：{app}"),
                "Application 1002 (hang)".into(),
                MODULE,
            ));
        }
    }
    if provider.contains("TerminalServices-LocalSessionManager") {
        let user = data_get(&data, "User").unwrap_or("?");
        let addr = data_get(&data, "Address").unwrap_or("-");
        return match id {
            21 | 25 => Some(ActivityEvent::plain(
                time,
                "用户登录（会话）",
                format!("会话登录：{user}"),
                format!("源 {addr} · TS-LocalSessionManager {id}"),
                MODULE,
            )),
            23 => Some(ActivityEvent::plain(
                time,
                "用户注销（会话）",
                format!("会话注销：{user}"),
                format!("源 {addr} · TS-LocalSessionManager 23"),
                MODULE,
            )),
            24 => Some(ActivityEvent::plain(
                time,
                "会话断开",
                format!("会话断开：{user}"),
                format!("源 {addr} · TS-LocalSessionManager 24"),
                MODULE,
            )),
            _ => None,
        };
    }
    if provider.contains("TaskScheduler") {
        // 106=任务注册 107=任务触发 141=任务删除 201=动作完成
        let task = data_get(&data, "TaskName").unwrap_or("?");
        let user = data_get(&data, "User").unwrap_or("");
        return match id {
            106 | 141 => {
                let is_ms = task.to_ascii_lowercase().starts_with("\\microsoft");
                let action = if id == 106 { "注册计划任务" } else { "删除计划任务" };
                let mut ev = ActivityEvent::plain(
                    time,
                    if id == 106 { "任务注册（日志）" } else { "任务删除（日志）" },
                    format!("{action}：{task}"),
                    format!(
                        "TaskScheduler {id}{} · 注册动作留痕——任务文件事后被删也能溯源",
                        if user.is_empty() { String::new() } else { format!(" · 操作者 {user}") }
                    ),
                    MODULE,
                );
                if id == 106 && !is_ms {
                    ev.sev = crate::model::Sev::Yellow;
                    ev.tags.push(crate::model::Tag {
                        sev: crate::model::Sev::Yellow,
                        text: "R-020 非微软任务注册".into(),
                    });
                }
                Some(ev)
            }
            107 => Some(ActivityEvent::plain(
                time,
                "任务触发（日志）",
                format!("计划任务被触发：{task}"),
                format!("TaskScheduler 107 · 该时刻任务开始运行"),
                MODULE,
            )),
            201 => Some(ActivityEvent::plain(
                time,
                "任务完成（日志）",
                format!("计划任务动作完成：{task}"),
                format!(
                    "TaskScheduler 201{} · 结果码 {}",
                    if user.is_empty() { String::new() } else { format!(" · {user}") },
                    data_get(&data, "ResultCode").unwrap_or("-")
                ),
                MODULE,
            )),
            _ => None,
        };
    }
    if provider.contains("MsiInstaller") {
        return match id {
            1035 | 11707 => Some(ActivityEvent::plain(
                time,
                "安装程序开始",
                format!("Windows Installer 开始：{}", data_get(&data, "param1").unwrap_or("?")),
                format!("MsiInstaller {id}"),
                MODULE,
            )),
            1033 | 11724 => Some(ActivityEvent::plain(
                time,
                "安装程序结束",
                format!("Windows Installer 结束：{}", data_get(&data, "param1").unwrap_or("?")),
                format!("MsiInstaller {id}"),
                MODULE,
            )),
            _ => None,
        };
    }
    let ev = match id {
        42 => ActivityEvent::plain(
            time,
            "进入睡眠",
            "系统进入睡眠（Suspend）".into(),
            "System 42 (Kernel-Power)".into(),
            MODULE,
        ),
        107 => ActivityEvent::plain(
            time,
            "从睡眠唤醒",
            "系统从睡眠中恢复".into(),
            "System 107 (Kernel-Power)".into(),
            MODULE,
        ),
        6005 => ActivityEvent::plain(
            time,
            "系统启动",
            "事件日志服务已启动（开机）".into(),
            "System 6005".into(),
            MODULE,
        ),
        6006 => ActivityEvent::plain(
            time,
            "系统关机",
            "正常关机".into(),
            "System 6006".into(),
            MODULE,
        ),
        6008 => ActivityEvent::plain(
            time,
            "异常关机",
            "上次关机是意外的（断电/崩溃/强关）".into(),
            "System 6008".into(),
            MODULE,
        ),
        104 => ActivityEvent::plain(
            time,
            "日志清空",
            "System 事件日志被清除".into(),
            "System 104".into(),
            MODULE,
        ),
        7045 => {
            let name = data_get(&data, "ServiceName")
                .or_else(|| data_get(&data, "param1"))
                .unwrap_or("<未知>");
            let path = data_get(&data, "ImagePath")
                .or_else(|| data_get(&data, "param2"))
                .unwrap_or("<未知>");
            let start = data_get(&data, "StartType")
                .or_else(|| data_get(&data, "param4"))
                .unwrap_or("?");
            let account = data_get(&data, "Account")
                .or_else(|| data_get(&data, "param5"))
                .unwrap_or("?");
            ActivityEvent::plain(
                time,
                "新服务安装",
                format!("安装新服务：\"{name}\""),
                format!("{path} · 启动类型 {start} · 帐户 {account}"),
                MODULE,
            )
        }
        _ => return None,
    };
    Some(ev)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn rec(id: i64, data: serde_json::Value) -> serde_json::Value {
        let mut event = json!({
            "System": {
                "EventID": id,
                "TimeCreated": {"#attributes": {"SystemTime": "2026-09-22T02:42:13.245Z"}}
            }
        });
        if let Some(obj) = event.as_object_mut() {
            for (k, v) in data.as_object().into_iter().flatten() {
                obj.insert(k.clone(), v.clone());
            }
        }
        json!({"Event": event})
    }

    fn rec_with_provider(id: i64, provider: &str, data: serde_json::Value) -> serde_json::Value {
        let mut event = json!({
            "System": {
                "EventID": id,
                "Provider": {"#attributes": {"Name": provider}},
                "TimeCreated": {"#attributes": {"SystemTime": "2026-09-22T02:42:13.245Z"}}
            }
        });
        if let Some(obj) = event.as_object_mut() {
            for (k, v) in data.as_object().into_iter().flatten() {
                obj.insert(k.clone(), v.clone());
            }
        }
        json!({"Event": event})
    }

    #[test]
    fn maps_sleep_and_resume() {
        assert_eq!(map_event(&rec(42, json!({}))).unwrap().kind, "进入睡眠");
        assert_eq!(map_event(&rec(107, json!({}))).unwrap().kind, "从睡眠唤醒");
    }

    #[test]
    fn maps_wlan_events() {
        let v = rec_with_provider(
            8001,
            "Microsoft-Windows-WLAN-AutoConfig",
            json!({"EventData":{"Name":"Office-5G","ConnectionMode":"手动"}}),
        );
        let e = map_event(&v).unwrap();
        assert_eq!(e.kind, "无线网络连接");
        assert!(e.desc.contains("Office-5G"), "{}", e.desc);
        let v3 = rec_with_provider(
            8003,
            "Microsoft-Windows-WLAN-AutoConfig",
            json!({"EventData":{"Name":"Office-5G"}}),
        );
        assert_eq!(map_event(&v3).unwrap().kind, "无线网络断开");
    }

    #[test]
    fn maps_ts_session_events() {
        let v = rec_with_provider(
            21,
            "Microsoft-Windows-TerminalServices-LocalSessionManager",
            json!({"EventData":{"User":"CORP_admin","Address":"10.0.0.9","SessionID":"3"}}),
        );
        let e = map_event(&v).unwrap();
        assert_eq!(e.kind, "用户登录（会话）");
        assert!(e.desc.contains("admin"));
        assert!(e.info.contains("10.0.0.9"));
        let v23 = rec_with_provider(
            23,
            "Microsoft-Windows-TerminalServices-LocalSessionManager",
            json!({"EventData":{"User":"CORP_admin","Address":"10.0.0.9"}}),
        );
        assert_eq!(map_event(&v23).unwrap().kind, "用户注销（会话）");
    }

    #[test]
    fn maps_network_profile_events() {
        let v = rec_with_provider(
            10000,
            "Microsoft-Windows-NetworkProfile/Operational",
            json!({"EventData":{"Name":"以太网","Description":"Realtek GbE"}}),
        );
        let e = map_event(&v).unwrap();
        assert_eq!(e.kind, "网络连接");
        assert!(e.desc.contains("以太网"));
        let v2 = rec_with_provider(
            10001,
            "Microsoft-Windows-NetworkProfile/Operational",
            json!({"EventData":{"Name":"以太网"}}),
        );
        assert_eq!(map_event(&v2).unwrap().kind, "网络断开");
    }

    #[test]
    fn maps_boot_event() {
        let e = map_event(&rec(6005, json!({}))).unwrap();
        assert_eq!(e.kind, "系统启动");
        assert!(e.desc.contains("开机"));
        assert_eq!(e.module, "事件日志（系统/应用/网络）");
    }

    #[test]
    fn maps_shutdown_events() {
        assert_eq!(map_event(&rec(6006, json!({}))).unwrap().kind, "系统关机");
        assert_eq!(map_event(&rec(6008, json!({}))).unwrap().kind, "异常关机");
    }

    #[test]
    fn maps_log_cleared() {
        let e = map_event(&rec(104, json!({}))).unwrap();
        assert_eq!(e.kind, "日志清空");
        assert!(e.desc.contains("System"));
    }

    #[test]
    fn maps_service_install_named_fields() {
        let v = rec(7045, json!({"EventData":{
            "ServiceName":"SysUpdate",
            "ImagePath":"C:\\Users\\Public\\s.exe",
            "ServiceType":"用户模式",
            "StartType":"自动",
            "Account":"LocalSystem"
        }}));
        let e = map_event(&v).unwrap();
        assert_eq!(e.kind, "新服务安装");
        assert!(e.desc.contains("SysUpdate"));
        assert!(e.info.contains("C:\\Users\\Public\\s.exe"));
        assert!(e.info.contains("自动"));
    }

    #[test]
    fn maps_service_install_param_fields() {
        let v = rec(7045, json!({"EventData":[
            {"#attributes":{"Name":"param1"},"#text":"Svc"},
            {"#attributes":{"Name":"param2"},"#text":"C:\\x\\s.exe"},
            {"#attributes":{"Name":"param3"},"#text":"1"},
            {"#attributes":{"Name":"param4"},"#text":"2"},
            {"#attributes":{"Name":"param5"},"#text":"LocalSystem"}
        ]}));
        let e = map_event(&v).unwrap();
        assert!(e.desc.contains("Svc"));
        assert!(e.info.contains("C:\\x\\s.exe"));
    }

    #[test]
    fn maps_task_scheduler_events() {
        let v = rec_with_provider(
            106,
            "Microsoft-Windows-TaskScheduler",
            json!({"EventData":{"TaskName":"\\Evil\\Update","User":"PC\\alice"}}),
        );
        let e = map_event(&v).unwrap();
        assert_eq!(e.kind, "任务注册（日志）");
        assert!(e.desc.contains(r"\Evil\Update"));
        assert!(e.tags.iter().any(|t| t.text.contains("R-020")), "非微软任务应标 R-020");
        // 微软命名空间任务注册不标记
        let v2 = rec_with_provider(
            106,
            "Microsoft-Windows-TaskScheduler",
            json!({"EventData":{"TaskName":"\\Microsoft\\Windows\\ChkDsk"}}),
        );
        let e2 = map_event(&v2).unwrap();
        assert!(e2.tags.is_empty());
        let v3 = rec_with_provider(
            107,
            "Microsoft-Windows-TaskScheduler",
            json!({"EventData":{"TaskName":"\\Evil\\Update"}}),
        );
        assert_eq!(map_event(&v3).unwrap().kind, "任务触发（日志）");
    }

    #[test]
    fn unknown_id_is_none() {
        assert!(map_event(&rec(9999, json!({}))).is_none());
    }

    #[test]
    fn missing_time_is_none() {
        let v = json!({"Event":{"System":{"EventID":6005}}});
        assert!(map_event(&v).is_none());
    }

    #[test]
    #[ignore = "需要真实 System.evtx，仅在本机执行 cargo test -- --ignored"]
    fn collector_reads_real_system_log() {
        let c = EvtxSystemCollector::default();
        let r = c.run();
        assert_eq!(r.module, "事件日志（系统/应用/网络）");
        assert!(r.count >= 1, "真实机器上至少有一条开机记录：{:?}", r.logs);
        assert!(!r.logs.is_empty());
    }

    #[test]
    fn scan_report_sorts_desc_and_builds_summary() {
        let report = crate::modules::run_scan_with(|_evtx_path| {
            vec![
                map_event(&json!({"Event":{"System":{
                    "EventID":6005,
                    "TimeCreated":{"#attributes":{"SystemTime":"2026-09-22T02:00:00.000Z"}}}}})).unwrap(),
                map_event(&json!({"Event":{"System":{
                    "EventID":6006,
                    "TimeCreated":{"#attributes":{"SystemTime":"2026-09-23T02:00:00.000Z"}}}}})).unwrap(),
            ]
        });
        assert!(report.events[0].time >= report.events[1].time);
        assert_eq!(report.modules.len(), 1);
    }
}
