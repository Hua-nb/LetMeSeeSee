//! Security 日志模块：4624 登录成功 / 4625 登录失败 / 4648 显式凭据 /
//! 4688 进程创建（含命令行——按时间段排查的核心）/ 1102 日志清空。
//! 通道需要管理员权限：非管理员优雅降级并说明。

use crate::evtxdata::{data_get, event_data, event_id, event_time_raw, provider_name};
use crate::model::{ActivityEvent, Collector, ModuleResult, ModuleStatus};
use crate::timeutil::evtx_time_to_local;
use evtx::EvtxParser;
use serde_json::Value;
use std::path::PathBuf;
use std::time::Instant;

pub const MODULE: &str = "安全日志（Security）";

const CHANNEL: &str = "Security";
const LIVE_PATH: &str = r"C:\Windows\System32\winevt\Logs\Security.evtx";
/// 4625 聚合的爆破判定阈值（同源同账户失败次数）
const BRUTE_FORCE_THRESHOLD: usize = 5;

pub fn map_security_event(record: &Value) -> Option<ActivityEvent> {
    let id = event_id(record)?;
    let time = evtx_time_to_local(event_time_raw(record)?)?;
    let data = event_data(record);
    let _ = provider_name(record);
    match id {
        4624 | 4625 => {
            let user = data_get(&data, "TargetUserName").unwrap_or("?");
            let domain = data_get(&data, "TargetDomainName").unwrap_or("");
            let logon_type = data_get(&data, "LogonType").unwrap_or("?");
            let ip = data_get(&data, "IpAddress").unwrap_or("-");
            let (kind, desc) = if id == 4624 {
                ("登录成功", format!("账户 {domain}\\{user} 登录成功"))
            } else {
                ("登录失败", format!("账户 {domain}\\{user} 登录失败"))
            };
            // 登录类型：2=交互 3=网络 10=RDP远程
            let lt: u32 = logon_type.parse().unwrap_or(0);
            let lt_desc = match lt {
                2 => "交互登录",
                3 => "网络登录",
                4 => "批处理",
                5 => "服务",
                7 => "解锁",
                8 => "网络明文",
                9 => "新凭据",
                10 => "RDP 远程登录",
                _ => "其他",
            };
            Some(ActivityEvent::plain(
                time,
                kind,
                desc,
                format!("类型 {logon_type}（{lt_desc}）· 源 {ip} · Security {id}"),
                MODULE,
            ))
        }
        4648 => {
            let user = data_get(&data, "TargetUserName").unwrap_or("?");
            let target = data_get(&data, "TargetServerName").unwrap_or("?");
            let proc = data_get(&data, "ProcessName").unwrap_or("-");
            Some(ActivityEvent::plain(
                time,
                "显式凭据登录",
                format!("使用显式凭据访问 {target}（账户 {user}）"),
                format!("进程 {proc} · Security 4648 · 横向移动常见征兆"),
                MODULE,
            ))
        }
        4778 | 4779 => {
            // RDP 会话重连/断开（含源地址，会话漂移到其他终端时触发）
            let user = data_get(&data, "AccountName").unwrap_or("?");
            let addr = data_get(&data, "Address").unwrap_or("-");
            let sess = data_get(&data, "SessionName").unwrap_or("");
            Some(ActivityEvent::plain(
                time,
                if id == 4778 { "会话重连（RDP）" } else { "会话断开（RDP）" },
                format!("{}：账户 {user}", if id == 4778 { "RDP 会话重连" } else { "RDP 会话断开" }),
                format!("源 {addr} · 会话 {sess} · Security {id}"),
                MODULE,
            ))
        }
        4697 => {
            let name = data_get(&data, "ServiceName").unwrap_or("?");
            let path = data_get(&data, "ServiceFileName").unwrap_or("-");
            let account = data_get(&data, "ServiceAccount").unwrap_or("-");
            Some(ActivityEvent::plain(
                time,
                "服务安装（Security）",
                format!("安装新服务：{name}"),
                format!("{path} · 帐户 {account} · Security 4697"),
                MODULE,
            ))
        }
        4698 | 4702 => {
            // 任务创建/更新：任务文件可被攻击者删除，Security 日志留痕是补充证据
            let name = data_get(&data, "TaskName").unwrap_or("?");
            let action = if id == 4698 { "创建计划任务" } else { "更新计划任务" };
            let mut content = data_get(&data, "TaskContent").unwrap_or("").to_string();
            if content.len() > 300 {
                content = format!("{}…（截断）", &content[..300]);
            }
            Some(ActivityEvent::plain(
                time,
                if id == 4698 { "任务创建（Security）" } else { "任务更新（Security）" },
                format!("{action}：{name}"),
                if content.is_empty() {
                    format!("Security {id}")
                } else {
                    format!("任务 XML：{content} · Security {id}")
                },
                MODULE,
            ))
        }
        4719 => {
            let subj = data_get(&data, "SubjectUserName").unwrap_or("?");
            let policy = data_get(&data, "AuditPolicyChanges").unwrap_or("-");
            Some(ActivityEvent::plain(
                time,
                "审核策略更改",
                format!("系统审核策略被更改（{policy}）"),
                format!("操作者 {subj} · Security 4719 · 关闭审核是反取证常见动作"),
                MODULE,
            ))
        }
        4616 => {
            let subj = data_get(&data, "SubjectUserName").unwrap_or("?");
            let new = data_get(&data, "NewTime").unwrap_or("?");
            let old = data_get(&data, "PreviousTime").unwrap_or("?");
            Some(ActivityEvent::plain(
                time,
                "系统时间更改",
                format!("系统时间被更改：{old} → {new}"),
                format!("操作者 {subj} · Security 4616 · 会影响日志时间线可信度"),
                MODULE,
            ))
        }
        4688 => {
            let proc = data_get(&data, "NewProcessName").unwrap_or("?");
            let cmdline = data_get(&data, "CommandLine").unwrap_or("");
            let parent = data_get(&data, "ParentProcessName").unwrap_or("");
            Some(ActivityEvent::plain(
                time,
                "进程创建（逐次）",
                proc.to_string(),
                format!("命令行 {cmdline} · 父进程 {parent} · Security 4688"),
                MODULE,
            ))
        }
        4720 | 4722 | 4724 | 4726 | 4728 | 4732 => {
            // 账号管理事件：创建/启用/重置密码/删除/加组（应急关注"攻击者建号提权"）
            let action = match id {
                4720 => "创建账户",
                4722 => "启用账户",
                4724 => "重置账户密码",
                4726 => "删除账户",
                4728 => "加入全局组",
                _ => "加入本地组",
            };
            // 加组事件：TargetUserName=组名、MemberName=成员（此前组名被丢，规则无法判定提权）
            let member = data_get(&data, "MemberName").or_else(|| {
                data_get(&data, "TargetUserName").filter(|v| *v != "-")
            });
            let group = if id == 4728 || id == 4732 {
                data_get(&data, "TargetUserName").unwrap_or("")
            } else {
                ""
            };
            let desc = match (member, group.is_empty()) {
                (Some(m), false) => format!("{action} {group}：{m}"),
                (Some(m), true) => format!("{action}：{m}"),
                _ => format!("{action}：?"),
            };
            let subj = data_get(&data, "SubjectUserName").unwrap_or("?");
            Some(ActivityEvent::plain(
                time,
                "账户管理",
                desc,
                format!("操作者 {subj} · Security {id}"),
                MODULE,
            ))
        }
        1102 => Some(ActivityEvent::plain(
            time,
            "日志清空",
            "安全日志被清除".into(),
            "Security 1102 · 反取证行为".into(),
            MODULE,
        )),
        _ => None,
    }
}

/// 暴力破解成功检测（R-030，纯函数便于测试）：
/// 同（源IP, 账户）失败 ≥ threshold 次构成爆破组；若该组末次失败后 window 分钟内
/// 出现同键的登录成功 → 判定"口令疑似被攻破"。时间串为定长格式，字典序即时间序。
pub fn detect_brute_success(
    fails: &std::collections::HashMap<(String, String), Vec<String>>,
    oks: &std::collections::HashMap<(String, String), Vec<String>>,
    threshold: usize,
    window_min: i64,
) -> Vec<ActivityEvent> {
    let mut out = Vec::new();
    for ((ip, user), times) in fails {
        if times.len() < threshold {
            continue;
        }
        let mut sorted = times.clone();
        sorted.sort();
        let first = sorted[0].clone();
        let last = sorted[sorted.len() - 1].clone();
        let deadline = time_plus_minutes(&last, window_min);
        if let Some(oks) = oks.get(&(ip.clone(), user.clone())) {
            if let Some(hit) = oks
                .iter()
                .filter(|t| t.as_str() >= last.as_str() && t.as_str() <= deadline.as_str())
                .min()
            {
                out.push(ActivityEvent {
                    time: hit.clone(),
                    kind: "暴力破解成功".into(),
                    desc: format!("源 {ip} 对账户 {user} 爆破 {} 次后登录成功", times.len()),
                    info: format!(
                        "失败 {first} ~ {last}，成功于 {hit} · Security 4625→4624 · 口令疑似被攻破"
                    ),
                    module: MODULE.into(),
                    sev: crate::model::Sev::Red,
                    tags: vec![crate::model::Tag {
                        sev: crate::model::Sev::Red,
                        text: "R-030 暴力破解后登录成功".into(),
                    }],
                });
            }
        }
    }
    out.sort_by(|a, b| b.time.cmp(&a.time));
    out
}

/// "YYYY-MM-DD HH:MM:SS.mmm" + N 分钟（字符串时间运算，模块内自洽）
fn time_plus_minutes(t: &str, mins: i64) -> String {
    let Ok(dt) = chrono::NaiveDateTime::parse_from_str(&t[..19.min(t.len())], "%Y-%m-%d %H:%M:%S")
    else {
        return t.to_string();
    };
    (dt + chrono::Duration::minutes(mins))
        .format("%Y-%m-%d %H:%M:%S%.3f")
        .to_string()
}

pub struct SecurityCollector;

impl Default for SecurityCollector {
    fn default() -> Self {
        Self
    }
}

impl Collector for SecurityCollector {
    fn id(&self) -> &'static str {
        MODULE
    }

    fn group(&self) -> &'static str {
        "安全日志（Security）"
    }

    fn run(&self) -> ModuleResult {
        let t0 = Instant::now();
        let mut logs = Vec::new();
        let mut events = Vec::new();
        let mut status = ModuleStatus::Ok;

        let path = PathBuf::from(LIVE_PATH);
        let mut parser_owned: Option<EvtxParser<std::fs::File>> = None;
        let mut tmp_copy: Option<PathBuf> = None;

        if let Ok(p) = EvtxParser::from_path(&path) {
            logs.push("直接读取 Security.evtx 成功".into());
            parser_owned = Some(p);
        } else {
            logs.push("直接读取失败，尝试 wevtutil 导出（需管理员）…".into());
            let tmp = std::env::temp_dir().join("LetMeSeeSee-Security.evtx");
            match crate::winapi::export_event_log(
                CHANNEL,
                Some("None"),
                tmp.to_string_lossy().as_ref(),
            )
            {
                Ok(()) => match EvtxParser::from_path(&tmp) {
                    Ok(p) => {
                        logs.push("已通过 wevtutil 导出副本解析".into());
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
                // 4625 失败登录按（源IP, 账户）聚合：爆破识别（≥5 次单独成事件）；
                // 4624 成功登录同键收集，供 R-030"爆破后成功"序列判定
                let mut fails: std::collections::HashMap<(String, String), Vec<String>> =
                    std::collections::HashMap::new();
                let mut oks: std::collections::HashMap<(String, String), Vec<String>> =
                    std::collections::HashMap::new();
                for r in parser.records_json_value() {
                    match r {
                        Ok(rec) => {
                            total += 1;
                            // 注：4688 曾投递进程树种子（B 档）；进程树已定稿为
                            // "仅当前存活进程"现场视图（2026-09-28 用户反馈），
                            // 历史创建事件只进时间线
                            if event_id(&rec.data) == Some(4625) {
                                let data = event_data(&rec.data);
                                let ip = data_get(&data, "IpAddress").unwrap_or("-").to_string();
                                let user = data_get(&data, "TargetUserName").unwrap_or("?").to_string();
                                let t = evtx_time_to_local(event_time_raw(&rec.data).unwrap_or(""))
                                    .unwrap_or_default();
                                if !t.is_empty() {
                                    fails.entry((ip, user)).or_default().push(t);
                                }
                            }
                            if event_id(&rec.data) == Some(4624) {
                                let data = event_data(&rec.data);
                                let ip = data_get(&data, "IpAddress").unwrap_or("-").to_string();
                                let user = data_get(&data, "TargetUserName").unwrap_or("?").to_string();
                                let t = evtx_time_to_local(event_time_raw(&rec.data).unwrap_or(""))
                                    .unwrap_or_default();
                                if !t.is_empty() {
                                    oks.entry((ip, user)).or_default().push(t);
                                }
                            }
                            if let Some(ev) = map_security_event(&rec.data) {
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
                let mut brute = 0usize;
                let mut agg: Vec<_> = fails.iter().collect();
                agg.sort_by(|a, b| b.1.len().cmp(&a.1.len()));
                for ((ip, user), times) in agg {
                    if times.len() < BRUTE_FORCE_THRESHOLD {
                        continue;
                    }
                    brute += 1;
                    let mut sorted = times.clone();
                    sorted.sort();
                    events.push(ActivityEvent {
                        time: sorted[0].clone(),
                        kind: "疑似暴力破解".into(),
                        desc: format!("源 {ip} 对账户 {user} 登录失败 {} 次", times.len()),
                        info: format!(
                            "{} ~ {} · Security 4625 聚合 · 阈值 {} 次",
                            sorted[0],
                            sorted[sorted.len() - 1],
                            BRUTE_FORCE_THRESHOLD
                        ),
                        module: MODULE.into(),
                        sev: crate::model::Sev::Red,
                        tags: vec![crate::model::Tag {
                            sev: crate::model::Sev::Red,
                            text: "R-016 疑似暴力破解".into(),
                        }],
                    });
                }
                // R-030：爆破组末次失败后 10 分钟内出现同（源,账户）的登录成功
                let compromised = detect_brute_success(&fails, &oks, BRUTE_FORCE_THRESHOLD, 10);
                let n_comp = compromised.len();
                events.extend(compromised);
                logs.push(format!(
                    "共解析 {total} 条，命中登录/进程事件 {} 条（爆破聚合 {brute} 组，其中爆破后成功 {n_comp} 组）",
                    events.len()
                ));
                if events.is_empty() {
                    status = ModuleStatus::Warn;
                    logs.push("无命中事件（审核策略可能未开启，如 4688 需'审核进程创建'）".into());
                }
            }
            None => {
                status = ModuleStatus::Warn;
                logs.push("Security 日志不可读：以管理员身份运行可解锁（4624/4625/4648/4688/1102/4720系列）".into());
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

    fn rec(id: i64, data: Value) -> Value {
        let mut event = json!({
            "System": {
                "EventID": id,
                "TimeCreated": {"#attributes": {"SystemTime": "2026-09-22T10:00:00.000Z"}}
            }
        });
        if let Some(obj) = event.as_object_mut() {
            if let Some(d) = data.as_object() {
                for (k, v) in d {
                    obj.insert(k.clone(), v.clone());
                }
            }
        }
        json!({"Event": event})
    }

    fn with_data(id: i64, fields: &[(&str, &str)]) -> Value {
        let mut m = serde_json::Map::new();
        for (k, v) in fields {
            m.insert(k.to_string(), json!(v));
        }
        rec(id, json!({"EventData": m}))
    }

    #[test]
    fn maps_logon_success_with_type() {
        let v = with_data(
            4624,
            &[
                ("TargetUserName", "admin"),
                ("TargetDomainName", "CORP"),
                ("LogonType", "10"),
                ("IpAddress", "10.0.0.5"),
            ],
        );
        let e = map_security_event(&v).unwrap();
        assert_eq!(e.kind, "登录成功");
        assert!(e.desc.contains("admin"));
        assert!(e.info.contains("RDP 远程登录"), "{}", e.info);
        assert!(e.info.contains("10.0.0.5"));
    }

    #[test]
    fn maps_logon_failure() {
        let v = with_data(4625, &[("TargetUserName", " administrator"), ("LogonType", "3")]);
        assert_eq!(map_security_event(&v).unwrap().kind, "登录失败");
    }

    #[test]
    fn maps_explicit_creds() {
        let v = with_data(
            4648,
            &[
                ("TargetUserName", "Administrator"),
                ("TargetServerName", "WEB01"),
                ("ProcessName", r"C:\Windows\System32\mstsc.exe"),
            ],
        );
        let e = map_security_event(&v).unwrap();
        assert_eq!(e.kind, "显式凭据登录");
        assert!(e.desc.contains("WEB01"));
    }

    #[test]
    fn maps_process_creation_with_cmdline() {
        let v = with_data(
            4688,
            &[
                ("NewProcessName", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
                ("CommandLine", "powershell -nop -w hidden -enc SQBFAFgA"),
                ("ParentProcessName", r"C:\Windows\explorer.exe"),
            ],
        );
        let e = map_security_event(&v).unwrap();
        assert_eq!(e.kind, "进程创建（逐次）");
        assert!(e.info.contains("-enc"));
    }

    #[test]
    fn maps_log_clear() {
        assert_eq!(map_security_event(&rec(1102, json!({}))).unwrap().kind, "日志清空");
    }

    #[test]
    fn maps_account_created() {
        let v = with_data(
            4720,
            &[("TargetUserName", "hack$"), ("SubjectUserName", "admin")],
        );
        let e = map_security_event(&v).unwrap();
        assert_eq!(e.kind, "账户管理");
        assert!(e.desc.contains("创建账户") && e.desc.contains("hack$"));
        assert!(e.info.contains("admin"));
    }

    #[test]
    fn maps_group_member_added() {
        // 4732 的成员在 MemberName，组名在 TargetUserName（改进后组名保留进 desc）
        let v = with_data(4732, &[("TargetUserName", "Administrators"), ("MemberName", "CORP\\backdoor"), ("SubjectUserName", "admin")]);
        let e = map_security_event(&v).unwrap();
        assert!(e.desc.contains("加入本地组 Administrators") && e.desc.contains("backdoor"), "{}", e.desc);
    }

    #[test]
    fn brute_force_success_detected() {
        use std::collections::HashMap;
        let mut fails: HashMap<(String, String), Vec<String>> = HashMap::new();
        let mut oks: HashMap<(String, String), Vec<String>> = HashMap::new();
        fails.insert(
            ("1.2.3.4".into(), "admin".into()),
            (0..10).map(|i| format!("2026-09-28 02:{:02}:00.000", i * 2)).collect(),
        );
        // 末次失败 02:18，3 分钟后成功 → 命中
        oks.insert(
            ("1.2.3.4".into(), "admin".into()),
            vec!["2026-09-28 02:21:00.000".into()],
        );
        // 另一组爆破但未成功 → 不命中
        fails.insert(
            ("5.6.7.8".into(), "root".into()),
            (0..9).map(|i| format!("2026-09-28 03:{:02}:00.000", i)).collect(),
        );
        let out = detect_brute_success(&fails, &oks, 5, 10);
        assert_eq!(out.len(), 1, "{out:?}");
        assert!(out[0].desc.contains("1.2.3.4") && out[0].desc.contains("爆破 10 次"));
        assert!(out[0].tags.iter().any(|t| t.text.contains("R-030")));
        // 成功太晚（超出窗口）也不命中
        oks.insert(
            ("5.6.7.8".into(), "root".into()),
            vec!["2026-09-28 04:30:00.000".into()],
        );
        let out2 = detect_brute_success(&fails, &oks, 5, 10);
        assert_eq!(out2.len(), 1, "仅第一组命中");
    }

    #[test]
    fn maps_service_install_4697() {
        let v = with_data(4697, &[
            ("ServiceName", "EvilSvc"),
            ("ServiceFileName", r"C:\Users\Public\evil.exe"),
            ("ServiceAccount", "LocalSystem"),
        ]);
        let e = map_security_event(&v).unwrap();
        assert_eq!(e.kind, "服务安装（Security）");
        assert!(e.desc.contains("EvilSvc") && e.info.contains("Public"));
    }

    #[test]
    fn maps_task_created_4698_with_xml() {
        let v = with_data(4698, &[("TaskName", r"\Evil\Update"), ("TaskContent", "<Task></Task>")]);
        let e = map_security_event(&v).unwrap();
        assert_eq!(e.kind, "任务创建（Security）");
        assert!(e.desc.contains(r"\Evil\Update") && e.info.contains("<Task>"));
    }

    #[test]
    fn maps_audit_policy_change_and_time_change() {
        let v = with_data(4719, &[("SubjectUserName", "admin"), ("AuditPolicyChanges", "%%8448")]);
        assert_eq!(map_security_event(&v).unwrap().kind, "审核策略更改");
        let v2 = with_data(4616, &[
            ("SubjectUserName", "admin"),
            ("NewTime", "2026-01-01T00:00:00"),
            ("PreviousTime", "2025-01-01T00:00:00"),
        ]);
        assert_eq!(map_security_event(&v2).unwrap().kind, "系统时间更改");
    }

    #[test]
    fn maps_rdp_session_reconnect() {
        let v = with_data(4778, &[("AccountName", "CORP\\u1"), ("Address", "10.0.0.9"), ("SessionName", "RDP-Tcp#3")]);
        let e = map_security_event(&v).unwrap();
        assert_eq!(e.kind, "会话重连（RDP）");
        assert!(e.info.contains("10.0.0.9"));
        let v2 = with_data(4779, &[("AccountName", "u1"), ("Address", "10.0.0.9")]);
        assert_eq!(map_security_event(&v2).unwrap().kind, "会话断开（RDP）");
    }

    #[test]
    fn collector_degrades_without_admin() {
        let r = SecurityCollector::default().run();
        assert!(!r.logs.is_empty());
        matches!(r.status, ModuleStatus::Ok | ModuleStatus::Warn);
    }
}
