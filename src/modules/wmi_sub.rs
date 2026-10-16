//! WMI 事件订阅模块：root\subscription 命名空间的 __EventFilter /
//! CommandLineEventConsumer / ActiveScriptEventConsumer / __FilterToConsumerBinding。
//! 无文件持久化的经典落点。WMI 订阅无可靠时间戳 → 一律"（无时间戳）"（实事求是）。
//! 系统默认的 SCM Event Log 订阅豁免（灰），其余命令行/脚本消费者红（R-014）。
//! 查询走 winapi::query_wmi_subscriptions（COM IWbemServices 直调，零子进程）。

use crate::model::{ActivityEvent, Collector, ModuleResult, ModuleStatus, RawTable, Sev, Tag};
use std::time::Instant;

pub const MODULE: &str = "WMI事件订阅";

const RAW_COLS: &[&str] = &["类", "名称", "详情", "判定"];

/// 默认豁免名单：系统自带的 SCM 事件日志订阅（Win10/11 全系存在）
const BASELINE_NAMES: &[&str] = &["SCM Event Log Filter", "SCM Event Log Consumer"];

pub fn is_baseline(name: &str) -> bool {
    BASELINE_NAMES.iter().any(|b| b.eq_ignore_ascii_case(name))
}

/// 聚合条目字段为详情串（顺序：查询/命令行/脚本/过滤器/消费者）
pub fn build_detail(
    query: &str,
    command_line: &str,
    script: &str,
    filter: &str,
    consumer: &str,
) -> String {
    let mut parts = Vec::new();
    for (v, label) in [
        (query, "查询"),
        (command_line, "命令行"),
        (script, "脚本"),
        (filter, "过滤器"),
        (consumer, "消费者"),
    ] {
        if !v.is_empty() {
            parts.push(format!("{label} {v}"));
        }
    }
    parts.join(" · ")
}

/// 订阅条目定级：基线=灰；命令行/脚本消费者或其绑定=红；其他=黄
pub fn classify(class: &str, name: &str, detail: &str) -> (Sev, String) {
    if is_baseline(name) {
        return (Sev::Gray, "系统默认订阅（豁免）".into());
    }
    if class == "CommandLineEventConsumer" || class == "ActiveScriptEventConsumer" {
        return (Sev::Red, "非默认命令行/脚本消费者——无文件持久化典型特征".into());
    }
    // 绑定指向基线成员的豁免；指向其他消费者则随目标升级
    let references_baseline = BASELINE_NAMES
        .iter()
        .any(|b| detail.contains(b));
    if class == "__FilterToConsumerBinding" {
        if references_baseline {
            return (Sev::Gray, "系统默认绑定（豁免）".into());
        }
        return (Sev::Red, "绑定指向非默认消费者".into());
    }
    (Sev::Yellow, "非默认事件过滤器".into())
}

pub struct WmiSubCollector;

impl Default for WmiSubCollector {
    fn default() -> Self {
        Self
    }
}

impl Collector for WmiSubCollector {
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

        let entries = match crate::winapi::query_wmi_subscriptions() {
            Ok(v) => v,
            Err(e) => {
                // WMI 服务被禁用/损坏时如实报 Err——
                // WMI 订阅是高价值持久化点，静默空表会让分析者误判"无订阅"
                logs.push(format!(
                    "WMI 查询失败：{e}——本模块无数据，请人工复核 root\\subscription 命名空间"
                ));
                return ModuleResult {
                    module: self.id().into(),
                    status: ModuleStatus::Err,
                    count: 0,
                    duration_ms: t0.elapsed().as_millis(),
                    logs,
                    events: Vec::new(),
                    raw: None,
                };
            }
        };

        let mut rows: Vec<Vec<String>> = Vec::new();
        for e in &entries {
            let detail = build_detail(
                &e.query, &e.command_line, &e.script, &e.filter, &e.consumer,
            );
            let name = if e.name.is_empty() {
                "（未命名）"
            } else {
                &e.name
            };
            let (sev, note) = classify(&e.class, name, &detail);
            let tag = if sev >= Sev::Yellow {
                Some(Tag {
                    sev,
                    text: "R-014 WMI 可疑订阅".into(),
                })
            } else {
                None
            };
            events.push(ActivityEvent {
                time: "（无时间戳）".into(),
                kind: "WMI事件订阅".into(),
                desc: format!("{}：{}", e.class, name),
                info: if detail.is_empty() {
                    note.clone()
                } else {
                    format!("{detail} · {note}")
                },
                module: MODULE.into(),
                sev,
                tags: tag.into_iter().collect(),
            });
            rows.push(vec![e.class.clone(), name.to_string(), detail, note]);
        }
        let baseline = events.iter().filter(|e| e.sev == Sev::Gray).count();
        let suspicious = events.iter().filter(|e| e.sev >= Sev::Yellow).count();
        logs.push(format!(
            "共 {} 条订阅：系统默认 {} 条，需关注 {} 条（WMI 订阅无时间戳属正常）",
            events.len(),
            baseline,
            suspicious
        ));
        ModuleResult {
            module: self.id().into(),
            status: if suspicious > 0 {
                ModuleStatus::Warn
            } else if events.is_empty() {
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

    #[test]
    fn detail_aggregates_in_order() {
        let d = build_detail("select * from x", "", "calc.exe", "", "");
        assert_eq!(d, "查询 select * from x · 脚本 calc.exe");
        assert_eq!(build_detail("", "", "", "", ""), "");
        let full = build_detail("q", "cmd /c x", "s", r#"__EventFilter.Name="F""#, r#"CommandLineEventConsumer.Name="C""#);
        assert_eq!(
            full,
            r#"查询 q · 命令行 cmd /c x · 脚本 s · 过滤器 __EventFilter.Name="F" · 消费者 CommandLineEventConsumer.Name="C""#
        );
    }

    #[test]
    fn classify_baseline_and_threats() {
        assert_eq!(classify("__EventFilter", "SCM Event Log Filter", "").0, Sev::Gray);
        assert_eq!(
            classify("CommandLineEventConsumer", "evil", "cmd /c").0,
            Sev::Red
        );
        assert_eq!(
            classify("ActiveScriptEventConsumer", "s", "VBScript").0,
            Sev::Red
        );
        assert_eq!(
            classify("__FilterToConsumerBinding", "b", "Filter __EventFilter.Name=\"SCM Event Log Filter\"").0,
            Sev::Gray
        );
        assert_eq!(classify("__EventFilter", "myfilter", "select").0, Sev::Yellow);
    }

    #[test]
    #[ignore = "真实 WMI；本机 cargo test -- --ignored"]
    fn collector_sees_baseline_subscription() {
        let r = WmiSubCollector::default().run();
        // 基线至少含 SCM Event Log Filter 及其绑定（消费者类型随系统而异，可能不在查询清单）
        assert!(r.count >= 2, "默认 SCM 订阅应存在：{:?}", r.logs);
        assert!(r.events.iter().any(|e| e.desc.contains("SCM Event Log Filter")));
        // 干净系统的订阅应全部为豁免级（灰）
        assert!(r.events.iter().all(|e| e.sev == Sev::Gray), "{:?}", r.events);
    }
}
