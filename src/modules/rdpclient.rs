//! RDP 客户端历史模块：HKU\<sid>\SOFTWARE\Microsoft\Terminal Server Client\Servers。
//! 每个子键 = 本机曾用 mstsc 连接过的一台远程主机（IP/主机名），键时间≈最后连接。
//! 这是"从受害机向外横向移动"的第一手证据（4648/4778 是日志侧，此处是注册表侧）。

use crate::model::{ActivityEvent, Collector, ModuleResult, ModuleStatus, RawTable, Sev};
use crate::regutil::{key_last_write, read_string_value, subkeys, HKEY};
use std::time::Instant;

pub const MODULE: &str = "RDP 客户端历史";

const RAW_COLS: &[&str] = &["连接目标", "友好名称", "用户名提示", "用户", "最后写入时间"];

pub struct RdpClientCollector;

impl Default for RdpClientCollector {
    fn default() -> Self {
        Self
    }
}

impl Collector for RdpClientCollector {
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

        for sid in crate::regutil::user_sids() {
            let root = format!(
                r"{sid}\SOFTWARE\Microsoft\Terminal Server Client\Servers"
            );
            let Ok(targets) = subkeys(HKEY::users(), &root) else {
                continue;
            };
            for target in targets {
                if target.eq_ignore_ascii_case("default") {
                    continue; // Default 子键是 MRU 元数据，非目标
                }
                let key = format!(r"{root}\{target}");
                let friendly = read_string_value(HKEY::users(), &key, "")
                    .or_else(|_| read_string_value(HKEY::users(), &key, "FriendlyName"))
                    .unwrap_or_default();
                let hint = read_string_value(HKEY::users(), &format!(r"{key}\UsernameHint"), "")
                    .unwrap_or_default();
                let time = key_last_write(HKEY::users(), &key)
                    .unwrap_or_else(|| "（无时间戳）".into());
                let info = format!(
                    "mstsc 客户端记录 · 用户 {sid}{}{} · 键最后写入时间（≈最后连接）",
                    if friendly.is_empty() {
                        String::new()
                    } else {
                        format!(" · 友好名 {friendly}")
                    },
                    if hint.is_empty() {
                        String::new()
                    } else {
                        format!(" · 用户名提示 {hint}")
                    },
                );
                events.push(ActivityEvent {
                    time: time.clone(),
                    kind: "RDP 连接记录".into(),
                    desc: format!("本机 → {target}"),
                    info,
                    module: MODULE.into(),
                    sev: Sev::None,
                    tags: vec![],
                });
                rows.push(vec![
                    target.clone(),
                    friendly,
                    hint,
                    sid.clone(),
                    time,
                ]);
            }
        }
        logs.push(format!(
            "共 {} 条 RDP 客户端连接记录（该机向外连过的远程主机；与 Security 4648/4778 相互印证）",
            events.len()
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

    #[test]
    fn collector_degrades_when_no_rdp_history() {
        let r = RdpClientCollector::default().run();
        assert!(!r.logs.is_empty());
        matches!(r.status, ModuleStatus::Ok | ModuleStatus::Warn);
    }
}
