use crate::model::{ActivityEvent, Collector, ModuleResult, ModuleStatus, Sev};
use crate::regutil::{key_last_write, read_value, subkeys, HKEY};
use std::time::Instant;

pub const MODULE: &str = "软件安装";

/// InstallDate（YYYYMMDD 字符串）→ 展示时间；非法返回 None
pub fn parse_install_date(s: &str) -> Option<String> {
    if s.len() != 8 || !s.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let y: i32 = s[0..4].parse().ok()?;
    let m: u32 = s[4..6].parse().ok()?;
    let d: u32 = s[6..8].parse().ok()?;
    if !(1990..=2100).contains(&y) || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    Some(format!("{y:04}-{m:02}-{d:02} 00:00:00.000"))
}

pub fn best_time(install_date: Option<&str>, key_time: Option<&String>) -> String {
    parse_install_date(install_date.unwrap_or(""))
        .or_else(|| key_time.map(|s| s.clone()))
        .unwrap_or_else(|| "（无时间戳）".into())
}

pub struct SoftwareCollector;

impl Default for SoftwareCollector {
    fn default() -> Self {
        Self
    }
}

impl Collector for SoftwareCollector {
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
        let mut roots: Vec<(String, &'static str)> = vec![
            (
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall".into(),
                "HKLM",
            ),
            (
                r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall".into(),
                "HKLM",
            ),
        ];
        for sid in crate::regutil::user_sids() {
            roots.push((
                format!(
                    r"{sid}\Software\Microsoft\Windows\CurrentVersion\Uninstall"
                ),
                "HKU",
            ));
        }
        for (root, hive) in roots {
            // HKU 路径必须用 users 根，HKLM 用 local_machine
            let hkey = if hive == "HKU" {
                HKEY::users()
            } else {
                HKEY::local_machine()
            };
            let Ok(apps) = subkeys(hkey, &root) else {
                continue;
            };
            let _ = hkey;
            // HKU 路径必须用 users 根，HKLM 用 local_machine
            let hkey = if hive == "HKU" {
                HKEY::users()
            } else {
                HKEY::local_machine()
            };
            for app in apps {
                let key_path = format!(r"{root}\{app}");
                let Ok(name) = crate::regutil::read_string_value(hkey, &key_path, "DisplayName")
                else {
                    continue;
                };
                let name = name.trim_end_matches('\0').to_string();
                if name.is_empty() {
                    continue;
                }
                let version = crate::regutil::read_string_value(hkey, &key_path, "DisplayVersion")
                    .unwrap_or_default()
                    .trim_end_matches('\0')
                    .to_string();
                let install_date = crate::regutil::read_string_value(hkey, &key_path, "InstallDate")
                    .ok()
                    .map(|s| s.trim_end_matches('\0').to_string());
                let key_time = key_last_write(hkey, &key_path);
                let mut info_parts: Vec<String> = Vec::new();
                if !version.is_empty() {
                    info_parts.push(version);
                }
                info_parts.push(format!("来源 {hive}"));
                events.push(ActivityEvent {
                    time: best_time(install_date.as_deref(), key_time.as_ref()),
                    kind: "软件安装".into(),
                    desc: name,
                    info: info_parts.join(" · "),
                    module: MODULE.into(),
                    sev: Sev::None,
                    tags: vec![],
                });
            }
        }
        logs.push(format!("共 {} 个已安装软件", events.len()));
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
            raw: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_date_parses() {
        assert_eq!(
            parse_install_date("20251023").unwrap(),
            "2025-10-23 00:00:00.000"
        );
        assert!(parse_install_date("abc").is_none());
        assert!(parse_install_date("20251399").is_none());
        assert!(parse_install_date("2025102").is_none());
    }

    #[test]
    fn picks_best_time() {
        assert_eq!(
            best_time(Some("20251023"), Some(&"2025-11-01 10:00:00.000".into())),
            "2025-10-23 00:00:00.000"
        );
        assert_eq!(
            best_time(None, Some(&"2025-11-01 10:00:00.000".into())),
            "2025-11-01 10:00:00.000"
        );
        assert_eq!(best_time(None, None), "（无时间戳）");
    }

    #[test]
    #[ignore = "真实 HKLM；本机 cargo test -- --ignored"]
    fn collector_reads_real_uninstall() {
        let r = SoftwareCollector::default().run();
        assert!(r.count >= 10, "{:?}", r.logs);
    }
}
