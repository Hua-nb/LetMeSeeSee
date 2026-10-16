//! 自启动项模块：Run/RunOnce（HKLM + WOW6432Node + 每用户 HKU）、
//! Winlogon（Userinit/Shell 劫持检查）、启动文件夹（公共 + 每用户）。
//! 时间=各注册表键最后写入时间 / 启动文件修改时间（如实标注来源）。

use crate::model::{ActivityEvent, Collector, ModuleResult, ModuleStatus, RawTable, Sev};
use crate::regutil::{key_last_write, read_string_value, value_names, HKEY};
use std::time::Instant;

pub const MODULE: &str = "自启动项";

const RAW_COLS: &[&str] = &["位置", "名称", "数据", "来源类型", "最后写入时间"];

/// Winlogon 默认值之外的条目即疑似劫持（纯函数便于测试）
pub fn winlogon_abnormal(userinit: &str, shell: &str) -> Vec<&'static str> {
    let mut notes = Vec::new();
    let bad = |val: &str, allowed: &str| -> bool {
        val.split(',')
            .map(|t| t.trim().to_ascii_lowercase())
            .filter(|t| !t.is_empty())
            .any(|t| t != allowed)
    };
    if bad(userinit, "userinit.exe") {
        notes.push("Userinit 非默认值");
    }
    if bad(shell, "explorer.exe") {
        notes.push("Shell 非默认值");
    }
    notes
}

fn fmt_mtime(p: &std::path::Path) -> Option<String> {
    let m = std::fs::metadata(p).ok()?.modified().ok()?;
    Some(
        chrono::DateTime::<chrono::Local>::from(m)
            .format("%Y-%m-%d %H:%M:%S.000")
            .to_string(),
    )
}

fn push_startup_dir(
    events: &mut Vec<ActivityEvent>,
    rows: &mut Vec<Vec<String>>,
    dir: &str,
    scope: &str,
    logs: &mut Vec<String>,
) {
    let entries = match std::fs::read_dir(dir) {
        Ok(d) => d.filter_map(|e| e.ok()).collect::<Vec<_>>(),
        Err(_) => return, // 目录不存在（如无该用户）属正常
    };
    let mut n = 0;
    for e in entries {
        let path = e.path();
        if !path.is_file() {
            continue;
        }
        let name = e.file_name().to_string_lossy().to_string();
        if name.starts_with('.') {
            continue;
        }
        let t = fmt_mtime(&path).unwrap_or_else(|| "（无时间戳）".into());
        events.push(ActivityEvent {
            time: t.clone(),
            kind: "自启动项".into(),
            desc: format!("启动文件夹：{name}"),
            info: format!("{dir} · {scope} · 文件修改时间"),
            module: MODULE.into(),
            sev: Sev::None,
            tags: vec![],
        });
        rows.push(vec![
            dir.to_string(),
            name.clone(),
            "（启动项文件）".into(),
            scope.to_string(),
            t,
        ]);
        n += 1;
    }
    if n > 0 {
        logs.push(format!("{scope}：{n} 项"));
    }
}

pub struct AutoStartCollector;

impl Default for AutoStartCollector {
    fn default() -> Self {
        Self
    }
}

impl Collector for AutoStartCollector {
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

        // ---- 注册表 Run/RunOnce 家族 ----
        let mut run_keys: Vec<(HKEY, String, String, String)> = vec![
            (
                HKEY::local_machine(),
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run".into(),
                "HKLM Run".into(),
                "HKLM".into(),
            ),
            (
                HKEY::local_machine(),
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce".into(),
                "HKLM RunOnce".into(),
                "HKLM".into(),
            ),
            (
                HKEY::local_machine(),
                r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run".into(),
                "HKLM Run（32位）".into(),
                "HKLM".into(),
            ),
            (
                HKEY::local_machine(),
                r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce".into(),
                "HKLM RunOnce（32位）".into(),
                "HKLM".into(),
            ),
        ];
        for sid in crate::regutil::user_sids() {
            run_keys.push((
                HKEY::users(),
                format!(r"{sid}\Software\Microsoft\Windows\CurrentVersion\Run"),
                "用户 Run".into(),
                format!("HKU\\{sid}"),
            ));
            run_keys.push((
                HKEY::users(),
                format!(r"{sid}\Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                "用户 RunOnce".into(),
                format!("HKU\\{sid}"),
            ));
        }
        for (root, path, label, rootdisp) in run_keys {
            let Ok(names) = value_names(root, &path) else {
                continue;
            };
            let key_time = key_last_write(root, &path);
            let mut n = 0;
            for name in names {
                if name.is_empty() {
                    continue;
                }
                let cmd = read_string_value(root, &path, &name).unwrap_or_default();
                let t = key_time.clone().unwrap_or_else(|| "（无时间戳）".into());
                events.push(ActivityEvent {
                    time: t.clone(),
                    kind: "自启动项".into(),
                    desc: format!("{label}：{name}"),
                    info: format!("{cmd} · 键最后写入时间"),
                    module: MODULE.into(),
                    sev: Sev::None,
                    tags: vec![],
                });
                rows.push(vec![
                    format!(r"{rootdisp}\{path}"),
                    name.clone(),
                    cmd,
                    label.clone(),
                    t,
                ]);
                n += 1;
            }
            if n > 0 {
                logs.push(format!("{label}：{n} 项"));
            }
        }

        // ---- Winlogon 劫持检查 ----
        let wl = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
        let userinit = read_string_value(HKEY::local_machine(), wl, "Userinit").unwrap_or_default();
        let shell = read_string_value(HKEY::local_machine(), wl, "Shell").unwrap_or_default();
        if !userinit.is_empty() || !shell.is_empty() {
            let notes = winlogon_abnormal(&userinit, &shell);
            let note_txt = if notes.is_empty() {
                "默认值，未见劫持".to_string()
            } else {
                format!("⚠ {}", notes.join("；"))
            };
            let key_time = key_last_write(HKEY::local_machine(), wl);
            let t = key_time.unwrap_or_else(|| "（无时间戳）".into());
            events.push(ActivityEvent {
                time: t.clone(),
                kind: "自启动项".into(),
                desc: "Winlogon（Userinit/Shell）".into(),
                info: format!(
                    "Userinit={userinit} · Shell={shell} · {note_txt} · 键最后写入时间"
                ),
                module: MODULE.into(),
                sev: Sev::None,
                tags: vec![],
            });
            rows.push(vec![
                format!("HKLM\\{wl}"),
                "Userinit / Shell".into(),
                format!("Userinit={userinit}；Shell={shell}（{note_txt}）"),
                "Winlogon".into(),
                t,
            ]);
            if !notes.is_empty() {
                logs.push(format!("Winlogon 存在非默认值：{note_txt}"));
            }
        }

        // ---- 启动文件夹 ----
        push_startup_dir(
            &mut events,
            &mut rows,
            r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
            "公共启动文件夹",
            &mut logs,
        );
        if let Ok(users) = std::fs::read_dir(r"C:\Users") {
            for u in users.filter_map(|e| e.ok()) {
                let uname = u.file_name().to_string_lossy().to_string();
                let dir = format!(
                    r"C:\Users\{uname}\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
                );
                push_startup_dir(&mut events, &mut rows, &dir, &format!("用户 {uname} 启动文件夹"), &mut logs);
            }
        }

        if events.is_empty() {
            logs.push("未发现自启动项（异常：Run 键至少应有系统条目）".into());
        }
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
    fn winlogon_defaults_are_normal() {
        assert!(winlogon_abnormal("userinit.exe,", "explorer.exe").is_empty());
        assert!(winlogon_abnormal("userinit.exe", "explorer.exe").is_empty());
    }

    #[test]
    fn winlogon_hijack_detected() {
        let n = winlogon_abnormal("userinit.exe,C:\\x\\evil.exe,", "explorer.exe");
        assert_eq!(n, vec!["Userinit 非默认值"]);
        let n2 = winlogon_abnormal("userinit.exe,", "explorer.exe,evil.dll");
        assert_eq!(n2, vec!["Shell 非默认值"]);
    }

    #[test]
    #[ignore = "真实注册表；本机 cargo test -- --ignored"]
    fn collector_lists_run_entries() {
        let r = AutoStartCollector::default().run();
        assert!(r.count >= 5, "本机 Run 家族应至少数条：{:?}", r.logs);
        assert!(r.events.iter().any(|e| e.desc.contains("Winlogon")));
    }
}
