//! 高级持久化检查：Run/任务/服务/WMI 之外的高频劫持落点。
//! - IFEO Debugger（映像劫持：启动目标程序时改为启动调试器命令）
//! - AppInit_DLLs（全局 DLL 注入）
//! - LSA SecurityPackages/AuthenticationPackages（mimikatz 内存凭据持久化）
//! - 屏幕保护程序劫持（HKU 每用户）
//! 全部为纯注册表读取，无外部命令依赖。命中 → R-019。

use crate::model::{ActivityEvent, Collector, ModuleResult, ModuleStatus, RawTable, Sev, Tag};
use crate::regutil::{key_last_write, read_string_value, subkeys, value_names, HKEY};
use std::time::Instant;

pub const MODULE: &str = "高级持久化检查";

const RAW_COLS: &[&str] = &["类型", "位置", "数据", "判定", "键最后写入时间"];

/// LSA SecurityPackages 的系统默认成员（多出的即注入）
pub const DEFAULT_SECURITY_PACKAGES: &[&str] = &[
    "kerberos", "msv1_0", "schannel", "wdigest", "tspkg", "pku2u", "cloudap", "negoexts",
];

/// AuthenticationPackages 默认只有 msv1_0
pub const DEFAULT_AUTH_PACKAGES: &[&str] = &["msv1_0"];

/// LSA 包列表相对默认集合多出的条目（逗号/空格分隔；大小写不敏感）
pub fn extra_lsa_packages(value: &str, defaults: &[&str]) -> Vec<String> {
    value
        .split([',', ' '])
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .filter(|s| !defaults.iter().any(|d| d.eq_ignore_ascii_case(s)))
        .map(|s| s.to_string())
        .collect()
}

fn tag19(sev: Sev) -> Vec<Tag> {
    vec![Tag {
        sev,
        text: "R-019 持久化劫持".into(),
    }]
}

pub struct AdvPersistCollector;

impl Default for AdvPersistCollector {
    fn default() -> Self {
        Self
    }
}

impl Collector for AdvPersistCollector {
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
        let mut hits = 0usize;

        let mut push = |kind: &str,
                        loc: &str,
                        data: &str,
                        note: &str,
                        sev: Sev,
                        time: Option<String>,
                        events: &mut Vec<ActivityEvent>,
                        rows: &mut Vec<Vec<String>>| {
            let t = time.unwrap_or_else(|| "（无时间戳）".into());
            events.push(ActivityEvent {
                time: t.clone(),
                kind: kind.into(),
                desc: loc.to_string(),
                info: format!("{data} · {note} · 键最后写入时间"),
                module: MODULE.into(),
                sev,
                tags: tag19(sev),
            });
            rows.push(vec![
                kind.into(),
                loc.into(),
                data.into(),
                note.into(),
                t,
            ]);
        };

        // ---- IFEO Debugger（含 WOW6432Node）----
        for (root_path, tag) in [
            (
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
                "IFEO",
            ),
            (
                r"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
                "IFEO（32位）",
            ),
        ] {
            if let Ok(names) = subkeys(HKEY::local_machine(), root_path) {
                for exe in names {
                    let key_path = format!(r"{root_path}\{exe}");
                    if let Ok(dbg) = read_string_value(HKEY::local_machine(), &key_path, "Debugger")
                    {
                        if !dbg.trim().is_empty() {
                            hits += 1;
                            push(
                                "持久化劫持",
                                &format!("{tag} Debugger：{exe}"),
                                &dbg,
                                "启动该程序时将转而执行 Debugger 命令",
                                Sev::Red,
                                key_last_write(HKEY::local_machine(), &key_path),
                                &mut events,
                                &mut rows,
                            );
                        }
                    }
                }
            }
        }

        // ---- AppInit_DLLs（含 WOW6432Node）----
        for (win_path, tag) in [
            (
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
                "AppInit_DLLs",
            ),
            (
                r"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows",
                "AppInit_DLLs（32位）",
            ),
        ] {
            if let Ok(dlls) = read_string_value(HKEY::local_machine(), win_path, "AppInit_DLLs") {
                if !dlls.trim().is_empty() {
                    hits += 1;
                    push(
                        "持久化劫持",
                        &format!("{tag}（HKLM）"),
                        &dlls,
                        "将注入到每个使用标准 USER32 的 GUI 进程",
                        Sev::Red,
                        key_last_write(HKEY::local_machine(), win_path),
                        &mut events,
                        &mut rows,
                    );
                }
            }
        }

        // ---- LSA 包注入 ----
        let lsa = r"SYSTEM\CurrentControlSet\Control\Lsa";
        for (value, defaults, label) in [
            ("SecurityPackages", DEFAULT_SECURITY_PACKAGES, "LSA SecurityPackages"),
            ("AuthenticationPackages", DEFAULT_AUTH_PACKAGES, "LSA AuthenticationPackages"),
        ] {
            if let Ok(v) = read_string_value(HKEY::local_machine(), lsa, value) {
                let extra = extra_lsa_packages(&v, defaults);
                if !extra.is_empty() {
                    hits += 1;
                    push(
                        "持久化劫持",
                        &format!("{label}（HKLM）"),
                        &v,
                        &format!("多出默认集合之外的包：{}（加载进 lsass，mimikatz 持久化常见）", extra.join("、")),
                        Sev::Red,
                        key_last_write(HKEY::local_machine(), lsa),
                        &mut events,
                        &mut rows,
                    );
                }
            }
        }

        // ---- 屏保劫持（每用户 HKU）----
        for sid in crate::regutil::user_sids() {
            let desk = format!(r"{sid}\Control Panel\Desktop");
            if let Ok(scr) = read_string_value(HKEY::users(), &desk, "SCRNSAVE.EXE") {
                if !scr.trim().is_empty() {
                    let l = scr.to_ascii_lowercase();
                    let in_system = l.starts_with(r"c:\windows\system32\") || l.starts_with(r"c:\windows\");
                    let note = if in_system {
                        "系统目录内（通常为正常屏保）"
                    } else {
                        "屏保指向系统目录之外——登录触发执行"
                    };
                    let sev = if in_system { Sev::None } else { Sev::Yellow };
                    if !in_system {
                        hits += 1;
                    }
                    // 系统目录内的正常屏保也记入原表（完整性），但不进时间线
                    let t = key_last_write(HKEY::users(), &desk);
                    rows.push(vec![
                        "屏保".into(),
                        format!(r"HKU\{sid}\Control Panel\Desktop\SCRNSAVE.EXE"),
                        scr.clone(),
                        note.into(),
                        t.clone().unwrap_or_else(|| "（无时间戳）".into()),
                    ]);
                    if !in_system {
                        events.push(ActivityEvent {
                            time: t.unwrap_or_else(|| "（无时间戳）".into()),
                            kind: "持久化劫持".into(),
                            desc: format!("屏保劫持（用户 {sid}）"),
                            info: format!(
                                "{scr} · 登录空闲触发执行 · 键最后写入时间"
                            ),
                            module: MODULE.into(),
                            sev,
                            tags: tag19(sev),
                        });
                    }
                }
            }
        }

        // 健康说明：以上各键全部为空/默认时 events 为空——这正是期望状态
        let checked = value_names(HKEY::local_machine(), r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows")
            .is_ok();
        logs.push(format!(
            "检查项：IFEO Debugger / AppInit_DLLs / LSA 包 / 屏保{}；命中 {hits} 项（无命中为健康状态）",
            if checked { " / 启动文件夹继承自自启动模块" } else { "" }
        ));
        ModuleResult {
            module: self.id().into(),
            status: if hits > 0 {
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
    fn extra_lsa_packages_detected() {
        assert_eq!(
            extra_lsa_packages("kerberos msv1_0 schannel wdigest tspkg pku2u", DEFAULT_SECURITY_PACKAGES),
            Vec::<String>::new()
        );
        assert_eq!(
            extra_lsa_packages("msv1_0, evil.dll", DEFAULT_AUTH_PACKAGES),
            vec!["evil.dll".to_string()]
        );
        // 大小写不敏感；空串干净
        assert_eq!(
            extra_lsa_packages("MSV1_0", DEFAULT_AUTH_PACKAGES),
            Vec::<String>::new()
        );
        assert_eq!(extra_lsa_packages("", DEFAULT_SECURITY_PACKAGES), Vec::<String>::new());
    }

    #[test]
    fn collector_runs_clean() {
        let r = AdvPersistCollector::default().run();
        assert!(!r.logs.is_empty());
        matches!(r.status, ModuleStatus::Ok | ModuleStatus::Warn);
    }
}
