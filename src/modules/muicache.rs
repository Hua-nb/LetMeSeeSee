//! MUICache 模块：HKU\<sid>\Software\Classes\Local Settings\Software\
//! Microsoft\Windows\Shell\MuiCache——经 shell 启动过的程序清单。
//! 实测本机 1392 条，是经 shell 启动过的程序清单的重要数据源
//! （当 Prefetch 被清理时）。值名形如 "C:\path\app.exe.FriendlyAppName"。

use crate::model::{ActivityEvent, Collector, ModuleResult, ModuleStatus, Sev};
use crate::regutil::{key_last_write, value_names, HKEY};
use std::time::Instant;

pub const MODULE: &str = "程序启动缓存（MUICache）";

/// 从值名剥出 exe 路径："C:\x\app.exe.FriendlyAppName" → "C:\x\app.exe"
pub fn exe_path_from_value_name(name: &str) -> Option<String> {
    let lower = name.to_ascii_lowercase();
    let pos = lower.rfind(".exe")?;
    let path = &name[..pos + 4];
    if path.contains(':') {
        Some(path.to_string())
    } else {
        None
    }
}

pub struct MuiCacheCollector;

impl Default for MuiCacheCollector {
    fn default() -> Self {
        Self
    }
}

impl Collector for MuiCacheCollector {
    fn id(&self) -> &'static str {
        MODULE
    }

    fn group(&self) -> &'static str {
        "程序运行记录"
    }

    fn run(&self) -> ModuleResult {
        let t0 = Instant::now();
        let mut logs = Vec::new();
        let mut events = Vec::new();
        for sid in crate::regutil::user_sids() {
            // Win10+ 位置；旧系统位置作后备
            let paths = [
                format!(r"{sid}\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"),
                format!(r"{sid}\Software\Microsoft\Windows\CurrentVersion\Explorer\MUICache"),
            ];
            for key_path in paths {
                let Ok(names) = value_names(HKEY::users(), &key_path) else {
                    continue;
                };
                // 整键一个最后写入时间：只能作近似
                let key_time = key_last_write(HKEY::users(), &key_path);
                let mut count = 0usize;
                for n in names {
                    if let Some(path) = exe_path_from_value_name(&n) {
                        let ver = crate::verinfo::file_version_info(&path)
                            .map(|v| format!("{v} · "))
                            .unwrap_or_default();
                        // 存在性核验：MUICache 记录的是历史启动清单，程序可能已删除
                        let (enote, esuffix) = if !path.contains('\\') || path.starts_with(r"\\") {
                            ("", "")
                        } else if std::path::Path::new(&path).exists() {
                            ("", "")
                        } else {
                            (" · 路径已核验不存在（历史启动记录，文件可能已被删除/移动）", "（已不存在）")
                        };
                        events.push(ActivityEvent {
                            time: key_time
                                .clone()
                                .unwrap_or_else(|| "（无时间戳）".into()),
                            kind: "程序运行记录".into(),
                            desc: format!("{path}{esuffix}"),
                            info: format!(
                                "{ver}MUICache · 用户 {sid} · 时间为键最后写入（近似）{enote}"
                            ),
                            module: MODULE.into(),
                            sev: Sev::None,
                            tags: vec![],
                        });
                        count += 1;
                    }
                }
                if count > 0 {
                    logs.push(format!("{sid}：{count} 条程序路径"));
                }
            }
        }
        if events.is_empty() {
            logs.push("未发现 MUICache 记录".into());
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
            raw: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_exe_path() {
        assert_eq!(
            exe_path_from_value_name(r"C:\Tools\app.exe.FriendlyAppName"),
            Some(r"C:\Tools\app.exe".into())
        );
        assert_eq!(exe_path_from_value_name("LangID"), None);
    }

    #[test]
    fn uppercase_exe_suffix_handled() {
        assert_eq!(
            exe_path_from_value_name(r"D:\Bin\Tool.EXE.FriendlyAppName"),
            Some(r"D:\Bin\Tool.EXE".into())
        );
    }

    #[test]
    #[ignore = "真实 HKU；本机 cargo test -- --ignored"]
    fn collector_reads_real_muicache() {
        let r = MuiCacheCollector::default().run();
        assert!(r.count >= 100, "本机实测应上千条：{:?}", r.logs);
    }
}
