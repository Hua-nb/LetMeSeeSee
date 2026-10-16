//! 落盘文件扫描模块：ProgramData/Public/Temp/AppData 等用户可写目录中
//! 近 N 天（默认 14，LMSS_DROPPED_DAYS 覆盖）创建或修改的可执行文件。
//! 回答"攻击者丢下了什么文件"——与 Prefetch/AmCache 的"执行过什么"互补。
//! 噪声控制：排除 Package Cache 等安装器缓存、深度与数量上限、跳过符号链接。

use crate::model::{ActivityEvent, Collector, ModuleResult, ModuleStatus, RawTable, Sev, Tag};
use std::time::Instant;

pub const MODULE: &str = "落盘文件扫描";

const RAW_COLS: &[&str] = &["路径", "大小", "创建时间", "修改时间"];

const MAX_DEPTH: usize = 5;
const MAX_RESULTS: usize = 2000;

/// 值得关注的可执行/脚本扩展名
pub fn is_watchable_file(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    [".exe", ".dll", ".scr", ".sys", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".msi", ".hta"]
        .iter()
        .any(|e| l.ends_with(e))
}

/// 已知高噪声子目录（安装器缓存/系统组件/开发工具缓存），命中即整棵跳过
const NOISY: &[&str] = &[
    r"\package cache\",
    r"\usoshared\",
    r"\microsoft\windows defender\",
    r"\microsoft\windows\dnscache\",
    r"\microsoft\windows\appx\",
    r"\microsoft\windows\apps\",
    r"\microsoft\windows\deliveryoptimization\",
    r"\microsoft\vault\",
    r"\regid.1991-06.com.microsoft\",
    r"\desktopspotlight\",
    r"\npm\",
    r"\npm-cache\",
    r"\nuget\",
    r"\pip\cache\",
    r"\python\lib\site-packages\",
];

/// R-021 只对"直接可执行/脚本"打标——Temp 里的 .dll/.msi 多为安装器/更新器解压
/// 噪声（Chrome 更新一次就是几十个 dll），.exe/.scr/.hta 等才是投递信号；
/// 其余文件仍进时间线与原表，只是不打标
const TAG_EXTS: &[&str] = &[
    ".exe", ".scr", ".hta", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".com", ".pif", ".jse",
    ".wsf",
];

pub fn is_taggable(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    TAG_EXTS.iter().any(|e| l.ends_with(e))
}

/// R-021 只标"经典投递点"（Temp/Public/Perflogs/启动文件夹）——ProgramData/Roaming
/// 里大量为正规软件自更新产物，全标黄会稀释告警（仍进时间线与原表，只是不打标）
fn is_classic_drop_spot(p: &str) -> bool {
    let l = p.to_ascii_lowercase();
    l.contains(r"\temp\") || l.contains(r"c:\windows\temp") || l.contains(r"c:\users\public") || l.contains(r"c:\perflogs")
}

pub fn is_noisy_path(p: &str) -> bool {
    let l = p.to_ascii_lowercase();
    NOISY.iter().any(|n| l.contains(n))
}

fn fmt_time(t: Option<std::time::SystemTime>) -> String {
    t.map(|x| {
        chrono::DateTime::<chrono::Local>::from(x)
            .format("%Y-%m-%d %H:%M:%S.000")
            .to_string()
    })
    .unwrap_or_else(|| "（无时间戳）".into())
}

fn within_days(sys: std::time::SystemTime, days: i64) -> bool {
    let Ok(elapsed) = sys.elapsed() else {
        return false; // 未来时间戳（时钟异常）——不当作近期
    };
    elapsed.as_secs() <= (days * 86400) as u64
}

pub struct DroppedCollector {
    pub days: i64,
}

impl Default for DroppedCollector {
    fn default() -> Self {
        let days = std::env::var("LMSS_DROPPED_DAYS")
            .ok()
            .and_then(|s| s.parse().ok())
            .filter(|d| *d > 0 && *d <= 365)
            .unwrap_or(14);
        Self { days }
    }
}

impl Collector for DroppedCollector {
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

        // 扫描根：固定目录 + 每用户 AppData 两处
        let mut roots: Vec<String> = vec![
            r"C:\ProgramData".into(),
            r"C:\Users\Public".into(),
            r"C:\Windows\Temp".into(),
            r"C:\Perflogs".into(),
        ];
        if let Ok(users) = std::fs::read_dir(r"C:\Users") {
            for u in users.flatten() {
                let n = u.file_name().to_string_lossy().into_owned();
                if n.starts_with('.') {
                    continue;
                }
                roots.push(format!(r"C:\Users\{n}\AppData\Local\Temp"));
                roots.push(format!(r"C:\Users\{n}\AppData\Roaming"));
            }
        }

        let mut scanned = 0usize;
        for root in &roots {
            self.walk_dir(
                std::path::Path::new(root),
                0,
                &mut scanned,
                &mut events,
                &mut rows,
            );
            if rows.len() >= MAX_RESULTS {
                logs.push(format!("结果达 {MAX_RESULTS} 条上限，其余不再列出（可缩小天数重扫）"));
                break;
            }
        }
        logs.push(format!(
            "扫描 {} 个目录树、约 {scanned} 个文件；命中 {} 个近 {} 天可执行/脚本文件（时间=文件修改时间，创建时间见原表）",
            roots.len(),
            rows.len(),
            self.days
        ));
        ModuleResult {
            module: self.id().into(),
            status: if rows.is_empty() {
                ModuleStatus::Ok // 无近期落盘本身是正常健康状态
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

impl DroppedCollector {
    fn walk_dir(
        &self,
        dir: &std::path::Path,
        depth: usize,
        scanned: &mut usize,
        events: &mut Vec<ActivityEvent>,
        rows: &mut Vec<Vec<String>>,
    ) {
        if depth > MAX_DEPTH || rows.len() >= MAX_RESULTS {
            return;
        }
        if is_noisy_path(&dir.to_string_lossy()) {
            return;
        }
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            if rows.len() >= MAX_RESULTS {
                return;
            }
            let path = e.path();
            // 跳过符号链接/联接点，防止环路与越界遍历
            if e.file_type().map(|t| t.is_symlink()).unwrap_or(false) {
                continue;
            }
            if path.is_dir() {
                self.walk_dir(&path, depth + 1, scanned, events, rows);
                continue;
            }
            *scanned += 1;
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if !is_watchable_file(name) {
                continue;
            }
            let Ok(meta) = std::fs::metadata(&path) else {
                continue;
            };
            let modified = match meta.modified() {
                Ok(m) => m,
                Err(_) => continue,
            };
            let created = meta.created().ok();
            let recent_mod = within_days(modified, self.days);
            let recent_create = created.map(|c| within_days(c, self.days)).unwrap_or(false);
            if !recent_mod && !recent_create {
                continue;
            }
            let mtime = fmt_time(Some(modified));
            let ctime = fmt_time(created);
            let size = meta.len();
            let p_str = path.to_string_lossy();
            let classic = is_classic_drop_spot(&p_str) && is_taggable(name);
            events.push(ActivityEvent {
                time: mtime.clone(),
                kind: "近期落盘文件".into(),
                desc: p_str.into_owned(),
                info: format!(
                    "{size} 字节 · 创建 {ctime} · 时间=文件修改时间 · 用户可写目录近 {} 天{}",
                    self.days,
                    if classic { " · 位于经典投递目录" } else { "" }
                ),
                module: MODULE.into(),
                sev: if classic { Sev::Yellow } else { Sev::None },
                tags: if classic {
                    vec![Tag {
                        sev: Sev::Yellow,
                        text: "R-021 近期落盘可执行文件".into(),
                    }]
                } else {
                    vec![]
                },
            });
            rows.push(vec![
                path.to_string_lossy().into_owned(),
                size.to_string(),
                ctime,
                mtime,
            ]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watchable_extensions() {
        assert!(is_watchable_file("x.EXE"));
        assert!(is_watchable_file("payload.ps1"));
        assert!(is_watchable_file("mshta.hta"));
        assert!(!is_watchable_file("note.txt"));
        assert!(!is_watchable_file("photo.jpg"));
    }

    #[test]
    fn noisy_paths_excluded() {
        assert!(is_noisy_path(r"C:\ProgramData\Package Cache\{GUID}\vcredist.exe"));
        assert!(!is_noisy_path(r"C:\ProgramData\MyApp\svc.exe"));
    }

    #[test]
    fn taggable_narrowed_to_direct_executables() {
        // 误报治理：dll/msi（安装器解压噪声）不打标，exe/脚本才打
        assert!(is_taggable("dropped.EXE"));
        assert!(is_taggable("run.bat"));
        assert!(is_taggable("shell.hta"));
        assert!(!is_taggable("chrome_child.dll"));
        assert!(!is_taggable("update.msi"));
        assert!(!is_taggable("readme.txt"));
    }

    #[test]
    fn collector_runs_fast_on_this_machine() {
        let r = DroppedCollector { days: 1 }.run();
        assert!(!r.logs.is_empty());
        assert!(r.duration_ms < 60_000, "扫描不应超过 60s：{}", r.duration_ms);
    }
}
