use crate::model::{ActivityEvent, Collector, ModuleResult, ModuleStatus, Sev};
use std::time::Instant;

pub const MODULE: &str = "崩溃记录（WER/Minidump）";

/// 从 WER Report.wer（INI 文本）取字段值
pub fn wer_field(ini: &str, key: &str) -> Option<String> {
    for line in ini.lines() {
        let line = line.trim();
        if let Some((k, v)) = line.split_once('=') {
            if k.trim().eq_ignore_ascii_case(key) {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

/// 读 .wer 文件（UTF-8 或 UTF-16LE 试探）
fn read_wer_text(path: &std::path::Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    if bytes.starts_with(&[0xFF, 0xFE]) {
        let units: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        Some(String::from_utf16_lossy(&units))
    } else {
        Some(crate::encoding::decode_ansi_or_utf8(&bytes))
    }
}

fn mtime_string(p: &std::path::Path) -> Option<String> {
    use std::time::UNIX_EPOCH;
    let t = std::fs::metadata(p).ok()?.modified().ok()?;
    let ms = t.duration_since(UNIX_EPOCH).ok()?.as_millis() as i64;
    use chrono::TimeZone;
    let local = chrono::Local.timestamp_millis_opt(ms).single()?;
    Some(local.format("%Y-%m-%d %H:%M:%S%.3f").to_string())
}

pub fn dump_event(filename: &str, time: &str) -> ActivityEvent {
    ActivityEvent {
        time: time.into(),
        kind: "蓝屏".into(),
        desc: format!("内核转储 {filename}"),
        info: "C:\\Windows\\Minidump · 蓝屏转储文件".into(),
        module: MODULE.into(),
        sev: Sev::None,
        tags: vec![],
    }
}

pub struct CrashesCollector;

impl Default for CrashesCollector {
    fn default() -> Self {
        Self
    }
}

impl Collector for CrashesCollector {
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

        // 1) 内核 Minidump（蓝屏小转储）+ 完整内存转储 MEMORY.DMP
        match std::fs::read_dir(r"C:\Windows\Minidump") {
            Ok(entries) => {
                let mut n = 0;
                for e in entries.flatten() {
                    let p = e.path();
                    if p.extension().and_then(|x| x.to_str()) == Some("dmp") {
                        let time = mtime_string(&p).unwrap_or_else(|| "（无时间戳）".into());
                        events.push(dump_event(
                            &e.file_name().to_string_lossy(),
                            &time,
                        ));
                        n += 1;
                    }
                }
                logs.push(format!("Minidump：{n} 个内核转储"));
            }
            Err(e) => logs.push(format!("Minidump 不可读（多需管理员）：{e}")),
        }
        let full_dump = r"C:\Windows\MEMORY.DMP";
        if let Ok(meta) = std::fs::metadata(full_dump) {
            if meta.is_file() {
                let time = mtime_string(std::path::Path::new(full_dump))
                    .unwrap_or_else(|| "（无时间戳）".into());
                events.push(ActivityEvent {
                    time,
                    kind: "蓝屏".into(),
                    desc: "MEMORY.DMP（完整内存转储）".into(),
                    info: format!(
                        "C:\\Windows\\MEMORY.DMP · {} MB · 一次完整蓝屏转储",
                        meta.len() / 1024 / 1024
                    ),
                    module: MODULE.into(),
                    sev: Sev::None,
                    tags: vec![],
                });
                logs.push("MEMORY.DMP：存在完整内存转储".into());
            }
        }

        // 2) 用户态 WER 归档/队列（应用崩溃）。
        // 两级存储都要扫：每用户 AppData（用户态应用）+ ProgramData（系统级，
        // 服务/提权进程的报告都落这里——只扫用户目录会漏掉整机大部分报告）
        let mut wer_n = 0usize;
        let mut sources: Vec<(std::path::PathBuf, String)> = Vec::new();
        if let Ok(users) = std::fs::read_dir(r"C:\Users") {
            for user in users.flatten() {
                for sub in ["ReportArchive", "ReportQueue"] {
                    sources.push((
                        user.path()
                            .join(r"AppData\Local\Microsoft\Windows\WER")
                            .join(sub),
                        format!("用户 {}", user.file_name().to_string_lossy()),
                    ));
                }
            }
        }
        for sub in ["ReportArchive", "ReportQueue"] {
            sources.push((
                std::path::PathBuf::from(r"C:\ProgramData\Microsoft\Windows\WER").join(sub),
                "系统级（ProgramData）".into(),
            ));
        }
        for (dir, source) in &sources {
            let Ok(reports) = std::fs::read_dir(dir) else {
                continue;
            };
            for r in reports.flatten() {
                let wer_file = r.path().join("Report.wer");
                if !wer_file.is_file() {
                    continue;
                }
                let time = mtime_string(&wer_file).unwrap_or_else(|| "（无时间戳）".into());
                let text = read_wer_text(&wer_file);
                let app = text
                    .as_deref()
                    .and_then(|t| {
                        wer_field(t, "AppName").or_else(|| wer_field(t, "AppPath"))
                    })
                    .unwrap_or_else(|| r.file_name().to_string_lossy().into_owned());
                let event_type = text
                    .as_deref()
                    .and_then(|t| wer_field(t, "EventType"))
                    .unwrap_or_default();
                events.push(ActivityEvent {
                    time,
                    kind: "应用崩溃".into(),
                    desc: app,
                    info: format!("WER · {event_type} · {source}"),
                    module: MODULE.into(),
                    sev: Sev::None,
                    tags: vec![],
                });
                wer_n += 1;
            }
        }
        logs.push(format!("WER：{wer_n} 份应用崩溃报告（用户级 + 系统级）"));
        if events.is_empty() {
            logs.push("无崩溃记录（或权限不足）".into());
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
    fn wer_app_name_from_ini() {
        let ini = "Version=1\r\n[_unsigned]\r\nAppName=Everything\r\nAppPath=C:\\x\r\n";
        assert_eq!(wer_field(ini, "AppName").as_deref(), Some("Everything"));
        assert_eq!(
            wer_field(ini, "appname").as_deref(),
            Some("Everything"),
            "大小写不敏感"
        );
        assert_eq!(wer_field(ini, "Nope"), None);
    }

    #[test]
    fn kernel_dump_name_parses() {
        let e = dump_event("091922-6789-01.dmp", "2026-09-19 22:47:52.003");
        assert!(e.desc.contains("091922"));
        assert!(e.info.contains("蓝屏"));
    }

    #[test]
    fn collector_handles_empty_sources() {
        let r = CrashesCollector::default().run();
        assert!(!r.logs.is_empty());
    }

    /// 回归：ProgramData WER ReportArchive 存在 N 份报告时模块必须产出事件——
    /// 旧版只扫每用户 AppData，本机 38 份系统级报告全部不可见（count=0 而无异常）
    #[test]
    #[ignore = "真实 WER；本机 cargo test -- --ignored"]
    fn collector_sees_programdata_wer_reports() {
        let mut n = 0usize;
        for sub in ["ReportArchive", "ReportQueue"] {
            let dir = std::path::Path::new(r"C:\ProgramData\Microsoft\Windows\WER").join(sub);
            if let Ok(reports) = std::fs::read_dir(&dir) {
                for r in reports.flatten() {
                    if r.path().join("Report.wer").is_file() {
                        n += 1;
                    }
                }
            }
        }
        let res = CrashesCollector::default().run();
        if n > 0 {
            assert!(
                res.count >= n,
                "ProgramData 有 {n} 份 WER 报告但模块仅 {} 条：{:?}",
                res.count,
                res.logs
            );
        }
    }
}
