use crate::model::{ActivityEvent, Collector, ModuleResult, ModuleStatus, Sev};
use crate::regutil::{read_value, subkeys, value_names, HKEY};
use crate::timeutil::filetime_to_local;
use std::time::Instant;

pub const MODULE: &str = "后台活动监控（BAM/DAM）";

/// BAM 值数据：FILETIME(8)，部分版本后附 4 字节未知量
pub fn parse_bam_value(b: &[u8]) -> Option<u64> {
    if b.len() < 8 {
        return None;
    }
    Some(u64::from_le_bytes(b[..8].try_into().unwrap()))
}

pub struct BamCollector;

impl Default for BamCollector {
    fn default() -> Self {
        Self
    }
}

impl Collector for BamCollector {
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
        let mut status = ModuleStatus::Ok;

        let root = r"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings";
        let sids = match subkeys(HKEY::local_machine(), root) {
            Ok(s) => s,
            Err(e) => {
                logs.push(format!(
                    "{e}（BAM 通常需要管理员权限；Win11 22H2+ 可能已移除该键）"
                ));
                return ModuleResult {
                    module: self.id().into(),
                    status: ModuleStatus::Warn,
                    count: 0,
                    duration_ms: t0.elapsed().as_millis(),
                    logs,
                    events,
                    raw: None,
                };
            }
        };
        for sid in sids {
            let key_path = format!(r"{root}\{sid}");
            let Ok(names) = value_names(HKEY::local_machine(), &key_path) else {
                continue;
            };
            for name in names {
                if name == "SequenceNumber" {
                    continue;
                }
                let Ok((bytes, _ty)) = read_value(HKEY::local_machine(), &key_path, &name) else {
                    continue;
                };
                // 值名即程序完整路径（winreg 已解码为 UTF-8 字符串）
                if let Some(ft) = parse_bam_value(&bytes) {
                    if let Some(t) = filetime_to_local(ft) {
                        events.push(ActivityEvent {
                            time: t,
                            kind: "程序最后执行".into(),
                            desc: name,
                            info: format!("后台活动监控 · 用户 {sid}"),
                            module: MODULE.into(),
                            sev: Sev::None,
                            tags: vec![],
                        });
                    }
                }
            }
        }
        logs.push(format!("共 {} 条 BAM 记录", events.len()));
        if events.is_empty() {
            status = ModuleStatus::Warn;
            logs.push("无 BAM 记录（需管理员 / 新版 Windows 已移除）".into());
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

    #[test]
    fn parses_8byte_filetime() {
        let ft: u64 = 134_345_473_332_450_000;
        assert_eq!(parse_bam_value(&ft.to_le_bytes()).unwrap(), ft);
    }

    #[test]
    fn parses_12_byte_variant() {
        let ft: u64 = 134_345_473_332_450_000;
        let mut b = vec![];
        b.extend_from_slice(&ft.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(parse_bam_value(&b).unwrap(), ft);
    }

    #[test]
    fn too_short_is_none() {
        assert!(parse_bam_value(&[0u8; 4]).is_none());
    }

    #[test]
    fn collector_degrades_gracefully_without_admin() {
        // 非管理员机器上该模块必须返回 Warn 而非 panic
        let r = BamCollector::default().run();
        assert!(!r.logs.is_empty());
        matches!(r.status, ModuleStatus::Ok | ModuleStatus::Warn);
    }
}
