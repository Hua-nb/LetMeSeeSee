//! 回收站模块：解析各盘 \$Recycle.Bin\<SID>\$I*（删除元数据）。
//! $I v2（Win8+，本机 Win10 22H2 十六进制实测布局）：
//!   [u64 版本=2][u64 原始大小][u64 删除 FILETIME][u32 路径字符数][UTF-16 原路径 NUL 结尾]
//!   ——路径从偏移 28 起；漏读 4 字节长度前缀会把长度字节当路径，全部条目被静默丢弃
//! $I v1（Vista/7）：[u64 版本=1][u64 原始大小][u32 删除时间 epoch][UTF-16 原路径]
//! 时间=真实删除时刻；可执行文件被删尤其值得关注（攻击者清理痕迹）。

use crate::model::{ActivityEvent, Collector, ModuleResult, ModuleStatus, RawTable, Sev, Tag};
use crate::timeutil::filetime_to_local;
use std::time::Instant;

pub const MODULE: &str = "回收站";

const RAW_COLS: &[&str] = &["原路径", "删除时间", "大小", "删除者 SID", "盘"];

/// 解析 $I 文件 → (原路径, 删除时间毫秒 epoch, 大小)
pub fn parse_dollar_i(b: &[u8]) -> Option<(String, Option<i64>, u64)> {
    if b.len() >= 8 {
        let ver = u64::from_le_bytes(b[..8].try_into().ok()?);
        if ver == 2 && b.len() >= 28 {
            let size = u64::from_le_bytes(b[8..16].try_into().ok()?);
            let ft = u64::from_le_bytes(b[16..24].try_into().ok()?);
            // 24..28 = u32 路径长度（字符数，含结尾 NUL）；路径本体从偏移 28 起
            let units: Vec<u16> = b[28..]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .take_while(|&u| u != 0)
                .collect();
            let path = String::from_utf16_lossy(&units);
            if path.is_empty() {
                return None;
            }
            let ms = if ft > 0 {
                Some((ft / 10_000) as i64 - 11_644_473_600_000)
            } else {
                None
            };
            return Some((path, ms, size));
        }
        if ver == 1 && b.len() >= 20 {
            let size = u64::from_le_bytes(b[8..16].try_into().ok()?);
            let epoch = u32::from_le_bytes(b[16..20].try_into().ok()?);
            let units: Vec<u16> = b[20..]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .take_while(|&u| u != 0)
                .collect();
            let path = String::from_utf16_lossy(&units);
            if path.is_empty() {
                return None;
            }
            return Some((path, (epoch > 0).then(|| epoch as i64 * 1000), size));
        }
    }
    None
}

/// 原路径合法性：须为盘符路径或 UNC（实测存在仅含 1 个控制字符的 $I 变体垃圾）
pub fn plausible_path(p: &str) -> bool {
    p.contains(r":\") || p.starts_with(r"\\")
}

fn is_executable(p: &str) -> bool {
    let l = p.to_ascii_lowercase();
    [".exe", ".dll", ".scr", ".sys", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".msi"]
        .iter()
        .any(|e| l.ends_with(e))
}

pub struct RecycleBinCollector;

impl Default for RecycleBinCollector {
    fn default() -> Self {
        Self
    }
}

impl Collector for RecycleBinCollector {
    fn id(&self) -> &'static str {
        MODULE
    }

    fn group(&self) -> &'static str {
        "文件访问记录"
    }

    fn run(&self) -> ModuleResult {
        let t0 = Instant::now();
        let mut logs = Vec::new();
        let mut events = Vec::new();
        let mut rows: Vec<Vec<String>> = Vec::new();

        // 枚举所有存在的固定盘 C:..Z:
        for c in b'C'..=b'Z' {
            let root = format!("{}:\\$Recycle.Bin", c as char);
            let Ok(sids) = std::fs::read_dir(&root) else {
                continue;
            };
            for sid_entry in sids.flatten() {
                let sid = sid_entry.file_name().to_string_lossy().into_owned();
                if sid.starts_with('.') {
                    continue;
                }
                let Ok(files) = std::fs::read_dir(sid_entry.path()) else {
                    continue;
                };
                for f in files.flatten() {
                    let name = f.file_name().to_string_lossy().into_owned();
                    if !name.starts_with("$I") {
                        continue;
                    }
                    let Ok(bytes) = std::fs::read(f.path()) else {
                        continue;
                    };
                    let Some((path, ms, size)) = parse_dollar_i(&bytes) else {
                        continue;
                    };
                    if !plausible_path(&path) {
                        continue; // 布局变体产出的垃圾串
                    }
                    let time = ms
                        .and_then(|m| {
                            use chrono::TimeZone;
                            chrono::Local
                                .timestamp_millis_opt(m)
                                .single()
                                .map(|d| d.format("%Y-%m-%d %H:%M:%S.000").to_string())
                        })
                        .unwrap_or_else(|| "（无时间戳）".into());
                    let exec = is_executable(&path);
                    events.push(ActivityEvent {
                        time: time.clone(),
                        kind: "回收站删除".into(),
                        desc: path.clone(),
                        info: format!(
                            "删除时大小 {size} 字节 · 用户 {} · {}盘回收站{}",
                            sid,
                            c as char,
                            if exec { " · 可执行文件被删除（痕迹清理关注点）" } else { "" }
                        ),
                        module: MODULE.into(),
                        sev: if exec { Sev::Yellow } else { Sev::None },
                        tags: if exec {
                            vec![Tag {
                                sev: Sev::Yellow,
                                text: "R-021 近期落盘可执行文件".into(),
                            }]
                        } else {
                            vec![]
                        },
                    });
                    rows.push(vec![
                        path,
                        time,
                        size.to_string(),
                        sid.clone(),
                        (c as char).to_string(),
                    ]);
                }
            }
        }
        logs.push(format!(
            "共 {} 条回收站删除记录（$R 文件仍在回收站内未清空时可恢复取证）",
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

    fn v2_i(path: &str, ft: u64, size: u64) -> Vec<u8> {
        let units: Vec<u16> = path.encode_utf16().collect();
        let mut b = Vec::new();
        b.extend_from_slice(&2u64.to_le_bytes());
        b.extend_from_slice(&size.to_le_bytes());
        b.extend_from_slice(&ft.to_le_bytes());
        // 真实布局：24..28 是 u32 路径字符数（含结尾 NUL），路径本体从偏移 28 起
        b.extend_from_slice(&((units.len() + 1) as u32).to_le_bytes());
        for u in units {
            b.extend_from_slice(&u.to_le_bytes());
        }
        b.extend_from_slice(&0u16.to_le_bytes());
        b
    }

    /// 本机 Win10 22H2 真实捕获的 $I v2（2026-10-16 11:31 删除的 txt）：
    /// 前缀字节逐字节照抄（含 size=0、FILETIME、0x21 长度前缀），防布局再错
    #[test]
    fn parses_real_captured_v2_prefix() {
        let path = r"C:\Users\user1\Desktop\test.txt";
        let units: Vec<u16> = path.encode_utf16().collect();
        let mut b: Vec<u8> = Vec::new();
        b.extend_from_slice(&[
            0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // u64 版本=2
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // u64 大小=0（实测出现过）
            0x30, 0x58, 0xad, 0xdd, 0x1e, 0x5d, 0xdd, 0x01, // u64 FILETIME（实测值）
        ]);
        b.extend_from_slice(&((units.len() + 1) as u32).to_le_bytes()); // 长度前缀
        for u in units {
            b.extend_from_slice(&u.to_le_bytes());
        }
        b.extend_from_slice(&0u16.to_le_bytes());
        let (p, ms, s) = parse_dollar_i(&b).unwrap();
        assert_eq!(p, path);
        assert_eq!(s, 0);
        assert!(ms.is_some(), "实测 FILETIME 应解出时间");
    }

    #[test]
    fn parses_v2() {
        use chrono::TimeZone;
        let ft: u64 = 134_345_473_332_450_000; // 2026-09-22 18:42:13.245 +08
        let b = v2_i(r"C:\Users\user1\Desktop\工具.exe", ft, 123456);
        let (p, ms, s) = parse_dollar_i(&b).unwrap();
        assert_eq!(p, r"C:\Users\user1\Desktop\工具.exe");
        assert_eq!(s, 123456);
        let local = chrono::Local
            .timestamp_millis_opt(ms.unwrap())
            .single()
            .unwrap();
        assert!(local.format("%Y-%m-%d %H:%M").to_string().starts_with("2026-09-22"), "{local}");
    }

    #[test]
    fn parses_v1_epoch() {
        let mut b = Vec::new();
        b.extend_from_slice(&1u64.to_le_bytes());
        b.extend_from_slice(&100u64.to_le_bytes());
        b.extend_from_slice(&1_700_000_000u32.to_le_bytes());
        for u in "C:\\x.txt".encode_utf16() {
            b.extend_from_slice(&u.to_le_bytes());
        }
        b.extend_from_slice(&0u16.to_le_bytes());
        let (p, ms, s) = parse_dollar_i(&b).unwrap();
        assert_eq!(p, "C:\\x.txt");
        assert_eq!(s, 100);
        assert_eq!(ms, Some(1_700_000_000_000));
    }

    #[test]
    fn garbage_rejected() {
        assert!(parse_dollar_i(&[]).is_none());
        assert!(parse_dollar_i(&[0u8; 10]).is_none());
        // 版本未知
        assert!(parse_dollar_i(&99u64.to_le_bytes()).is_none());
    }

    #[test]
    fn implausible_paths_rejected() {
        assert!(plausible_path(r"C:\Users\x\tool.exe"));
        assert!(plausible_path(r"\\server\share\f.exe"));
        assert!(!plausible_path(" "));
        assert!(!plausible_path("\u{1d}"));
        assert!(!plausible_path(""));
    }

    #[test]
    fn collector_runs_gracefully() {
        let r = RecycleBinCollector::default().run();
        assert!(!r.logs.is_empty());
    }
}

#[cfg(test)]
mod diag {
    use super::*;
    /// 回归：磁盘上存在 $I 文件时，模块必须产出同量级事件——
    /// 旧版布局错误导致 277 个文件全部被静默解析失败（count=0、无任何日志）
    #[test]
    #[ignore = "真实回收站；本机 cargo test -- --ignored"]
    fn collector_sees_existing_i_files() {
        let mut n = 0usize;
        for c in b'C'..=b'Z' {
            let root = format!(r"{}:\$Recycle.Bin", c as char);
            if let Ok(sids) = std::fs::read_dir(&root) {
                for s in sids.flatten() {
                    if let Ok(fs) = std::fs::read_dir(s.path()) {
                        n += fs
                            .flatten()
                            .filter(|f| f.file_name().to_string_lossy().starts_with("$I"))
                            .count();
                    }
                }
            }
        }
        let r = RecycleBinCollector::default().run();
        if n > 0 {
            assert!(r.count > 0, "磁盘有 {n} 个 $I 但模块 0 条：{:?}", r.logs);
            assert!(
                r.count >= n / 2,
                "磁盘 {n} 个 $I 仅解析出 {} 条，过半不可解需排查：{:?}",
                r.count,
                r.logs
            );
        } else {
            assert_eq!(r.count, 0, "无 $I 文件时不应有事件：{:?}", r.logs);
        }
    }
}
