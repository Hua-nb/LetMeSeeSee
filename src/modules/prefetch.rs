//! Prefetch 模块：解析 C:\Windows\Prefetch\*.pf（SCCA v30/v31，Win10/11）。
//! 关键布局：version@0x00、"SCCA"@0x04、exe 路径 UTF16@0x10、
//! 最近 8 次运行 FILETIME@0x88、已用槽位@0xC8、总运行次数@0xD0。
//! **每次运行生成一条事件**（应急按时间段排查的核心诉求）。

use crate::model::{ActivityEvent, Collector, ModuleResult, ModuleStatus, Sev};
use crate::timeutil::filetime_to_local;
use std::path::Path;
use std::time::Instant;

pub const MODULE: &str = "程序预读取（Prefetch）";

const RUN_TIMES_OFF: usize = 0x88;
const SLOTS_USED_OFF: usize = 0xC8;
const TOTAL_RUNS_OFF: usize = 0xD0;

#[derive(Debug, PartialEq)]
pub struct PrefetchFile {
    pub exe_path: String,
    pub run_times: Vec<u64>,   // 实际使用的时间槽
    pub total_runs: u32,
}

/// 解析单个 .pf 文件（v30/v31）
pub fn parse_pf(b: &[u8]) -> Option<PrefetchFile> {
    if b.len() < 0xD4 {
        return None;
    }
    let version = u32::from_le_bytes(b[0..4].try_into().ok()?);
    if !(30..=31).contains(&version) || &b[4..8] != b"SCCA" {
        return None;
    }
    // exe 路径：UTF16 @0x10，到 NUL 为止（区界 0x54 前）
    let name_units: Vec<u16> = b[0x10..0x54]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&u| u != 0)
        .collect();
    if name_units.is_empty() {
        return None;
    }
    let exe_path = String::from_utf16_lossy(&name_units);
    let slots_used = u32::from_le_bytes(b[SLOTS_USED_OFF..SLOTS_USED_OFF + 4].try_into().ok()?)
        as usize;
    let slots = slots_used.min(8);
    let mut run_times = Vec::with_capacity(slots);
    for i in 0..slots {
        let off = RUN_TIMES_OFF + i * 8;
        let ft = u64::from_le_bytes(b[off..off + 8].try_into().ok()?);
        if ft > 0 {
            run_times.push(ft);
        }
    }
    let mut total_runs = u32::from_le_bytes(b[TOTAL_RUNS_OFF..TOTAL_RUNS_OFF + 4].try_into().ok()?);
    if total_runs == 0 {
        total_runs = run_times.len() as u32; // 部分 v31 文件该字段为 0，用时间槽数兜底
    }
    Some(PrefetchFile {
        exe_path,
        run_times,
        total_runs,
    })
}

pub struct PrefetchCollector {
    pub dir: std::path::PathBuf,
}

impl Default for PrefetchCollector {
    fn default() -> Self {
        // 支持环境变量覆盖（提权导出副本/离线取证场景）
        let dir = std::env::var("LMSS_PREFETCH_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| std::path::PathBuf::from(r"C:\Windows\Prefetch"));
        Self { dir }
    }
}

impl Collector for PrefetchCollector {
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

        let entries = match std::fs::read_dir(&self.dir) {
            Ok(e) => e,
            Err(e) => {
                logs.push(format!(
                    "无法枚举 {}：{e}。Prefetch 需要管理员权限；部分加固系统会限制普通用户枚举。以管理员运行本工具即可解锁。",
                    self.dir.display()
                ));
                return wrap(self.id(), ModuleStatus::Warn, events, logs, t0);
            }
        };
        let mut file_count = 0usize;
        let mut mam_count = 0usize;
        let mut decompress_fail = 0usize;
        let mut no_time_events = 0usize;
        for ent in entries.flatten() {
            let path = ent.path();
            let ext_ok = path
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e.eq_ignore_ascii_case("pf"));
            if !ext_ok {
                continue;
            }
            let Ok(bytes) = std::fs::read(&path) else {
                continue;
            };
            file_count += 1;
            let decoded;
            let pf_bytes: &[u8] = if bytes.starts_with(b"MAM") {
                // Win10/11 压缩格式：ntdll XPRESS-Huff 解压
                match crate::pf_mam::decompress_mam(&bytes) {
                    Some(d) => {
                        mam_count += 1;
                        decoded = d;
                        &decoded
                    }
                    None => {
                        decompress_fail += 1;
                        continue;
                    }
                }
            } else {
                &bytes
            };
            if let Some(pf) = parse_pf(pf_bytes) {
                if pf.run_times.is_empty() {
                    // 无时间戳的也给一条（至少证明执行过）
                    events.push(mk_event(
                        "（无时间戳）",
                        &pf.exe_path,
                        pf.total_runs,
                        "无运行时间记录",
                    ));
                    no_time_events += 1;
                    continue;
                }
                for ft in &pf.run_times {
                    if let Some(t) = filetime_to_local(*ft) {
                        events.push(mk_event(&t, &pf.exe_path, pf.total_runs, "Prefetch 记录的运行时间"));
                    }
                }
            }
        }
        if file_count == 0 {
            status = ModuleStatus::Warn;
            logs.push(
                "Prefetch 目录无 .pf 文件（可能被清理工具清空，或系统禁用）——程序执行证据由其他模块补充".into(),
            );
        } else {
            logs.push(format!(
                "{file_count} 个 .pf（含 {mam_count} 个 MAM 压缩）→ {} 条逐次执行记录（其中 {no_time_events} 条无时间戳）{fail_note}",
                events.len(),
                fail_note = if decompress_fail > 0 {
                    format!("，{decompress_fail} 个解压失败")
                } else {
                    String::new()
                }
            ));
        }
        wrap(self.id(), status, events, logs, t0)
    }
}

fn mk_event(time: &str, exe: &str, total: u32, note: &str) -> ActivityEvent {
    ActivityEvent {
        time: time.into(),
        kind: "程序运行（逐次）".into(),
        desc: exe.to_string(),
        info: format!("总运行 {total} 次 · {note}"),
        module: MODULE.into(),
        sev: Sev::None,
        tags: vec![],
    }
}

fn wrap(
    id: &str,
    status: ModuleStatus,
    events: Vec<ActivityEvent>,
    logs: Vec<String>,
    t0: Instant,
) -> ModuleResult {
    ModuleResult {
        module: id.into(),
        status,
        count: events.len(),
        duration_ms: t0.elapsed().as_millis(),
        logs,
        events,
        raw: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造合成 v30 .pf：3 个运行时间戳 + 总 10 次
    fn synthetic_pf(name: &str, times: &[u64], total: u32) -> Vec<u8> {
        let mut b = vec![0u8; 0xD4];
        b[0..4].copy_from_slice(&30u32.to_le_bytes());
        b[4..8].copy_from_slice(b"SCCA");
        let units: Vec<u16> = name.encode_utf16().collect();
        for (i, u) in units.iter().enumerate() {
            b[0x10 + i * 2..0x12 + i * 2].copy_from_slice(&u.to_le_bytes());
        }
        for (i, ft) in times.iter().enumerate() {
            b[0x88 + i * 8..0x90 + i * 8].copy_from_slice(&ft.to_le_bytes());
        }
        b[0xC8..0xCC].copy_from_slice(&(times.len() as u32).to_le_bytes());
        b[0xD0..0xD4].copy_from_slice(&total.to_le_bytes());
        b
    }

    #[test]
    fn parses_synthetic_v30() {
        let fts = [
            134_345_473_332_450_000u64,
            134_345_833_332_450_000,
            134_346_193_332_450_000,
        ];
        let b = synthetic_pf(r"C:\Windows\System32\cmd.exe", &fts, 10);
        let pf = parse_pf(&b).unwrap();
        assert_eq!(pf.exe_path, r"C:\Windows\System32\cmd.exe");
        assert_eq!(pf.run_times, fts);
        assert_eq!(pf.total_runs, 10);
    }

    #[test]
    fn slots_capped_at_8() {
        let fts: Vec<u64> = (0..12).map(|i| 134_345_473_332_450_000 + i as u64).collect();
        let mut b = vec![0u8; 0xD4 + 96];
        b[0..4].copy_from_slice(&31u32.to_le_bytes());
        b[4..8].copy_from_slice(b"SCCA");
        b[0x10..0x12].copy_from_slice(&0x43u16.to_le_bytes()); // "C"
        for (i, ft) in fts.iter().take(8).enumerate() {
            b[0x88 + i * 8..0x90 + i * 8].copy_from_slice(&ft.to_le_bytes());
        }
        b[0xC8..0xCC].copy_from_slice(&12u32.to_le_bytes()); // 声明 12 → 截到 8
        b[0xD0..0xD4].copy_from_slice(&12u32.to_le_bytes());
        let pf = parse_pf(&b).unwrap();
        assert_eq!(pf.run_times.len(), 8);
    }

    #[test]
    fn rejects_wrong_signature() {
        let mut b = vec![0u8; 0xD4];
        b[0..4].copy_from_slice(&30u32.to_le_bytes());
        assert!(parse_pf(&b).is_none()); // 无 SCCA
    }

    #[test]
    fn collector_handles_empty_dir() {
        // 本机 Prefetch 为空也必须优雅返回 Warn
        let r = PrefetchCollector::default().run();
        assert!(!r.logs.is_empty());
        matches!(r.status, ModuleStatus::Ok | ModuleStatus::Warn);
    }
}
