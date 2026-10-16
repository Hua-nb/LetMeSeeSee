//! ShimCache (AppCompatCache) 模块。
//! Win10 布局来源：EricZimmerman/AppCompatCacheParser → AppCompatCache/Windows10.cs
//! 头部：raw[0..4] = 记录区偏移（本机实测 0x34）；条目数在 0x24（0x34 时在 0x28，实测不可靠）。
//! 条目：["10ts"][unknown u32][dataSize u32][pathSize u16][UTF-16 路径(字节数)]
//!       [最后修改 FILETIME u64][dataSize2 i32][data…]，data 尾 4 字节 ==1 表示执行过。
//! 记录区起点采用"头部偏移优先、首个 "10ts" 扫描兜底"的自定位策略。

use crate::model::{ActivityEvent, Collector, ModuleResult, ModuleStatus, Sev};
use crate::regutil::{read_value, utf16_bytes_to_string, HKEY};
use crate::timeutil::filetime_to_local;
use std::time::Instant;

pub const MODULE: &str = "程序执行缓存（ShimCache）";

#[derive(Debug, PartialEq)]
pub enum Format {
    Xp,    // 0xDEADBEEF
    Win7,  // 0xBADC0FFE
    Win8,  // 0x1-0x4
    Win10, // 0x30-0x35（记录区偏移恰好落在此区间的 Win10 家族）
    Unknown,
}

pub fn detect_format(b: &[u8]) -> Format {
    if b.len() < 4 {
        return Format::Unknown;
    }
    let first = u32::from_le_bytes(b[..4].try_into().unwrap());
    match first {
        0xDEADBEEF => Format::Xp,
        0xBADC0FFE => Format::Win7,
        0x1..=0x4 => Format::Win8,
        0x30..=0x35 => Format::Win10,
        _ => Format::Unknown,
    }
}

pub struct ShimEntry {
    pub path: String,
    pub filetime: Option<u64>,
    pub executed: bool,
}

/// 定位记录区起点：优先头部声明的偏移，兜底扫描首个 "10ts"
fn records_offset(b: &[u8]) -> Option<usize> {
    let declared = u32::from_le_bytes(b.get(..4)?.try_into().ok()?) as usize;
    if b.get(declared..declared + 4) == Some(b"10ts") {
        return Some(declared);
    }
    b.windows(4).position(|w| w == b"10ts")
}

/// Win10 家族（"10ts" 条目）解析
pub fn parse_win10(b: &[u8]) -> Option<Vec<ShimEntry>> {
    let mut off = records_offset(b)?;
    let mut out = Vec::new();
    while off + 4 <= b.len() {
        if b.get(off..off + 4) != Some(b"10ts") {
            break;
        }
        off += 4;
        off += 4; // unknown u32
        let _ce_data_size =
            u32::from_le_bytes(b.get(off..off + 4)?.try_into().ok()?) as usize;
        off += 4;
        let path_size = u16::from_le_bytes(b.get(off..off + 2)?.try_into().ok()?) as usize;
        off += 2;
        if off + path_size + 8 + 4 > b.len() {
            return None;
        }
        let path_raw = &b[off..off + path_size];
        off += path_size;
        let ft = u64::from_le_bytes(b[off..off + 8].try_into().ok()?);
        off += 8;
        let data_size = i32::from_le_bytes(b[off..off + 4].try_into().ok()?).unsigned_abs() as usize;
        off += 4;
        let data = b.get(off..off + data_size)?;
        off += data_size;
        let executed = data.len() >= 4
            && u32::from_le_bytes(data[data.len() - 4..].try_into().unwrap()) == 1;
        let path = utf16_bytes_to_string(path_raw).replace(r"\??\", "");
        out.push(ShimEntry {
            path,
            filetime: (ft > 0).then_some(ft),
            executed,
        });
    }
    Some(out)
}

/// Win7（0xBADC0FFE）条目解析：
/// 头部 128 字节（魔数 + 统计）；条目 [u16 路径字节数][u16 未知]
/// [u64 文件修改 FILETIME][u64 插入时间 FILETIME][u32 数据长度][UTF-16 路径][数据]。
/// 布局来源：EricZimmerman/AppCompatCacheParser Windows7.cs。
pub fn parse_win7(b: &[u8]) -> Option<Vec<ShimEntry>> {
    if b.len() < 128 {
        return None;
    }
    let mut off = 128usize;
    let mut out = Vec::new();
    while off + 24 <= b.len() {
        let path_size = u16::from_le_bytes(b[off..off + 2].try_into().ok()?) as usize;
        if path_size == 0 {
            break;
        }
        let ft = u64::from_le_bytes(b[off + 4..off + 12].try_into().ok()?);
        let data_size = u32::from_le_bytes(b[off + 20..off + 24].try_into().ok()?) as usize;
        let path_off = off + 24;
        let data_off = path_off + path_size;
        if path_size % 2 != 0 || data_off + data_size > b.len() {
            break; // 损坏条目：返回已解析部分（部分证据好过全无）
        }
        let path = utf16_bytes_to_string(&b[path_off..data_off]).replace(r"\??\", "");
        if !path.is_empty() {
            out.push(ShimEntry {
                path,
                filetime: (ft > 0).then_some(ft),
                executed: false, // Win7 条目无"已执行"标志位
            });
        }
        off = data_off + data_size;
    }
    Some(out)
}

pub struct ShimCacheCollector;

impl Default for ShimCacheCollector {
    fn default() -> Self {
        Self
    }
}

impl Collector for ShimCacheCollector {
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

        let (blob, _) = match read_value(
            HKEY::local_machine(),
            r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache",
            "AppCompatCache",
        ) {
            Ok(v) => v,
            Err(e) => {
                logs.push(e);
                return wrap(ModuleStatus::Err, events, logs, t0, self.id());
            }
        };
        logs.push(format!("blob 大小 {} 字节", blob.len()));
        let (entries, fmt_note) = match detect_format(&blob) {
            Format::Win10 => (parse_win10(&blob), "Win10"),
            Format::Win7 => (
                parse_win7(&blob),
                "Win7（无已执行标志位，条目=文件存在痕迹）",
            ),
            f => {
                logs.push(format!("暂不支持的 ShimCache 格式：{f:?}（后续里程碑补充）"));
                return wrap(ModuleStatus::Warn, events, logs, t0, self.id());
            }
        };
        match entries {
            Some(list) => {
                logs.push(format!("格式：{fmt_note}"));
                let mut no_time = 0usize;
                for e in list {
                    // ShimCache 的时间是文件上次修改时间，并非执行时间
                    let t = e.filetime.and_then(filetime_to_local);
                    if t.is_none() {
                        no_time += 1;
                    }
                    // UWP 包记录的"路径"是制表符分隔的包身份信息（含发布者/架构），非文件路径
                    let is_uwp = e.path.contains('\t');
                    events.push(ActivityEvent {
                        time: t.unwrap_or_else(|| "（无时间戳）".into()),
                        kind: if is_uwp { "UWP应用痕迹" } else { "程序执行痕迹" }.into(),
                        desc: e.path,
                        info: format!(
                            "ShimCache · {}{}",
                            if is_uwp { "UWP 包记录 · " } else { "文件修改时间 · " },
                            if e.executed { "标志为已执行" } else { "" }
                        )
                        .trim_end_matches(" · ")
                        .to_string(),
                        module: MODULE.into(),
                        sev: Sev::None,
                        tags: vec![],
                    });
                }
                logs.push(format!(
                    "解析 {} 条（{no_time} 条无有效时间戳）",
                    events.len()
                ));
            }
            None => {
                logs.push("布局解析失败（条目魔数不符或截断）".into());
                status = ModuleStatus::Err;
            }
        }
        wrap(status, events, logs, t0, self.id())
    }
}

fn wrap(
    status: ModuleStatus,
    events: Vec<ActivityEvent>,
    logs: Vec<String>,
    t0: Instant,
    id: &str,
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

    fn entry(path: &str, ft: u64, exec_flag: bool) -> Vec<u8> {
        let punits: Vec<u16> = path.encode_utf16().collect();
        let mut path_bytes = Vec::new();
        for u in punits {
            path_bytes.extend_from_slice(&u.to_le_bytes());
        }
        let data: Vec<u8> = if exec_flag {
            vec![0, 0, 0, 0, 1, 0, 0, 0]
        } else {
            vec![0, 0, 0, 0, 2, 0, 0, 0]
        };
        let mut e = vec![];
        e.extend_from_slice(b"10ts");
        e.extend_from_slice(&0u32.to_le_bytes()); // unknown
        e.extend_from_slice(&(data.len() as u32).to_le_bytes()); // ceDataSize
        e.extend_from_slice(&(path_bytes.len() as u16).to_le_bytes()); // pathSize（字节）
        e.extend_from_slice(&path_bytes);
        e.extend_from_slice(&ft.to_le_bytes());
        e.extend_from_slice(&(data.len() as i32).to_le_bytes());
        e.extend_from_slice(&data);
        e
    }

    fn blob(entries: &[Vec<u8>]) -> Vec<u8> {
        let mut b = vec![0x34, 0, 0, 0]; // 声明记录区偏移=0x34? 构造时让头部指向真实位置
        b.extend_from_slice(&[0u8; 48]); // 头部填充到 52 字节
        // 头部偏移声明 0x34=52，正好是条目区起点
        for e in entries {
            b.extend_from_slice(e);
        }
        b
    }

    #[test]
    fn detects_format() {
        assert_eq!(detect_format(&[0x34, 0, 0, 0]), Format::Win10);
        assert_eq!(detect_format(&[0xEF, 0xBE, 0xAD, 0xDE]), Format::Xp);
        assert_eq!(detect_format(&[0xFE, 0x0F, 0xDC, 0xBA]), Format::Win7);
        assert_eq!(detect_format(&[0x01, 0, 0, 0]), Format::Win8);
        assert_eq!(detect_format(&[0x99, 0, 0, 0]), Format::Unknown);
    }

    #[test]
    fn parses_synthetic_win10_entries() {
        let ft = 134_345_473_332_450_000u64;
        let b = blob(&[
            entry(r"\??\C:\Tools\test.exe", ft, true),
            entry("C:\\Windows\\System32\\cmd.exe", 0, false),
        ]);
        let list = parse_win10(&b).unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].path, r"C:\Tools\test.exe"); // \??\ 前缀被剥除
        assert_eq!(list[0].filetime, Some(ft));
        assert!(list[0].executed);
        assert!(!list[1].executed);
    }

    #[test]
    fn falls_back_to_scan_when_header_offset_wrong() {
        let ft = 134_345_473_332_450_000u64;
        let mut b = vec![0x34, 0, 0, 0];
        b.extend_from_slice(&[0u8; 56]); // 头部声明的 52 处不是 10ts（56 处才是）
        b.extend_from_slice(&entry("C:\\x.exe", ft, false));
        let list = parse_win10(&b).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].path, "C:\\x.exe");
    }

    #[test]
    fn truncated_returns_none() {
        let mut b = blob(&[entry("C:\\x.exe", 1, false)]);
        b.truncate(b.len() - 3);
        assert!(parse_win10(&b).is_none());
    }

    /// 构造 Win7 条目：[u16 pathSize][u16 unknown][u64 mtime][u64 insert][u32 dataSize][UTF16 path][data]
    fn win7_entry(path: &str, ft: u64) -> Vec<u8> {
        let mut path_bytes = Vec::new();
        for u in path.encode_utf16() {
            path_bytes.extend_from_slice(&u.to_le_bytes());
        }
        let data = vec![0xAA, 0xBB];
        let mut e = Vec::new();
        e.extend_from_slice(&(path_bytes.len() as u16).to_le_bytes());
        e.extend_from_slice(&0u16.to_le_bytes());
        e.extend_from_slice(&ft.to_le_bytes());
        e.extend_from_slice(&(ft + 1).to_le_bytes());
        e.extend_from_slice(&(data.len() as u32).to_le_bytes());
        e.extend_from_slice(&path_bytes);
        e.extend_from_slice(&data);
        e
    }

    fn win7_blob(entries: &[Vec<u8>]) -> Vec<u8> {
        let mut b = vec![0xFE, 0x0F, 0xDC, 0xBA]; // 0xBADC0FFE LE
        b.extend_from_slice(&[0u8; 124]); // 头部补齐 128 字节
        for e in entries {
            b.extend_from_slice(e);
        }
        b
    }

    #[test]
    fn parses_win7_entries() {
        let ft = 134_345_473_332_450_000u64;
        let b = win7_blob(&[
            win7_entry(r"C:\Tools\a.exe", ft),
            win7_entry(r"C:\Windows\b.dll", 0),
        ]);
        let list = parse_win7(&b).unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].path, r"C:\Tools\a.exe");
        assert_eq!(list[0].filetime, Some(ft));
        assert!(!list[0].executed, "Win7 条目无已执行标志");
    }

    #[test]
    fn win7_corrupted_entry_returns_partial() {
        let ft = 134_345_473_332_450_000u64;
        let mut b = win7_blob(&[win7_entry(r"C:\x.exe", ft)]);
        b.extend_from_slice(&[0xFF, 0xFF]); // 尾部残缺条目
        let list = parse_win7(&b).unwrap();
        assert_eq!(list.len(), 1);
    }

    #[test]
    #[ignore = "读取真实注册表；本机执行 cargo test -- --ignored"]
    fn collector_reads_real_shimcache() {
        let r = ShimCacheCollector::default().run();
        assert!(r.count >= 10, "真实 309KB blob 应有大量条目：{:?}", r.logs);
        for e in &r.events {
            // 合法形态：文件路径（含盘符/Device）、UWP 包记录（制表符分隔）、
            // 或 SIGN.MEDIA= 安装媒体签名条目；其余视为乱码
            assert!(
                e.desc.contains(':') || e.desc.contains("\\Device") || e.desc.contains('\t')
                    || e.desc.starts_with("SIGN.MEDIA="),
                "可疑路径：{}",
                e.desc
            );
        }
    }
}
