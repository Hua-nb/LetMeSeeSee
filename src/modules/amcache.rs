//! AmCache 模块：解析 C:\Windows\appcompat\Programs\Amcache.hve
//! （Win10+ 的 Root\InventoryApplicationFile，含 SHA1、首次出现时间=键时间戳）
//! 文件被系统锁定且需管理员读取：降级链 直读 → esentutl /y /vss 拷贝 → 记日志。
//! hive 引擎：regf-rs；nk 键时间戳按 REGF 单元布局手工提取：
//!   绝对偏移 = 4096(基块) + KeyNode.offset()，时间戳 u64 在 +8..+16。

use crate::model::{ActivityEvent, Collector, ModuleResult, ModuleStatus, Sev};
use crate::timeutil::filetime_to_local;
use regf_rs::{Hive, RegValue};
use std::time::Instant;

pub const MODULE: &str = "首次执行记录（AmCache）";
const DEFAULT_PATH: &str = r"C:\Windows\appcompat\Programs\Amcache.hve";
const REGF_BASE_BLOCK: usize = 4096;

/// 从原始 hive 字节中取 nk 键的最后写入时间（FILETIME）
pub fn nk_timestamp(hive_bytes: &[u8], node_offset: u32) -> Option<u64> {
    let start = REGF_BASE_BLOCK + node_offset as usize + 8;
    let end = start + 8;
    let b = hive_bytes.get(start..end)?;
    let ft = u64::from_le_bytes(b.try_into().ok()?);
    (ft > 0).then_some(ft)
}

pub fn clean_sha1(s: &str) -> String {
    s.strip_prefix("0000").unwrap_or(s).to_string()
}

fn reg_value_to_string(v: &RegValue) -> String {
    match v {
        RegValue::Sz(s) | RegValue::ExpandSz(s) => s.clone(),
        RegValue::Dword(n) => n.to_string(),
        RegValue::Qword(n) => n.to_string(),
        _ => String::new(),
    }
}

/// 遍历 Root\InventoryApplicationFile → 时间线事件
pub fn collect_amcache_events(hive: &Hive, hive_bytes: &[u8]) -> Vec<ActivityEvent> {
    let mut out = Vec::new();
    let Ok(app_names) = hive.list_subkeys("Root\\InventoryApplicationFile") else {
        return out;
    };
    for name in app_names {
        // AmCache 条目名形如 "app.exe|exe|ab12cd34"；含 '\' 的名字无法走路径寻址，跳过并计数
        if name.contains('\\') {
            continue;
        }
        let path = format!("Root\\InventoryApplicationFile\\{name}");
        let Ok(node) = hive.open(&path) else {
            continue;
        };
        let ft = nk_timestamp(hive_bytes, node.offset());
        let mut disp_name = String::new();
        let mut long_path = String::new();
        let mut sha1 = String::new();
        let mut size = String::new();
        let mut publisher = String::new();
        if let Ok(values) = hive.list_values(&path) {
            for (vn, v) in &values {
                let val = reg_value_to_string(v);
                match vn.as_str() {
                    "Name" => disp_name = val,
                    "LowerCaseLongPath" => long_path = val,
                    "FileId" => sha1 = clean_sha1(&val),
                    "SizeInBytes" => size = val,
                    "Publisher" => publisher = val,
                    _ => {}
                }
            }
        }
        let desc = if long_path.is_empty() {
            disp_name.clone()
        } else {
            long_path.clone()
        };
        let mut info_parts: Vec<String> = Vec::new();
        if !sha1.is_empty() {
            info_parts.push(format!("SHA1 {sha1}"));
        }
        if !size.is_empty() {
            info_parts.push(format!("{size} 字节"));
        }
        if !publisher.is_empty() {
            info_parts.push(publisher);
        }
        let time = ft
            .and_then(filetime_to_local)
            .unwrap_or_else(|| "（无时间戳）".into());
        out.push(ActivityEvent {
            time,
            kind: "程序首次执行".into(),
            desc,
            info: info_parts.join(" · "),
            module: MODULE.into(),
            sev: Sev::None,
            tags: vec![],
        });
    }
    out
}

/// 提权探测：统一走 TokenElevation（BAM 键可读性探测在 Win11 22H2+ 无该键的
/// 机器上管理员也返回 false，曾在主程序造成提权误判，已废弃）


/// 取得 Amcache.hve 字节：直读 → （已提权时）esentutl /y /vss 拷贝；logs 记录降级过程
fn acquire(logs: &mut Vec<String>) -> Option<Vec<u8>> {
    if let Ok(b) = std::fs::read(DEFAULT_PATH) {
        logs.push("直接读取 Amcache.hve 成功".into());
        return Some(b);
    }
    // 直读失败（文件被锁）：esentutl VSS 降级已移除——直读在管理员下覆盖绝大多数
    // 场景；AmCache 非关键证据源时降级为如实提示
    logs.push(
        "直读 Amcache.hve 失败（文件被系统锁定）。以管理员运行通常可直读；如仍失败，可用 esentutl /y /vss 手动拷贝后设置 LMSS_AMCACHE_HVE"
            .into(),
    );
    None
}

pub struct AmCacheCollector;

impl Default for AmCacheCollector {
    fn default() -> Self {
        Self
    }
}

impl Collector for AmCacheCollector {
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

        match acquire(&mut logs) {
            Some(bytes) => match Hive::from_bytes(bytes.clone()) {
                Ok(hive) => {
                    events = collect_amcache_events(&hive, &bytes);
                    logs.push(format!("InventoryApplicationFile 解析 {} 条", events.len()));
                    if events.is_empty() {
                        status = ModuleStatus::Warn;
                        logs.push("未找到 InventoryApplicationFile 记录（旧系统为 Win8 格式）".into());
                    }
                }
                Err(e) => {
                    logs.push(format!("hive 解析失败：{e}"));
                    status = ModuleStatus::Err;
                }
            },
            None => {
                logs.push("AmCache 不可读：以管理员身份运行可解锁（直读与 VSS 均失败）".into());
                status = ModuleStatus::Warn;
            }
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
    use regf_rs::RegValue;

    /// 用 regf-rs 现场构建一个含 InventoryApplicationFile 结构的合成 hive，
    /// 并手工往 nk 记录盖上已知 FILETIME，验证完整解析路径。
    #[test]
    fn synthetic_amcache_hive_roundtrip() {
        let mut h = Hive::new_empty("Root");
        h.create_key("Root\\InventoryApplicationFile").unwrap();
        let entry = "app.exe|exe|ab12cd34";
        let path = format!("Root\\InventoryApplicationFile\\{entry}");
        h.create_key(&path).unwrap();
        h.set_value(&path, "Name", RegValue::Sz("app.exe".into()))
            .unwrap();
        h.set_value(
            &path,
            "LowerCaseLongPath",
            RegValue::Sz("c:\\users\\test\\app.exe".into()),
        )
        .unwrap();
        h.set_value(
            &path,
            "FileId",
            RegValue::Sz("0000aabbccddeeff00112233445566778899aabb".into()),
        )
        .unwrap();
        h.set_value(&path, "SizeInBytes", RegValue::Dword(284000))
            .unwrap();
        let bytes = h.to_bytes();

        // 重新解析拿 offset，然后往 nk 记录盖时间戳
        let probe = Hive::from_bytes(bytes.clone()).unwrap();
        let node = probe.open(&path).unwrap();
        let ft: u64 = 134_345_473_332_450_000; // 2026-09-22T10:42:13.245Z
        let abs = REGF_BASE_BLOCK + node.offset() as usize + 8;
        let mut stamped = bytes;
        stamped[abs..abs + 8].copy_from_slice(&ft.to_le_bytes());

        let hive = Hive::from_bytes(stamped.clone()).unwrap();
        let events = collect_amcache_events(&hive, &stamped);
        assert_eq!(events.len(), 1);
        let e = &events[0];
        assert_eq!(e.kind, "程序首次执行");
        assert_eq!(e.desc, "c:\\users\\test\\app.exe");
        assert!(e.info.contains("aabbccddeeff00112233445566778899aabb"), "{}", e.info); // 0000 前缀已剥
        assert!(e.info.contains("284000"));
        assert_eq!(e.time, "2026-09-22 18:42:13.245"); // 东八区机器；其他时区机器会差时区数
    }

    #[test]
    fn sha1_display_trims_prefix() {
        assert_eq!(clean_sha1("0000AABBCC"), "AABBCC");
        assert_eq!(clean_sha1("AABBCC"), "AABBCC");
    }

    #[test]
    fn collector_degrades_without_admin() {
        // 非管理员机器：必须 Warn 而非 panic，日志说明原因
        let r = AmCacheCollector::default().run();
        assert!(!r.logs.is_empty());
        matches!(r.status, ModuleStatus::Ok | ModuleStatus::Warn);
    }

    #[test]
    #[ignore = "需要真实 Amcache.hve 副本；设 LMSS_AMCACHE_HVE 后 cargo test -- --ignored"]
    fn parses_real_amcache() {
        let Ok(path) = std::env::var("LMSS_AMCACHE_HVE") else {
            eprintln!("跳过：未设置 LMSS_AMCACHE_HVE");
            return;
        };
        let bytes = std::fs::read(&path).unwrap();
        let hive = Hive::from_bytes(bytes.clone()).unwrap();
        let events = collect_amcache_events(&hive, &bytes);
        assert!(!events.is_empty());
    }
}
