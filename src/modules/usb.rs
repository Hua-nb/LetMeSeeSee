//! USB 设备历史模块：解析 C:\Windows\inf\setupapi.dev.log（ANSI 文本）。
//! 设备安装段 `>>>  [Device Install … - <设备ID>]` + `>>>  Section start <本地时间>`
//! 提供真实的设备接入时间线；设备从系统移除后 USBSTOR 注册表键即消失，
//! 而 setupapi 日志长期保留——因此以日志为主源。
//! 时间=Section start 原文（日志本身为本地时间，如实沿用）。

use crate::model::{ActivityEvent, Collector, ModuleResult, ModuleStatus, RawTable, Sev};
use std::time::Instant;

pub const MODULE: &str = "USB 设备历史";

#[derive(Debug, PartialEq)]
pub struct UsbInstall {
    pub device: String,
    /// "YYYY/MM/DD HH:MM:SS.mmm"（日志原文，本地时间）
    pub first: String,
    pub last: String,
    pub count: usize,
}

/// 段标题行是否为 USB 相关设备安装。
/// 注意 WPDBUSENUM 枚举的是"所有便携设备"（含 SD 卡的 SWD\WPDBUSENUM\_??_SD#…），
/// 只有内嵌 USBSTOR 的才是 U 盘/移动硬盘
pub fn is_usb_device(id: &str) -> bool {
    let l = id.to_ascii_uppercase();
    l.contains("USBSTOR") || l.starts_with("USB\\VID_") || l.contains("WPDBUSENUM\\_??_USBSTOR")
}

/// 解析 setupapi.dev.log 文本：按设备聚合安装记录（首末时间+次数）
pub fn parse_setupapi(text: &str) -> Vec<UsbInstall> {
    use std::collections::HashMap;
    let mut agg: HashMap<String, (String, String, usize)> = HashMap::new();
    let mut pending: Option<String> = None;
    for line in text.lines() {
        let t = line.trim_start();
        if t.starts_with(">>>  [") && t.ends_with(']') {
            let inner = &t[6..t.len() - 1];
            // 仅统计安装段（排除 Delete Device 等其他段落）
            pending = if inner.contains("Device Install") {
                inner.rsplit(" - ").next().map(|s| s.to_string())
            } else {
                None
            };
        } else if let (Some(dev), Some(ts)) = (&pending, t.strip_prefix(">>>  Section start ")) {
            if is_usb_device(dev) && ts.len() >= 19 {
                let e = agg.entry(dev.clone()).or_insert((ts.to_string(), ts.to_string(), 0));
                e.1 = ts.to_string();
                e.2 += 1;
            }
            pending = None;
        }
    }
    let mut out: Vec<UsbInstall> = agg
        .into_iter()
        .map(|(device, (first, last, count))| UsbInstall {
            device,
            first,
            last,
            count,
        })
        .collect();
    out.sort_by(|a, b| b.first.cmp(&a.first));
    out
}

/// 设备 ID 转可读名称。三种形态：
/// USBSTOR\DISK&VEN__X&PROD__Y\序列号、SWD\WPDBUSENUM\_??_USBSTOR#Disk&Ven_X&Prod_Y#序列号、
/// USB\VID_x&PID_y\实例
pub fn friendly_device_name(id: &str) -> String {
    let mut vendor = String::new();
    let mut product = String::new();
    for tok in id.split(['\\', '#', '&']) {
        let t = tok.trim_matches('_');
        let low = t.to_ascii_lowercase();
        if product.is_empty() && low.starts_with("prod_") {
            product = t[5..].replace('_', " ").trim().to_string();
        } else if vendor.is_empty() && low.starts_with("ven_") {
            vendor = t[4..].replace('_', " ").trim().to_string();
        }
    }
    // 序列号：足够长的非 GUID 段；优先纯十六进制形态（排除 Rev_1.00 版本段与 Prod_/Ven_ 描述段）
    let is_noise = |s: &str| {
        let l = s.to_ascii_lowercase();
        l.starts_with("rev_") || l.starts_with("prod_") || l.starts_with("ven_") || l == "disk"
    };
    let candidates: Vec<&str> = id
        .split(['\\', '#', '&'])
        .filter(|s| s.len() >= 6 && !s.starts_with('{') && !is_noise(s))
        .collect();
    let serial = candidates
        .iter()
        .rev()
        .find(|s| s.chars().all(|c| c.is_ascii_hexdigit()))
        .or_else(|| candidates.last())
        .copied()
        .unwrap_or("");
    if !product.is_empty() || !vendor.is_empty() {
        let model = if product.is_empty() {
            vendor
        } else if vendor.is_empty() {
            product
        } else {
            format!("{vendor} {product}")
        };
        if serial.is_empty() {
            format!("USB 存储 {model}")
        } else {
            format!("USB 存储 {model} · 序列号 {serial}")
        }
    } else {
        let vid = id
            .split(['\\', '&'])
            .find(|s| s.starts_with("VID_"))
            .unwrap_or("");
        let pid = id
            .split(['\\', '&'])
            .find(|s| s.starts_with("PID_"))
            .unwrap_or("");
        if serial.is_empty() {
            format!("USB 设备 {vid} {pid}")
        } else {
            format!("USB 设备 {vid} {pid} · 序列号 {serial}")
        }
    }
}

/// "2026/02/19 20:28:03.754" → "2026-02-19 20:28:03.754"
pub fn setupapi_ts_to_iso(ts: &str) -> Option<String> {
    let d = chrono::NaiveDateTime::parse_from_str(ts, "%Y/%m/%d %H:%M:%S%.f").ok()?;
    Some(d.format("%Y-%m-%d %H:%M:%S%.3f").to_string())
}

pub struct UsbCollector;

impl Default for UsbCollector {
    fn default() -> Self {
        Self
    }
}

impl Collector for UsbCollector {
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

        // 当前日志 + 归档（setupapi.dev.YYYYMMDD_*.log）：只读当前文件会漏掉
        // 滚动归档前的早期接入历史
        let inf_dir = std::path::Path::new(r"C:\Windows\inf");
        let mut log_files: Vec<std::path::PathBuf> = Vec::new();
        if inf_dir.join("setupapi.dev.log").exists() {
            log_files.push(inf_dir.join("setupapi.dev.log"));
        }
        if let Ok(entries) = std::fs::read_dir(inf_dir) {
            let mut arch: Vec<_> = entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| {
                    let Some(n) = p.file_name().and_then(|n| n.to_str()) else {
                        return false;
                    };
                    n.starts_with("setupapi.dev.") && n.ends_with(".log") && n != "setupapi.dev.log"
                })
                .collect();
            arch.sort();
            log_files.extend(arch);
        }
        if log_files.is_empty() {
            logs.push("C:\\Windows\\inf 下无 setupapi.dev 日志".into());
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
        // 跨文件聚合：同设备的首末时间取全部日志的 min/max
        let mut agg: std::collections::HashMap<String, (String, String, usize)> =
            std::collections::HashMap::new();
        let mut merged = String::new();
        for f in &log_files {
            if let Ok(b) = std::fs::read(f) {
                merged.push_str(&crate::encoding::decode_ansi_or_utf8(&b));
                merged.push('\n');
            }
        }
        let installs = parse_setupapi(&merged);
        for (device, (first, last, count)) in
            installs.into_iter().map(|u| (u.device, (u.first, u.last, u.count)))
        {
            agg.insert(device, (first, last, count));
        }
        let mut installs: Vec<UsbInstall> = agg
            .into_iter()
            .map(|(device, (first, last, count))| UsbInstall {
                device,
                first,
                last,
                count,
            })
            .collect();
        installs.sort_by(|a, b| b.first.cmp(&a.first));
        logs.push(format!("读取 {} 个 setupapi 日志文件", log_files.len()));
        for u in &installs {
            let time = setupapi_ts_to_iso(&u.first).unwrap_or_else(|| u.first.clone());
            let last = setupapi_ts_to_iso(&u.last).unwrap_or_else(|| u.last.clone());
            let info = format!(
                "首次接入 {time} · 最近 {last} · 共 {} 次安装记录 · setupapi.dev.log",
                u.count
            );
            events.push(ActivityEvent {
                time: time.clone(),
                kind: "USB设备".into(),
                desc: friendly_device_name(&u.device),
                info,
                module: MODULE.into(),
                sev: Sev::None,
                tags: vec![],
            });
            rows.push(vec![
                friendly_device_name(&u.device),
                time,
                last,
                u.count.to_string(),
            ]);
        }
        logs.push(format!(
            "共 {} 个 USB 设备安装记录（设备移除后日志仍保留，可回溯历史接入）",
            installs.len()
        ));
        ModuleResult {
            module: self.id().into(),
            status: if installs.is_empty() {
                ModuleStatus::Warn
            } else {
                ModuleStatus::Ok
            },
            count: events.len(),
            duration_ms: t0.elapsed().as_millis(),
            logs,
            events,
            raw: Some(RawTable {
                columns: ["设备", "首次接入", "最近接入", "安装次数"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
                rows,
                refs: Vec::new(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
>>>  [Device Install (Hardware initiated) - SWD\\WPDBUSENUM\\_??_USBSTOR#Disk&Ven_SanDisk&Prod_3.2GEN1&Rev_1.00#0401E168&0#{53f56307}]
>>>  Section start 2026/02/19 20:28:03.754
      cmd: x
<<<  Section end 2026/02/19 20:28:03.762
>>>  [Device Install - USBSTOR\\DISK&VEN__USB&PROD__SANDISK_3.2GEN1&REV_1.00\\0401E168EBA3]
>>>  Section start 2026/02/19 20:28:04.100
<<<  Section end 2026/02/19 20:28:04.900
>>>  [Device Install - USB\\VID_248D&PID_5B5F\\6&1909A956&0&0000]
>>>  Section start 2026/01/02 09:00:00.123
<<<  Section end 2026/01/02 09:00:00.200
>>>  [Device Install - PCI\\VEN_8086&DEV_1234]
>>>  Section start 2026/03/01 10:00:00.000
<<<  Section end 2026/03/01 10:00:01.000
>>>  [Device Install - USBSTOR\\DISK&VEN__USB&PROD__SANDISK_3.2GEN1&REV_1.00\\0401E168EBA3]
>>>  Section start 2026/05/11 11:11:11.500
<<<  Section end 2026/05/11 11:11:12.000
";

    #[test]
    fn parses_and_aggregates_usb_sections() {
        let v = parse_setupapi(SAMPLE);
        // PCI 段忽略；SanDisk USBSTOR 两段聚合；WPDBUSENUM 与 USB\VID 各一段
        assert_eq!(v.len(), 3, "{v:?}");
        let sd = v
            .iter()
            .find(|u| u.device.contains("SANDISK_3.2GEN1") && u.device.starts_with("USBSTOR"))
            .unwrap();
        assert_eq!(sd.count, 2);
        assert_eq!(sd.first, "2026/02/19 20:28:04.100");
        assert_eq!(sd.last, "2026/05/11 11:11:11.500");
        assert!(v.iter().all(|u| is_usb_device(&u.device)));
    }

    #[test]
    fn friendly_names() {
        assert!(friendly_device_name(
            r"USBSTOR\DISK&VEN__USB&PROD__SANDISK_3.2GEN1&REV_1.00\0401E168EBA3"
        )
        .contains("SANDISK 3.2GEN1"));
        assert!(friendly_device_name(
            r"SWD\WPDBUSENUM\_??_USBSTOR#Disk&Ven_General&Prod_USB_Flash_Disk&Rev_1.00#0401E168&0#{53f56307}"
        )
        .contains("USB Flash Disk"));
        let usb_vid = friendly_device_name(r"USB\VID_248D&PID_5B5F\6&1909A956&0&0000");
        assert!(usb_vid.contains("VID_248D") && usb_vid.contains("1909A956"), "{usb_vid}");
    }

    #[test]
    fn ts_conversion() {
        assert_eq!(
            setupapi_ts_to_iso("2026/02/19 20:28:03.754").unwrap(),
            "2026-02-19 20:28:03.754"
        );
        assert!(setupapi_ts_to_iso("garbage").is_none());
    }

    #[test]
    fn usb_detection_predicates() {
        assert!(is_usb_device(r"USBSTOR\DISK\x"));
        assert!(is_usb_device(r"USB\VID_1&PID_2\3"));
        assert!(is_usb_device(r"SWD\WPDBUSENUM\...USBSTOR#..."));
        assert!(!is_usb_device(r"PCI\VEN_8086"));
        // SD 卡等非 USB 便携设备：WPDBUSENUM 但无 USBSTOR → 不算 USB
        assert!(!is_usb_device(r"SWD\WPDBUSENUM\_??_SD#Ven_Samsung&Prod_"));
    }

    #[test]
    #[ignore = "真实日志；本机 cargo test -- --ignored"]
    fn parses_real_setupapi() {
        let r = UsbCollector::default().run();
        assert!(r.count >= 1, "本机实测有 USB 接入记录：{:?}", r.logs);
        // 原表行数与事件数一致，列=4
        let raw = r.raw.as_ref().unwrap();
        assert_eq!(raw.rows.len(), r.count);
        assert_eq!(raw.columns.len(), 4);
    }
}
