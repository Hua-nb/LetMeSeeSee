use crate::model::{ActivityEvent, Collector, ModuleResult, ModuleStatus, Sev};
use std::path::PathBuf;
use std::time::Instant;

pub const MODULE: &str = "最近文档（RecentDocs）";

/// 解析 RecentDocs 注册表值数据：[u16 SHITEMID 大小][IDL][UTF-16 目标路径 NUL 结尾]。
/// 返回目标路径（失败 None）——LNK 文件被删后注册表 MRU 仍留痕，是删除 resistant 的证据源
pub fn recentdocs_value_path(b: &[u8]) -> Option<String> {
    if b.len() < 4 {
        return None;
    }
    let cb = u16::from_le_bytes(b.get(0..2)?.try_into().ok()?) as usize;
    if cb == 0 || 2 + cb >= b.len() {
        return None;
    }
    let units: Vec<u16> = b[2 + cb..]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&u| u != 0)
        .collect();
    let s = String::from_utf16_lossy(&units);
    (!s.is_empty()).then_some(s)
}

/// 解析 LNK 的 LinkInfo.LocalBasePath（最小实现，MS-SHLLINK 2.3）
/// 失败返回 None（调用方降级用 LNK 文件名）
pub fn lnk_local_base_path(b: &[u8]) -> Option<String> {
    if b.len() < 0x4C || b[..4] != [0x4C, 0x00, 0x00, 0x00] {
        return None;
    }
    let flags = u32::from_le_bytes(b.get(0x14..0x18)?.try_into().ok()?);
    let mut off = 0x4Cusize;
    if flags & 0x1 != 0 {
        // HasLinkTargetIDList：2 字节 IDList 大小（含自身）→ 跳过
        let idl_size = u16::from_le_bytes(b.get(off..off + 2)?.try_into().ok()?) as usize;
        off += idl_size;
    }
    // LinkInfo
    let li = b.get(off..)?;
    let li_size = u32::from_le_bytes(li.get(0..4)?.try_into().ok()?) as usize;
    if li_size < 0x1C {
        return None;
    }
    let li_flags = u32::from_le_bytes(li.get(8..12)?.try_into().ok()?);
    if li_flags & 0x1 == 0 {
        return None; // 无 VolumeIDAndLocalBasePath
    }
    let base_off = u32::from_le_bytes(li.get(16..20)?.try_into().ok()?) as usize;
    if base_off == 0 || base_off >= li.len() {
        return None;
    }
    let mut end = base_off;
    while end < li.len() && end < off + li_size && li[end] != 0 {
        end += 1;
    }
    if end == base_off {
        return None;
    }
    Some(crate::encoding::decode_ansi_or_utf8(&li[base_off..end]))
}

/// 文件系统时间 → 展示字符串
fn mtime_string(p: &std::path::Path) -> Option<String> {
    use std::time::UNIX_EPOCH;
    let t = std::fs::metadata(p).ok()?.modified().ok()?;
    let ms = t.duration_since(UNIX_EPOCH).ok()?.as_millis() as i64;
    use chrono::TimeZone;
    let local = chrono::Local
        .timestamp_millis_opt(ms)
        .single()?;
    Some(local.format("%Y-%m-%d %H:%M:%S%.3f").to_string())
}

pub struct RecentDocsCollector;

impl Default for RecentDocsCollector {
    fn default() -> Self {
        Self
    }
}

impl Collector for RecentDocsCollector {
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
        // 遍历 C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent
        let users_dir = PathBuf::from(r"C:\Users");
        let Ok(users) = std::fs::read_dir(&users_dir) else {
            logs.push("无法枚举 C:\\Users".into());
            return wrap(self.id(), ModuleStatus::Err, events, logs, t0);
        };
        // 用户名 → HKU SID（经 ProfileList 的 ProfileImagePath 基名对应）
        let pl_root = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";
        let mut name_to_sid: Vec<(String, String)> = Vec::new();
        if let Ok(sids) = crate::regutil::subkeys(crate::regutil::HKEY::local_machine(), pl_root) {
            for sid in sids {
                if let Ok(p) = crate::regutil::read_string_value(
                    crate::regutil::HKEY::local_machine(),
                    &format!(r"{pl_root}\{sid}"),
                    "ProfileImagePath",
                ) {
                    let base = crate::encoding::expand_env_vars(&p)
                        .rsplit('\\')
                        .next()
                        .unwrap_or_default()
                        .to_ascii_lowercase();
                    if !base.is_empty() {
                        name_to_sid.push((base, sid));
                    }
                }
            }
        }
        for user in users.flatten() {
            let uname = user.file_name().to_string_lossy().into_owned();
            let recent = user.path().join(r"AppData\Roaming\Microsoft\Windows\Recent");
            let mut seen: Vec<String> = Vec::new();
            let mut count = 0usize;
            if let Ok(files) = std::fs::read_dir(&recent) {
                for f in files.flatten() {
                    let path = f.path();
                    let is_lnk = path
                        .extension()
                        .and_then(|e| e.to_str())
                        .is_some_and(|e| e.eq_ignore_ascii_case("lnk"));
                    if !is_lnk {
                        continue;
                    }
                    let Ok(bytes) = std::fs::read(&path) else {
                        continue;
                    };
                    // LNK 解析失败时退化为文件名——必须标注，避免被误当完整路径
                    let (target, unparsed) = match lnk_local_base_path(&bytes) {
                        Some(p) => (p, false),
                        None => (
                            path.file_stem()
                                .map(|s| s.to_string_lossy().into_owned())
                                .unwrap_or_default(),
                            true,
                        ),
                    };
                    if !target.is_empty() {
                        seen.push(target.to_ascii_lowercase());
                    }
                    let time = mtime_string(&path).unwrap_or_else(|| "（无时间戳）".into());
                    // 存在性核验（仅 LNK 解析出的路径；LNK 名降级形态不核验）
                    let (enote, esuffix) = if unparsed
                        || !target.contains('\\')
                        || target.starts_with(r"\\")
                        || std::path::Path::new(&target).exists()
                    {
                        ("", "")
                    } else {
                        (" · 路径已核验不存在（历史打开记录，文件可能已被删除/移动）", "（已不存在）")
                    };
                    events.push(ActivityEvent {
                        time,
                        kind: "打开文档".into(),
                        desc: if unparsed {
                            format!("（LNK 名，目标未解析）{target}")
                        } else {
                            format!("{target}{esuffix}")
                        },
                        info: format!(
                            "最近文档 · 用户 {uname}{}{enote}",
                            if unparsed { " · LNK 结构不完整，显示文件名" } else { "" }
                        ),
                        module: MODULE.into(),
                        sev: Sev::None,
                        tags: vec![],
                    });
                    count += 1;
                }
            }
            // 注册表 RecentDocs MRU：LNK 已被删除的文档历史（删除 resistant）
            let mut reg_only = 0usize;
            let sid = name_to_sid
                .iter()
                .find(|(n, _)| *n == uname.to_ascii_lowercase())
                .map(|(_, s)| s.clone())
                .unwrap_or_default();
            let rd_key = format!(
                r"{sid}\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
            );
            if !rd_key.starts_with('\\') && !rd_key.is_empty() {
                if let Ok(names) =
                    crate::regutil::value_names(crate::regutil::HKEY::users(), &rd_key)
                {
                    for n in names {
                        // MRUListEx 是索引顺序（二进制），跳过；条目值名是 "0"~"N"
                        if n == "MRUListEx" || !n.chars().all(|c| c.is_ascii_digit()) {
                            continue;
                        }
                        let Ok((bytes, _ty)) = crate::regutil::read_value(
                            crate::regutil::HKEY::users(),
                            &rd_key,
                            &n,
                        ) else {
                            continue;
                        };
                        let Some(p) = recentdocs_value_path(&bytes) else {
                            continue;
                        };
                        if seen.contains(&p.to_ascii_lowercase()) {
                            continue; // 文件扫描已覆盖
                        }
                        reg_only += 1;
                        events.push(ActivityEvent {
                            time: "（无时间戳）".into(),
                            kind: "打开文档".into(),
                            desc: p,
                            info: format!(
                                "最近文档（注册表 MRU，LNK 文件已不存在——可能被清理/删除）· 用户 {uname}"
                            ),
                            module: MODULE.into(),
                            sev: Sev::None,
                            tags: vec![],
                        });
                    }
                }
            }
            logs.push(format!(
                "{uname}：{count} 条最近文档（另有 {reg_only} 条仅注册表留痕）",
            ));
        }
        let empty = events.is_empty();
        if empty {
            logs.push("Recent 文件夹为空或不可读（常见于关闭'最近文件'隐私设置）".into());
        }
        wrap(
            self.id(),
            if empty { ModuleStatus::Warn } else { ModuleStatus::Ok },
            events,
            logs,
            t0,
        )
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

    /// 构造最小合法 LNK：头 + HasLinkTargetIDList + 空 IDList + LinkInfo(LocalBasePath)
    fn minimal_lnk(base_path: &[u8]) -> Vec<u8> {
        let mut b = vec![0x4C, 0x00, 0x00, 0x00];
        b.extend_from_slice(&[0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46]); // CLSID
        b.extend_from_slice(&0x01u32.to_le_bytes()); // LinkFlags: HasLinkTargetIDList
        b.extend_from_slice(&[0u8; 0x34]);           // FileAttributes..Reserved 到 0x4C
        b.extend_from_slice(&0x02u16.to_le_bytes()); // IDList 大小=2（空）
        // LinkInfo
        let mut li = Vec::new();
        li.extend_from_slice(&0u32.to_le_bytes());        // size 回填
        li.extend_from_slice(&0x1Cu32.to_le_bytes());     // header size
        li.extend_from_slice(&0x01u32.to_le_bytes());     // flags: VolumeIDAndLocalBasePath
        li.extend_from_slice(&0x18u32.to_le_bytes());     // VolumeIdOffset（头24字节后）
        li.extend_from_slice(&0x20u32.to_le_bytes());     // LocalBasePathOffset（头24+VolumeID8）
        li.extend_from_slice(&0u32.to_le_bytes());        // CommonNetworkRelativeLinkOffset
        li.extend_from_slice(&[0; 8]);                    // VolumeID（占位）
        li.extend_from_slice(base_path);
        li.push(0);
        let size = li.len() as u32;
        li[0..4].copy_from_slice(&size.to_le_bytes());
        b.extend_from_slice(&li);
        b
    }

    #[test]
    fn parses_minimal_lnk_local_base_path() {
        let b = minimal_lnk(b"C:\\docs\\x.txt");
        assert_eq!(lnk_local_base_path(&b).unwrap(), "C:\\docs\\x.txt");
    }

    #[test]
    fn lnk_garbage_is_none() {
        assert!(lnk_local_base_path(&[0; 32]).is_none());
        assert!(lnk_local_base_path(&[]).is_none());
    }

    #[test]
    fn recentdocs_registry_value_parsed() {
        // [u16 cb=2][IDL 2 字节][UTF-16 路径][NUL]
        let mut b = Vec::new();
        b.extend_from_slice(&2u16.to_le_bytes());
        b.extend_from_slice(&[0xAB, 0xCD]);
        for u in r"C:\docs\报告.docx".encode_utf16() {
            b.extend_from_slice(&u.to_le_bytes());
        }
        b.extend_from_slice(&0u16.to_le_bytes());
        assert_eq!(recentdocs_value_path(&b).as_deref(), Some(r"C:\docs\报告.docx"));
        // cb=0 / 过短 / 空
        assert!(recentdocs_value_path(&[0, 0, 0, 0]).is_none());
        assert!(recentdocs_value_path(&[1, 2, 3]).is_none());
        let empty_path = {
            let mut v = vec![2, 0, 0xAB, 0xCD, 0, 0];
            v.extend_from_slice(&0u16.to_le_bytes());
            v
        };
        assert!(recentdocs_value_path(&empty_path).is_none());
    }

    #[test]
    fn collector_runs_without_recent() {
        // 本机 Recent 为空也必须优雅返回
        let r = RecentDocsCollector::default().run();
        assert!(!r.logs.is_empty());
    }
}
