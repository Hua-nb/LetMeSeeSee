//! SHITEMID（Shell Item）结构化解析。
//! 布局依据：本机真实 BagMRU/OpenSavePidlMRU 2217 个注册表节点实测（2026-09-25）：
//!
//! 0x31 家族（0x31/0x32/0x35/0x36/0xB1，文件/文件夹项，占真实数据 ~95%）：
//! ```text
//! [0]=类型 [1..6]=标志/保留(常 0) [6..10]=FAT日期时间 [10..12]=0x0010
//! [12..]=ASCII 短名(8.3) + NUL（实测 1914/1914 条均为可打印 ASCII+NUL）
//! —— 扩展块（自短名 NUL 后的偶偏移起）：
//! [size:2][09 00][04 00][ef be + FAT日期组][…][u32 文件大小]
//! [UTF-16 长名 + 0000][可选 "@shell32.dll,-NNNN" 本地化名引用 + 0000][尾 u16]
//! ```
//! 0x74：`74 00 1c 00 "CFSF" 16 00` 前缀后为内嵌 0x31 结构（自偏移 10）。
//! 0x2F：卷项，`2F` 后跟 ASCII+NUL 盘符（如 "D:\"）。
//! 0xC3：UNC 网络共享项，`C3 01 C1` 后跟 ASCII+NUL 的 \\server\share。
//! 其余类型（0x1F/0x71/0x78/0x00/0x61 等 GUID/属性块）→ 无名称：
//! 读不出就承认读不出，绝不用猜测性捞串制造假路径（实事求是）。


#[derive(Debug, Default)]
pub struct ShellItemInfo {
    pub name: Option<String>,
    pub raw_len: usize,
}

/// 按 [cb:2][data] 游走整个 ITEMIDLIST；cb==0 结束；越界/长度异常返回 None
pub fn walk_items(pidl: &[u8]) -> Option<Vec<ShellItemInfo>> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + 2 <= pidl.len() {
        let cb = u16::from_le_bytes([pidl[off], pidl[off + 1]]) as usize;
        if cb < 2 {
            break; // 0 或 1 = 终止/异常
        }
        if off + cb > pidl.len() {
            return None; // 结构损坏
        }
        let data = &pidl[off + 2..off + cb];
        out.push(parse_one(data, cb));
        off += cb;
    }
    Some(out)
}

fn parse_one(data: &[u8], cb: usize) -> ShellItemInfo {
    let name = match data.first() {
        // 0x31/0x32/0x35/0x36/0xB1 实测同族：短名@12 + 扩展块（0x32/0x36 为文件项变体）
        Some(t) if matches!(t, 0x31 | 0x32 | 0x35 | 0x36 | 0xB1) => folder_item_name(data, 0),
        Some(0x74) => {
            // 前缀 10 字节后应为内嵌 0x31 结构；不符则放弃（自校验）
            if data.get(10) == Some(&0x31) {
                folder_item_name(data, 10)
            } else {
                None
            }
        }
        Some(0x2F) => ansi_cstr_at(data, 1), // 盘符 "D:\"
        Some(0xC3) => ansi_cstr_at(data, 3), // \\server\share
        _ => None,                           // 未知类型：无名称，不猜测
    };
    ShellItemInfo { name, raw_len: cb }
}

/// 偏移 off 处的 ASCII NUL 终止串；不可打印即无效
fn ansi_cstr_at(data: &[u8], off: usize) -> Option<String> {
    ansi_cstr_range(data, off).map(|(s, _)| s)
}

/// 偏移 off 处的 ASCII NUL 终止串 + 终止符后的偏移；不可打印即无效
fn ansi_cstr_range(data: &[u8], off: usize) -> Option<(String, usize)> {
    if off >= data.len() {
        return None;
    }
    let rel = data[off..].iter().position(|&b| b == 0)?;
    if rel == 0 {
        return None;
    }
    let seg = &data[off..off + rel];
    if !seg.iter().all(|&b| (0x20..=0x7e).contains(&b)) {
        return None;
    }
    Some((String::from_utf8_lossy(seg).into_owned(), off + rel + 1))
}

/// 偏移 off 处的 UTF-16LE NUL 终止串 + 终止符后的偏移；出现不可读单元即无效。
/// 短名槽的第二形态：名字以中文等非 ASCII 开头时，Windows 直接在短名槽存 UTF-16
/// （实测 data[12..18] = ee 76 55 5f 00 00 = "目录"）
fn utf16_cstr_range(data: &[u8], off: usize) -> Option<(String, usize)> {
    let mut units = Vec::new();
    let mut i = off;
    while i + 2 <= data.len() {
        let u = u16::from_le_bytes([data[i], data[i + 1]]);
        if u == 0 {
            if units.is_empty() {
                return None;
            }
            return Some((String::from_utf16_lossy(&units), i + 2));
        }
        if !printable_unit(u) {
            return None;
        }
        units.push(u);
        i += 2;
    }
    None
}

/// 0x31 家族：短名（偏移 12，ASCII 或 UTF-16 双形态）+ 扩展块 UTF-16 长名（优先，更可读）。
/// 旧版只按 ANSI 读短名槽——中文名开头的条目（短名槽为 UTF-16）整条无名丢弃
fn folder_item_name(data: &[u8], base: usize) -> Option<String> {
    let (short, mut ext) = match ansi_cstr_range(data, base + 12) {
        Some((s, e)) => (s, e),
        None => utf16_cstr_range(data, base + 12)?,
    };
    ext += ext & 1; // 扩展块字段字对齐：偶偏移（奇偏移解析必为乱码）
    let ext_data = &data[ext.min(data.len())..];
    // 扩展块内 ef be（BEEF）标记后跟两组 FAT 日期——日期字节对常落 CJK 区
    // （eb 58 83 65 → "士斃"），绝不可当名字。长名扫描从 标记+10（跳标记与日期）起；
    // 找不到结构标记则不猜长名（只用短名，实事求是）
    let scan: &[u8] = {
        let limit = ext_data.len().min(32);
        let mut start = None;
        let mut i = 0;
        while i + 2 <= limit {
            if ext_data[i] == 0xef && ext_data[i + 1] == 0xbe {
                start = Some(i + 10);
                break;
            }
            i += 2;
        }
        match start {
            Some(s) => &ext_data[s.min(ext_data.len())..],
            None => &[],
        }
    };
    let long = last_long_name(scan).map(|l| trim_size_prefix(&l, &short));
    Some(long.unwrap_or(short))
}

/// 长名区前固定有 4 字节文件大小，其字节可能落可打印区粘在名字头（如
/// "b6 62 31 00"+"wwmapp" → "抶1wwmapp"）。8.3 短名与长名共享首字符——
/// 试剥 0/1/2 个前导字符，取首字符与短名一致的最长候选。
fn trim_size_prefix(run: &str, short: &str) -> String {
    let first = short.chars().next().map(|c| c.to_ascii_lowercase());
    let mut best: Option<String> = None;
    for skipped in [0usize, 1, 2] {
        let cand: String = run.chars().skip(skipped).collect();
        if cand.is_empty() {
            continue;
        }
        let cf = cand.chars().next().unwrap().to_ascii_lowercase();
        if Some(cf) == first {
            if best.as_ref().map_or(true, |b| cand.len() > b.len()) {
                best = Some(cand);
            }
        }
    }
    best.unwrap_or_else(|| run.to_string())
}

/// UTF-16 单元是否可读（ASCII 可打印 / CJK / 常用全角符号）
fn printable_unit(u: u16) -> bool {
    (0x20..=0x7e).contains(&u)
        || (0x4e00..=0x9fff).contains(&u)
        || matches!(u, 0xff08 | 0xff09 | 0x3010 | 0x3011 | 0x00b7 | 0x2014 | 0x00b7)
}

/// 收集扩展块内全部合法 UTF-16 NUL 终止串（仅偶偏移扫描）
fn utf16_runs(data: &[u8]) -> Vec<String> {
    let mut runs = Vec::new();
    let mut i = 0usize;
    while i + 2 <= data.len() {
        let mut units = Vec::new();
        let mut j = i;
        let mut terminated = false;
        while j + 2 <= data.len() {
            let u = u16::from_le_bytes([data[j], data[j + 1]]);
            if u == 0 {
                terminated = true;
                break;
            }
            if !printable_unit(u) {
                break; // 非可读单元：本 run 非干净字符串，丢弃
            }
            units.push(u);
            j += 2;
        }
        if terminated && units.len() >= 2 {
            runs.push(String::from_utf16_lossy(&units));
        }
        i = (if j > i { j + 2 } else { i + 2 }).max(i + 2);
        i += i & 1; // 保持偶偏移步进
    }
    runs
}

/// 扩展块长名选择：取最后一个合格串——跳过 "@shell32.dll,-NNNN" 本地化引用；
/// 质量门槛：含连续两字母数字、≥3 字符、或 2 字符中英混合（如 "D盾"）。
/// 全低字节为 0 的串是错位乱码，排除。
fn last_long_name(data: &[u8]) -> Option<String> {
    for r in utf16_runs(data).into_iter().rev() {
        if r.starts_with('@') {
            continue; // 资源引用不是名字
        }
        let chars: Vec<char> = r.chars().collect();
        let has_run2 = chars
            .windows(2)
            .any(|w| w[0].is_ascii_alphanumeric() && w[1].is_ascii_alphanumeric());
        let has_cjk = chars.iter().any(|c| ('\u{4e00}'..='\u{9fff}').contains(c));
        let has_alnum = chars.iter().any(|c| c.is_ascii_alphanumeric());
        let all_low_zero = r.encode_utf16().all(|u| u & 0xff == 0);
        let ok = has_run2
            || chars.len() >= 3
            || (chars.len() == 2 && has_cjk && has_alnum); // "D盾" 类真名
        if ok && !all_low_zero {
            return Some(r);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // 本机 OpenSavePidlMRU 真实捕获（725 字节完整 PIDL，机器生成杜绝转写误差）。
    // 夹具含真实路径不入库（隐私）；本地缺失时返回 None，用到的测试自动跳过
    fn real_osmru() -> Option<Vec<u8>> {
        std::fs::read(std::path::Path::new("testdata/osmru-longest.bin")).ok()
    }

    fn folder_item(short: &str, long: Option<&str>, res_ref: Option<&str>) -> Vec<u8> {
        // 按实测布局构造 0x31 条目（含完整扩展块）
        let mut it = vec![0x31u8, 0, 0, 0, 0, 0];
        it.extend_from_slice(&[0xeb, 0x58, 0x04, 0x66]); // FAT 日期组（曾制造 士斃 乱码）
        it.extend_from_slice(&[0x10, 0x00]);
        it.extend_from_slice(short.as_bytes());
        it.push(0); // NUL
        if (12 + short.len() + 1) % 2 == 1 {
            it.push(0); // 垫至偶边界（实测：偶长名 NUL 后还有一个垫零）
        }
        if long.is_some() || res_ref.is_some() {
            let mut ext = vec![0x09u8, 0x00, 0x04, 0x00];
            ext.extend_from_slice(&[0xef, 0xbe, 0xeb, 0x58, 0xd7, 0x64, 0xeb, 0x58, 0x04, 0x66]);
            ext.extend_from_slice(&[0x2e, 0x00, 0x00, 0x00, 0x3f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00]);
            ext.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            // 文件大小：取实测样本的字节（对齐后不落可打印区，避免与名字粘连）
            ext.extend_from_slice(&0x8d_bf_aeu32.to_le_bytes());
            if let Some(l) = long {
                for u in l.encode_utf16() {
                    ext.extend_from_slice(&u.to_le_bytes());
                }
                ext.extend_from_slice(&[0, 0]);
            }
            if let Some(rf) = res_ref {
                for u in rf.encode_utf16() {
                    ext.extend_from_slice(&u.to_le_bytes());
                }
                ext.extend_from_slice(&[0, 0]);
            }
            ext.extend_from_slice(&[0x14, 0x00]); // 尾标记
            let ext_len = (ext.len() + 2) as u16;
            it.extend_from_slice(&ext_len.to_le_bytes());
            it.extend_from_slice(&ext);
        }
        let mut pidl = ((it.len() + 2) as u16).to_le_bytes().to_vec();
        pidl.extend_from_slice(&it);
        pidl
    }

    fn pidl_of(items: &[Vec<u8>]) -> Vec<u8> {
        let mut p = Vec::new();
        for it in items {
            p.extend_from_slice(it);
        }
        p.extend_from_slice(&[0, 0]);
        p
    }

    #[test]
    fn walks_real_fixture_by_length() {
        let Some(osmru) = real_osmru() else { eprintln!("跳过：无 osmru 夹具"); return; };
        let items = walk_items(&osmru).unwrap();
        assert!(items.len() >= 3, "条目数 {}", items.len());
        assert_eq!(items[0].raw_len, 20); // My Computer GUID 项
    }

    #[test]
    fn extracts_real_fixture_name() {
        let Some(osmru) = real_osmru() else { eprintln!("跳过：无 osmru 夹具"); return; };
        let items = walk_items(&osmru).unwrap();
        let names: Vec<&str> = items.iter().filter_map(|i| i.name.as_deref()).collect();
        assert!(
            names.iter().any(|n| n.contains("sqlmap")),
            "真实路径名称应包含 sqlmap：{names:?}"
        );
    }

    #[test]
    fn user_case_users_long_name_wins_over_resource_ref() {
        // 用户实测案例：D:\data\user1\Documents 链
        let pidl = pidl_of(&[
            folder_item("Users", Some("Users"), Some("@shell32.dll,-21813")),
            folder_item("user1", Some("user1"), None),
            folder_item("DOCUME~1", Some("Documents"), Some("@shell32.dll,-21770")),
        ]);
        let items = walk_items(&pidl).unwrap();
        let names: Vec<&str> = items.iter().filter_map(|i| i.name.as_deref()).collect();
        assert_eq!(names, vec!["Users", "user1", "Documents"]);
    }

    #[test]
    fn ctf_case_short_and_long() {
        // 用户报告的 D:\CTF8\士斃士斃.\e8] 案例：真实名称为 CTF7PL~1 / CTF7plusDocs
        let pidl = pidl_of(&[folder_item("CTF7PL~1", Some("CTF7plusDocs"), None)]);
        assert_eq!(walk_items(&pidl).unwrap()[0].name.as_deref(), Some("CTF7plusDocs"));
        let pidl2 = pidl_of(&[folder_item("CTF", Some("CTF"), None)]);
        assert_eq!(walk_items(&pidl2).unwrap()[0].name.as_deref(), Some("CTF"));
    }

    #[test]
    fn fat_date_bytes_never_leak_as_name() {
        // 头部 FAT 日期 eb 58 83 65 曾被误读为 "士斃"——结构化解析后不再可能
        let pidl = pidl_of(&[folder_item("wang", Some("wang"), None)]);
        let n = walk_items(&pidl).unwrap()[0].name.clone().unwrap();
        assert_eq!(n, "wang");
    }

    #[test]
    fn chinese_long_name_extracted() {
        let pidl = pidl_of(&[folder_item("1-AP~1", Some("1.信息收集"), None)]);
        assert_eq!(walk_items(&pidl).unwrap()[0].name.as_deref(), Some("1.信息收集"));
    }

    #[test]
    fn short_name_only_when_no_ext() {
        let pidl = pidl_of(&[folder_item("GUI-S~1", None, None)]);
        assert_eq!(walk_items(&pidl).unwrap()[0].name.as_deref(), Some("GUI-S~1"));
    }

    #[test]
    fn volume_item_gives_drive_letter() {
        let mut it = vec![0x2Fu8];
        it.extend_from_slice(b"D:\\");
        it.push(0);
        it.extend_from_slice(&[0u8; 16]);
        let mut pidl = ((it.len() + 2) as u16).to_le_bytes().to_vec();
        pidl.extend_from_slice(&it);
        pidl.extend_from_slice(&[0, 0]);
        assert_eq!(walk_items(&pidl).unwrap()[0].name.as_deref(), Some("D:\\"));
    }

    #[test]
    fn unc_network_item() {
        let mut it = vec![0xC3u8, 0x01, 0xC1];
        it.extend_from_slice(br"\\192.168.95.181\Users");
        it.push(0);
        it.extend_from_slice(b"Microsoft Network");
        it.extend_from_slice(&[0, 0, 0x02, 0x00]);
        let mut pidl = ((it.len() + 2) as u16).to_le_bytes().to_vec();
        pidl.extend_from_slice(&it);
        pidl.extend_from_slice(&[0, 0]);
        assert_eq!(
            walk_items(&pidl).unwrap()[0].name.as_deref(),
            Some(r"\\192.168.95.181\Users")
        );
    }

    #[test]
    /// 真实捕获回归：短名槽为 UTF-16 形态的中文名条目（2026-10-16 实测，
    /// 旧版只按 ANSI 读导致整条无名丢弃——D:\CTF\dictionary字典\目录 链消失）
    #[test]
    fn utf16_short_name_parses() {
        // BagMRU 值[1]（"目录"，0x35，76 字节逐字节照抄）
        let dir_item: [u8; 76] = [
            0x4a, 0x00, 0x35, 0x00, 0x00, 0x00, 0x00, 0x00, 0xeb, 0x58, 0x83, 0x65,
            0x10, 0x00, 0xee, 0x76, 0x55, 0x5f, 0x00, 0x00, 0x36, 0x00, 0x09, 0x00,
            0x04, 0x00, 0xef, 0xbe, 0xeb, 0x58, 0x83, 0x65, 0xf0, 0x58, 0x0e, 0x12,
            0x2e, 0x00, 0x00, 0x00, 0x10, 0xd0, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xd5, 0x7e, 0xa9, 0x00, 0xee, 0x76, 0x55, 0x5f, 0x00, 0x00,
            0x14, 0x00, 0x00, 0x00,
        ];
        let items = walk_items(&dir_item).unwrap();
        assert_eq!(items[0].name.as_deref(), Some("目录"));

        // BagMRU 28\1 值[2]（"新建文件夹 (3)"，0x35，104 字节逐字节照抄）
        let new_folder: [u8; 104] = [
            0x66, 0x00, 0x35, 0x00, 0x00, 0x00, 0x00, 0x00, 0xeb, 0x58, 0x83, 0x65,
            0x10, 0x00, 0xb0, 0x65, 0xfa, 0x5e, 0x87, 0x65, 0xf6, 0x4e, 0x39, 0x59,
            0x20, 0x00, 0x28, 0x00, 0x33, 0x00, 0x29, 0x00, 0x00, 0x00, 0x44, 0x00,
            0x09, 0x00, 0x04, 0x00, 0xef, 0xbe, 0xeb, 0x58, 0x83, 0x65, 0xf0, 0x58,
            0x0e, 0x12, 0x2e, 0x00, 0x00, 0x00, 0x21, 0xd0, 0x01, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x1a, 0xf4, 0xa9, 0x00, 0xb0, 0x65, 0xfa, 0x5e,
            0x87, 0x65, 0xf6, 0x4e, 0x39, 0x59, 0x20, 0x00, 0x28, 0x00, 0x33, 0x00,
            0x29, 0x00, 0x00, 0x00, 0x22, 0x00, 0x00, 0x00,
        ];
        let items = walk_items(&new_folder).unwrap();
        assert_eq!(items[0].name.as_deref(), Some("新建文件夹 (3)"));
    }

    fn embedded_0x74_requires_0x31_signature() {
        // 前缀不符时不得硬解
        let mut it = vec![0x74u8, 0x00, 0x1c, 0x00, b'C', b'F', b'S', b'F', 0x16, 0x00, 0x32];
        it.extend_from_slice(&[0u8; 12]);
        let mut pidl = ((it.len() + 2) as u16).to_le_bytes().to_vec();
        pidl.extend_from_slice(&it);
        pidl.extend_from_slice(&[0, 0]);
        assert!(walk_items(&pidl).unwrap()[0].name.is_none());
    }

    #[test]
    fn unknown_types_have_no_name() {
        for t in [0x1Fu8, 0x71, 0x78, 0x00, 0x61] {
            let mut it = vec![t];
            it.extend_from_slice(&[0x58u8; 20]);
            let mut pidl = ((it.len() + 2) as u16).to_le_bytes().to_vec();
            pidl.extend_from_slice(&it);
            pidl.extend_from_slice(&[0, 0]);
            let info = &walk_items(&pidl).unwrap()[0];
            assert!(info.name.is_none(), "类型 {t:#x} 不应猜名");
        }
    }

    #[test]
    fn filesize_prefix_trimmed_from_long_name() {
        // 本机真实条目：短名 "wwmapp"，文件大小 b6 62 31 00 粘连成 "抶1wwmapp"
        let raw: [u8; 82] = [
            0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0xcc, 0x5a, 0xbc, 0x39, 0x10, 0x00, 0x77, 0x77,
            0x6d, 0x61, 0x70, 0x70, 0x00, 0x00, 0x3e, 0x00, 0x09, 0x00, 0x04, 0x00, 0xef, 0xbe,
            0xcc, 0x5a, 0xbc, 0x39, 0x31, 0x5c, 0x8c, 0x0b, 0x2e, 0x00, 0x00, 0x00, 0x40, 0x01,
            0x0d, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb6, 0x62, 0x31, 0x00, 0x77, 0x00, 0x77, 0x00,
            0x6d, 0x00, 0x61, 0x00, 0x70, 0x00, 0x70, 0x00, 0x00, 0x00, 0x16, 0x00,
        ];
        let mut pidl = ((raw.len() + 2) as u16).to_le_bytes().to_vec();
        pidl.extend_from_slice(&raw);
        pidl.extend_from_slice(&[0, 0]);
        assert_eq!(
            walk_items(&pidl).unwrap()[0].name.as_deref(),
            Some("wwmapp")
        );
    }

    #[test]
    fn misaligned_low_zero_run_rejected() {
        // 全低字节为 0 的 "串"（错位解码产物）必须被排除
        let junk: Vec<u16> = vec![0x6f00, 0x6300, 0x7500, 0x6d00];
        let mut data = Vec::new();
        for u in junk {
            data.extend_from_slice(&u.to_le_bytes());
        }
        data.extend_from_slice(&[0, 0]);
        assert!(last_long_name(&data).is_none());
    }

    #[test]
    fn corrupt_length_is_none() {
        assert!(walk_items(&[0x05, 0x00, 0x01]).is_none()); // 声明长度越界
    }

    #[test]
    #[ignore = "真实 HKCU；本机 cargo test -- --ignored"]
    fn real_shellbags_clean_of_mojibake() {
        use crate::model::Collector;
        let r = crate::modules::shellbags::ShellBagsCollector::default().run();
        assert!(r.count >= 100, "{:?}", r.logs);
        for e in &r.events {
            for ch in ['士', '斃', '獕', '牥', '啈', '抶'] {
                assert!(!e.desc.contains(ch), "残留乱码 {}：{}", ch, e.desc);
            }
        }
    }
}
