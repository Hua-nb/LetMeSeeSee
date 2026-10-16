//! 注册表浏览器：任意键路径的只读浏览（regedit 前端化后端）。
//! 只允许预定义根（HKLM/HKU/HKCU/HKCR/HKCC），KEY_READ 打不开的键如实报错。

use serde::Serialize;
use winreg::enums::*;
use winreg::{RegKey, RegValue};

const MAX_SUBKEYS: usize = 4000;
const MAX_VALUES: usize = 4000;
const MAX_BIN_PREVIEW: usize = 512; // 二进制值最多预览字节数

#[derive(Serialize)]
pub struct SubKeyInfo {
    pub name: String,
    pub last_write: String,
}

#[derive(Serialize)]
pub struct ValueInfo {
    pub name: String,
    pub ty: String,
    pub data: String,
    pub truncated: bool,
}

#[derive(Serialize)]
pub struct BrowseResult {
    pub path: String,
    pub last_write: String,
    pub subkeys: Vec<SubKeyInfo>,
    pub values: Vec<ValueInfo>,
    /// 截断/降级说明（空=完全列出）
    pub note: String,
}

/// 根名 → 预定义 HKEY
pub fn root_handle(root: &str) -> Option<isize> {
    Some(match root.to_ascii_uppercase().as_str() {
        "HKLM" => HKEY_LOCAL_MACHINE,
        "HKU" => HKEY_USERS,
        "HKCU" => HKEY_CURRENT_USER,
        "HKCR" => HKEY_CLASSES_ROOT,
        "HKCC" => HKEY_CURRENT_CONFIG,
        _ => return None,
    })
}

/// 规整用户输入路径 → (HKEY, 子键路径, 规范显示路径)
pub fn parse_path(input: &str) -> Result<(isize, String, String), String> {
    let norm = input.trim().trim_matches('\\').replace('/', "\\");
    let mut parts = norm.split('\\').filter(|s| !s.is_empty());
    let root = parts.next().unwrap_or("").to_string();
    let handle = root_handle(&root)
        .ok_or_else(|| format!("未知注册表根（支持 HKLM/HKU/HKCU/HKCR/HKCC）：{root}"))?;
    let sub: Vec<&str> = parts.collect();
    let disp = if sub.is_empty() {
        root.to_ascii_uppercase()
    } else {
        format!("{}\\{}", root.to_ascii_uppercase(), sub.join("\\"))
    };
    Ok((handle, sub.join("\\"), disp))
}

fn hex_preview(b: &[u8]) -> (String, bool) {
    if b.len() <= MAX_BIN_PREVIEW {
        (
            b.iter().map(|x| format!("{x:02X}")).collect::<Vec<_>>().join(" "),
            false,
        )
    } else {
        (
            b[..MAX_BIN_PREVIEW]
                .iter()
                .map(|x| format!("{x:02X}"))
                .collect::<Vec<_>>()
                .join(" ")
                + &format!(" …（共 {} 字节，已截断）", b.len()),
            true,
        )
    }
}

/// 渲染值数据（纯函数便于测试）：(类型名, 数据, 是否截断)
pub fn render_value(v: &RegValue) -> (String, String, bool) {
    use winreg::enums::RegType::*;
    let vt = v.vtype.clone();
    match vt {
        REG_SZ | REG_EXPAND_SZ => (
            format!("{:?}", v.vtype),
            crate::encoding::decode_reg_string(&v.bytes, vt),
            false,
        ),
        REG_DWORD if v.bytes.len() >= 4 => {
            let n = u32::from_le_bytes(v.bytes[..4].try_into().unwrap());
            ("REG_DWORD".into(), format!("{n} (0x{n:X})"), false)
        }
        REG_QWORD if v.bytes.len() >= 8 => {
            let n = u64::from_le_bytes(v.bytes[..8].try_into().unwrap());
            ("REG_QWORD".into(), format!("{n} (0x{n:X})"), false)
        }
        REG_MULTI_SZ => {
            let units: Vec<u16> = v
                .bytes
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            let mut cur = Vec::new();
            let mut lines = Vec::new();
            for u in units {
                if u == 0 {
                    if !cur.is_empty() {
                        lines.push(String::from_utf16_lossy(&cur));
                        cur.clear();
                    }
                } else {
                    cur.push(u);
                }
            }
            let (data, truncated) = if lines.len() > 200 {
                (lines[..200].join("\\n") + " …（截断）", true)
            } else {
                (lines.join("\\n"), false)
            };
            ("REG_MULTI_SZ".into(), data, truncated)
        }
        REG_NONE if v.bytes.is_empty() => ("REG_NONE".into(), "（空）".into(), false),
        REG_BINARY | REG_NONE => {
            let (hex, tr) = hex_preview(&v.bytes);
            ("REG_BINARY".into(), hex, tr)
        }
        other => {
            let (hex, tr) = hex_preview(&v.bytes);
            (format!("{other:?}"), hex, tr)
        }
    }
}

/// 浏览一个键：列出子键（含各自最后写入时间）与值
pub fn browse(input: &str) -> Result<BrowseResult, String> {
    let (handle, sub, disp) = parse_path(input)?;
    let key = if sub.is_empty() {
        RegKey::predef(handle)
    } else {
        RegKey::predef(handle)
            .open_subkey_with_flags(&sub, KEY_READ)
            .map_err(|e| format!("打开 {disp} 失败：{e}"))?
    };
    let last_write = key
        .query_info()
        .ok()
        .and_then(|i| {
            let st = i.get_last_write_time_system();
            crate::regutil::systemtime_utc_to_local(
                st.wYear as i32,
                st.wMonth as u32,
                st.wDay as u32,
                st.wHour as u32,
                st.wMinute as u32,
                st.wSecond as u32,
            )
        })
        .unwrap_or_default();

    let mut note = String::new();
    let mut subkeys = Vec::new();
    // 增量枚举：到达上限即停止（先收集后截断会把超大键的全部值数据读入内存）
    let mut names: Vec<String> = Vec::new();
    let mut key_total = 0usize;
    for n in key.enum_keys().flatten() {
        key_total += 1;
        if names.len() < MAX_SUBKEYS {
            names.push(n);
        }
    }
    names.sort_by_key(|a| a.to_lowercase());
    if key_total > MAX_SUBKEYS {
        note = format!("子键共 {} 个，仅列出前 {} 个", key_total, MAX_SUBKEYS);
    }
    for n in names {
        let child_path = if sub.is_empty() {
            n.clone()
        } else {
            format!(r"{sub}\{n}")
        };
        let lw = RegKey::predef(handle)
            .open_subkey_with_flags(&child_path, KEY_READ)
            .ok()
            .and_then(|k| k.query_info().ok())
            .and_then(|i| {
                let st = i.get_last_write_time_system();
                crate::regutil::systemtime_utc_to_local(
                    st.wYear as i32,
                    st.wMonth as u32,
                    st.wDay as u32,
                    st.wHour as u32,
                    st.wMinute as u32,
                    st.wSecond as u32,
                )
            })
            .unwrap_or_else(|| "（无权限读时间）".into());
        subkeys.push(SubKeyInfo { name: n, last_write: lw });
    }

    let mut values = Vec::new();
    let mut v_total = 0usize;
    let mut vlist: Vec<(String, RegValue)> = Vec::new();
    for item in key.enum_values().flatten() {
        v_total += 1;
        if vlist.len() < MAX_VALUES {
            vlist.push(item);
        }
    }
    if v_total > MAX_VALUES {
        if !note.is_empty() {
            note.push('；');
        }
        note.push_str(&format!("值共 {} 个，仅列出前 {} 个", v_total, MAX_VALUES));
    }
    vlist.sort_by_key(|(n, _)| if n.is_empty() { "\0默认".into() } else { n.to_lowercase() });
    for (n, v) in vlist {
        let (ty, data, truncated) = render_value(&v);
        values.push(ValueInfo {
            name: if n.is_empty() { "(默认)".into() } else { n },
            ty,
            data,
            truncated,
        });
    }
    Ok(BrowseResult {
        path: disp,
        last_write,
        subkeys,
        values,
        note,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use winreg::enums::RegType;

    #[test]
    fn parses_roots_case_insensitive() {
        let (h, sub, disp) = parse_path(" hklm\\Software/Microsoft ").unwrap();
        assert_eq!(h, HKEY_LOCAL_MACHINE);
        assert_eq!(sub, r"Software\Microsoft");
        assert_eq!(disp, r"HKLM\Software\Microsoft");
        let (_, sub, disp) = parse_path("HKU\\S-1-5-21-x\\").unwrap();
        assert_eq!(sub, r"S-1-5-21-x");
        assert_eq!(disp, r"HKU\S-1-5-21-x");
        let (_, sub, disp) = parse_path("HKLM").unwrap();
        assert_eq!(sub, "");
        assert_eq!(disp, "HKLM");
    }

    #[test]
    fn rejects_unknown_root() {
        assert!(parse_path("HKXX\\Software").is_err());
        assert!(parse_path("").is_err());
    }

    #[test]
    fn renders_dword_and_qword() {
        let v = RegValue {
            bytes: vec![0xd2, 0x04, 0x00, 0x00],
            vtype: RegType::REG_DWORD,
        };
        assert_eq!(render_value(&v).1, "1234 (0x4D2)");
        let q = RegValue {
            bytes: vec![1, 0, 0, 0, 0, 0, 0, 0],
            vtype: RegType::REG_QWORD,
        };
        assert_eq!(render_value(&q).1, "1 (0x1)");
    }

    #[test]
    fn renders_binary_with_truncation() {
        let small = RegValue {
            bytes: vec![0xAB, 0xCD],
            vtype: RegType::REG_BINARY,
        };
        assert_eq!(render_value(&small).1, "AB CD");
        let big = RegValue {
            bytes: vec![0u8; 600],
            vtype: RegType::REG_BINARY,
        };
        let (ty, data, truncated) = render_value(&big);
        assert_eq!(ty, "REG_BINARY");
        assert!(truncated && data.contains("共 600 字节"));
    }

    #[test]
    fn renders_multi_sz_lines() {
        fn utf16(items: &[&str]) -> Vec<u8> {
            let mut v = Vec::new();
            for it in items {
                for u in it.encode_utf16() {
                    v.extend_from_slice(&u.to_le_bytes());
                }
                v.extend_from_slice(&0u16.to_le_bytes());
            }
            v
        }
        let v = RegValue {
            bytes: utf16(&["line1", "line2"]),
            vtype: RegType::REG_MULTI_SZ,
        };
        assert_eq!(render_value(&v).1, "line1\\nline2");
    }

    #[test]
    #[ignore = "真实注册表；本机 cargo test -- --ignored"]
    fn browses_real_software_key() {
        let r = browse(r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion").unwrap();
        assert!(r.subkeys.iter().any(|k| k.name == "Winlogon"));
        assert!(r.values.iter().any(|v| v.name == "ProductName"));
    }
}
