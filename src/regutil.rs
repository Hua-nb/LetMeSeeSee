use winreg::enums::*;
use winreg::{RegKey, RegValue};

/// HKEY 句柄包装（windows-sys 的 HKEY 即 isize，这里语义化）
#[derive(Clone, Copy)]
pub struct HKEY(pub isize);

impl HKEY {
    pub const fn local_machine() -> Self {
        HKEY(HKEY_LOCAL_MACHINE)
    }
    pub const fn users() -> Self {
        HKEY(HKEY_USERS)
    }
    pub const fn current_user() -> Self {
        HKEY(HKEY_CURRENT_USER)
    }
}

/// 枚举 HKU 下真实用户 SID（S-1-5-21-* 且非 *_Classes）
pub fn user_sids() -> Vec<String> {
    let hku = RegKey::predef(HKEY_USERS);
    hku.enum_keys()
        .flatten()
        .filter(|k| k.starts_with("S-1-5-21-") && !k.ends_with("_Classes"))
        .collect()
}

/// 读任意键值：返回 (数据字节, 类型)；路径不存在/无权限 → Err(String)
pub fn read_value(root: HKEY, subkey: &str, value: &str) -> Result<(Vec<u8>, RegType), String> {
    let key = RegKey::predef(root.0)
        .open_subkey_with_flags(subkey, KEY_READ)
        .map_err(|e| format!("打开 {subkey} 失败：{e}"))?;
    let rv: RegValue = key
        .get_raw_value(value)
        .map_err(|e| format!("读取 {subkey}\\{value} 失败：{e}"))?;
    Ok((rv.bytes.clone(), rv.vtype))
}

/// 枚举某键的直接子键名
pub fn subkeys(root: HKEY, subkey: &str) -> Result<Vec<String>, String> {
    let key = RegKey::predef(root.0)
        .open_subkey_with_flags(subkey, KEY_READ)
        .map_err(|e| format!("打开 {subkey} 失败：{e}"))?;
    Ok(key.enum_keys().flatten().collect())
}

/// 枚举某键下所有值名
pub fn value_names(root: HKEY, subkey: &str) -> Result<Vec<String>, String> {
    let key = RegKey::predef(root.0)
        .open_subkey_with_flags(subkey, KEY_READ)
        .map_err(|e| format!("打开 {subkey} 失败：{e}"))?;
    Ok(key.enum_values().flatten().map(|(name, _)| name).collect())
}

/// 是否以管理员运行：检测进程令牌 TokenElevation（标准 API，可靠）
pub fn is_elevated() -> bool {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    unsafe {
        let mut token: windows_sys::Win32::Foundation::HANDLE = 0;
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elev: TOKEN_ELEVATION = std::mem::zeroed();
        let mut ret_len = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elev as *mut _ as *mut core::ffi::c_void,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret_len,
        );
        CloseHandle(token);
        ok != 0 && elev.TokenIsElevated != 0
    }
}

/// 读字符串值（按注册表类型正确解码，杜绝乱码）
pub fn read_string_value(root: HKEY, subkey: &str, value: &str) -> Result<String, String> {
    let (bytes, ty) = read_value(root, subkey, value)?;
    Ok(crate::encoding::decode_reg_string(&bytes, ty))
}

/// 读子键最后写入时间（"YYYY-MM-DD HH:MM:SS.000"，本地时区）。
/// RegQueryInfoKey 返回 UTC FILETIME，winreg 的 get_last_write_time_system 只做
/// FileTimeToSystemTime（不做 FileTimeToLocalFileTime）——返回的是 UTC，
/// 必须手动转到本地，否则中国时区整体超前 8 小时、与其余时间源错位。
pub fn key_last_write(root: HKEY, subkey: &str) -> Option<String> {
    let key = RegKey::predef(root.0)
        .open_subkey_with_flags(subkey, KEY_READ)
        .ok()?;
    let st = key.query_info().ok()?.get_last_write_time_system();
    systemtime_utc_to_local(
        st.wYear as i32,
        st.wMonth as u32,
        st.wDay as u32,
        st.wHour as u32,
        st.wMinute as u32,
        st.wSecond as u32,
    )
}

/// winreg SYSTEMTIME（实为 UTC）→ 本地时间字符串；字段非法返回 None
pub fn systemtime_utc_to_local(
    y: i32,
    mo: u32,
    d: u32,
    h: u32,
    mi: u32,
    s: u32,
) -> Option<String> {
    use chrono::{Local, TimeZone, Utc};
    let utc = Utc
        .with_ymd_and_hms(y, mo, d, h, mi, s)
        .single()?;
    Some(
        utc.with_timezone(&Local)
            .format("%Y-%m-%d %H:%M:%S.000")
            .to_string(),
    )
}

/// 打开与模块对应的 Windows 原生管理工具（白名单固定命令，无参数注入面）。
/// Let me see see 提权运行时，唤起的工具继承管理员权限。
pub fn open_native_tool(tool: &str) -> bool {
    use winreg::enums::KEY_SET_VALUE;
    // regedit：先写 LastKey 定位到 HKLM Run（经典定位技巧），再启动
    if tool == "regedit" {
        if let Ok(k) = RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(
            r"Software\Microsoft\Windows\CurrentVersion\Applets\Regedit",
            KEY_SET_VALUE,
        ) {
            let _ = k.set_value(
                "LastKey",
                &r"计算机\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            );
        }
        return shell_open("regedit.exe", "");
    }
    let msc = match tool {
        "taskschd" => "taskschd.msc",
        "services" => "services.msc",
        "eventvwr" => "eventvwr.msc",
        "lusrmgr" => "lusrmgr.msc",
        _ => return false,
    };
    shell_open("mmc.exe", msc)
}

/// ShellExecuteW 打开（处理文件关联/权限，返回值 >32 为成功）
fn shell_open(file: &str, args: &str) -> bool {
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    let wide = |s: &str| {
        let mut v: Vec<u16> = s.encode_utf16().collect();
        v.push(0);
        v
    };
    let r = unsafe {
        ShellExecuteW(
            0,
            wide("open").as_ptr(),
            wide(file).as_ptr(),
            wide(args).as_ptr(),
            std::ptr::null(),
            1, // SW_SHOWNORMAL
        )
    };
    r as isize > 32
}

/// UTF-16LE 字节 → String（丢弃尾部 NUL）
pub fn utf16_bytes_to_string(b: &[u8]) -> String {
    let units: Vec<u16> = b
        .chunks_exact(2)
        .take_while(|c| !(c[0] == 0 && c[1] == 0))
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_user_sids() {
        let sids = user_sids();
        assert!(sids
            .iter()
            .any(|s| s.starts_with("S-1-5-21-") && !s.ends_with("_Classes")));
    }

    #[test]
    fn hklm_product_name_readable() {
        let (v, ty) = read_value(
            HKEY::local_machine(),
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            "ProductName",
        )
        .expect("ProductName 应可读");
        assert_eq!(ty, RegType::REG_SZ);
        assert!(!v.is_empty());
    }

    #[test]
    fn utf16_decodes_and_trims_nul() {
        let b: Vec<u8> = vec![0x43, 0x00, 0x3a, 0x00, 0x00, 0x00, 0x00, 0x00]; // "C:" + NUL
        assert_eq!(utf16_bytes_to_string(&b), "C:");
    }

    #[test]
    fn missing_key_is_err() {
        assert!(read_value(HKEY::local_machine(), r"SOFTWARE\Nonexistent\LMSS", "x").is_err());
    }

    #[test]
    fn key_last_write_is_local_not_utc() {
        // 时区回归：新建键的写入时间应接近"当前本地时间"。
        // 若误用 UTC，在东八区机器上会超前 8 小时、必然超出 ±10 分钟窗口。
        use winreg::RegKey;
        let root = RegKey::predef(HKEY_CURRENT_USER);
        let test_path = r"Software\LMSS-TzTest";
        let (k, _) = root.create_subkey(test_path).expect("创建测试键");
        let _ = k.set_value("v", &1u32);
        let t = key_last_write(HKEY::current_user(), test_path).expect("应能读到键时间");
        let parsed = chrono::NaiveDateTime::parse_from_str(&t, "%Y-%m-%d %H:%M:%S%.f")
            .expect("时间格式合法");
        let now_local = chrono::Local::now().naive_local();
        let diff = (parsed - now_local).num_minutes().abs();
        assert!(diff <= 10, "键时间 {t} 与本地当前时间差 {diff} 分钟（时区转换缺失？）");
        let _ = root.delete_subkey_all(test_path);
    }

    #[test]
    fn utc_systemtime_converts_to_local() {
        // 固定 UTC 时刻：本地结果应等于该时刻按本地时区换算（与 chrono 直算一致）
        let s = systemtime_utc_to_local(2026, 9, 25, 2, 0, 0).unwrap();
        let expect = chrono::DateTime::parse_from_rfc3339("2026-09-25T02:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Local)
            .format("%Y-%m-%d %H:%M:%S.000")
            .to_string();
        assert_eq!(s, expect);
    }
}
