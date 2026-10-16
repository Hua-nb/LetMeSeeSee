//! 文件版本资源读取：给执行痕迹补充
//! "公司 · 描述 · 版本"信息（版本详情列）。

use windows_sys::Win32::Storage::FileSystem::{
    GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW,
};

/// 读取 PE 文件的版本信息 → "公司 · 文件描述 · 文件版本"
pub fn file_version_info(path: &str) -> Option<String> {
    let lower = path.to_ascii_lowercase();
    if ![".exe", ".dll", ".scr", ".sys", ".ocx"].iter().any(|e| lower.ends_with(e)) {
        return None;
    }
    let mut wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        let len = GetFileVersionInfoSizeW(wide.as_mut_ptr(), std::ptr::null_mut());
        if len == 0 {
            return None;
        }
        let mut buf = vec![0u8; len as usize];
        if GetFileVersionInfoW(wide.as_mut_ptr(), 0, len, buf.as_mut_ptr() as _) == 0 {
            return None;
        }
        // 查 Translation 拿语言码
        let mut trans_ptr: *const u8 = std::ptr::null();
        let mut trans_len: u32 = 0;
        let trans_query = to_wide("\\VarFileInfo\\Translation");
        if VerQueryValueW(
            buf.as_ptr() as _,
            trans_query.as_ptr(),
            &mut trans_ptr as *mut _ as _,
            &mut trans_len,
        ) == 0
            || trans_len < 4
        {
            return None;
        }
        let lang = u16::from_le_bytes([*trans_ptr, *trans_ptr.add(1)]);
        let code = u16::from_le_bytes([*trans_ptr.add(2), *trans_ptr.add(3)]);
        let prefix = format!("\\StringFileInfo\\{lang:04x}{code:04x}\\");
        let mut parts: Vec<String> = Vec::new();
        for field in ["CompanyName", "FileDescription", "FileVersion"] {
            let q = to_wide(&(prefix.clone() + field));
            let mut val_ptr: *const u16 = std::ptr::null();
            let mut val_len: u32 = 0;
            if VerQueryValueW(
                buf.as_ptr() as _,
                q.as_ptr(),
                &mut val_ptr as *mut _ as _,
                &mut val_len,
            ) != 0
            && !val_ptr.is_null()
            && val_len > 1
        {
            // 长度钳制：取证工具会读取不可信样本的版本资源，API 返回的 val_len
            // 不可尽信，最多读到 buf 末尾，防止越界构造 slice
            let buf_end = (buf.as_ptr() as usize) + buf.len();
            let max_units = buf_end.saturating_sub(val_ptr as usize) / 2;
            let units = (val_len as usize - 1).min(max_units);
            let s = String::from_utf16_lossy(std::slice::from_raw_parts(val_ptr, units));
            let s = s.trim();
            if !s.is_empty() {
                parts.push(s.to_string());
            }
        }
        }
        if parts.is_empty() {
            None
        } else {
            Some(parts.join(" · "))
        }
    }
}

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_cmd_version_info() {
        let info = file_version_info(r"C:\Windows\System32\cmd.exe");
        assert!(info.is_some(), "cmd.exe 应有版本信息");
        assert!(
            info.as_deref().unwrap().contains("Microsoft"),
            "{}",
            info.unwrap()
        );
    }

    #[test]
    fn missing_file_returns_none() {
        assert!(file_version_info(r"C:\nonexistent\xyz.exe").is_none());
    }

    #[test]
    fn non_exe_returns_none() {
        assert!(file_version_info(r"C:\Windows\System32\drivers\etc\hosts").is_none());
    }
}
