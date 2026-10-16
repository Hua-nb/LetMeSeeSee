//! 编码工具：注册表 REG_SZ 为 UTF-16LE；ANSI 内容按系统活动代码页解码
//! （中文 GBK、日文 CP932 等，经 GetACP 动态选择），统一入口杜绝乱码。

#[link(name = "kernel32")]
extern "system" {
    fn GetACP() -> u32;
}

/// 系统 ANSI 代码页 → 解码器（GetACP 动态选择；未知代码页回退 GBK——
/// 本工具主要使用环境为中文 Windows）
fn ansi_decoder() -> &'static encoding_rs::Encoding {
    match unsafe { GetACP() } {
        932 => encoding_rs::SHIFT_JIS,
        949 => encoding_rs::EUC_KR,
        950 => encoding_rs::BIG5,
        1250 => encoding_rs::WINDOWS_1250,
        1251 => encoding_rs::WINDOWS_1251,
        1252 => encoding_rs::WINDOWS_1252,
        1253 => encoding_rs::WINDOWS_1253,
        1254 => encoding_rs::WINDOWS_1254,
        1255 => encoding_rs::WINDOWS_1255,
        1256 => encoding_rs::WINDOWS_1256,
        1257 => encoding_rs::WINDOWS_1257,
        1258 => encoding_rs::WINDOWS_1258,
        65001 => encoding_rs::UTF_8,
        _ => encoding_rs::GBK,
    }
}

/// 解码"可能是 UTF-8 也可能是系统 ANSI"的字节（文件内容、命令输出）
pub fn decode_ansi_or_utf8(b: &[u8]) -> String {
    if let Ok(s) = std::str::from_utf8(b) {
        return s.trim_end_matches('\0').to_string();
    }
    let (cow, _, _) = ansi_decoder().decode(b);
    cow.trim_end_matches('\0').to_string()
}

/// 展开 %Var% 形式的环境变量引用（大小写不敏感；未定义的变量保留原样）。
/// 用于 ProfileImagePath 等 REG_EXPAND_SZ 值，避免产出含 %SystemDrive% 的伪路径。
pub fn expand_env_vars(s: &str) -> String {
    let lower = s.to_ascii_lowercase();
    let mut out = String::with_capacity(s.len());
    let mut pos = 0usize;
    while let Some(i) = lower[pos..].find('%') {
        out.push_str(&s[pos..pos + i]);
        let start = pos + i + 1;
        match lower[start..].find('%') {
            Some(j) => {
                let name = &s[start..start + j];
                if name.is_empty() {
                    out.push('%'); // "%%" 转义为一个 %
                } else if let Ok(v) = std::env::var(name) {
                    out.push_str(&v);
                } else {
                    out.push_str(&s[pos + i..start + j + 1]); // 未定义：原样保留
                }
                pos = start + j + 1;
            }
            None => {
                out.push_str(&s[pos + i..]);
                pos = s.len();
            }
        }
    }
    out.push_str(&s[pos.min(s.len())..]);
    out
}

/// 解码注册表原始值字节（按类型）
pub fn decode_reg_string(b: &[u8], ty: winreg::enums::RegType) -> String {
    use winreg::enums::RegType;
    match ty {
        RegType::REG_SZ | RegType::REG_EXPAND_SZ => utf16(b),
        RegType::REG_DWORD if b.len() >= 4 => {
            u32::from_le_bytes(b[..4].try_into().unwrap()).to_string()
        }
        _ => decode_ansi_or_utf8(b),
    }
}

fn utf16(b: &[u8]) -> String {
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
    fn gbk_decodes_chinese() {
        // "微信" 的 GBK 编码
        assert_eq!(decode_ansi_or_utf8(&[0xCE, 0xA2, 0xD0, 0xC5]), "微信");
    }

    #[test]
    fn utf8_passthrough() {
        assert_eq!(decode_ansi_or_utf8("正常UTF8".as_bytes()), "正常UTF8");
    }

    #[test]
    fn reg_sz_utf16_decodes() {
        // "哔哩哔哩" 的 UTF-16LE
        let mut b = Vec::new();
        for u in "哔哩哔哩".encode_utf16() {
            b.extend_from_slice(&u.to_le_bytes());
        }
        b.extend_from_slice(&[0, 0]);
        use winreg::enums::RegType;
        assert_eq!(
            decode_reg_string(&b, RegType::REG_SZ),
            "哔哩哔哩"
        );
    }

    #[test]
    fn reg_dword_to_string() {
        use winreg::enums::RegType;
        assert_eq!(decode_reg_string(&1u32.to_le_bytes(), RegType::REG_DWORD), "1");
    }

    #[test]
    fn env_vars_expanded() {
        std::env::set_var("LMSS_TEST_VAR", r"C:\XYZ");
        assert_eq!(expand_env_vars(r"%LMSS_TEST_VAR%\Users\h"), r"C:\XYZ\Users\h");
        // 大小写不敏感（注册表中 %systemdrive% 常为小写）
        assert_eq!(expand_env_vars("%lmss_test_var%"), r"C:\XYZ");
        // 未定义变量与无变量串原样保留
        assert_eq!(expand_env_vars(r"%NO_SUCH_VAR%\x"), r"%NO_SUCH_VAR%\x");
        assert_eq!(expand_env_vars(r"C:\plain\path"), r"C:\plain\path");
        assert_eq!(expand_env_vars("100%%"), "100%");
        std::env::remove_var("LMSS_TEST_VAR");
    }
}
