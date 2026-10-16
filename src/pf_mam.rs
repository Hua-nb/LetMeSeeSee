//! MAM 压缩 Prefetch 解压：Win10/11 压缩 .pf = "MAM\x04" + u32 解压后大小 + XPRESS Huffman 流。
//! 解码直接用 ntdll 原生 API（RtlDecompressBufferEx，COMPRESSION_FORMAT_XPRESS_HUFF），
//! 与 KAPE PECmd/Zimmerman Prefetch 库同源（Windows 8+ 可用，无需第三方算法）。

#[link(name = "ntdll")]
extern "system" {
    fn RtlGetCompressionWorkSpaceSize(
        compression_format: u16,
        compress_buffer_work_space_size: *mut usize,
        compress_fragment_work_space_size: *mut usize,
    ) -> u32;
    fn RtlDecompressBufferEx(
        compression_format_and_engine: u16,
        uncompressed_buffer: *mut u8,
        uncompressed_buffer_size: u32,
        compressed_buffer: *const u8,
        compressed_buffer_size: u32,
        final_uncompressed_size: *mut u32,
        workspace: *mut u8,
    ) -> u32;
}

const COMPRESSION_FORMAT_XPRESS_HUFF: u16 = 0x0004;

/// MAM 压缩字节 → 解压后的 SCCA .pf 内容；非 MAM 输入或失败返回 None
pub fn decompress_mam(bytes: &[u8]) -> Option<Vec<u8>> {
    if bytes.len() < 12 || &bytes[..4] != b"MAM\x04" {
        return None;
    }
    let out_size = u32::from_le_bytes(bytes[4..8].try_into().ok()?) as usize;
    if out_size == 0 || out_size > 64 * 1024 * 1024 {
        return None;
    }
    let compressed = &bytes[8..];
    unsafe {
        let mut ws_buf = 0usize;
        let mut ws_frag = 0usize;
        let st = RtlGetCompressionWorkSpaceSize(
            COMPRESSION_FORMAT_XPRESS_HUFF,
            &mut ws_buf,
            &mut ws_frag,
        );
        if st != 0 {
            return None;
        }
        let mut workspace = vec![0u8; ws_frag.max(1)];
        let mut out = vec![0u8; out_size];
        let mut final_size: u32 = 0;
        let st = RtlDecompressBufferEx(
            COMPRESSION_FORMAT_XPRESS_HUFF,
            out.as_mut_ptr(),
            out_size as u32,
            compressed.as_ptr(),
            compressed.len() as u32,
            &mut final_size,
            workspace.as_mut_ptr(),
        );
        if st != 0 || final_size == 0 {
            return None;
        }
        out.truncate(final_size as usize);
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 真实夹具（本机拷出，含用户 2026-09-25 上午的 8 次 cmd 启动）；
    /// 夹具不入库（隐私），缺失时自动跳过
    #[test]
    fn decompresses_real_cmd_pf() {
        let path = std::path::Path::new("testdata/real-cmd.pf");
        if !path.exists() {
            eprintln!("跳过：无真实夹具");
            return;
        }
        let raw = std::fs::read(path).unwrap();
        let pf = decompress_mam(&raw).expect("MAM 解压失败");
        assert_eq!(&pf[4..8], b"SCCA", "解压后应为标准 Prefetch");
        let parsed = crate::modules::prefetch::parse_pf(&pf).expect("解析失败");
        assert!(
            parsed.exe_path.to_ascii_uppercase().contains("CMD.EXE"),
            "{}",
            parsed.exe_path
        );
        assert!(
            !parsed.run_times.is_empty(),
            "应有运行时间槽：total={}",
            parsed.total_runs
        );
    }

    #[test]
    fn decompresses_real_sample_pf() {
        let path = std::path::Path::new("testdata/real.pf");
        if !path.exists() {
            eprintln!("跳过：无真实夹具");
            return;
        }
        let raw = std::fs::read(path).unwrap();
        let pf = decompress_mam(&raw).expect("MAM 解压失败");
        assert_eq!(&pf[4..8], b"SCCA");
        assert!(crate::modules::prefetch::parse_pf(&pf).is_some());
    }

    #[test]
    fn non_mam_input_is_none() {
        assert!(decompress_mam(b"SCCAxxxx").is_none());
        assert!(decompress_mam(&[]).is_none());
    }
}
