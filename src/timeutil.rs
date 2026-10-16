use chrono::{DateTime, FixedOffset, Local, TimeZone};

/// evtx SystemTime 字符串 → 本地时间字符串（用于生产）
pub fn evtx_time_to_local(s: &str) -> Option<String> {
    let offset = Local.offset_from_utc_datetime(&chrono::Utc::now().naive_utc());
    evtx_time_to_local_tz(s, &offset)
}

/// evtx SystemTime 字符串 → 本地毫秒时间戳（进程树排序/窗口判断用）
pub fn evtx_time_to_ms(s: &str) -> Option<i64> {
    let normalized = normalize_frac(s)?;
    let dt = DateTime::parse_from_rfc3339(&normalized).ok()?;
    use chrono::TimeZone;
    Some(dt.with_timezone(&Local).timestamp_millis())
}

/// 指定时区版本（用于测试）
pub fn evtx_time_to_local_tz(s: &str, tz: &FixedOffset) -> Option<String> {
    let normalized = normalize_frac(s)?;
    let dt = DateTime::parse_from_rfc3339(&normalized).ok()?;
    let local = dt.with_timezone(tz);
    Some(local.format("%Y-%m-%d %H:%M:%S%.3f").to_string())
}

/// 当前 unix 毫秒
fn now_ms() -> i64 {
    use chrono::TimeZone;
    chrono::Utc::now().timestamp_millis()
}

/// Windows FILETIME（1601 纪元、100ns 单位）→ 本地时间字符串。
/// 拒绝 0、1980-01-01 之前、以及"当前时间+24小时"之后的值
/// （执行痕迹不可能来自未来——2194 这类是乱码误读）。
pub fn filetime_to_local_tz(ft: u64, tz: &FixedOffset) -> Option<String> {
    if ft == 0 {
        return None;
    }
    const EPOCH_DIFF_MS: i64 = 11_644_473_600_000;
    const MIN_UNIX_MS: i64 = 315_532_800_000; // 1980-01-01
    let unix_ms = (ft / 10_000) as i64 - EPOCH_DIFF_MS;
    if !(MIN_UNIX_MS..=(now_ms() + 86_400_000)).contains(&unix_ms) {
        return None;
    }
    let secs = unix_ms.div_euclid(1000);
    let millis = unix_ms.rem_euclid(1000) as u32;
    use chrono::TimeZone;
    let dt = tz.timestamp_opt(secs, millis * 1_000_000).single()?;
    Some(dt.format("%Y-%m-%d %H:%M:%S%.3f").to_string())
}

/// 扫描级合理性（比转换级更紧）：2000-01-01 ~ 当前+24h。
/// 供 SHITEMID 等滑窗扫描过滤乱码；误读值（如 2194 年）在此被拒。
pub fn filetime_plausible_scan(ft: u64) -> bool {
    if ft == 0 {
        return false;
    }
    const EPOCH_DIFF_MS: i64 = 11_644_473_600_000;
    const MIN_SCAN_MS: i64 = 946_684_800_000; // 2000-01-01
    let unix_ms = (ft / 10_000) as i64 - EPOCH_DIFF_MS;
    (MIN_SCAN_MS..=(now_ms() + 86_400_000)).contains(&unix_ms)
}

pub fn filetime_to_local(ft: u64) -> Option<String> {
    let offset = Local.offset_from_utc_datetime(&chrono::Utc::now().naive_utc());
    filetime_to_local_tz(ft, &offset)
}

/// 把 RFC3339 变体的小数秒规整为恰好 6 位；无小数则原样返回
fn normalize_frac(s: &str) -> Option<String> {
    let dot = match s.find('.') {
        Some(i) => i,
        None => return Some(s.to_string()),
    };
    let tail = &s[dot + 1..];
    let tz_pos = tail
        .find(|c: char| c == 'Z' || c == '+' || c == '-')
        .map(|i| dot + 1 + i);
    let (frac, tz) = match tz_pos {
        Some(p) => (&s[dot + 1..p], &s[p..]),
        None => (&s[dot + 1..], ""),
    };
    if frac.is_empty() || frac.len() > 9 || !frac.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let mut f: String = frac.chars().take(6).collect();
    while f.len() < 6 {
        f.push('0');
    }
    Some(format!("{}.{}{}", &s[..dot], f, tz))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::FixedOffset;

    #[test]
    fn converts_with_fixed_offset() {
        let tz = FixedOffset::east_opt(8 * 3600).unwrap();
        // evtx 实际输出的小数位长度不定（这里 7 位）
        assert_eq!(
            evtx_time_to_local_tz("2026-09-22T10:42:13.2455000Z", &tz).unwrap(),
            "2026-09-22 18:42:13.245"
        );
    }

    #[test]
    fn accepts_3_digit_fraction() {
        let tz = FixedOffset::east_opt(8 * 3600).unwrap();
        assert_eq!(
            evtx_time_to_local_tz("2026-09-22T10:42:13.245Z", &tz).unwrap(),
            "2026-09-22 18:42:13.245"
        );
    }

    #[test]
    fn accepts_no_fraction() {
        let tz = FixedOffset::east_opt(0).unwrap();
        assert_eq!(
            evtx_time_to_local_tz("2026-09-22T10:42:13Z", &tz).unwrap(),
            "2026-09-22 10:42:13.000"
        );
    }

    #[test]
    fn rejects_garbage() {
        let tz = FixedOffset::east_opt(8 * 3600).unwrap();
        assert!(evtx_time_to_local_tz("not-a-time", &tz).is_none());
    }

    #[test]
    fn filetime_converts() {
        let tz = FixedOffset::east_opt(8 * 3600).unwrap();
        // 2026-09-22 10:42:13.245 UTC 的 FILETIME（100ns tick，1601 纪元）
        let ft: u64 = 134_345_473_332_450_000;
        assert_eq!(
            filetime_to_local_tz(ft, &tz).unwrap(),
            "2026-09-22 18:42:13.245"
        );
    }

    #[test]
    fn filetime_zero_and_absurd_are_none() {
        let tz = FixedOffset::east_opt(8 * 3600).unwrap();
        assert!(filetime_to_local_tz(0, &tz).is_none());
        assert!(filetime_to_local_tz(u64::MAX, &tz).is_none());
        // 用户实测出现过的乱码年份 2194：必须被拒
        let y2194_ms: i64 = 7_062_393_600_000; // 2194-01-01
        let ft_2194 = ((y2194_ms + 11_644_473_600_000) * 10_000) as u64;
        assert!(filetime_to_local_tz(ft_2194, &tz).is_none(), "2194 年应被拒");
        assert!(!filetime_plausible_scan(ft_2194));
        // 2005 年的正常时间保留
        let y2005_ms: i64 = 1_104_537_600_000;
        let ft_2005 = ((y2005_ms + 11_644_473_600_000) * 10_000) as u64;
        assert!(filetime_to_local_tz(ft_2005, &tz).is_some());
    }
}
