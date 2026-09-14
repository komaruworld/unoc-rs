use std::fmt;

use crate::error::{Result, UnocRsError};

// macOS may already reserve more address space than the default cap at startup.
pub const DEFAULT_MEMORY_LIMIT: &str = if cfg!(all(unix, not(target_vendor = "apple"))) {
    "12g"
} else {
    "0"
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryLimit {
    bytes: Option<u64>,
}

impl MemoryLimit {
    pub fn disabled() -> Self {
        Self { bytes: None }
    }

    pub fn from_bytes(bytes: u64) -> Self {
        Self { bytes: Some(bytes) }
    }

    pub fn bytes(self) -> Option<u64> {
        self.bytes
    }
}

impl fmt::Display for MemoryLimit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.bytes {
            Some(bytes) => formatter.write_str(&format_bytes(bytes)),
            None => formatter.write_str("disabled"),
        }
    }
}

pub fn parse_memory_limit(value: &str) -> std::result::Result<MemoryLimit, String> {
    let normalized = value.trim().to_ascii_lowercase().replace('_', "");
    if normalized.is_empty() {
        return Err("memory limit cannot be empty".to_string());
    }
    if matches!(
        normalized.as_str(),
        "0" | "off" | "none" | "disabled" | "unlimited"
    ) {
        return Ok(MemoryLimit::disabled());
    }

    let units = [
        ("gib", 1024_u64 * 1024 * 1024),
        ("gb", 1024_u64 * 1024 * 1024),
        ("g", 1024_u64 * 1024 * 1024),
        ("mib", 1024_u64 * 1024),
        ("mb", 1024_u64 * 1024),
        ("m", 1024_u64 * 1024),
        ("kib", 1024_u64),
        ("kb", 1024_u64),
        ("k", 1024_u64),
        ("b", 1_u64),
    ];

    let (number, multiplier) = units
        .iter()
        .find_map(|(suffix, multiplier)| {
            normalized
                .strip_suffix(suffix)
                .map(|number| (number, *multiplier))
        })
        .unwrap_or((normalized.as_str(), 1));

    if number.is_empty() {
        return Err(format!("invalid memory limit: {value}"));
    }

    let quantity = number
        .parse::<f64>()
        .map_err(|_| format!("invalid memory limit: {value}"))?;
    if !quantity.is_finite() || quantity <= 0.0 {
        return Err(format!(
            "memory limit must be positive or 0 to disable: {value}"
        ));
    }

    let bytes = quantity * multiplier as f64;
    if bytes > u64::MAX as f64 {
        return Err(format!("memory limit is too large: {value}"));
    }

    Ok(MemoryLimit::from_bytes(bytes.ceil() as u64))
}

pub fn apply_memory_limit(limit: MemoryLimit) -> Result<()> {
    let Some(bytes) = limit.bytes() else {
        return Ok(());
    };
    apply_memory_limit_bytes(bytes)
}

pub fn trim_unused_memory() {
    trim_allocator();
}

#[cfg(unix)]
fn apply_memory_limit_bytes(bytes: u64) -> Result<()> {
    let requested = bytes as libc::rlim_t;
    if requested as u64 != bytes || requested == libc::RLIM_INFINITY {
        return Err(UnocRsError::MemoryLimitTooLarge {
            limit: format_bytes(bytes),
        });
    }

    let mut current = std::mem::MaybeUninit::<libc::rlimit>::uninit();
    // SAFETY: getrlimit initializes the rlimit struct when it returns 0.
    let get_result = unsafe { libc::getrlimit(libc::RLIMIT_AS, current.as_mut_ptr()) };
    if get_result != 0 {
        return Err(UnocRsError::MemoryLimitFailed {
            limit: format_bytes(bytes),
            source: std::io::Error::last_os_error(),
        });
    }
    // SAFETY: getrlimit above succeeded, so current is initialized.
    let current = unsafe { current.assume_init() };

    if current.rlim_max != libc::RLIM_INFINITY && requested > current.rlim_max {
        return Err(UnocRsError::MemoryLimitAboveHardLimit {
            limit: format_bytes(bytes),
            hard_limit: format_rlim(current.rlim_max),
        });
    }

    let next = libc::rlimit {
        rlim_cur: requested,
        rlim_max: current.rlim_max,
    };
    // SAFETY: next is a valid rlimit value and points to initialized memory.
    let set_result = unsafe { libc::setrlimit(libc::RLIMIT_AS, &next) };
    if set_result != 0 {
        return Err(UnocRsError::MemoryLimitFailed {
            limit: format_bytes(bytes),
            source: std::io::Error::last_os_error(),
        });
    }

    Ok(())
}

#[cfg(not(unix))]
fn apply_memory_limit_bytes(_bytes: u64) -> Result<()> {
    Err(UnocRsError::MemoryLimitUnsupported)
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn trim_allocator() {
    // SAFETY: malloc_trim is a process-local allocator maintenance call.
    unsafe {
        libc::malloc_trim(0);
    }
}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
fn trim_allocator() {}

#[cfg(unix)]
fn format_rlim(value: libc::rlim_t) -> String {
    if value == libc::RLIM_INFINITY {
        "unlimited".to_string()
    } else {
        format_bytes(value)
    }
}

fn format_bytes(bytes: u64) -> String {
    let gib = 1024_u64 * 1024 * 1024;
    let mib = 1024_u64 * 1024;
    if bytes.is_multiple_of(gib) {
        format!("{}g", bytes / gib)
    } else if bytes.is_multiple_of(mib) {
        format!("{}m", bytes / mib)
    } else {
        format!("{bytes}b")
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_memory_limit, MemoryLimit};

    #[test]
    fn parses_gibibytes() {
        assert_eq!(
            parse_memory_limit("12g").expect("memory limit"),
            MemoryLimit::from_bytes(12 * 1024 * 1024 * 1024)
        );
    }

    #[test]
    fn parses_decimal_megabytes() {
        assert_eq!(
            parse_memory_limit("1.5m").expect("memory limit"),
            MemoryLimit::from_bytes(1536 * 1024)
        );
    }

    #[test]
    fn parses_disabled_limit() {
        assert_eq!(
            parse_memory_limit("0").expect("memory limit"),
            MemoryLimit::disabled()
        );
        assert_eq!(
            parse_memory_limit("off").expect("memory limit"),
            MemoryLimit::disabled()
        );
    }

    #[test]
    fn rejects_invalid_limit() {
        assert!(parse_memory_limit("wat").is_err());
        assert!(parse_memory_limit("-1g").is_err());
    }
}
