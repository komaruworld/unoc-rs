pub fn read_package_name(bytes: &[u8]) -> Option<String> {
    if bytes.starts_with(b"<manifest") {
        return read_text_manifest_package(bytes);
    }
    read_binary_manifest_package(bytes)
}

fn read_text_manifest_package(bytes: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(bytes).ok()?;
    let package_pos = text.find("package=\"")?;
    let value_start = package_pos + "package=\"".len();
    let value_end = text[value_start..].find('"')? + value_start;
    Some(text[value_start..value_end].to_string())
}

fn read_binary_manifest_package(bytes: &[u8]) -> Option<String> {
    let needle = b"package";
    let pos = bytes
        .windows(needle.len())
        .position(|window| window == needle)?;
    let tail = &bytes[pos + needle.len()..];
    let ascii_start = tail.iter().position(|byte| byte.is_ascii_alphanumeric())?;
    let tail = &tail[ascii_start..];
    let ascii_end = tail
        .iter()
        .position(|byte| !byte.is_ascii_alphanumeric() && *byte != b'.' && *byte != b'_')
        .unwrap_or(tail.len());
    let value = std::str::from_utf8(&tail[..ascii_end]).ok()?;
    if value.contains('.') {
        Some(value.to_string())
    } else {
        None
    }
}
