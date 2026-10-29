//! shlwapi path/URL helpers.

use super::*;

// ── shlwapi path helpers: pure string operations on the guest path form ──

/// Windows "drive spec": an alphabetic character followed by `:`.
pub(crate) fn shlwapi_is_drive_spec(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

/// PathRelativePathToW: build the relative path from `from` to `to` with
/// the documented algorithm — strip the common prefix, then one `..\`
/// per remaining component of `from`, then the remaining components of
/// `to`.  Different drives or no common root yield `None` (FALSE with an
/// empty output buffer).
pub(crate) fn shlwapi_relative_path_to(from: &str, to: &str) -> Option<String> {
    let drive = |path: &str| -> Option<char> {
        let bytes = path.as_bytes();
        if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
            Some(bytes[0] as char)
        } else {
            None
        }
    };
    let from_drive = drive(from)?;
    let to_drive = drive(to)?;
    if from_drive != to_drive {
        return None;
    }
    let normalize = |path: &str| -> Vec<String> {
        path.replace('/', "\\")
            .split('\\')
            .filter(|component| !component.is_empty() && *component != ".")
            .map(str::to_string)
            .collect::<Vec<_>>()
    };
    let from_components = normalize(from);
    let to_components = normalize(to);
    let mut common = 0usize;
    while common < from_components.len()
        && common < to_components.len()
        && from_components[common] == to_components[common]
    {
        common += 1;
    }
    if common == 0 {
        return None;
    }
    let mut parts = Vec::new();
    for _ in common..from_components.len() {
        parts.push("..".to_string());
    }
    parts.extend(to_components[common..].iter().cloned());
    let mut relative = parts.join("\\");
    if relative.is_empty() {
        relative = ".".to_string();
    }
    Some(relative)
}

/// PathIsRelativeW: TRUE when the path is not drive-qualified and does not
/// begin with a backslash (an empty path counts as relative).
pub(crate) fn shlwapi_path_is_relative(path: &str) -> bool {
    let bytes = path.as_bytes();
    if bytes.is_empty() {
        return true;
    }
    !(bytes[0] == b'\\' || (bytes.len() >= 2 && bytes[1] == b':'))
}

/// PathFindExtensionW: byte offset of the extension (the last `.` after the
/// last `\`, `/`, `:`, or space), or `path.len()` when there is none.
pub(crate) fn shlwapi_path_find_extension_offset(path: &str) -> usize {
    let mut last_dot = None;
    for (index, ch) in path.char_indices() {
        match ch {
            '\\' | '/' | ':' | ' ' => last_dot = None,
            '.' => last_dot = Some(index),
            _ => {}
        }
    }
    last_dot.unwrap_or(path.len())
}

/// PathFindFileNameW: byte offset of the final path component (after the
/// last `\`, `/`, or `:` that is followed by a non-separator character).
pub(crate) fn shlwapi_path_find_file_name_offset(path: &str) -> usize {
    let chars: Vec<char> = path.chars().collect();
    let mut candidate = 0_usize;
    for (index, ch) in chars.iter().enumerate() {
        if (*ch == '\\' || *ch == '/' || *ch == ':')
            && chars
                .get(index + 1)
                .is_some_and(|next| *next != '\\' && *next != '/')
        {
            candidate = index + 1;
        }
    }
    chars[..candidate].iter().map(|ch| ch.len_utf8()).sum()
}

/// PathSkipRootW: byte offset past the root (`X:\` or `\\server\share\`),
/// or None when the path has no root.
pub(crate) fn shlwapi_path_skip_root_offset(path: &str) -> Option<usize> {
    let bytes = path.as_bytes();
    if bytes.len() >= 2 && bytes[0] == b'\\' && bytes[1] == b'\\' {
        let rest = &path[2..];
        let server_end = rest.find('\\')?;
        let after_server = &rest[server_end + 1..];
        let share_end = after_server.find('\\')?;
        Some(2 + server_end + 1 + share_end + 1)
    } else if bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && bytes[2] == b'\\'
    {
        Some(3)
    } else {
        None
    }
}

/// PathIsRootW: TRUE for `X:\`, `X:/`, the naked drive spec `X:`, the
/// single separator `\`, and UNC roots (`\\server\share` with optional
/// trailing separators).
pub(crate) fn shlwapi_path_is_root(path: &str) -> bool {
    let bytes = path.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    if bytes[0] == b'\\' {
        if bytes.get(1) == Some(&b'\\') {
            // UNC: a server and a share must exist; only separators may
            // follow the share name.
            let rest = &path[2..];
            let Some(server_end) = rest.find('\\') else {
                return false;
            };
            let after_server = &rest[server_end + 1..];
            if after_server.is_empty() {
                return false;
            }
            return match after_server.find('\\') {
                None => true,
                Some(index) => after_server[index..].chars().all(|ch| ch == '\\'),
            };
        }
        return bytes.len() == 1;
    }
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return bytes.len() == 2 || (bytes.len() == 3 && (bytes[2] == b'\\' || bytes[2] == b'/'));
    }
    false
}

/// PathRemoveFileSpecW semantics: remove the trailing file name (and the
/// separator before it), keeping the root intact.  Returns the shortened
/// path, or None when nothing could be removed (the path stays unchanged).
pub(crate) fn shlwapi_path_remove_file_spec(path: &str) -> Option<String> {
    if path.is_empty() {
        return None;
    }
    let bytes = path.as_bytes();
    let root_end = if shlwapi_is_drive_spec(path) {
        if bytes.get(2) == Some(&b'\\') { 3 } else { 2 }
    } else {
        let mut root_end = 0_usize;
        if bytes.first() == Some(&b'\\') {
            root_end = 1;
        }
        if bytes.get(root_end + 1).is_some() && bytes.get(root_end + 1) != Some(&b'?') {
            if bytes.get(root_end) == Some(&b'\\') {
                root_end += 1;
            }
            if root_end > 1 && shlwapi_is_drive_spec(&path[root_end..]) {
                root_end += 2;
            }
            if bytes.get(root_end) == Some(&b'\\')
                && bytes.get(root_end + 1).is_some()
                && bytes.get(root_end + 1) != Some(&b'\\')
            {
                root_end += 1;
            }
        }
        root_end
    };
    let tail = &path[root_end..];
    if let Some(relative_slash) = tail.rfind('\\') {
        let slash = root_end + relative_slash;
        if slash != root_end {
            let truncate_at = if bytes.get(slash - 1) == Some(&b'\\') {
                slash - 1
            } else {
                slash
            };
            return Some(path[..truncate_at].to_string());
        }
    }
    if root_end >= path.len() {
        return None;
    }
    Some(path[..root_end].to_string())
}

/// PathIsUNCServerShareW semantics: `\\server\share` with no further
/// separators.
pub(crate) fn shlwapi_is_unc_server_share(chars: &[char]) -> bool {
    if chars.len() >= 2 && chars[0] == '\\' && chars[1] == '\\' {
        let rest = &chars[2..];
        if let Some(server_end) = rest.iter().position(|ch| *ch == '\\') {
            return rest[server_end + 1..].iter().all(|ch| *ch != '\\');
        }
    }
    false
}

/// PathCanonicalizeW semantics: copy the root (`\` or `X:\`), resolve `.`
/// and `..` segments, keep the trailing separator, and append `\` to a
/// naked drive spec.  The empty path canonicalizes to `\`.
pub(crate) fn shlwapi_path_canonicalize(path: &str) -> String {
    let chars: Vec<char> = path.chars().collect();
    if chars.is_empty() {
        return "\\".to_string();
    }
    let mut out: Vec<char> = Vec::new();
    let mut src = 0_usize;
    if chars[src] == '\\' {
        out.push(chars[src]);
        src += 1;
    } else if src + 1 < chars.len() && chars[src + 1] == ':' {
        out.push(chars[src]);
        out.push(chars[src + 1]);
        src += 2;
        if src < chars.len() && chars[src] == '\\' {
            out.push(chars[src]);
            src += 1;
        }
    }
    let out_char = |out: &[char], index: usize| out.get(index).copied().unwrap_or('\0');
    while src < chars.len() {
        if chars[src] == '.' {
            let next = chars.get(src + 1).copied();
            let prev = out.last().copied();
            if next == Some('\\') && (src == 0 || prev == Some('\\') || prev == Some(':')) {
                src += 2; // "." — skip the segment
            } else if next == Some('.') && !out.is_empty() && prev == Some('\\') {
                // ".." — back up over the previous component (never above
                // the root; the initial `\\` of a UNC path is protected).
                let mut dst = out.len();
                if dst > 1 && out[dst - 1] == '\\' && (out[dst - 2] != '\\' || dst > 2) {
                    if out[dst - 2] == ':' && (dst > 3 || out[dst - 3] == ':') {
                        dst -= 2;
                        while dst > 0 && out_char(&out, dst) != '\\' {
                            dst -= 1;
                        }
                        if out_char(&out, dst) == '\\' {
                            dst += 1;
                        } else {
                            dst = 0;
                        }
                    } else if out[dst - 2] != ':' && !shlwapi_is_unc_server_share(&out[..dst]) {
                        dst -= 2;
                    }
                }
                while dst > 0 && out_char(&out, dst) != '\\' {
                    dst -= 1;
                }
                if dst == 0 {
                    out.push('\\');
                    src += 1;
                } else {
                    out.truncate(dst);
                }
                src += 2;
            } else {
                out.push(chars[src]);
                src += 1;
            }
        } else {
            out.push(chars[src]);
            src += 1;
        }
    }
    // A naked drive spec gets its backslash appended.
    if out.len() == 2 && out[1] == ':' {
        out.push('\\');
    }
    out.into_iter().collect()
}

/// PathCombineW semantics: combine `dir` and `file` into one path and
/// canonicalize it.  `dir` NULL or empty yields `file` alone; a
/// fully-qualified `file` (drive or UNC) replaces `dir`; a `file` that
/// begins with `\` but is not UNC is rooted at `dir`'s root.
pub(crate) fn shlwapi_path_combine(dir: Option<&str>, file: &str) -> Option<String> {
    let dir = match dir {
        Some(dir) => dir,
        // NULL dir: the file alone — or an empty result when both are
        // missing (the NULL-returning PathCombineW failure case).
        None => {
            if file.is_empty() {
                return None;
            }
            return Some(shlwapi_path_canonicalize(file));
        }
    };
    if file.is_empty() {
        return Some(shlwapi_path_canonicalize(dir));
    }
    if dir.is_empty() {
        return Some(shlwapi_path_canonicalize(file));
    }
    if !shlwapi_path_is_relative(file) {
        // Not relative: either fully-qualified (use file alone) or a
        // leading-separator path rooted at dir's root.
        if file.starts_with('\\') && !file.starts_with("\\\\") {
            let root = shlwapi_path_strip_to_root(dir);
            return Some(shlwapi_path_canonicalize(&format!(
                "{root}{}",
                file.trim_start_matches(['\\', '/'])
            )));
        }
        return Some(shlwapi_path_canonicalize(file));
    }
    let joined = if dir.ends_with('\\') || dir.ends_with('/') {
        format!("{dir}{file}")
    } else {
        format!("{dir}\\{file}")
    };
    Some(shlwapi_path_canonicalize(&joined))
}

/// PathStripToRootW semantics: reduce a path to its root (`X:\` or
/// `\\server\share\`); the input must be drive-qualified or UNC.
pub(crate) fn shlwapi_path_strip_to_root(path: &str) -> String {
    if let Some(offset) = shlwapi_path_skip_root_offset(path) {
        return path[..offset].to_string();
    }
    path.to_string()
}

/// PathAppendW semantics: append a path element in place.  A leading `\`
/// on the appended part is skipped (unless UNC); a fully-qualified append
/// replaces the path; `..`-prefixed appends pop the last element first.
pub(crate) fn shlwapi_path_append(base: &str, more: &str) -> String {
    if base.is_empty() && more.is_empty() {
        return String::new();
    }
    let more = if more.starts_with('\\') && !more.starts_with("\\\\") {
        more.trim_start_matches(['\\', '/'])
    } else {
        more
    };
    if base.is_empty() {
        return shlwapi_path_canonicalize(more);
    }
    shlwapi_path_combine(Some(base), more).unwrap_or_else(|| base.to_string())
}

/// PathMatchSpecW semantics: DOS wildcard matching (`*`, `?`), with
/// `;`-separated alternates; `*.*` matches everything.
pub(crate) fn shlwapi_path_match_spec(path: &str, spec: &str) -> bool {
    if spec == "*.*" {
        return true;
    }
    let path_chars: Vec<char> = path.chars().collect();
    let spec_chars: Vec<char> = spec.chars().collect();
    fn matches(path: &[char], spec: &[char]) -> bool {
        let mut i = 0;
        let mut j = 0;
        while i < path.len() && j < spec.len() && spec[j] != ';' {
            if spec[j] == '*' {
                for start in i..=path.len() {
                    if matches(&path[start..], &spec[j + 1..]) {
                        return true;
                    }
                }
                return false;
            }
            let path_char = path[i].to_lowercase().next().unwrap_or(path[i]);
            let spec_char = spec[j].to_lowercase().next().unwrap_or(spec[j]);
            if spec_char != path_char && spec[j] != '?' {
                return false;
            }
            i += 1;
            j += 1;
        }
        if i == path.len() {
            let mut k = j;
            while k < spec.len() && spec[k] == '*' {
                k += 1;
            }
            if k >= spec.len() || spec[k] == ';' {
                return true;
            }
        }
        false
    }
    let mut offset = 0;
    while offset < spec_chars.len() {
        while offset < spec_chars.len() && spec_chars[offset] == ' ' {
            offset += 1;
        }
        if matches(&path_chars, &spec_chars[offset..]) {
            return true;
        }
        match spec_chars[offset..].iter().position(|ch| *ch == ';') {
            Some(relative) => offset += relative + 1,
            None => break,
        }
    }
    false
}

/// The URL scheme table (scheme name → URL_SCHEME_* value).
pub(crate) const SHLWAPI_URL_SCHEMES: &[(&str, u32)] = &[
    ("ftp", 2),
    ("http", 3),
    ("gopher", 4),
    ("mailto", 5),
    ("news", 6),
    ("nntp", 7),
    ("telnet", 8),
    ("wais", 9),
    ("file", 10),
    ("mk", 11),
    ("https", 12),
    ("shell", 13),
    ("snews", 14),
    ("local", 15),
    ("javascript", 16),
    ("vbscript", 17),
    ("about", 18),
    ("res", 19),
];

/// ParseURLW semantics: identify the URL scheme (alphanumeric plus `-`,
/// `+`, `.` characters, at least two, terminated by `:`).  Returns
/// (scheme length, URL_SCHEME_* value, suffix offset).
pub(crate) fn shlwapi_parse_url(url: &str) -> Option<(usize, u32, usize)> {
    let scheme_len = url
        .chars()
        .take_while(|ch| ch.is_alphanumeric() || *ch == '-' || *ch == '+' || *ch == '.')
        .count();
    if scheme_len <= 1 {
        return None;
    }
    let scheme_end = url
        .char_indices()
        .nth(scheme_len)
        .map(|(index, _)| index)
        .unwrap_or(url.len());
    if !url[scheme_end..].starts_with(':') {
        return None;
    }
    let scheme = &url[..scheme_end];
    let n_scheme = SHLWAPI_URL_SCHEMES
        .iter()
        .find(|(name, _)| scheme.eq_ignore_ascii_case(name))
        .map(|(_, number)| *number)
        .unwrap_or(0);
    Some((scheme_len, n_scheme, scheme_end + 1))
}

/// Whether a known URL scheme uses a `//host` authority part.
pub(crate) fn shlwapi_scheme_uses_hostname(n_scheme: u32) -> bool {
    matches!(n_scheme, 2..=4 | 6..=9 | 12 | 14)
}

/// UrlCanonicalizeW semantics (flags = 0): strip surrounding whitespace and
/// C0 controls, drop embedded tabs/newlines, lowercase the scheme and a
/// known-scheme hostname, normalize `\` to `/`, resolve `.`/`..` segments,
/// and preserve the `?query`/`#fragment` tail.  The empty URL canonicalizes
/// to the empty string.
pub(crate) fn shlwapi_url_canonicalize(url: &str) -> String {
    if url.is_empty() {
        return String::new();
    }
    let cleaned: String = url
        .trim_matches(|ch| ch <= '\u{20}')
        .chars()
        .filter(|ch| *ch != '\t' && *ch != '\n' && *ch != '\r')
        .collect();
    let chars: Vec<char> = cleaned.chars().collect();
    let mut out: Vec<char> = Vec::new();
    let mut src = 0_usize;
    let scheme_len = chars
        .iter()
        .take_while(|ch| ch.is_alphanumeric() || **ch == '+' || **ch == '-' || **ch == '.')
        .count();
    let has_scheme = scheme_len >= 2 && chars.get(scheme_len) == Some(&':');
    if has_scheme {
        for ch in &chars[..=scheme_len] {
            out.push(ch.to_lowercase().next().unwrap_or(*ch));
        }
        src = scheme_len + 1;
    } else if chars.first() == Some(&'\\') && chars.get(1) == Some(&'\\') {
        out.extend("file:".chars());
        src = 2;
    }
    let n_scheme = if has_scheme {
        SHLWAPI_URL_SCHEMES
            .iter()
            .find(|(name, _)| {
                chars[..scheme_len]
                    .iter()
                    .collect::<String>()
                    .eq_ignore_ascii_case(name)
            })
            .map(|(_, number)| *number)
            .unwrap_or(0)
    } else {
        0
    };
    let mut is_relative = false;
    if has_scheme
        && shlwapi_scheme_uses_hostname(n_scheme)
        && chars.get(src) == Some(&'/')
        && chars.get(src + 1) == Some(&'/')
    {
        out.push('/');
        out.push('/');
        src += 2;
        let host_start = src;
        while src < chars.len()
            && chars[src] != '/'
            && chars[src] != '\\'
            && chars[src] != '?'
            && chars[src] != '#'
        {
            src += 1;
        }
        let hostname = &chars[host_start..src];
        if n_scheme != 0 {
            for ch in hostname {
                out.push(ch.to_lowercase().next().unwrap_or(*ch));
            }
        } else {
            out.extend(hostname);
        }
        if src < chars.len() && (chars[src] == '/' || chars[src] == '\\') {
            out.push('/');
            src += 1;
        } else {
            out.push('/');
        }
        if (chars.get(src) == Some(&'.') && chars.get(src + 1) == Some(&'.'))
            || (chars.get(src) == Some(&'.') && chars.get(src + 1) == Some(&'/'))
        {
            is_relative = true;
        }
    }
    let root_offset = out.len();
    // Split the remaining text into the path body and the ?query/#fragment
    // tail (kept verbatim, in original order).
    let mut body_end = chars.len();
    for (index, ch) in chars.iter().enumerate().skip(src) {
        if *ch == '?' || *ch == '#' {
            body_end = index;
            break;
        }
    }
    let body = &chars[src..body_end];
    let mut i = 0_usize;
    while i < body.len() {
        let segment_start = i;
        while i < body.len() && body[i] != '/' && body[i] != '\\' {
            i += 1;
        }
        let segment: String = body[segment_start..i].iter().collect();
        if segment == "." {
            if i < body.len() {
                i += 1;
            }
            continue;
        }
        if segment == ".." {
            if !is_relative && out.len() > root_offset {
                let mut end = out.len();
                if end > root_offset && out[end - 1] == '/' {
                    end -= 1;
                }
                while end > root_offset && out[end - 1] != '/' {
                    end -= 1;
                }
                out.truncate(end);
            }
            if i < body.len() {
                i += 1;
            }
            continue;
        }
        if !segment.is_empty() {
            out.extend(segment.chars());
        }
        if i < body.len() {
            out.push('/');
            i += 1;
        }
    }
    for ch in &chars[body_end..] {
        out.push(*ch);
    }
    let mut result: String = out.into_iter().collect();
    if result.is_empty() && !cleaned.is_empty() {
        result.push('/');
    }
    result
}

/// UrlCombineW semantics (flags = 0): resolve `relative` against `base`
/// (RFC-3986-style: a relative URL with its own scheme wins; `//location`
/// replaces the authority; otherwise the base's last leaf is replaced) and
/// canonicalize the result.
pub(crate) fn shlwapi_url_combine(base: &str, relative: &str) -> String {
    if relative.is_empty() {
        return shlwapi_url_canonicalize(base);
    }
    if base.is_empty() || shlwapi_parse_url(base).is_none() {
        return shlwapi_url_canonicalize(relative);
    }
    if shlwapi_parse_url(relative).is_some() || relative.starts_with("//") {
        return shlwapi_url_canonicalize(relative);
    }
    let (_, _, suffix_offset) = shlwapi_parse_url(base).expect("checked above");
    let suffix = &base[suffix_offset..];
    let tail_start = suffix
        .char_indices()
        .find(|(_, ch)| *ch == '?' || *ch == '#')
        .map(|(index, _)| index)
        .unwrap_or(suffix.len());
    let location = &suffix[..tail_start];
    // A root-relative reference replaces the base path: keep the scheme and
    // the authority (the `//host` part) only.
    let combined = if relative.starts_with('/') && location.starts_with("//") {
        let authority_end = match location[2..].find('/') {
            Some(relative_index) => 2 + relative_index + 1,
            None => location.len(),
        };
        format!(
            "{}{}{}",
            &base[..suffix_offset],
            &location[..authority_end],
            relative.trim_start_matches('/')
        )
    } else {
        match location.rfind('/') {
            Some(last_slash) => {
                format!(
                    "{}{}{}",
                    &base[..suffix_offset],
                    &location[..=last_slash],
                    relative
                )
            }
            None => format!("{}{}/{}", &base[..suffix_offset], location, relative),
        }
    };
    shlwapi_url_canonicalize(&combined)
}

/// StrFromTimeIntervalW semantics: round to whole seconds and format
/// ` <hours> hr <minutes> min <seconds> sec`, keeping `digits` significant
/// digits across the classes (1..=7); returns None when the interval
/// cannot be formatted (empty output).
pub(crate) fn shlwapi_format_time_interval(milliseconds: u32, digits: i32) -> Option<String> {
    if digits <= 0 || digits > 7 {
        return None;
    }
    let mut total = (u64::from(milliseconds) + 500) / 1000;
    let hours = total / 3600;
    total -= hours * 3600;
    let minutes = total / 60;
    total -= minutes * 60;
    let seconds = total;
    fn write_class(out: &mut String, value: u64, unit: &str, digits: i32) -> i32 {
        let text = value.to_string();
        let mut number = String::with_capacity(text.len());
        for (index, ch) in text.chars().enumerate() {
            if index >= digits as usize {
                number.push('0');
            } else {
                number.push(ch);
            }
        }
        out.push(' ');
        out.push_str(&number);
        out.push_str(unit);
        digits - number.chars().count() as i32
    }
    let mut out = String::new();
    let mut digits_left = digits;
    if hours != 0 {
        digits_left = write_class(&mut out, hours, " hr", digits_left);
    }
    if minutes != 0 && digits_left > 0 {
        digits_left = write_class(&mut out, minutes, " min", digits_left);
    }
    if digits_left > 0 {
        let _ = write_class(&mut out, seconds, " sec", digits_left);
    }
    Some(out)
}

/// StrToIntW semantics: optional sign followed by decimal digits; stops at
/// the first non-digit; 0 when no digits are present.
pub(crate) fn shlwapi_str_to_int(input: &str) -> i32 {
    let mut chars = input.chars();
    let negative = matches!(chars.clone().next(), Some('-'));
    if matches!(chars.clone().next(), Some('-') | Some('+')) {
        chars.next();
    }
    let mut value: i64 = 0;
    let mut saw_digit = false;
    for ch in chars {
        if let Some(digit) = ch.to_digit(10) {
            saw_digit = true;
            value = value * 10 + i64::from(digit);
        } else {
            break;
        }
    }
    if !saw_digit {
        return 0;
    }
    let value = if negative { -value } else { value };
    value as i32
}

/// Case-fold a single UTF-16 code unit (the shlwapi NORM_IGNORECASE
/// machinery over single units; surrogate halves fold to themselves).
pub(crate) fn fold_utf16_unit(unit: u16) -> u16 {
    match char::from_u32(u32::from(unit)) {
        Some(ch) => ch
            .to_lowercase()
            .next()
            .map(|folded| {
                let mut buffer = [0_u16; 2];
                let units = folded.encode_utf16(&mut buffer);
                units[0]
            })
            .unwrap_or(ch as u16),
        None => unit,
    }
}

/// Substring search over case-folded text; returns the byte offset of the
/// first match in `haystack` (or None).
pub(crate) fn find_case_fold_substring(
    haystack: &str,
    needle: &str,
    case_insensitive: bool,
) -> Option<usize> {
    if needle.is_empty() {
        return None;
    }
    if case_insensitive {
        let folded_needle: String = needle.to_lowercase();
        let folded_haystack: String = haystack.to_lowercase();
        if let Some(relative) = folded_haystack.find(&folded_needle) {
            let mut char_offset = folded_haystack[..relative].chars().count();
            let mut byte_offset = 0;
            for ch in haystack.chars() {
                if char_offset == 0 {
                    break;
                }
                byte_offset += ch.len_utf8();
                char_offset -= 1;
            }
            return Some(byte_offset);
        }
        None
    } else {
        haystack.find(needle)
    }
}

pub(crate) fn file_attributes_mask(attributes: &[String]) -> u32 {
    let mut raw = 0_u32;
    for attribute in attributes {
        match attribute.as_str() {
            "directory" => raw |= FILE_ATTRIBUTE_DIRECTORY,
            "readonly" => raw |= FILE_ATTRIBUTE_READONLY,
            "hidden" => raw |= FILE_ATTRIBUTE_HIDDEN,
            "system" => raw |= FILE_ATTRIBUTE_SYSTEM,
            "archive" => raw |= FILE_ATTRIBUTE_ARCHIVE,
            "reparse_point" => raw |= FILE_ATTRIBUTE_REPARSE_POINT,
            _ => {}
        }
    }
    if raw == 0 { FILE_ATTRIBUTE_NORMAL } else { raw }
}

pub(crate) fn file_attributes_from_mask(raw: u32) -> Vec<String> {
    let mut attributes = Vec::new();
    if raw & FILE_ATTRIBUTE_DIRECTORY != 0 {
        attributes.push("directory".to_string());
    }
    if raw & FILE_ATTRIBUTE_READONLY != 0 {
        attributes.push("readonly".to_string());
    }
    if raw & FILE_ATTRIBUTE_HIDDEN != 0 {
        attributes.push("hidden".to_string());
    }
    if raw & FILE_ATTRIBUTE_SYSTEM != 0 {
        attributes.push("system".to_string());
    }
    if raw & FILE_ATTRIBUTE_ARCHIVE != 0 {
        attributes.push("archive".to_string());
    }
    if raw & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        attributes.push("reparse_point".to_string());
    }
    attributes
}
