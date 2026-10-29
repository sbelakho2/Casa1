//! Winsock/networking guest-structure helpers.

use super::*;

pub(crate) fn winsock_address_family(value: i32) -> Option<AddressFamily> {
    match value {
        AF_INET => Some(AddressFamily::Ipv4),
        AF_INET6 => Some(AddressFamily::Ipv6),
        _ => None,
    }
}

pub(crate) fn winsock_family_value(family: AddressFamily) -> i32 {
    match family {
        AddressFamily::Ipv4 => AF_INET,
        AddressFamily::Ipv6 => AF_INET6,
    }
}

pub(crate) fn guest_sockaddr_len(family: AddressFamily) -> u16 {
    match family {
        AddressFamily::Ipv4 => 16,
        AddressFamily::Ipv6 => 28,
    }
}

pub(crate) fn guest_addrinfo_size(guest_arch: GuestArch) -> u64 {
    if guest_arch == GuestArch::X86 { 32 } else { 48 }
}

pub(crate) fn write_guest_size_t(
    memory: &mut MemoryImage,
    address: u64,
    value: u64,
    guest_arch: GuestArch,
) -> AppResult<()> {
    if guest_arch == GuestArch::X86 {
        write_u32(memory, address, value as u32);
    } else {
        write_u64(memory, address, value);
    }
    Ok(())
}

pub(crate) fn write_guest_sockaddr(
    memory: &mut MemoryImage,
    address: u64,
    addr: &SockAddr,
) -> AppResult<()> {
    match addr.family {
        AddressFamily::Ipv4 => {
            let host = addr.host.parse::<Ipv4Addr>().map_err(|error| {
                AppError::new(ReasonCode::RcCliInvalid, "invalid IPv4 socket address")
                    .with_hint(error.to_string())
            })?;
            memory.map_bytes(address, &(AF_INET as u16).to_le_bytes());
            memory.map_bytes(address + 2, &addr.port.to_be_bytes());
            memory.map_bytes(address + 4, &host.octets());
            memory.map_bytes(address + 8, &[0_u8; 8]);
        }
        AddressFamily::Ipv6 => {
            let host = addr.host.parse::<Ipv6Addr>().map_err(|error| {
                AppError::new(ReasonCode::RcCliInvalid, "invalid IPv6 socket address")
                    .with_hint(error.to_string())
            })?;
            memory.map_bytes(address, &(AF_INET6 as u16).to_le_bytes());
            memory.map_bytes(address + 2, &addr.port.to_be_bytes());
            memory.map_bytes(address + 4, &0_u32.to_le_bytes());
            memory.map_bytes(address + 8, &host.octets());
            memory.map_bytes(address + 24, &0_u32.to_le_bytes());
        }
    }
    Ok(())
}

pub(crate) fn wsabuf_stride(guest_arch: GuestArch) -> u64 {
    if guest_arch == GuestArch::X86 { 8 } else { 16 }
}

pub(crate) fn wsabuf_buffer_offset(guest_arch: GuestArch) -> u64 {
    if guest_arch == GuestArch::X86 { 4 } else { 8 }
}

pub(crate) fn read_wsabuf_entry(
    memory: &MemoryImage,
    address: u64,
    guest_arch: GuestArch,
) -> AppResult<(u64, u32)> {
    Ok((
        read_guest_pointer(
            memory,
            address + wsabuf_buffer_offset(guest_arch),
            guest_arch,
        )?,
        read_guest_u32(memory, address)?,
    ))
}

pub(crate) fn total_wsabuf_len(
    memory: &MemoryImage,
    address: u64,
    count: u32,
    guest_arch: GuestArch,
) -> AppResult<usize> {
    let mut total = 0usize;
    for index in 0..count {
        let (_, len) = read_wsabuf_entry(
            memory,
            address + (index as u64 * wsabuf_stride(guest_arch)),
            guest_arch,
        )?;
        total = total.saturating_add(len as usize);
    }
    Ok(total)
}

pub(crate) fn read_wsabuf_bytes(
    memory: &MemoryImage,
    address: u64,
    count: u32,
    guest_arch: GuestArch,
) -> AppResult<Vec<u8>> {
    let mut bytes = Vec::new();
    for index in 0..count {
        let (buffer, len) = read_wsabuf_entry(
            memory,
            address + (index as u64 * wsabuf_stride(guest_arch)),
            guest_arch,
        )?;
        if len != 0 {
            bytes.extend(read_guest_bytes(memory, buffer, len as usize)?);
        }
    }
    Ok(bytes)
}

pub(crate) fn write_wsabuf_bytes(
    memory: &mut MemoryImage,
    address: u64,
    count: u32,
    guest_arch: GuestArch,
    bytes: &[u8],
) -> AppResult<usize> {
    let mut written = 0usize;
    for index in 0..count {
        if written >= bytes.len() {
            break;
        }
        let (buffer, len) = read_wsabuf_entry(
            memory,
            address + (index as u64 * wsabuf_stride(guest_arch)),
            guest_arch,
        )?;
        let remaining = bytes.len() - written;
        let chunk_len = remaining.min(len as usize);
        if chunk_len != 0 {
            memory.map_bytes(buffer, &bytes[written..written + chunk_len]);
            written += chunk_len;
        }
    }
    Ok(written)
}

pub(crate) fn fd_set_sockets(
    memory: &MemoryImage,
    address: u64,
    guest_arch: GuestArch,
) -> AppResult<Vec<u64>> {
    if address == 0 {
        return Ok(Vec::new());
    }
    let count = read_guest_u32(memory, address)? as usize;
    let pointer_bytes = guest_arch.pointer_bytes() as u64;
    let array_base = align_up_u64(address + 4, pointer_bytes);
    let mut sockets = Vec::with_capacity(count);
    for index in 0..count {
        sockets.push(read_guest_pointer(
            memory,
            array_base + index as u64 * pointer_bytes,
            guest_arch,
        )?);
    }
    Ok(sockets)
}

pub(crate) fn write_fd_set_sockets(
    memory: &mut MemoryImage,
    address: u64,
    guest_arch: GuestArch,
    sockets: &[u64],
) -> AppResult<()> {
    if address == 0 {
        return Ok(());
    }
    let pointer_bytes = guest_arch.pointer_bytes() as u64;
    let array_base = align_up_u64(address + 4, pointer_bytes);
    write_u32(memory, address, sockets.len() as u32);
    for (index, socket) in sockets.iter().enumerate() {
        write_guest_pointer(
            memory,
            array_base + index as u64 * pointer_bytes,
            *socket,
            guest_arch,
        )?;
    }
    Ok(())
}

pub(crate) fn read_guest_sockaddr(
    memory: &MemoryImage,
    address: u64,
    length: u32,
) -> AppResult<SockAddr> {
    if address == 0 || length < 8 {
        return Err(AppError::new(
            ReasonCode::RcCliInvalid,
            "sockaddr pointer must reference at least 8 bytes",
        ));
    }
    match i32::from(read_guest_u16(memory, address)?) {
        AF_INET => {
            if length < 16 {
                return Err(AppError::new(
                    ReasonCode::RcCliInvalid,
                    "sockaddr_in requires 16 bytes",
                ));
            }
            let port = u16::from_be(read_guest_u16(memory, address + 2)?);
            let octets = [
                memory.read_u8(address + 4)?,
                memory.read_u8(address + 5)?,
                memory.read_u8(address + 6)?,
                memory.read_u8(address + 7)?,
            ];
            Ok(SockAddr {
                family: AddressFamily::Ipv4,
                host: Ipv4Addr::from(octets).to_string(),
                port,
            })
        }
        AF_INET6 => {
            if length < 28 {
                return Err(AppError::new(
                    ReasonCode::RcCliInvalid,
                    "sockaddr_in6 requires 28 bytes",
                ));
            }
            let port = u16::from_be(read_guest_u16(memory, address + 2)?);
            let octets = memory.read_bytes(address + 8, 16)?;
            let mut bytes = [0_u8; 16];
            bytes.copy_from_slice(&octets);
            Ok(SockAddr {
                family: AddressFamily::Ipv6,
                host: Ipv6Addr::from(bytes).to_string(),
                port,
            })
        }
        family => Err(AppError::new(
            ReasonCode::RcCliInvalid,
            format!("unsupported sockaddr family {family}"),
        )),
    }
}

/// The guest-visible service database (port, tcp name, udp name) backing
/// `getservbyname` and the service half of `getnameinfo`.  This is the
/// guest's own view of the services — it never consults the host's
/// /etc/services.
pub(crate) const GUEST_SERVICES: &[(u16, &str, &str)] = &[
    (7, "echo", "echo"),
    (9, "discard", "discard"),
    (13, "daytime", "daytime"),
    (17, "qotd", "qotd"),
    (19, "chargen", "chargen"),
    (20, "ftp-data", "ftp-data"),
    (21, "ftp", "ftp"),
    (22, "ssh", "ssh"),
    (23, "telnet", "telnet"),
    (25, "smtp", "smtp"),
    (37, "time", "time"),
    (42, "nameserver", "nameserver"),
    (43, "whois", "whois"),
    (53, "domain", "domain"),
    (67, "bootps", "bootps"),
    (68, "bootpc", "bootpc"),
    (69, "tftp", "tftp"),
    (70, "gopher", "gopher"),
    (79, "finger", "finger"),
    (80, "http", "http"),
    (88, "kerberos", "kerberos"),
    (110, "pop3", "pop3"),
    (111, "sunrpc", "sunrpc"),
    (113, "auth", "auth"),
    (119, "nntp", "nntp"),
    (123, "ntp", "ntp"),
    (137, "netbios-ns", "netbios-ns"),
    (138, "netbios-dgm", "netbios-dgm"),
    (139, "netbios-ssn", "netbios-ssn"),
    (143, "imap", "imap"),
    (161, "snmp", "snmp"),
    (162, "snmptrap", "snmptrap"),
    (179, "bgp", "bgp"),
    (194, "irc", "irc"),
    (389, "ldap", "ldap"),
    (443, "https", "https"),
    (445, "microsoft-ds", "microsoft-ds"),
    (465, "smtps", "smtps"),
    (514, "shell", "shell"),
    (515, "printer", "printer"),
    (548, "afp", "afp"),
    (554, "rtsp", "rtsp"),
    (587, "submission", "submission"),
    (631, "ipp", "ipp"),
    (636, "ldaps", "ldaps"),
    (873, "rsync", "rsync"),
    (993, "imaps", "imaps"),
    (995, "pop3s", "pop3s"),
    (1080, "socks", "socks"),
    (1433, "ms-sql-s", "ms-sql-s"),
    (1900, "ssdp", "ssdp"),
    (3306, "mysql", "mysql"),
    (3389, "ms-wbt-server", "ms-wbt-server"),
    (5353, "mdns", "mdns"),
    (5432, "postgresql", "postgresql"),
    (8080, "http-alt", "http-alt"),
    (8443, "pcsync-https", "pcsync-https"),
];

/// The guest-visible protocol database backing `getprotobyname`.
pub(crate) const GUEST_PROTOCOLS: &[(&str, i16)] =
    &[("ip", 0), ("icmp", 1), ("tcp", 6), ("udp", 17)];

/// `inet_addr` dotted-decimal parsing with the documented Windows partial
/// forms: `a.b.c.d`, `a.b.c` (c up to 16 bits), `a.b` (b up to 16 bits) and
/// `a`.  The result is the address in NETWORK byte order — the numeric
/// value whose in-memory byte layout is the address octets.
pub(crate) fn parse_guest_inet_addr(input: &str) -> Option<u32> {
    let components = input.split('.').collect::<Vec<_>>();
    if components.is_empty() || components.len() > 4 {
        return None;
    }
    let mut octets = [0_u8; 4];
    for (index, component) in components.iter().enumerate() {
        if component.is_empty() {
            return None;
        }
        let is_last = index + 1 == components.len();
        let max_value: u32 = if is_last {
            match components.len() {
                1 => 0xFFFF_FFFF,
                2 => 0xFFFF,
                3 => 0xFFFF,
                _ => 255,
            }
        } else {
            255
        };
        let value: u32 = component.parse().ok()?;
        if value > max_value {
            return None;
        }
        if is_last {
            if components.len() == 1 {
                octets = value.to_be_bytes();
            } else if components.len() == 2 {
                octets[2] = (value >> 8) as u8;
                octets[3] = value as u8;
            } else {
                octets[3] = value as u8;
            }
        } else {
            octets[index] = value as u8;
        }
    }
    // The caller observes the in_addr bytes; report the network-order
    // numeric value (LE layout of the octets on little-endian hosts).
    Some(u32::from_ne_bytes(octets))
}

/// Read the handle value out of a guest SecHandle (two pointer-sized
/// words; `dwLower` carries the value, `dwUpper` is 0).
pub(crate) fn read_guest_sec_handle(
    memory: &MemoryImage,
    address: u64,
    guest_arch: GuestArch,
) -> AppResult<u64> {
    if address == 0 {
        return Ok(0);
    }
    read_guest_pointer(memory, address, guest_arch)
}

/// Write a handle value into a guest SecHandle.
pub(crate) fn write_guest_sec_handle(
    memory: &mut MemoryImage,
    address: u64,
    value: u64,
    guest_arch: GuestArch,
) -> AppResult<()> {
    if address == 0 {
        return Ok(());
    }
    write_guest_pointer(memory, address, value, guest_arch)?;
    write_guest_pointer(
        memory,
        address + guest_arch.pointer_bytes() as u64,
        0,
        guest_arch,
    )
}

/// The stride of a guest `SecBuffer` (cbBuffer, BufferType, pvBuffer).
pub(crate) fn sec_buffer_stride(guest_arch: GuestArch) -> u64 {
    if guest_arch == GuestArch::X86 { 12 } else { 24 }
}

/// The offset of `pvBuffer` inside a guest `SecBuffer`.
pub(crate) fn sec_buffer_buffer_offset(guest_arch: GuestArch) -> u64 {
    if guest_arch == GuestArch::X86 { 8 } else { 16 }
}

/// Read the SECBUFFER_TOKEN payload out of a SecBufferDesc.  Returns
/// `None` when the descriptor has no token buffer.
pub(crate) fn read_sec_buffer_desc_token(
    memory: &MemoryImage,
    desc: u64,
    guest_arch: GuestArch,
) -> AppResult<Option<Vec<u8>>> {
    if desc == 0 {
        return Ok(None);
    }
    let count = read_guest_u32(memory, desc + 4)?;
    if count == 0 {
        return Ok(None);
    }
    let buffers = read_guest_pointer(memory, desc + 8, guest_arch)?;
    if buffers == 0 {
        return Ok(None);
    }
    let stride = sec_buffer_stride(guest_arch);
    for index in 0..count {
        let entry = buffers + u64::from(index) * stride;
        let cb = read_guest_u32(memory, entry)?;
        let buffer_type = read_guest_u32(memory, entry + 4)?;
        let pv = read_guest_pointer(
            memory,
            entry + sec_buffer_buffer_offset(guest_arch),
            guest_arch,
        )?;
        if buffer_type == crate::sspi::SECBUFFER_TOKEN {
            if cb == 0 || pv == 0 {
                return Ok(Some(Vec::new()));
            }
            return Ok(Some(read_guest_bytes(memory, pv, cb as usize)?));
        }
    }
    Ok(None)
}

/// Write a token into the SECBUFFER_TOKEN buffer of a SecBufferDesc.
/// Returns `false` when the descriptor has no writable token buffer.
pub(crate) fn write_sec_buffer_desc_token(
    memory: &mut MemoryImage,
    desc: u64,
    guest_arch: GuestArch,
    token: &[u8],
) -> AppResult<bool> {
    if desc == 0 {
        return Ok(false);
    }
    let count = read_guest_u32(memory, desc + 4)?;
    if count == 0 {
        return Ok(false);
    }
    let buffers = read_guest_pointer(memory, desc + 8, guest_arch)?;
    if buffers == 0 {
        return Ok(false);
    }
    let stride = sec_buffer_stride(guest_arch);
    for index in 0..count {
        let entry = buffers + u64::from(index) * stride;
        let buffer_type = read_guest_u32(memory, entry + 4)?;
        if buffer_type == crate::sspi::SECBUFFER_TOKEN {
            let pv = read_guest_pointer(
                memory,
                entry + sec_buffer_buffer_offset(guest_arch),
                guest_arch,
            )?;
            if pv == 0 {
                return Ok(false);
            }
            write_u32(memory, entry, token.len() as u32);
            if !token.is_empty() {
                memory.map_bytes(pv, token);
            }
            return Ok(true);
        }
    }
    Ok(false)
}

/// Read the concatenation of the data buffers (every buffer except the
/// SECBUFFER_TOKEN at index 0) of a SecBufferDesc.
pub(crate) fn read_sec_buffer_desc_data(
    memory: &MemoryImage,
    desc: u64,
    guest_arch: GuestArch,
) -> AppResult<Vec<u8>> {
    if desc == 0 {
        return Ok(Vec::new());
    }
    let count = read_guest_u32(memory, desc + 4)?;
    if count == 0 {
        return Ok(Vec::new());
    }
    let buffers = read_guest_pointer(memory, desc + 8, guest_arch)?;
    if buffers == 0 {
        return Ok(Vec::new());
    }
    let stride = sec_buffer_stride(guest_arch);
    let mut data = Vec::new();
    for index in 1..count {
        let entry = buffers + u64::from(index) * stride;
        let cb = read_guest_u32(memory, entry)?;
        let pv = read_guest_pointer(
            memory,
            entry + sec_buffer_buffer_offset(guest_arch),
            guest_arch,
        )?;
        if cb != 0 {
            if pv == 0 {
                continue;
            }
            data.extend(read_guest_bytes(memory, pv, cb as usize)?);
        }
    }
    Ok(data)
}

/// Overwrite the data buffers (index 1..) of a SecBufferDesc with `data`,
/// writing as many bytes as the buffers hold.
pub(crate) fn write_sec_buffer_desc_data(
    memory: &mut MemoryImage,
    desc: u64,
    guest_arch: GuestArch,
    data: &[u8],
) -> AppResult<()> {
    if desc == 0 || data.is_empty() {
        return Ok(());
    }
    let count = read_guest_u32(memory, desc + 4)?;
    if count == 0 {
        return Ok(());
    }
    let buffers = read_guest_pointer(memory, desc + 8, guest_arch)?;
    if buffers == 0 {
        return Ok(());
    }
    let stride = sec_buffer_stride(guest_arch);
    let mut written = 0_usize;
    for index in 1..count {
        if written >= data.len() {
            break;
        }
        let entry = buffers + u64::from(index) * stride;
        let cb = read_guest_u32(memory, entry)?;
        let pv = read_guest_pointer(
            memory,
            entry + sec_buffer_buffer_offset(guest_arch),
            guest_arch,
        )?;
        if cb == 0 || pv == 0 {
            continue;
        }
        let chunk_len = (cb as usize).min(data.len() - written);
        memory.map_bytes(pv, &data[written..written + chunk_len]);
        written += chunk_len;
    }
    Ok(())
}

/// Allocate one guest-heap block big enough for `struct_size` plus the
/// UTF-16 forms of `strings`, and write the strings after the struct.
/// Returns `(base, string_pointers)` — the caller writes the pointers into
/// the struct fields.  The single-block layout mirrors the documented
/// netapi32 contract (one buffer, freed with a single NetApiBufferFree).
pub(crate) fn alloc_packed_string_block(
    runtime: &mut PeHostRuntime,
    memory: &mut MemoryImage,
    struct_size: usize,
    strings: &[&str],
) -> AppResult<(u64, Vec<u64>)> {
    let string_bytes: usize = strings
        .iter()
        .map(|value| value.encode_utf16().count() * 2 + 2)
        .sum();
    let base = runtime.alloc_heap(memory, struct_size + string_bytes, true)?;
    let mut cursor = base + struct_size as u64;
    let mut pointers = Vec::with_capacity(strings.len());
    for value in strings {
        let mut bytes = Vec::with_capacity(value.len() * 2 + 2);
        for unit in value.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes.extend_from_slice(&0_u16.to_le_bytes());
        memory.map_bytes(cursor, &bytes);
        pointers.push(cursor);
        cursor += bytes.len() as u64;
    }
    Ok((base, pointers))
}
