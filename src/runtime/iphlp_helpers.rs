//! iphlpapi guest-structure writers.

use super::*;

/// The canonical guest network config for the runtime's guest identity.
pub(crate) fn guest_net_config(runtime: &PeHostRuntime) -> crate::network::GuestNetworkConfig {
    crate::network::guest_network_config(&runtime.win32.ge().config.user_name)
}

// ---------------------------------------------------------------------------
// iphlpapi guest-structure writers
// ---------------------------------------------------------------------------
//
// Every table is derived from the guest network configuration
// (`guest_network_config`) — the host's real adapters never leak into the
// guest.  The layouts below mirror the documented iphlpapi structures for
// both guest ABIs (pointer fields widen on x64; ULONGLONG members stay
// 8-aligned on x86).

/// Size of MIB_IFROW (860 bytes on both ABIs — no pointer members).
pub(crate) const MIB_IFROW_SIZE: u32 = 860;
/// Size of MIB_IPFORWARDROW (44 bytes on both ABIs).
pub(crate) const MIB_IPFORWARDROW_SIZE: u32 = 44;

/// Write one MIB_IFROW (the guest adapter) at `address`; returns the next
/// cursor.  The row layout is ABI-independent (fixed-width members only).
pub(crate) fn write_guest_mib_ifrow(
    memory: &mut MemoryImage,
    address: u64,
    adapter: &crate::network::GuestAdapter,
) -> AppResult<u64> {
    let name_units = adapter.adapter_name.encode_utf16().collect::<Vec<_>>();
    for (index, unit) in name_units.iter().enumerate().take(256) {
        memory.map_bytes(address + index as u64 * 2, &unit.to_le_bytes());
    }
    memory.map_bytes(address + name_units.len() as u64 * 2, &0_u16.to_le_bytes());
    write_u32(memory, address + 512, adapter.index);
    write_u32(memory, address + 516, adapter.if_type);
    write_u32(memory, address + 520, adapter.mtu);
    write_u32(memory, address + 524, adapter.speed as u32);
    write_u32(memory, address + 528, adapter.mac.len() as u32);
    memory.map_bytes(address + 532, &adapter.mac);
    write_u32(memory, address + 540, MIB_IF_ADMIN_STATUS_UP);
    write_u32(memory, address + 544, adapter.oper_status);
    write_u32(memory, address + 548, 0); // dwLastChange
    // Counters: the guest model has no traffic.
    for offset in [
        552_u64, 556, 560, 564, 568, 572, 576, 580, 584, 588, 592, 596,
    ] {
        write_u32(memory, address + offset, 0);
    }
    let description = adapter.description.as_bytes();
    let description_len = description.len().min(256);
    write_u32(memory, address + 600, description_len as u32);
    memory.map_bytes(address + 604, &description[..description_len]);
    Ok(address + u64::from(MIB_IFROW_SIZE))
}

/// Write one MIB_IPFORWARDROW (a guest route).
pub(crate) fn write_guest_mib_ipforwardrow(
    memory: &mut MemoryImage,
    address: u64,
    route: &crate::network::GuestRoute,
) -> AppResult<()> {
    write_u32(memory, address, u32::from_ne_bytes(route.dest.octets()));
    write_u32(memory, address + 4, u32::from_ne_bytes(route.mask.octets()));
    write_u32(memory, address + 8, 0); // dwForwardPolicy
    write_u32(
        memory,
        address + 12,
        u32::from_ne_bytes(route.next_hop.octets()),
    );
    write_u32(memory, address + 16, route.if_index);
    write_u32(memory, address + 20, route.route_type);
    write_u32(memory, address + 24, MIB_IPPROTO_NETMGMT);
    write_u32(memory, address + 28, 0); // dwForwardAge
    write_u32(memory, address + 32, 0); // dwForwardNextHopAS
    write_u32(memory, address + 36, route.metric); // dwForwardMetric1
    for offset in [40_u64, 44, 48, 52] {
        write_u32(memory, address + offset, 0);
    }
    Ok(())
}

/// The longest-prefix guest route for a destination (network-order u32).
pub(crate) fn best_guest_route(
    config: &crate::network::GuestNetworkConfig,
    dest_network_order: u32,
) -> &crate::network::GuestRoute {
    let dest = Ipv4Addr::from(dest_network_order.to_ne_bytes());
    let dest_u32 = u32::from_ne_bytes(dest.octets());
    let mut best: Option<&crate::network::GuestRoute> = None;
    let mut best_prefix = 0_u32;
    for route in &config.routes {
        let mask = u32::from_ne_bytes(route.mask.octets());
        let network = u32::from_ne_bytes(route.dest.octets());
        if dest_u32 & mask == network & mask {
            let prefix = mask.count_ones();
            if prefix >= best_prefix {
                best_prefix = prefix;
                best = Some(route);
            }
        }
    }
    best.unwrap_or_else(|| {
        config
            .routes
            .iter()
            .find(|route| route.mask == Ipv4Addr::UNSPECIFIED)
            .expect("the guest config always carries the default route")
    })
}

/// The size of the guest FIXED_INFO structure (per-arch).
pub(crate) fn guest_fixed_info_size(guest_arch: GuestArch) -> u32 {
    if guest_arch == GuestArch::X86 {
        592
    } else {
        608
    }
}

/// Write FIXED_INFO (GetNetworkParams) from the guest configuration.
pub(crate) fn write_guest_fixed_info(
    memory: &mut MemoryImage,
    address: u64,
    guest_arch: GuestArch,
    config: &crate::network::GuestNetworkConfig,
) -> AppResult<()> {
    let hostname = config.hostname.as_bytes();
    memory.map_bytes(address, hostname);
    memory.map_bytes(address + hostname.len() as u64, &[0]);
    let domain = config.domain.as_bytes();
    memory.map_bytes(address + 132, domain);
    memory.map_bytes(address + 132 + domain.len() as u64, &[0]);
    let dns_addr_ptr = if guest_arch == GuestArch::X86 {
        address + 272
    } else {
        address + 280
    };
    let dns_head_ptr = if guest_arch == GuestArch::X86 {
        address + 268
    } else {
        address + 272
    };
    write_guest_pointer(memory, dns_head_ptr, dns_addr_ptr, guest_arch)?;
    // DnsServerList: one entry (10.0.2.3), Next = NULL.
    let dns_ip = config
        .dns_servers
        .first()
        .map(String::as_str)
        .unwrap_or("10.0.2.3");
    let mut dns_bytes = dns_ip.as_bytes().to_vec();
    dns_bytes.push(0);
    memory.map_bytes(dns_addr_ptr, &[0_u8; 40]);
    if guest_arch == GuestArch::X64 {
        memory.map_bytes(dns_addr_ptr, &[0_u8; 48]);
    }
    memory.map_bytes(dns_addr_ptr + 4, &dns_bytes);
    memory.map_bytes(dns_addr_ptr + 20, b"255.255.255.255\x00");
    write_guest_pointer(memory, dns_addr_ptr, 0, guest_arch)?;
    write_u32(memory, dns_addr_ptr + 36, 0); // Context
    let node_type = if guest_arch == GuestArch::X86 {
        address + 312
    } else {
        address + 328
    };
    write_u32(memory, node_type, 1); // BROADCAST_NODETYPE
    // ScopeId (264 bytes) stays zeroed.
    let enable_routing = if guest_arch == GuestArch::X86 {
        address + 580
    } else {
        address + 596
    };
    write_u32(memory, enable_routing, 0);
    write_u32(memory, enable_routing + 4, 0); // EnableProxy
    write_u32(memory, enable_routing + 8, 1); // EnableDns
    Ok(())
}

/// The required GetAdaptersInfo buffer size (one IP_ADAPTER_INFO per guest
/// adapter).
pub(crate) fn guest_adapter_info_total_size(guest_arch: GuestArch, adapter_count: usize) -> u32 {
    let per = if guest_arch == GuestArch::X86 {
        688
    } else {
        736
    };
    (per * adapter_count) as u32
}

/// Write one IP_ADAPTER_INFO chain entry; returns the next cursor.
pub(crate) fn write_guest_ip_adapter_info(
    _runtime: &mut PeHostRuntime,
    memory: &mut MemoryImage,
    address: u64,
    guest_arch: GuestArch,
    adapter: &crate::network::GuestAdapter,
) -> AppResult<u64> {
    let pointer_bytes = guest_arch.pointer_bytes() as u64;
    let ip_addr_string_size = if guest_arch == GuestArch::X86 { 40 } else { 48 };
    let struct_size = if guest_arch == GuestArch::X86 {
        688
    } else {
        736
    };
    memory.map_bytes(address, &vec![0_u8; struct_size as usize]);
    write_u32(memory, address + pointer_bytes, 0); // ComboIndex
    let mut adapter_name = adapter.adapter_name.as_bytes().to_vec();
    adapter_name.push(0);
    memory.map_bytes(address + pointer_bytes + 4, &adapter_name);
    let mut description = adapter.description.as_bytes().to_vec();
    description.push(0);
    memory.map_bytes(address + pointer_bytes + 264, &description);
    write_u32(
        memory,
        address + pointer_bytes + 396,
        adapter.mac.len() as u32,
    );
    memory.map_bytes(address + pointer_bytes + 400, &adapter.mac);
    write_u32(memory, address + pointer_bytes + 408, adapter.index);
    write_u32(memory, address + pointer_bytes + 412, adapter.if_type);
    write_u32(
        memory,
        address + pointer_bytes + 416,
        u32::from(adapter.dhcp_enabled),
    );
    // CurrentIpAddress: NULL (the documented "may be NULL" state).
    let current = address + pointer_bytes + 420;
    write_guest_pointer(memory, current, 0, guest_arch)?;
    let ip_list = current + ip_addr_string_size;
    let gateway_list = ip_list + ip_addr_string_size;
    let dhcp_server = gateway_list + ip_addr_string_size;
    if let Some(ipv4) = &adapter.ipv4 {
        write_guest_ip_addr_string(
            memory,
            ip_list,
            guest_arch,
            &ipv4.address.to_string(),
            &ipv4.mask.to_string(),
        )?;
        let gateway = ipv4
            .gateway
            .map(|addr| addr.to_string())
            .unwrap_or_else(|| "0.0.0.0".to_string());
        write_guest_ip_addr_string(
            memory,
            gateway_list,
            guest_arch,
            &gateway,
            "255.255.255.255",
        )?;
    } else {
        write_guest_ip_addr_string(memory, ip_list, guest_arch, "0.0.0.0", "0.0.0.0")?;
        write_guest_ip_addr_string(memory, gateway_list, guest_arch, "0.0.0.0", "0.0.0.0")?;
    }
    let dhcp_ip = adapter
        .dns_servers
        .first()
        .cloned()
        .unwrap_or_else(|| "0.0.0.0".to_string());
    write_guest_ip_addr_string(memory, dhcp_server, guest_arch, &dhcp_ip, "255.255.255.255")?;
    let have_wins = dhcp_server + ip_addr_string_size;
    write_u32(memory, have_wins, 0);
    // Primary/SecondaryWinsServer: empty entries.
    let wins_primary = have_wins + 4;
    let wins_secondary = wins_primary + ip_addr_string_size;
    write_guest_ip_addr_string(memory, wins_primary, guest_arch, "0.0.0.0", "0.0.0.0")?;
    write_guest_ip_addr_string(memory, wins_secondary, guest_arch, "0.0.0.0", "0.0.0.0")?;
    let lease_obtained = align_up_u64(wins_secondary + ip_addr_string_size, 8);
    memory.map_bytes(lease_obtained, &0_u64.to_le_bytes());
    memory.map_bytes(lease_obtained + 8, &0_u64.to_le_bytes());
    Ok(lease_obtained + 16)
}

/// Write one IP_ADDR_STRING (Next + address + mask + context).
pub(crate) fn write_guest_ip_addr_string(
    memory: &mut MemoryImage,
    address: u64,
    guest_arch: GuestArch,
    ip: &str,
    mask: &str,
) -> AppResult<()> {
    let pointer_bytes = guest_arch.pointer_bytes() as u64;
    write_guest_pointer(memory, address, 0, guest_arch)?;
    let mut ip_bytes = ip.as_bytes().to_vec();
    ip_bytes.push(0);
    memory.map_bytes(address + pointer_bytes, &ip_bytes);
    let mut mask_bytes = mask.as_bytes().to_vec();
    mask_bytes.push(0);
    memory.map_bytes(address + pointer_bytes + 16, &mask_bytes);
    write_u32(memory, address + pointer_bytes + 32, 0); // Context
    Ok(())
}

/// The required GetAdaptersAddresses buffer size.
pub(crate) fn guest_adapters_addresses_total_size(
    guest_arch: GuestArch,
    adapter_count: usize,
) -> u32 {
    let per = if guest_arch == GuestArch::X86 {
        344
    } else {
        408
    };
    (per * adapter_count) as u32
}

/// Write one IP_ADAPTER_ADDRESSES entry (the Vista structure) for a guest
/// adapter; returns the next cursor.
pub(crate) fn write_guest_ip_adapter_addresses(
    runtime: &mut PeHostRuntime,
    memory: &mut MemoryImage,
    address: u64,
    guest_arch: GuestArch,
    adapter: &crate::network::GuestAdapter,
    family_filter: u32,
) -> AppResult<u64> {
    let _pointer_bytes = guest_arch.pointer_bytes() as u64;
    let x86 = guest_arch == GuestArch::X86;
    let struct_size = if x86 { 344 } else { 408 };
    // Per-arch field offsets (pointer fields widen on x64; ULONGLONG
    // members stay 8-aligned).
    let off_adapter_name = if x86 { 12 } else { 16 };
    let off_first_unicast = if x86 { 16 } else { 24 };
    let off_first_dns = if x86 { 28 } else { 48 };
    let off_dns_suffix = if x86 { 32 } else { 56 };
    let off_description = if x86 { 36 } else { 64 };
    let off_friendly_name = if x86 { 40 } else { 72 };
    let off_first_prefix = if x86 { 140 } else { 176 };
    let off_transmit_speed = if x86 { 144 } else { 184 };
    let off_receive_speed = if x86 { 152 } else { 192 };
    let off_first_gateway = if x86 { 164 } else { 208 };
    let off_ipv4_metric = if x86 { 168 } else { 216 };
    let off_ipv6_metric = if x86 { 172 } else { 220 };
    memory.map_bytes(address, &vec![0_u8; struct_size as usize]);
    write_u32(memory, address, struct_size); // Length
    write_u32(memory, address + 4, adapter.index); // IfIndex
    write_guest_pointer(memory, address + 8, 0, guest_arch)?; // Next
    let name_ptr = runtime.alloc_c_string(memory, &adapter.adapter_name)?;
    write_guest_pointer(memory, address + off_adapter_name, name_ptr, guest_arch)?;
    let dns_suffix = runtime.alloc_utf16_string(memory, "")?;
    let description = runtime.alloc_utf16_string(memory, &adapter.description)?;
    let friendly = runtime.alloc_utf16_string(memory, &adapter.friendly_name)?;
    write_guest_pointer(memory, address + off_dns_suffix, dns_suffix, guest_arch)?;
    write_guest_pointer(memory, address + off_description, description, guest_arch)?;
    write_guest_pointer(memory, address + off_friendly_name, friendly, guest_arch)?;
    let off_physical_address = if x86 { 44 } else { 80 };
    let off_physical_len = if x86 { 52 } else { 88 };
    let off_flags = if x86 { 56 } else { 92 };
    let off_mtu = if x86 { 60 } else { 96 };
    let off_if_type = if x86 { 64 } else { 100 };
    let off_oper_status = if x86 { 68 } else { 104 };
    let off_ipv6_if_index = if x86 { 72 } else { 108 };
    memory.map_bytes(address + off_physical_address, &adapter.mac);
    write_u32(memory, address + off_physical_len, adapter.mac.len() as u32);
    let flags = IP_ADAPTER_DDNS_ENABLED
        | IP_ADAPTER_REGISTER_ADAPTER_SUFFIX
        | (if adapter.dhcp_enabled {
            IP_ADAPTER_DHCP_ENABLED
        } else {
            0
        })
        | IP_ADAPTER_IPV4_ENABLED
        | IP_ADAPTER_IPV6_ENABLED;
    write_u32(memory, address + off_flags, flags);
    write_u32(memory, address + off_mtu, adapter.mtu);
    write_u32(memory, address + off_if_type, adapter.if_type);
    write_u32(memory, address + off_oper_status, adapter.oper_status);
    write_u32(memory, address + off_ipv6_if_index, 0); // Ipv6IfIndex
    // ZoneIndices[16] stays zeroed.
    // Unicast chain: the adapter's IPv4 (+ IPv6 when the filter allows).
    // The chain entries are guest-heap allocations referenced through the
    // struct's pointer fields — they never overlap the struct itself.
    let unicast_size = if x86 { 48 } else { 64 };
    let entry_size = if x86 { 20 } else { 32 };
    let mut unicast_entries = Vec::new();
    if let Some(ipv4) = &adapter.ipv4
        && (family_filter == AF_UNSPEC as u32 || family_filter == AF_INET as u32)
    {
        unicast_entries.push((AddressFamily::Ipv4, ipv4.address.to_string(), 24_u32));
    }
    if let Some(ipv6) = &adapter.ipv6
        && (family_filter == AF_UNSPEC as u32 || family_filter == AF_INET6 as u32)
    {
        unicast_entries.push((
            AddressFamily::Ipv6,
            ipv6.address.to_string(),
            u32::from(ipv6.prefix_len),
        ));
    }
    let mut unicast_ptrs = Vec::new();
    for (family, host, prefix_len) in unicast_entries {
        let entry = runtime.alloc_heap(memory, unicast_size as usize, true)?;
        unicast_ptrs.push(entry);
        write_guest_unicast_address(
            runtime, memory, entry, guest_arch, family, &host, prefix_len,
        )?;
    }
    write_guest_pointer(
        memory,
        address + off_first_unicast,
        unicast_ptrs.first().copied().unwrap_or(0),
        guest_arch,
    )?;
    for pair in unicast_ptrs.windows(2) {
        write_guest_pointer(memory, pair[0] + 8, pair[1], guest_arch)?;
    }
    // DNS server chain.
    let mut dns_ptrs = Vec::new();
    for server in &adapter.dns_servers {
        let entry = runtime.alloc_heap(memory, entry_size as usize, true)?;
        dns_ptrs.push(entry);
        write_guest_dns_entry(runtime, memory, entry, guest_arch, server)?;
    }
    write_guest_pointer(
        memory,
        address + off_first_dns,
        dns_ptrs.first().copied().unwrap_or(0),
        guest_arch,
    )?;
    for pair in dns_ptrs.windows(2) {
        write_guest_pointer(memory, pair[0] + 8, pair[1], guest_arch)?;
    }
    // Prefix chain (one on-link prefix for the IPv4 subnet).
    if let Some(ipv4) = &adapter.ipv4 {
        let prefix_ptr = runtime.alloc_heap(memory, 40, true)?;
        write_guest_prefix(
            runtime,
            memory,
            prefix_ptr,
            guest_arch,
            &ipv4.address.to_string(),
            24,
        )?;
        write_guest_pointer(memory, address + off_first_prefix, prefix_ptr, guest_arch)?;
    }
    write_u64(memory, address + off_transmit_speed, adapter.speed); // TransmitLinkSpeed
    write_u64(memory, address + off_receive_speed, adapter.speed); // ReceiveLinkSpeed
    // Gateway chain.
    if let Some(gateway) = adapter.ipv4.as_ref().and_then(|ipv4| ipv4.gateway) {
        let gateway_ptr = runtime.alloc_heap(memory, entry_size as usize, true)?;
        write_guest_socket_address_entry(
            runtime,
            memory,
            gateway_ptr,
            guest_arch,
            AddressFamily::Ipv4,
            &gateway.to_string(),
        )?;
        write_guest_pointer(memory, address + off_first_gateway, gateway_ptr, guest_arch)?;
    }
    write_u32(memory, address + off_ipv4_metric, adapter.metric); // Ipv4Metric
    write_u32(memory, address + off_ipv6_metric, 0); // Ipv6Metric
    // Luid stays zeroed; Dhcpv4Server/Dhcpv6Server stay zeroed.
    Ok(address + struct_size as u64)
}

/// Write one IP_ADAPTER_UNICAST_ADDRESS for the guest adapter.
pub(crate) fn write_guest_unicast_address(
    runtime: &mut PeHostRuntime,
    memory: &mut MemoryImage,
    address: u64,
    guest_arch: GuestArch,
    family: AddressFamily,
    host: &str,
    prefix_len: u32,
) -> AppResult<u64> {
    let pointer_bytes = guest_arch.pointer_bytes() as u64;
    let unicast_size = if guest_arch == GuestArch::X86 { 48 } else { 64 };
    let sockaddr_len = u32::from(guest_sockaddr_len(family));
    let sockaddr_ptr = runtime.alloc_heap(memory, sockaddr_len as usize, true)?;
    write_guest_sockaddr(
        memory,
        sockaddr_ptr,
        &SockAddr {
            family,
            host: host.to_string(),
            port: 0,
        },
    )?;
    memory.map_bytes(address, &vec![0_u8; unicast_size as usize]);
    write_guest_pointer(memory, address + 8, 0, guest_arch)?; // Next
    write_u32(memory, address + 12, sockaddr_len); // iSockaddrLength
    write_guest_pointer(
        memory,
        address + 12 + pointer_bytes,
        sockaddr_ptr,
        guest_arch,
    )?;
    write_u32(memory, address + 20, 0); // PrefixOrigin
    write_u32(memory, address + 24, 0); // SuffixOrigin
    write_u32(memory, address + 28, 0); // DadState
    write_u32(memory, address + 32, u32::MAX); // ValidLifetime
    write_u32(memory, address + 36, u32::MAX); // PreferredLifetime
    write_u32(memory, address + 40, u32::MAX); // LeaseLifetime
    memory.map_bytes(address + 44, &(prefix_len as u8).to_le_bytes()); // OnLinkPrefixLength
    memory.map_bytes(address + 45, &0_u8.to_le_bytes()); // SkipAsSource
    Ok(address + unicast_size as u64)
}

/// Write one IP_ADAPTER_DNS_SERVER_ADDRESS / GATEWAY entry.
pub(crate) fn write_guest_socket_address_entry(
    runtime: &mut PeHostRuntime,
    memory: &mut MemoryImage,
    address: u64,
    guest_arch: GuestArch,
    family: AddressFamily,
    host: &str,
) -> AppResult<u64> {
    let pointer_bytes = guest_arch.pointer_bytes() as u64;
    let entry_size = if guest_arch == GuestArch::X86 { 20 } else { 32 };
    let sockaddr_len = u32::from(guest_sockaddr_len(family));
    let sockaddr_ptr = runtime.alloc_heap(memory, sockaddr_len as usize, true)?;
    write_guest_sockaddr(
        memory,
        sockaddr_ptr,
        &SockAddr {
            family,
            host: host.to_string(),
            port: 0,
        },
    )?;
    memory.map_bytes(address, &vec![0_u8; entry_size as usize]);
    write_guest_pointer(memory, address + 8, 0, guest_arch)?; // Next
    write_u32(memory, address + 12, sockaddr_len);
    write_guest_pointer(
        memory,
        address + 12 + pointer_bytes,
        sockaddr_ptr,
        guest_arch,
    )?;
    Ok(address + entry_size as u64)
}

/// Write one IP_ADAPTER_DNS_SERVER_ADDRESS entry for a DNS server.
pub(crate) fn write_guest_dns_entry(
    runtime: &mut PeHostRuntime,
    memory: &mut MemoryImage,
    address: u64,
    guest_arch: GuestArch,
    server: &str,
) -> AppResult<u64> {
    write_guest_socket_address_entry(
        runtime,
        memory,
        address,
        guest_arch,
        AddressFamily::Ipv4,
        server,
    )
}

/// Write one IP_ADAPTER_PREFIX entry.
pub(crate) fn write_guest_prefix(
    runtime: &mut PeHostRuntime,
    memory: &mut MemoryImage,
    address: u64,
    guest_arch: GuestArch,
    host: &str,
    prefix_len: u32,
) -> AppResult<()> {
    let pointer_bytes = guest_arch.pointer_bytes() as u64;
    let prefix_size = if guest_arch == GuestArch::X86 { 28 } else { 40 };
    let sockaddr_len = u32::from(guest_sockaddr_len(AddressFamily::Ipv4));
    let sockaddr_ptr = runtime.alloc_heap(memory, sockaddr_len as usize, true)?;
    write_guest_sockaddr(
        memory,
        sockaddr_ptr,
        &SockAddr {
            family: AddressFamily::Ipv4,
            host: host.to_string(),
            port: 0,
        },
    )?;
    memory.map_bytes(address, &vec![0_u8; prefix_size as usize]);
    write_guest_pointer(memory, address + 8, 0, guest_arch)?; // Next
    write_u32(memory, address + 12, sockaddr_len);
    write_guest_pointer(
        memory,
        address + 12 + pointer_bytes,
        sockaddr_ptr,
        guest_arch,
    )?;
    write_u32(memory, address + 20, prefix_len);
    write_u32(memory, address + 24, 0); // Flags
    Ok(())
}
