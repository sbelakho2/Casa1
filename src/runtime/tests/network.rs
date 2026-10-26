use super::support::*;
use super::*;

// ── WebSocket enum validation tests ─────────────────────────────────────
#[test]
fn test_websocket_buffer_type_rejects_invalid() {
    with_big_stack(|| {
        use crate::winhttp::WinHttpWebSocketBufferType;
        assert!(WinHttpWebSocketBufferType::try_from_u32(6).is_err());
        assert!(WinHttpWebSocketBufferType::try_from_u32(100).is_err());
        assert!(WinHttpWebSocketBufferType::try_from_u32(u32::MAX).is_err());
        let err = WinHttpWebSocketBufferType::try_from_u32(99).unwrap_err();
        assert_eq!(err.code, ReasonCode::RcInvalidGuestEnum);
    })
}

#[test]
fn test_websocket_close_status_rejects_invalid() {
    with_big_stack(|| {
        use crate::winhttp::WinHttpWebSocketCloseStatus;
        assert!(WinHttpWebSocketCloseStatus::try_from_u32(999).is_err());
        assert!(WinHttpWebSocketCloseStatus::try_from_u32(1004).is_err());
        assert!(WinHttpWebSocketCloseStatus::try_from_u32(1016).is_err());
        assert!(WinHttpWebSocketCloseStatus::try_from_u32(0).is_err());
        let err = WinHttpWebSocketCloseStatus::try_from_u32(999).unwrap_err();
        assert_eq!(err.code, ReasonCode::RcInvalidGuestEnum);
    })
}

#[test]
fn evidence_net_sys_winsock_socket_lifecycle() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("evidence-net-sys-winsock");
        let mut memory = MemoryImage::default();

        // WSAStartup first: the transport records require the Winsock
        // refcount like every guest does.
        let wsa_startup = runtime.alloc_host_thunk(HostThunk::WsaStartup);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, wsa_startup, &[0x0202, 0]),
            0
        );

        // WSASocketW with a WSAPROTOCOL_INFOW: the family comes from the
        // structure (iAddressFamily at offset 76), like WinSock.
        let wsa_socket_w = runtime.alloc_host_thunk(HostThunk::WsaSocketW);
        let proto_info = 0x62_000;
        memory.map_bytes(proto_info, &[0_u8; 626]);
        write_u32(&mut memory, proto_info + 76, 2);
        let listener = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            wsa_socket_w,
            &[0, 0, 0, proto_info as u32, 0, 0],
        );
        assert_ne!(listener, 0);
        assert_ne!(listener, u32::MAX as u64);

        // bind + listen transition the socket into the listening state.
        let bind = runtime.alloc_host_thunk(HostThunk::Bind);
        let sockaddr = 0x62_200;
        write_guest_sockaddr(
            &mut memory,
            sockaddr,
            &SockAddr {
                family: AddressFamily::Ipv4,
                host: "127.0.0.1".to_string(),
                port: 4321,
            },
        )
        .expect("write sockaddr");
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                bind,
                &[listener as u32, sockaddr as u32, 16]
            ),
            0
        );
        let listen = runtime.alloc_host_thunk(HostThunk::Listen);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, listen, &[listener as u32, 5]),
            0
        );

        // getsockopt(SO_ACCEPTCONN) reports the listening state.
        let getsockopt = runtime.alloc_host_thunk(HostThunk::Getsockopt);
        let optval = 0x62_300;
        let optlen = 0x62_310;
        memory.map_bytes(optval, &[0_u8; 4]);
        write_u32(&mut memory, optlen, 4);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                getsockopt,
                &[
                    listener as u32,
                    0xFFFF,
                    0x0002,
                    optval as u32,
                    optlen as u32
                ]
            ),
            0
        );
        assert_eq!(read_u32(&memory, optval).expect("acceptconn"), 1);

        // A second WSASocketW socket becomes the client: WSAConnect
        // carries caller data (sent right after the connect) and a
        // callee-data WSABUF that gets zeroed.
        let client =
            dispatch_x86_thunk(&mut runtime, &mut memory, wsa_socket_w, &[2, 1, 6, 0, 0, 0]);
        assert_ne!(client, 0);
        let wsa_connect = runtime.alloc_host_thunk(HostThunk::WsaConnect);
        let caller_data = 0x62_400;
        let payload = 0x62_500;
        memory.map_bytes(caller_data, &[0_u8; 8]);
        write_u32(&mut memory, caller_data, 4);
        write_u32(&mut memory, caller_data + 4, payload as u32);
        memory.map_bytes(payload, b"ping");
        let callee_data = 0x62_600;
        memory.map_bytes(callee_data, &[0_u8; 8]);
        write_u32(&mut memory, callee_data, 0xDEAD);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                wsa_connect,
                &[
                    client as u32,
                    sockaddr as u32,
                    16,
                    caller_data as u32,
                    callee_data as u32,
                    0,
                    0
                ]
            ),
            0
        );
        assert_eq!(read_u32(&memory, callee_data).expect("callee len"), 0);

        // WSAPoll reports the listener readable (pending accept).
        let wsa_poll = runtime.alloc_host_thunk(HostThunk::WsaPoll);
        let pollfd = 0x62_700;
        memory.map_bytes(pollfd, &[0_u8; 16]);
        write_u32(&mut memory, pollfd, listener as u32);
        write_u32(&mut memory, pollfd + 4, 0x0100); // POLLRDNORM
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, wsa_poll, &[pollfd as u32, 1, 0]),
            1
        );
        let revents = read_u16(&memory, pollfd + 6).expect("revents");
        assert_ne!(revents & 0x0100, 0, "pending accept reports POLLRDNORM");
        assert_ne!(revents & 0x0010, 0, "listening sockets are writable");

        // accept pops the pending connection and mints a win32-table
        // socket handle for the accepted side.
        let accept = runtime.alloc_host_thunk(HostThunk::Accept);
        let addr_out = 0x62_800;
        let addr_len = 0x62_900;
        memory.map_bytes(addr_out, &[0_u8; 16]);
        write_u32(&mut memory, addr_len, 16);
        let accepted = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            accept,
            &[listener as u32, addr_out as u32, addr_len as u32],
        );
        assert_ne!(accepted, 0);
        assert_ne!(accepted, u32::MAX as u64);

        // The connect-time caller data is in the accepted socket's
        // receive queue; the send/recv pair round-trips on both sides.
        let send = runtime.alloc_host_thunk(HostThunk::Send);
        let recv = runtime.alloc_host_thunk(HostThunk::Recv);
        let recv_buf = 0x62_A00;
        memory.map_bytes(recv_buf, &[0_u8; 16]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                send,
                &[client as u32, payload as u32, 4, 0]
            ),
            4
        );
        // The accepted socket's queue holds the WSAConnect caller data
        // plus this send: both 4-byte "ping" payloads.
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                recv,
                &[accepted as u32, recv_buf as u32, 16, 0]
            ),
            8
        );
        assert_eq!(
            read_guest_bytes(&memory, recv_buf, 8).expect("data"),
            b"pingping"
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                send,
                &[accepted as u32, payload as u32, 4, 0]
            ),
            4
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                recv,
                &[client as u32, recv_buf as u32, 16, 0]
            ),
            4
        );
        assert_eq!(
            read_guest_bytes(&memory, recv_buf, 4).expect("echo"),
            b"ping"
        );

        // getsockopt(SO_TYPE) on the accepted socket reports SOCK_STREAM.
        write_u32(&mut memory, optlen, 4);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                getsockopt,
                &[
                    accepted as u32,
                    0xFFFF,
                    0x1008,
                    optval as u32,
                    optlen as u32
                ]
            ),
            0
        );
        assert_eq!(read_u32(&memory, optval).expect("type"), 1);

        // WSAAccept (no condition callback) accepts a second pending
        // connection the same way `accept` does.
        let wsa_accept = runtime.alloc_host_thunk(HostThunk::WsaAccept);
        let second_client =
            dispatch_x86_thunk(&mut runtime, &mut memory, wsa_socket_w, &[2, 1, 6, 0, 0, 0]);
        assert_ne!(second_client, 0);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                wsa_connect,
                &[second_client as u32, sockaddr as u32, 16, 0, 0, 0, 0]
            ),
            0
        );
        let accepted2 = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            wsa_accept,
            &[listener as u32, addr_out as u32, addr_len as u32, 0, 0],
        );
        assert_ne!(accepted2, 0);
        assert_ne!(accepted2, u32::MAX as u64);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                send,
                &[second_client as u32, payload as u32, 4, 0]
            ),
            4
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                recv,
                &[accepted2 as u32, recv_buf as u32, 16, 0]
            ),
            4
        );
        assert_eq!(
            read_guest_bytes(&memory, recv_buf, 4).expect("data2"),
            b"ping"
        );

        // closesocket tears the accepted/client/listener sockets down.
        let closesocket = runtime.alloc_host_thunk(HostThunk::Closesocket);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, closesocket, &[accepted2 as u32]),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                closesocket,
                &[second_client as u32]
            ),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, closesocket, &[accepted as u32]),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, closesocket, &[client as u32]),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, closesocket, &[listener as u32]),
            0
        );
    })
}

#[test]
fn evidence_net_sys_winsock_dns_service_and_conversion_helpers() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("evidence-net-sys-winsock-dns");
        let mut memory = MemoryImage::default();
        let wsa_startup = runtime.alloc_host_thunk(HostThunk::WsaStartup);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, wsa_startup, &[0x0202, 0]),
            0
        );
        let socket_w = runtime.alloc_host_thunk(HostThunk::WsaSocketW);

        // gethostname reports the configured guest host name.
        let gethostname = runtime.alloc_host_thunk(HostThunk::Gethostname);
        let name_buf = 0x63_000;
        memory.map_bytes(name_buf, &[0_u8; 64]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                gethostname,
                &[name_buf as u32, 64]
            ),
            0
        );
        assert_eq!(read_c_string(&memory, name_buf).expect("hostname"), "CASA1");
        // Truncated buffer → WSAEFAULT.
        memory.map_bytes(name_buf, &[0_u8; 8]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                gethostname,
                &[name_buf as u32, 4]
            ),
            u32::MAX as u64
        );
        assert_eq!(runtime.network.wsa_get_last_error(), WSAEFAULT);

        // gethostbyname resolves from the guest DNS records.
        let gethostbyname = runtime.alloc_host_thunk(HostThunk::Gethostbyname);
        let host = runtime
            .alloc_c_string(&mut memory, "example.com")
            .expect("host name");
        let hostent = dispatch_x86_thunk(&mut runtime, &mut memory, gethostbyname, &[host as u32]);
        assert_ne!(hostent, 0);
        let h_name = read_guest_pointer(&memory, hostent, GuestArch::X86).expect("h_name");
        assert_eq!(read_c_string(&memory, h_name).expect("name"), "example.com");
        let h_length = read_u16(&memory, hostent + 10).expect("h_length");
        assert_eq!(h_length, 4);
        let addr_list =
            read_guest_pointer(&memory, hostent + 12, GuestArch::X86).expect("addr list");
        let addr_ptr = read_guest_pointer(&memory, addr_list, GuestArch::X86).expect("addr");
        assert_eq!(
            read_guest_bytes(&memory, addr_ptr, 4).expect("bytes"),
            [93, 184, 216, 34]
        );
        // gethostbyaddr reverses the address into the guest DNS name.
        let gethostbyaddr = runtime.alloc_host_thunk(HostThunk::Gethostbyaddr);
        let addr_bytes = 0x63_100;
        memory.map_bytes(addr_bytes, &[93, 184, 216, 34]);
        let hostent2 = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            gethostbyaddr,
            &[addr_bytes as u32, 4, 2],
        );
        assert_ne!(hostent2, 0);
        let h_name2 = read_guest_pointer(&memory, hostent2, GuestArch::X86).expect("h_name");
        assert_eq!(
            read_c_string(&memory, h_name2).expect("name"),
            "example.com"
        );
        // Unknown address (outside the guest DNS records) → the
        // numeric form is the fallback name, like Windows.
        memory.map_bytes(addr_bytes, &[192, 0, 2, 1]);
        let hostent3 = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            gethostbyaddr,
            &[addr_bytes as u32, 4, 2],
        );
        assert_ne!(hostent3, 0);
        let h_name3 = read_guest_pointer(&memory, hostent3, GuestArch::X86).expect("h_name");
        assert_eq!(read_c_string(&memory, h_name3).expect("name"), "192.0.2.1");
        // Unsupported family → NULL.
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                gethostbyaddr,
                &[addr_bytes as u32, 4, 99]
            ),
            0
        );

        // getnameinfo: reverse name + service from the guest databases.
        let getnameinfo = runtime.alloc_host_thunk(HostThunk::Getnameinfo);
        let sa = 0x63_200;
        write_guest_sockaddr(
            &mut memory,
            sa,
            &SockAddr {
                family: AddressFamily::Ipv4,
                host: "93.184.216.34".to_string(),
                port: 80,
            },
        )
        .expect("sockaddr");
        let host_out = 0x63_300;
        let serv_out = 0x63_400;
        memory.map_bytes(host_out, &[0_u8; 64]);
        memory.map_bytes(serv_out, &[0_u8; 64]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                getnameinfo,
                &[sa as u32, 16, host_out as u32, 64, serv_out as u32, 64, 0]
            ),
            0
        );
        assert_eq!(
            read_c_string(&memory, host_out).expect("host"),
            "example.com"
        );
        assert_eq!(read_c_string(&memory, serv_out).expect("serv"), "http");
        // NI_NUMERICHOST | NI_NUMERICSERV forces the numeric forms.
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                getnameinfo,
                &[
                    sa as u32,
                    16,
                    host_out as u32,
                    64,
                    serv_out as u32,
                    64,
                    0x02 | 0x08
                ]
            ),
            0
        );
        assert_eq!(
            read_c_string(&memory, host_out).expect("host"),
            "93.184.216.34"
        );
        assert_eq!(read_c_string(&memory, serv_out).expect("serv"), "80");

        // getprotobyname / getservbyname from the guest databases.
        let getprotobyname = runtime.alloc_host_thunk(HostThunk::Getprotobyname);
        let tcp = runtime.alloc_c_string(&mut memory, "tcp").expect("tcp");
        let protoent = dispatch_x86_thunk(&mut runtime, &mut memory, getprotobyname, &[tcp as u32]);
        assert_ne!(protoent, 0);
        let p_name = read_guest_pointer(&memory, protoent, GuestArch::X86).expect("p_name");
        assert_eq!(read_c_string(&memory, p_name).expect("name"), "tcp");
        assert_eq!(read_u16(&memory, protoent + 8).expect("p_proto"), 6);
        let getservbyname = runtime.alloc_host_thunk(HostThunk::Getservbyname);
        let http = runtime.alloc_c_string(&mut memory, "http").expect("http");
        let servent = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            getservbyname,
            &[http as u32, tcp as u32],
        );
        assert_ne!(servent, 0);
        assert_eq!(
            read_u16(&memory, servent + 8).expect("s_port"),
            80_u16.to_be()
        );
        let s_proto = read_guest_pointer(&memory, servent + 12, GuestArch::X86).expect("s_proto");
        assert_eq!(read_c_string(&memory, s_proto).expect("proto"), "tcp");

        // inet_addr / inet_ntoa conversions (network byte order).
        let inet_addr = runtime.alloc_host_thunk(HostThunk::InetAddr);
        let dotted = runtime
            .alloc_c_string(&mut memory, "1.2.3.4")
            .expect("dotted");
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, inet_addr, &[dotted as u32]),
            0x0403_0201
        );
        let bad = runtime
            .alloc_c_string(&mut memory, "not-an-ip")
            .expect("bad");
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, inet_addr, &[bad as u32]),
            u32::MAX as u64
        );
        let inet_ntoa = runtime.alloc_host_thunk(HostThunk::InetNtoa);
        let rendered = dispatch_x86_thunk(&mut runtime, &mut memory, inet_ntoa, &[0x0403_0201]);
        assert_ne!(rendered, 0);
        assert_eq!(read_c_string(&memory, rendered).expect("ntoa"), "1.2.3.4");

        // WSADuplicateSocketW fills the WSAPROTOCOL_INFOW.
        let socket = dispatch_x86_thunk(&mut runtime, &mut memory, socket_w, &[2, 1, 6, 0, 0, 0]);
        assert_ne!(socket, 0);
        let wsa_dup = runtime.alloc_host_thunk(HostThunk::WsaDuplicateSocketW);
        let info = 0x63_500;
        memory.map_bytes(info, &[0_u8; 626]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                wsa_dup,
                &[socket as u32, 42, info as u32]
            ),
            0
        );
        assert_eq!(read_u32(&memory, info + 76).expect("family"), 2);
        assert_eq!(read_u32(&memory, info + 88).expect("type"), 1);
        assert_eq!(read_u32(&memory, info + 92).expect("proto"), 6);
        assert_eq!(read_u32(&memory, info + 108).expect("msg size"), 0);
        let closesocket = runtime.alloc_host_thunk(HostThunk::Closesocket);
        dispatch_x86_thunk(&mut runtime, &mut memory, closesocket, &[socket as u32]);
    })
}

#[test]
fn evidence_net_sys_sspi_handshake_envelopes_and_message_protection() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("evidence-net-sys-sspi");
        let mut memory = MemoryImage::default();

        // Guest memory layout for the SecBufferDesc pairs.  The token
        // buffers are 0x400 bytes each, so every region is spaced apart
        // (a token buffer must never cover another fixed region).
        let client_desc = 0x64_000;
        let client_bufs = 0x64_100;
        let client_token = 0x64_200; // 0x400 bytes: ..0x64_600
        let server_desc = 0x64_600;
        let server_bufs = 0x64_700;
        let server_token = 0x64_800; // 0x400 bytes: ..0x64_C00
        let cred_client = 0x64_C00;
        let cred_server = 0x64_D00;
        let ctx_client = 0x64_E00;
        let ctx_server = 0x64_F00;
        let data_buf = 0x65_000;
        let data_buf2 = 0x65_100;
        let attrs = 0x65_200;
        let expiry = 0x65_300;
        let package_w = runtime
            .alloc_utf16_string(&mut memory, "NTLM")
            .expect("package");
        let target_w = runtime
            .alloc_utf16_string(&mut memory, "server")
            .expect("target");
        memory.map_bytes(client_desc, &[0_u8; 12]);
        write_u32(&mut memory, client_desc + 4, 1);
        write_u32(&mut memory, client_desc + 8, client_bufs as u32);
        memory.map_bytes(client_bufs, &[0_u8; 12]);
        write_u32(&mut memory, client_bufs, 0x400);
        write_u32(&mut memory, client_bufs + 4, crate::sspi::SECBUFFER_TOKEN);
        write_u32(&mut memory, client_bufs + 8, client_token as u32);
        memory.map_bytes(client_token, &[0_u8; 0x400]);
        memory.map_bytes(server_desc, &[0_u8; 12]);
        write_u32(&mut memory, server_desc + 4, 1);
        write_u32(&mut memory, server_desc + 8, server_bufs as u32);
        memory.map_bytes(server_bufs, &[0_u8; 12]);
        write_u32(&mut memory, server_bufs, 0x400);
        write_u32(&mut memory, server_bufs + 4, crate::sspi::SECBUFFER_TOKEN);
        write_u32(&mut memory, server_bufs + 8, server_token as u32);
        memory.map_bytes(server_token, &[0_u8; 0x400]);
        memory.map_bytes(cred_client, &[0_u8; 8]);
        memory.map_bytes(cred_server, &[0_u8; 8]);
        memory.map_bytes(ctx_client, &[0_u8; 8]);
        memory.map_bytes(ctx_server, &[0_u8; 8]);
        memory.map_bytes(attrs, &[0_u8; 4]);
        memory.map_bytes(expiry, &[0_u8; 8]);
        memory.map_bytes(data_buf, &[0_u8; 64]);
        memory.map_bytes(data_buf2, &[0_u8; 64]);

        // AcquireCredentialsHandleW on both sides.
        let acquire = runtime.alloc_host_thunk(HostThunk::AcquireCredentialsHandleW);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                acquire,
                &[
                    0,
                    package_w as u32,
                    1, // SECPKG_CRED_OUTBOUND
                    0,
                    0,
                    0,
                    0,
                    cred_client as u32,
                    expiry as u32
                ]
            ),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                acquire,
                &[
                    0,
                    package_w as u32,
                    2, // SECPKG_CRED_INBOUND
                    0,
                    0,
                    0,
                    0,
                    cred_server as u32,
                    expiry as u32
                ]
            ),
            0
        );
        assert_eq!(
            read_u64(&memory, cred_client).expect("cred handle") >> 32,
            0_u64
        );
        let _client_cred = read_u32(&memory, cred_client).expect("cred handle");

        // Client call 1: NEGOTIATE message, SEC_I_CONTINUE_NEEDED.
        let init_ctx = runtime.alloc_host_thunk(HostThunk::InitializeSecurityContextW);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                init_ctx,
                &[
                    cred_client as u32,
                    0,
                    target_w as u32,
                    0,
                    0,
                    0,
                    0,
                    0,
                    ctx_client as u32,
                    client_desc as u32,
                    attrs as u32,
                    expiry as u32
                ]
            ),
            crate::sspi::SEC_I_CONTINUE_NEEDED as u64
        );
        let token_len = read_u32(&memory, client_bufs).expect("token len");
        assert!(token_len > 0);
        let token1 = read_guest_bytes(&memory, client_token, token_len as usize).expect("token");
        assert_eq!(&token1[..8], b"NTLMSSP\x00");
        assert_eq!(&token1[8..12], &1_u32.to_le_bytes());

        // Server call 1: CHALLENGE message, SEC_I_CONTINUE_NEEDED.
        let accept_ctx = runtime.alloc_host_thunk(HostThunk::AcceptSecurityContext);
        memory.map_bytes(server_token, &[0_u8; 0x400]);
        write_u32(&mut memory, server_bufs, 0x400);
        memory.map_bytes(client_token, &token1);
        write_u32(&mut memory, client_bufs, token1.len() as u32);
        let server_cred = read_u32(&memory, cred_server).expect("cred handle");
        assert_ne!(server_cred, 0);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                accept_ctx,
                &[
                    cred_server as u32,
                    0,
                    client_desc as u32,
                    0,
                    0,
                    ctx_server as u32,
                    server_desc as u32,
                    attrs as u32
                ]
            ),
            crate::sspi::SEC_I_CONTINUE_NEEDED as u64
        );
        let token2_len = read_u32(&memory, server_bufs).expect("token len");
        let token2 = read_guest_bytes(&memory, server_token, token2_len as usize).expect("token");
        assert_eq!(&token2[8..12], &2_u32.to_le_bytes());

        // Client call 2: AUTHENTICATE message, SEC_E_OK.
        let client_ctx = read_u32(&memory, ctx_client).expect("client ctx");
        assert_ne!(client_ctx, 0);
        memory.map_bytes(client_token, &[0_u8; 0x400]);
        write_u32(&mut memory, client_bufs, 0x400);
        memory.map_bytes(server_token, &token2);
        write_u32(&mut memory, server_bufs, token2.len() as u32);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                init_ctx,
                &[
                    cred_client as u32,
                    ctx_client as u32,
                    target_w as u32,
                    0,
                    0,
                    0,
                    server_desc as u32,
                    0,
                    ctx_client as u32,
                    client_desc as u32,
                    attrs as u32,
                    expiry as u32
                ]
            ),
            crate::sspi::SEC_E_OK as u64
        );
        let token3_len = read_u32(&memory, client_bufs).expect("token len");
        let token3 = read_guest_bytes(&memory, client_token, token3_len as usize).expect("token");
        assert_eq!(&token3[8..12], &3_u32.to_le_bytes());

        // Server call 2: handshake completes, SEC_E_OK.
        let server_ctx = read_u32(&memory, ctx_server).expect("server ctx");
        assert_ne!(server_ctx, 0);
        memory.map_bytes(server_token, &[0_u8; 0x400]);
        write_u32(&mut memory, server_bufs, 0x400);
        memory.map_bytes(client_token, &token3);
        write_u32(&mut memory, client_bufs, token3.len() as u32);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                accept_ctx,
                &[
                    cred_server as u32,
                    ctx_server as u32,
                    client_desc as u32,
                    0,
                    0,
                    ctx_server as u32,
                    server_desc as u32,
                    attrs as u32
                ]
            ),
            crate::sspi::SEC_E_OK as u64
        );

        // QueryContextAttributesW: sizes, session key, names.
        let query = runtime.alloc_host_thunk(HostThunk::QueryContextAttributesW);
        let sizes = 0x65_400;
        memory.map_bytes(sizes, &[0_u8; 16]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                query,
                &[
                    ctx_client as u32,
                    crate::sspi::SECPKG_ATTR_SIZES,
                    sizes as u32
                ]
            ),
            0
        );
        assert_eq!(read_u32(&memory, sizes).expect("cbMaxToken"), 0x1_0000);
        assert_eq!(read_u32(&memory, sizes + 4).expect("cbMaxSignature"), 16);
        let key_buf = 0x65_500;
        memory.map_bytes(key_buf, &[0_u8; 36]);
        write_u32(&mut memory, key_buf, 32);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                query,
                &[
                    ctx_client as u32,
                    crate::sspi::SECPKG_ATTR_SESSION_KEY,
                    key_buf as u32
                ]
            ),
            0
        );
        assert_eq!(read_u32(&memory, key_buf).expect("key len"), 32);
        let key = read_guest_bytes(&memory, key_buf + 4, 32).expect("key");
        let names = 0x65_600;
        memory.map_bytes(names, &[0_u8; 4]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                query,
                &[
                    ctx_client as u32,
                    crate::sspi::SECPKG_ATTR_NAMES,
                    names as u32
                ]
            ),
            0
        );
        let name_ptr = read_u32(&memory, names).expect("name ptr");
        assert!(!read_guest_utf16_string(&memory, name_ptr as u64, 64).is_empty());

        // MakeSignature / VerifySignature over a message envelope.
        let sig_desc = 0x65_700;
        let sig_bufs = 0x65_800;
        let sig_token = 0x65_900;
        memory.map_bytes(sig_desc, &[0_u8; 12]);
        write_u32(&mut memory, sig_desc + 4, 2);
        write_u32(&mut memory, sig_desc + 8, sig_bufs as u32);
        memory.map_bytes(sig_bufs, &[0_u8; 24]);
        write_u32(&mut memory, sig_bufs, 16); // cbBuffer
        write_u32(&mut memory, sig_bufs + 4, crate::sspi::SECBUFFER_TOKEN);
        write_u32(&mut memory, sig_bufs + 8, sig_token as u32);
        memory.map_bytes(sig_token, &[0_u8; 16]);
        write_u32(&mut memory, sig_bufs + 12, 5); // data buffer
        write_u32(&mut memory, sig_bufs + 16, crate::sspi::SECBUFFER_DATA);
        write_u32(&mut memory, sig_bufs + 20, data_buf as u32);
        memory.map_bytes(data_buf, b"hello");
        let make_sig = runtime.alloc_host_thunk(HostThunk::MakeSignature);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                make_sig,
                &[ctx_client as u32, 0, sig_desc as u32, 0]
            ),
            0
        );
        assert_eq!(read_u32(&memory, sig_bufs).expect("sig len"), 16);
        let verify_sig = runtime.alloc_host_thunk(HostThunk::VerifySignature);
        // The peer (server context) verifies the client's signature.
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                verify_sig,
                &[ctx_server as u32, sig_desc as u32, 0, 0]
            ),
            0
        );
        // Tampering with the payload → SEC_E_MESSAGE_ALTERED (a fresh
        // signature over the original payload is verified against the
        // modified data — replaying the consumed envelope would
        // correctly report SEC_E_OUT_OF_SEQ instead).
        write_u32(&mut memory, sig_bufs, 16);
        memory.map_bytes(sig_token, &[0_u8; 16]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                make_sig,
                &[ctx_client as u32, 0, sig_desc as u32, 0]
            ),
            0
        );
        memory.map_bytes(data_buf, b"hella");
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                verify_sig,
                &[ctx_server as u32, sig_desc as u32, 0, 0]
            ),
            crate::sspi::SEC_E_MESSAGE_ALTERED as u64
        );

        // EncryptMessage / DecryptMessage round-trip (seal envelope).
        memory.map_bytes(data_buf, b"hello");
        write_u32(&mut memory, sig_bufs, 16);
        memory.map_bytes(sig_token, &[0_u8; 16]);
        let encrypt = runtime.alloc_host_thunk(HostThunk::EncryptMessage);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                encrypt,
                &[ctx_client as u32, 0, sig_desc as u32, 0]
            ),
            0
        );
        let ciphertext = read_guest_bytes(&memory, data_buf, 5).expect("ciphertext");
        assert_ne!(ciphertext, b"hello");
        let decrypt = runtime.alloc_host_thunk(HostThunk::DecryptMessage);
        let qop = 0x65_A00;
        memory.map_bytes(qop, &[0_u8; 4]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                decrypt,
                &[ctx_server as u32, sig_desc as u32, 0, qop as u32]
            ),
            0
        );
        assert_eq!(
            read_guest_bytes(&memory, data_buf, 5).expect("plaintext"),
            b"hello"
        );

        // CompleteAuthToken / Impersonate / Revert / Delete / Free.
        let complete = runtime.alloc_host_thunk(HostThunk::CompleteAuthToken);
        write_u32(&mut memory, client_bufs, 1);
        memory.map_bytes(client_token, &token3);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                complete,
                &[ctx_client as u32, client_desc as u32]
            ),
            0
        );
        let impersonate = runtime.alloc_host_thunk(HostThunk::ImpersonateSecurityContext);
        let revert = runtime.alloc_host_thunk(HostThunk::RevertSecurityContext);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, impersonate, &[ctx_client as u32]),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, revert, &[ctx_client as u32]),
            0
        );
        let delete = runtime.alloc_host_thunk(HostThunk::DeleteSecurityContext);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, delete, &[ctx_client as u32]),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, delete, &[ctx_server as u32]),
            0
        );
        let free_cred = runtime.alloc_host_thunk(HostThunk::FreeCredentialsHandle);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, free_cred, &[cred_client as u32]),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, free_cred, &[cred_server as u32]),
            0
        );
        // Deleting a stale context → SEC_E_INVALID_HANDLE.
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, delete, &[ctx_client as u32]),
            crate::sspi::SEC_E_INVALID_HANDLE as u64
        );

        // EnumerateSecurityPackagesW: NTLM + Negotiate.
        let enumerate = runtime.alloc_host_thunk(HostThunk::EnumerateSecurityPackagesW);
        let pkg_count = 0x65_B00;
        let pkg_info = 0x65_C00;
        memory.map_bytes(pkg_count, &[0_u8; 4]);
        memory.map_bytes(pkg_info, &[0_u8; 4]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                enumerate,
                &[pkg_count as u32, pkg_info as u32]
            ),
            0
        );
        assert_eq!(read_u32(&memory, pkg_count).expect("count"), 2);

        // GetUserNameExW derives from the guest environment.
        let get_user_ex = runtime.alloc_host_thunk(HostThunk::GetUserNameExW);
        let user_out = 0x65_D00;
        let user_len = 0x65_E00;
        memory.map_bytes(user_out, &[0_u8; 64]);
        write_u32(&mut memory, user_len, 64);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_user_ex,
                &[2, user_out as u32, user_len as u32]
            ),
            1
        );
        assert_eq!(
            read_guest_utf16_string(&memory, user_out, 64),
            format!("WORKGROUP\\{}", runtime.win32.ge().config.user_name)
        );

        // The client/server session keys agree (documented PRF).
        assert_eq!(key.len(), 32);
        let _ = key;
    })
}

#[test]
fn evidence_net_sys_iphlpapi_tables_from_guest_config() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("evidence-net-sys-iphlpapi");
        let mut memory = MemoryImage::default();

        // GetAdaptersInfo: the size query reports 688 (x86), then the
        // chain is filled from the guest config.
        let get_adapters_info = runtime.alloc_host_thunk(HostThunk::GetAdaptersInfo);
        let len_slot = 0x66_000;
        memory.map_bytes(len_slot, &[0_u8; 4]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_adapters_info,
                &[0, len_slot as u32]
            ),
            ERROR_BUFFER_OVERFLOW as u64
        );
        assert_eq!(read_u32(&memory, len_slot).expect("required"), 688 * 2);
        let info_buf = 0x66_100;
        memory.map_bytes(info_buf, &[0_u8; 688 * 2]);
        write_u32(&mut memory, len_slot, 688 * 2);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_adapters_info,
                &[info_buf as u32, len_slot as u32]
            ),
            NO_ERROR as u64
        );
        assert_eq!(read_u32(&memory, len_slot).expect("used"), 688 * 2);
        // Loopback adapter (first entry).
        let adapter_name = read_c_string(&memory, info_buf + 8).expect("name");
        assert!(adapter_name.contains("CASA1-0000-0000-0000-000000000001"));
        assert_eq!(read_u32(&memory, info_buf + 412).expect("index"), 1);
        assert_eq!(read_u32(&memory, info_buf + 416).expect("type"), 24);
        // Ethernet adapter (second entry): 10.0.2.15/24, gateway.
        let eth = info_buf + 688;
        let ip_list = eth + 464;
        let ip_addr = read_c_string(&memory, ip_list + 4).expect("ip");
        assert_eq!(ip_addr, "10.0.2.15");
        let ip_mask = read_c_string(&memory, ip_list + 20).expect("mask");
        assert_eq!(ip_mask, "255.255.255.0");
        let gateway_list = eth + 504;
        let gateway = read_c_string(&memory, gateway_list + 4).expect("gateway");
        assert_eq!(gateway, "10.0.2.2");
        assert_eq!(read_u32(&memory, eth + 412).expect("index"), 2);
        assert_eq!(read_u32(&memory, eth + 416).expect("type"), 6);

        // GetAdaptersAddresses: size query + unicast/dns/gateway chains.
        let get_addresses = runtime.alloc_host_thunk(HostThunk::GetAdaptersAddresses);
        memory.map_bytes(len_slot, &[0_u8; 4]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_addresses,
                &[0, 0, 0, 0, len_slot as u32]
            ),
            ERROR_BUFFER_OVERFLOW as u64
        );
        assert_eq!(read_u32(&memory, len_slot).expect("required"), 344 * 2);
        let addr_buf = 0x66_500;
        memory.map_bytes(addr_buf, &[0_u8; 344 * 2]);
        write_u32(&mut memory, len_slot, 344 * 2);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_addresses,
                &[0, 0, 0, addr_buf as u32, len_slot as u32]
            ),
            NO_ERROR as u64
        );
        let eth_addr = addr_buf + 344;
        assert_eq!(read_u32(&memory, eth_addr).expect("length"), 344);
        assert_eq!(read_u32(&memory, eth_addr + 4).expect("ifindex"), 2);
        assert_eq!(read_u32(&memory, eth_addr + 64).expect("iftype"), 6);
        let unicast = read_u32(&memory, eth_addr + 16).expect("unicast head");
        assert_ne!(unicast, 0);
        let sockaddr_ptr = read_u32(&memory, unicast as u64 + 16).expect("sockaddr");
        let family = read_u16(&memory, sockaddr_ptr as u64).expect("family");
        assert_eq!(family, 2);
        assert_eq!(
            read_u32(&memory, u64::from(sockaddr_ptr) + 4).expect("addr"),
            u32::from_ne_bytes([10, 0, 2, 15])
        );
        assert_eq!(
            read_u32(&memory, eth_addr + 56).expect("flags") & IP_ADAPTER_IPV4_ENABLED,
            IP_ADAPTER_IPV4_ENABLED
        );
        let gateway_head = read_u32(&memory, eth_addr + 164).expect("gateway head");
        assert_ne!(gateway_head, 0);
        let gw_sockaddr = read_u32(&memory, u64::from(gateway_head) + 16).expect("gw sockaddr");
        assert_eq!(
            read_u32(&memory, gw_sockaddr as u64 + 4).expect("gw addr"),
            u32::from_ne_bytes([10, 0, 2, 2])
        );

        // GetIfTable: 2 rows from the guest adapters.
        let get_if_table = runtime.alloc_host_thunk(HostThunk::GetIfTable);
        let size_slot = 0x66_600;
        memory.map_bytes(size_slot, &[0_u8; 4]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_if_table,
                &[0, size_slot as u32]
            ),
            ERROR_INSUFFICIENT_BUFFER as u64
        );
        assert_eq!(read_u32(&memory, size_slot).expect("required"), 4 + 860 * 2);
        let table = 0x66_700;
        memory.map_bytes(table, &[0_u8; 4 + 860 * 2]);
        write_u32(&mut memory, size_slot, 4 + 860 * 2);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_if_table,
                &[table as u32, size_slot as u32]
            ),
            NO_ERROR as u64
        );
        assert_eq!(read_u32(&memory, table).expect("entries"), 2);
        assert_eq!(read_u32(&memory, table + 4 + 512).expect("idx0"), 1);
        assert_eq!(read_u32(&memory, table + 4 + 516).expect("type0"), 24);
        assert_eq!(read_u32(&memory, table + 4 + 860 + 512).expect("idx1"), 2);
        assert_eq!(
            read_u32(&memory, table + 4 + 860 + 520).expect("mtu1"),
            1500
        );

        // GetIfEntry fills the requested row by index.
        let get_if_entry = runtime.alloc_host_thunk(HostThunk::GetIfEntry);
        let row = 0x66_900;
        memory.map_bytes(row, &[0_u8; 860]);
        write_u32(&mut memory, row + 512, 2);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, get_if_entry, &[row as u32]),
            NO_ERROR as u64
        );
        assert_eq!(read_u32(&memory, row + 516).expect("type"), 6);
        assert_eq!(read_u32(&memory, row + 520).expect("mtu"), 1500);

        // GetIpAddrTable: one row per IPv4 adapter.
        let get_ip_addr_table = runtime.alloc_host_thunk(HostThunk::GetIpAddrTable);
        memory.map_bytes(size_slot, &[0_u8; 4]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_ip_addr_table,
                &[0, size_slot as u32]
            ),
            ERROR_INSUFFICIENT_BUFFER as u64
        );
        assert_eq!(read_u32(&memory, size_slot).expect("required"), 4 + 20 * 2);
        let ip_table = 0x66_A00;
        memory.map_bytes(ip_table, &[0_u8; 4 + 20 * 2]);
        write_u32(&mut memory, size_slot, 4 + 20 * 2);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_ip_addr_table,
                &[ip_table as u32, size_slot as u32]
            ),
            NO_ERROR as u64
        );
        assert_eq!(read_u32(&memory, ip_table).expect("entries"), 2);
        assert_eq!(
            read_u32(&memory, ip_table + 4).expect("addr0"),
            u32::from_ne_bytes([127, 0, 0, 1])
        );
        assert_eq!(
            read_u32(&memory, ip_table + 24).expect("addr1"),
            u32::from_ne_bytes([10, 0, 2, 15])
        );
        assert_eq!(read_u32(&memory, ip_table + 28).expect("idx1"), 2);

        // GetIpForwardTable: the three guest routes.
        let get_forward = runtime.alloc_host_thunk(HostThunk::GetIpForwardTable);
        memory.map_bytes(size_slot, &[0_u8; 4]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_forward,
                &[0, size_slot as u32]
            ),
            ERROR_INSUFFICIENT_BUFFER as u64
        );
        assert_eq!(read_u32(&memory, size_slot).expect("required"), 4 + 44 * 3);
        let fwd = 0x66_B00;
        memory.map_bytes(fwd, &[0_u8; 4 + 44 * 3]);
        write_u32(&mut memory, size_slot, 4 + 44 * 3);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_forward,
                &[fwd as u32, size_slot as u32]
            ),
            NO_ERROR as u64
        );
        assert_eq!(read_u32(&memory, fwd).expect("entries"), 3);
        // Default route row (dest 0.0.0.0, via 10.0.2.2, ifIndex 2).
        assert_eq!(read_u32(&memory, fwd + 4 + 88).expect("dest"), 0);
        assert_eq!(
            read_u32(&memory, fwd + 4 + 100).expect("nh"),
            u32::from_ne_bytes([10, 0, 2, 2])
        );
        assert_eq!(read_u32(&memory, fwd + 4 + 104).expect("ifidx"), 2);

        // GetNetworkParams: host/domain/DNS from the guest config.
        let get_params = runtime.alloc_host_thunk(HostThunk::GetNetworkParams);
        memory.map_bytes(len_slot, &[0_u8; 4]);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, get_params, &[0, len_slot as u32]),
            ERROR_BUFFER_OVERFLOW as u64
        );
        assert_eq!(read_u32(&memory, len_slot).expect("required"), 592);
        let fixed = 0x66_C00;
        memory.map_bytes(fixed, &[0_u8; 592]);
        write_u32(&mut memory, len_slot, 592);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_params,
                &[fixed as u32, len_slot as u32]
            ),
            NO_ERROR as u64
        );
        assert_eq!(read_c_string(&memory, fixed).expect("host"), "CASA1");
        assert_eq!(
            read_c_string(&memory, fixed + 132).expect("domain"),
            "WORKGROUP"
        );
        let dns_server = read_c_string(&memory, fixed + 276).expect("dns");
        assert_eq!(dns_server, "10.0.2.3");

        // GetBestInterface / GetBestRoute use the guest route table.
        let best_iface = runtime.alloc_host_thunk(HostThunk::GetBestInterface);
        let best_idx = 0x66_D00;
        memory.map_bytes(best_idx, &[0_u8; 4]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                best_iface,
                &[u32::from_ne_bytes([127, 0, 0, 1]), best_idx as u32]
            ),
            NO_ERROR as u64
        );
        assert_eq!(read_u32(&memory, best_idx).expect("idx"), 1);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                best_iface,
                &[u32::from_ne_bytes([8, 8, 8, 8]), best_idx as u32]
            ),
            NO_ERROR as u64
        );
        assert_eq!(read_u32(&memory, best_idx).expect("idx"), 2);
        let best_route = runtime.alloc_host_thunk(HostThunk::GetBestRoute);
        let route_out = 0x66_E00;
        memory.map_bytes(route_out, &[0_u8; 44]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                best_route,
                &[u32::from_ne_bytes([10, 0, 2, 15]), 0, route_out as u32]
            ),
            NO_ERROR as u64
        );
        assert_eq!(
            read_u32(&memory, route_out).expect("dest"),
            u32::from_ne_bytes([10, 0, 2, 0])
        );
        assert_eq!(
            read_u32(&memory, route_out + 4).expect("mask"),
            u32::from_ne_bytes([255, 255, 255, 0])
        );
        assert_eq!(read_u32(&memory, route_out + 16).expect("ifidx"), 2);

        // GetRTTAndHopCount: local = 1 hop, routed = 2 hops.
        let rtt = runtime.alloc_host_thunk(HostThunk::GetRTTAndHopCount);
        let hops = 0x66_F00;
        let rtt_out = 0x66_F10;
        memory.map_bytes(hops, &[0_u8; 4]);
        memory.map_bytes(rtt_out, &[0_u8; 4]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                rtt,
                &[
                    u32::from_ne_bytes([127, 0, 0, 1]),
                    hops as u32,
                    30,
                    rtt_out as u32
                ]
            ),
            NO_ERROR as u64
        );
        assert_eq!(read_u32(&memory, hops).expect("hops"), 1);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                rtt,
                &[
                    u32::from_ne_bytes([93, 184, 216, 34]),
                    hops as u32,
                    30,
                    rtt_out as u32
                ]
            ),
            NO_ERROR as u64
        );
        assert_eq!(read_u32(&memory, hops).expect("hops"), 2);

        // NotifyAddrChange / NotifyRouteChange: pending semantics +
        // CancelMibChangeNotify2 cancels the registration.
        let notify_addr = runtime.alloc_host_thunk(HostThunk::NotifyAddrChange);
        let notify_route = runtime.alloc_host_thunk(HostThunk::NotifyRouteChange);
        let cancel = runtime.alloc_host_thunk(HostThunk::CancelMibChangeNotify2);
        let notify_handle = 0x66_F20;
        memory.map_bytes(notify_handle, &[0_u8; 4]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                notify_addr,
                &[0, notify_handle as u32]
            ),
            ERROR_IO_PENDING as u64
        );
        let addr_handle = read_u32(&memory, notify_handle).expect("addr handle");
        assert_ne!(addr_handle, 0);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                notify_route,
                &[0, notify_handle as u32]
            ),
            ERROR_IO_PENDING as u64
        );
        let route_handle = read_u32(&memory, notify_handle).expect("route handle");
        assert_ne!(route_handle, 0);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, cancel, &[addr_handle]),
            NO_ERROR as u64
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, cancel, &[route_handle]),
            NO_ERROR as u64
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, cancel, &[addr_handle]),
            ERROR_INVALID_PARAMETER as u64
        );
    })
}

#[test]
fn evidence_net_sys_netapi32_workstation_and_user_info() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("evidence-net-sys-netapi32");
        let mut memory = MemoryImage::default();

        // NetWkstaGetInfo(level 100) fills WKSTA_INFO_100 from the guest
        // environment: platform id, computer name, workgroup, version.
        let wksta = runtime.alloc_host_thunk(HostThunk::NetWkstaGetInfo);
        let bufptr = 0x67_000;
        memory.map_bytes(bufptr, &[0_u8; 4]);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, wksta, &[0, 100, bufptr as u32]),
            0
        );
        let info = read_u32(&memory, bufptr).expect("info ptr");
        assert_eq!(read_u32(&memory, info as u64).expect("platform"), 400);
        let computer = read_u32(&memory, info as u64 + 4).expect("computer");
        assert_eq!(
            read_guest_utf16_string(&memory, computer as u64, 64),
            "CASA1"
        );
        let langroup = read_u32(&memory, info as u64 + 8).expect("langroup");
        assert_eq!(
            read_guest_utf16_string(&memory, langroup as u64, 64),
            "WORKGROUP"
        );
        assert_eq!(read_u32(&memory, info as u64 + 12).expect("major"), 10);
        assert_eq!(read_u32(&memory, info as u64 + 16).expect("minor"), 0);
        // The returned buffer is freed through NetApiBufferFree.
        let free = runtime.alloc_host_thunk(HostThunk::NetApiBufferFree);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, free, &[info as u32]),
            0
        );
        // Freeing it twice → ERROR_INVALID_PARAMETER.
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, free, &[info as u32]),
            ERROR_INVALID_PARAMETER as u64
        );

        // NetWkstaGetInfo(level 101) adds the lanroot and user counts.
        memory.map_bytes(bufptr, &[0_u8; 4]);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, wksta, &[0, 101, bufptr as u32]),
            0
        );
        let info101 = read_u32(&memory, bufptr).expect("info ptr");
        let lanroot = read_u32(&memory, info101 as u64 + 20).expect("lanroot");
        assert_eq!(
            read_guest_utf16_string(&memory, lanroot as u64, 64),
            "C:\\WINDOWS"
        );
        assert_eq!(
            read_u32(&memory, info101 as u64 + 24).expect("logged on"),
            1
        );
        // Unsupported level → ERROR_INVALID_LEVEL.
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, wksta, &[0, 999, bufptr as u32]),
            ERROR_INVALID_LEVEL as u64
        );

        // NetUserGetInfo(level 1) fills USER_INFO_1 for the guest user.
        let user_info = runtime.alloc_host_thunk(HostThunk::NetUserGetInfo);
        let user_w = runtime
            .alloc_utf16_string(&mut memory, "casa1")
            .expect("user");
        memory.map_bytes(bufptr, &[0_u8; 4]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                user_info,
                &[0, user_w as u32, 1, bufptr as u32]
            ),
            0
        );
        let info1 = read_u32(&memory, bufptr).expect("info ptr");
        let name = read_u32(&memory, info1 as u64).expect("name");
        assert_eq!(read_guest_utf16_string(&memory, name as u64, 64), "casa1");
        assert_eq!(read_u32(&memory, info1 as u64 + 12).expect("priv"), 1);
        assert_eq!(read_u32(&memory, info1 as u64 + 24).expect("flags"), 0x0200);
        let home = read_u32(&memory, info1 as u64 + 16).expect("home");
        assert_eq!(
            read_guest_utf16_string(&memory, home as u64, 128),
            "C:\\Users\\casa1"
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, free, &[info1 as u32]),
            0
        );
        // Unknown user → NERR_UserNotFound.
        let other_w = runtime
            .alloc_utf16_string(&mut memory, "administrator")
            .expect("other");
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                user_info,
                &[0, other_w as u32, 1, bufptr as u32]
            ),
            NERR_UserNotFound as u64
        );
        // Unsupported level → ERROR_INVALID_LEVEL.
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                user_info,
                &[0, user_w as u32, 9, bufptr as u32]
            ),
            ERROR_INVALID_LEVEL as u64
        );

        // NetServerEnum: the empty guest server list terminates with
        // ERROR_NO_MORE_ITEMS and a correctly-filled empty structure.
        let server_enum = runtime.alloc_host_thunk(HostThunk::NetServerEnum);
        let entries_read = 0x67_100;
        let total_entries = 0x67_200;
        memory.map_bytes(entries_read, &[0_u8; 4]);
        memory.map_bytes(total_entries, &[0_u8; 4]);
        memory.map_bytes(bufptr, &[0_u8; 4]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                server_enum,
                &[
                    0,
                    1,
                    bufptr as u32,
                    0x1000,
                    entries_read as u32,
                    total_entries as u32,
                    0
                ]
            ),
            ERROR_NO_MORE_ITEMS as u64
        );
        assert_eq!(read_u32(&memory, entries_read).expect("read"), 0);
        assert_eq!(read_u32(&memory, total_entries).expect("total"), 0);
        assert_eq!(read_u32(&memory, bufptr).expect("bufptr"), 0);
        // Unsupported level → ERROR_INVALID_LEVEL.
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                server_enum,
                &[
                    0,
                    2,
                    bufptr as u32,
                    0x1000,
                    entries_read as u32,
                    total_entries as u32,
                    0
                ]
            ),
            ERROR_INVALID_LEVEL as u64
        );
    })
}

#[test]
fn winhttp_thunk_headers_write_credentials_and_proxy() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "winhttp-thunks",
            GeArch::X86,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();

        let open = runtime.alloc_host_thunk(HostThunk::WinHttpOpen);
        let connect = runtime.alloc_host_thunk(HostThunk::WinHttpConnect);
        let open_request = runtime.alloc_host_thunk(HostThunk::WinHttpOpenRequest);
        let add_headers = runtime.alloc_host_thunk(HostThunk::WinHttpAddRequestHeaders);
        let write_data = runtime.alloc_host_thunk(HostThunk::WinHttpWriteData);
        let set_credentials = runtime.alloc_host_thunk(HostThunk::WinHttpSetCredentials);
        let close = runtime.alloc_host_thunk(HostThunk::WinHttpCloseHandle);

        let agent = runtime
            .alloc_utf16_string(&mut memory, "Casa1 Test")
            .expect("agent");
        let session = dispatch_x86_thunk(&mut runtime, &mut memory, open, &[agent as u32, 0, 0, 0]);
        assert_ne!(session, 0);

        let server = runtime
            .alloc_utf16_string(&mut memory, "api.example.com")
            .expect("server");
        let connection = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            connect,
            &[session as u32, server as u32, 443, 0],
        );
        assert_ne!(connection, 0);

        let verb = runtime
            .alloc_utf16_string(&mut memory, "POST")
            .expect("verb");
        let path = runtime
            .alloc_utf16_string(&mut memory, "/login")
            .expect("path");
        let request = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            open_request,
            &[connection as u32, verb as u32, path as u32, 0, 0, 0, 0],
        );
        assert_ne!(request, 0);

        // WinHttpAddRequestHeaders accepts an extra header (TRUE).
        let headers = runtime
            .alloc_c_string(&mut memory, "X-Casa1: 1")
            .expect("headers");
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                add_headers,
                &[request as u32, headers as u32, 11, 0],
            ),
            1
        );
        // An invalid request handle fails with ERROR_INVALID_HANDLE.
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                add_headers,
                &[0xDEAD, headers as u32, 11, 0],
            ),
            0
        );
        assert_eq!(runtime.last_error, ERROR_INVALID_HANDLE);

        // WinHttpWriteData reports the bytes written.
        let payload = 0x64_000;
        memory.map_bytes(payload, b"payload");
        let written = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            write_data,
            &[request as u32, payload as u32, 7],
        );
        assert_eq!(written, 7);

        // WinHttpSetCredentials stores the credential on the request.
        let user = runtime
            .alloc_utf16_string(&mut memory, "user")
            .expect("user");
        let pass = runtime
            .alloc_utf16_string(&mut memory, "pass")
            .expect("pass");
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                set_credentials,
                &[request as u32, 0, 1, user as u32, pass as u32],
            ),
            1
        );

        // WinHttpCloseHandle releases session/connection/request.
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, close, &[request as u32]),
            1
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, close, &[connection as u32]),
            1
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, close, &[session as u32]),
            1
        );

        // WinHttpGetIEProxyConfigForCurrentUser fills INTERNET_PROXY_INFO.
        let proxy_info = 0x61_000;
        memory.map_bytes(proxy_info, &[0_u8; 32]);
        let ie_proxy = runtime.alloc_host_thunk(HostThunk::WinHttpGetIEProxyConfigForCurrentUser);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, ie_proxy, &[proxy_info as u32]),
            1
        );
        assert_eq!(read_u32(&memory, proxy_info).expect("fAutoDetect"), 1);
        assert_eq!(
            read_guest_pointer(&memory, proxy_info + 8, GuestArch::X86).expect("auto url"),
            0
        );

        // WinHttpGetProxyForUrl honors the explicit env proxy (TRUE) and
        // reports FALSE when no proxy is configured.
        let get_proxy = runtime.alloc_host_thunk(HostThunk::WinHttpGetProxyForUrl);
        let url = runtime
            .alloc_utf16_string(&mut memory, "https://api.example.com/login")
            .expect("url");
        unsafe {
            std::env::set_var("https_proxy", "http://explicit.proxy:9000");
        }
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_proxy,
                &[session as u32, url as u32, 0, 0],
            ),
            1
        );
        unsafe {
            std::env::remove_var("https_proxy");
        }
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_proxy,
                &[session as u32, url as u32, 0, 0],
            ),
            0
        );
    })
}

// -- wininet dispatch -----------------------------------------------------
#[test]
fn wininet_ftp_failure_domain_dispatch() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge =
            GameEnvironment::create_in(temp_dir.path(), "wininet-ftp", GeArch::X86, "win11-23h2")
                .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();

        let file = runtime
            .alloc_utf16_string(&mut memory, "file.bin")
            .expect("file name");

        // No control connection exists for the bogus handle, so every FTP
        // operation reports its documented failure domain.
        let open_file = runtime.alloc_host_thunk(HostThunk::FtpOpenFileW);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                open_file,
                &[0x1234, file as u32, 0, 0]
            ),
            0,
            "FtpOpenFileW fails without a control connection"
        );

        let get_file = runtime.alloc_host_thunk(HostThunk::FtpGetFileW);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_file,
                &[0x1234, file as u32, 0, 0, 0]
            ),
            0,
            "FtpGetFileW fails without a control connection"
        );
        assert_eq!(
            runtime.last_error, 12003,
            "ERROR_INTERNET_OPERATION_CANCELLED"
        );

        let put_file = runtime.alloc_host_thunk(HostThunk::FtpPutFileW);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                put_file,
                &[0x1234, 0, file as u32, 0]
            ),
            0,
            "FtpPutFileW fails without a control connection"
        );
        assert_eq!(
            runtime.last_error, 12003,
            "ERROR_INTERNET_OPERATION_CANCELLED"
        );

        let find_first = runtime.alloc_host_thunk(HostThunk::FtpFindFirstFileW);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                find_first,
                &[0x1234, file as u32, 0, 0]
            ),
            0,
            "FtpFindFirstFileW fails without a control connection"
        );
        assert_eq!(runtime.last_error, 12018, "ERROR_INTERNET_NO_FILES");
    })
}

#[test]
fn urlmon_bind_ctx_moniker_and_status_callback_dispatch() {
    with_big_stack(|| {
        let (mut runtime, _temp) = test_runtime("urlmon");
        let mut memory = MemoryImage::default();
        let create_moniker = runtime.alloc_host_thunk(HostThunk::CreateURLMoniker);
        let create_bind_ctx = runtime.alloc_host_thunk(HostThunk::CreateAsyncBindCtx);
        let register_callback = runtime.alloc_host_thunk(HostThunk::RegisterBindStatusCallback);

        // CreateURLMoniker returns a real guest IMoniker object whose
        // GetDisplayName round-trips the URL.
        let url_ptr = runtime
            .alloc_utf16_string(&mut memory, "http://example.com/game")
            .expect("url");
        let moniker_out = 0x41_000;
        let display_out = 0x41_020;
        memory.map_bytes(moniker_out as u64, &[0; 8]);
        memory.map_bytes(display_out as u64, &[0; 8]);
        let result = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_moniker,
            &[0, url_ptr as u32, moniker_out],
        );
        assert_eq!(result, 0);
        let moniker_addr = memory.read_u64(moniker_out as u64).expect("moniker out");
        assert_ne!(moniker_addr, 0, "a moniker object must be produced");
        let vtable = memory.read_u64(moniker_addr).expect("moniker vtable");
        assert_ne!(vtable, 0, "the moniker must have a real vtable");
        let display = runtime.alloc_host_thunk(HostThunk::MonikerGetDisplayName);
        let result = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            display,
            &[moniker_addr as u32, 0, 0, display_out as u32],
        );
        assert_eq!(result, 0);
        let name = memory.read_u64(display_out).expect("display out");
        assert_eq!(
            read_utf16_string(&memory, name).expect("moniker url"),
            "http://example.com/game"
        );
        // A NULL moniker out pointer fails with E_INVALIDARG.
        let result = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_moniker,
            &[0, url_ptr as u32, 0],
        );
        assert_eq!(result, 0x8007_0057);
        assert_eq!(runtime.last_error, ERROR_INVALID_PARAMETER);
        // An empty URL is a syntax error and writes a NULL moniker.
        let empty_ptr = runtime
            .alloc_utf16_string(&mut memory, "")
            .expect("empty url");
        memory.map_bytes(moniker_out as u64, &[0; 8]);
        let result = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_moniker,
            &[0, empty_ptr as u32, moniker_out],
        );
        assert_eq!(result, 0x8004_01E4);
        assert_eq!(memory.read_u64(moniker_out as u64).expect("moniker out"), 0);

        // CreateAsyncBindCtx writes a bind-context record into the out slot.
        let bind_ctx_out = 0x41_010;
        memory.map_bytes(bind_ctx_out as u64, &[0; 4]);
        let result = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_bind_ctx,
            &[0, 0, 0, bind_ctx_out],
        );
        assert_eq!(result, 0);
        let bind_ctx = memory.read_u32(bind_ctx_out as u64).expect("bind ctx out") as u64;
        assert_ne!(bind_ctx, 0, "an async bind context must be produced");
        assert_eq!(
            read_utf16_string(&memory, bind_ctx).expect("bind ctx tag"),
            "AsyncBindCtx"
        );
        // A NULL bind-ctx out pointer fails with E_INVALIDARG.
        let result = dispatch_x86_thunk(&mut runtime, &mut memory, create_bind_ctx, &[0, 0, 0, 0]);
        assert_eq!(result, 0x8007_0057);
        assert_eq!(runtime.last_error, ERROR_INVALID_PARAMETER);

        // RegisterBindStatusCallback accepts the bind context and returns S_OK.
        let result = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            register_callback,
            &[bind_ctx as u32, 0, 0, 0],
        );
        assert_eq!(result, 0);
        assert_eq!(runtime.last_error, 0);
    })
}

#[test]
fn evidence_ldap_http_pdh_evt_wlan_surfaces() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("evidence-svc");
        let mut memory = MemoryImage::default();

        // ── wldap32 ──
        let ldap_init: u64 = runtime.alloc_host_thunk(HostThunk::LdapInit);
        let ldap_search_s: u64 = runtime.alloc_host_thunk(HostThunk::LdapSearchS);
        let ldap_count: u64 = runtime.alloc_host_thunk(HostThunk::LdapCountEntries);
        let ldap_unbind: u64 = runtime.alloc_host_thunk(HostThunk::LdapUnbind);
        let host_ptr = 0x41_000_u64;
        let host_wide: Vec<u16> = "localhost".encode_utf16().chain([0]).collect();
        for (i, unit) in host_wide.iter().enumerate() {
            write_guest_u16(&mut memory, host_ptr + (i as u64 * 2), *unit).ok();
        }
        let session = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            ldap_init,
            &[host_ptr as u32, 389],
        );
        assert_ne!(session, 0);
        let msg_out = 0x41_100_u64;
        let message = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            ldap_search_s,
            &[session as u32, 0, 2, 0, 0, 0, msg_out as u32],
        );
        assert_ne!(message, 0, "the empty search result message");
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                ldap_count,
                &[session as u32, message as u32]
            ),
            0,
            "zero entries"
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, ldap_unbind, &[session as u32]),
            0
        );

        // ── httpapi ──
        let http_init: u64 = runtime.alloc_host_thunk(HostThunk::HttpInitialize);
        let http_handle: u64 = runtime.alloc_host_thunk(HostThunk::HttpCreateHttpHandle);
        let http_add_url: u64 = runtime.alloc_host_thunk(HostThunk::HttpAddUrl);
        let http_receive: u64 = runtime.alloc_host_thunk(HostThunk::HttpReceiveHttpRequest);
        let http_term: u64 = runtime.alloc_host_thunk(HostThunk::HttpTerminate);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, http_init, &[0x0001_0000, 1, 0]),
            0
        );
        let queue_out = 0x41_200_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                http_handle,
                &[queue_out as u32, 0]
            ),
            0
        );
        let queue = read_guest_pointer(&memory, queue_out, GuestArch::X86).unwrap();
        assert_ne!(queue, 0);
        let url_ptr = 0x41_210_u64;
        let url_wide: Vec<u16> = "http://+:8080/".encode_utf16().chain([0]).collect();
        for (i, unit) in url_wide.iter().enumerate() {
            write_guest_u16(&mut memory, url_ptr + (i as u64 * 2), *unit).ok();
        }
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                http_add_url,
                &[queue as u32, url_ptr as u32, 0]
            ),
            0
        );
        assert_eq!(
            runtime.http_queues.get(&queue).unwrap().len(),
            1,
            "URL registered"
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                http_receive,
                &[queue as u32, 0, 0, 0, 0, 0, 0]
            ),
            997,
            "ERROR_IO_PENDING"
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, http_term, &[1]),
            0
        );

        // ── pdh ──
        let pdh_open: u64 = runtime.alloc_host_thunk(HostThunk::PdhOpenQuery);
        let pdh_add: u64 = runtime.alloc_host_thunk(HostThunk::PdhAddCounter);
        let pdh_format: u64 = runtime.alloc_host_thunk(HostThunk::PdhGetFormattedCounterValue);
        let pdh_close: u64 = runtime.alloc_host_thunk(HostThunk::PdhCloseQuery);
        let query_out = 0x41_300_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                pdh_open,
                &[0, 0, query_out as u32]
            ),
            0
        );
        let query = read_guest_pointer(&memory, query_out, GuestArch::X86).unwrap();
        let counter_path = 0x41_310_u64;
        let path_wide: Vec<u16> = "\\Server\\Processor(_Total)\\% Processor Time"
            .encode_utf16()
            .chain([0])
            .collect();
        for (i, unit) in path_wide.iter().enumerate() {
            write_guest_u16(&mut memory, counter_path + (i as u64 * 2), *unit).ok();
        }
        let counter_out = 0x41_320_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                pdh_add,
                &[query as u32, counter_path as u32, 0, counter_out as u32]
            ),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                pdh_format,
                &[0x8000_0000, 0, 0x41_330, 0x41_340]
            ),
            0x8000_07d5,
            "PDH_CSTATUS_NO_DATA"
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, pdh_close, &[query as u32]),
            0
        );

        // ── wevtapi ──
        let evt_query: u64 = runtime.alloc_host_thunk(HostThunk::EvtQuery);
        let evt_next: u64 = runtime.alloc_host_thunk(HostThunk::EvtNext);
        let evt_close: u64 = runtime.alloc_host_thunk(HostThunk::EvtClose);
        let evt_out = 0x41_400_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                evt_query,
                &[0, 0x41_410, 0x41_420, 1, evt_out as u32]
            ),
            0
        );
        let evt = read_guest_pointer(&memory, evt_out, GuestArch::X86).unwrap();
        assert_ne!(evt, 0);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                evt_next,
                &[evt as u32, 1, 0x41_430, 0, 0]
            ),
            259,
            "ERROR_NO_MORE_ITEMS"
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, evt_close, &[evt as u32]),
            0
        );

        // ── wlanapi ──
        let wlan_open: u64 = runtime.alloc_host_thunk(HostThunk::WlanOpenHandle);
        let wlan_enum: u64 = runtime.alloc_host_thunk(HostThunk::WlanEnumInterfaces);
        let wlan_close: u64 = runtime.alloc_host_thunk(HostThunk::WlanCloseHandle);
        let version_out = 0x41_500_u64;
        let client_out = 0x41_510_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                wlan_open,
                &[2, 0, version_out as u32, client_out as u32]
            ),
            0
        );
        assert_eq!(read_guest_u32(&memory, version_out).unwrap(), 2);
        let client = read_guest_pointer(&memory, client_out, GuestArch::X86).unwrap();
        assert_ne!(client, 0);
        let list_out = 0x41_520_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                wlan_enum,
                &[client as u32, 0, list_out as u32]
            ),
            0
        );
        assert_eq!(
            read_guest_u32(&memory, list_out).unwrap(),
            8,
            "interface list header"
        );
        assert_eq!(
            read_guest_u32(&memory, list_out + 4).unwrap(),
            0,
            "zero interfaces"
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, wlan_close, &[client as u32, 0]),
            0
        );
    })
}
