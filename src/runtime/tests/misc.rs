use super::support::*;
use super::*;

#[test]
fn verify_version_info_w_matches_win11_profile_and_rejects_higher_build_x86() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "verify-version-info",
            GeArch::X86,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();

        let info = runtime
            .alloc_heap(&mut memory, OSVERSIONINFOEXW_SIZE as usize, true)
            .expect("version info buffer");
        write_u32(&mut memory, info, OSVERSIONINFOEXW_SIZE);
        write_u32(&mut memory, info + 4, 10);
        write_u32(&mut memory, info + 8, 0);
        write_u32(&mut memory, info + 12, 22621);
        write_u32(&mut memory, info + 16, VER_PLATFORM_WIN32_NT);
        memory.map_bytes(info + 276, &0_u16.to_le_bytes());
        memory.map_bytes(info + 278, &0_u16.to_le_bytes());
        memory.map_bytes(info + 280, &0_u16.to_le_bytes());
        memory.map_bytes(info + 282, &[VER_NT_WORKSTATION, 0]);

        let mut condition_mask = 0;
        condition_mask = apply_ver_condition_mask(
            condition_mask,
            VER_MAJORVERSION | VER_MINORVERSION | VER_BUILDNUMBER,
            VER_GREATER_EQUAL,
        );
        condition_mask =
            apply_ver_condition_mask(condition_mask, VER_PLATFORMID | VER_PRODUCT_TYPE, VER_EQUAL);
        let thunk = runtime.alloc_host_thunk(HostThunk::VerifyVersionInfoW);
        let type_mask = VER_MAJORVERSION
            | VER_MINORVERSION
            | VER_BUILDNUMBER
            | VER_PLATFORMID
            | VER_PRODUCT_TYPE;

        let result = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            thunk,
            &[
                info as u32,
                type_mask,
                condition_mask as u32,
                (condition_mask >> 32) as u32,
            ],
        );
        assert_eq!(result, 1);
        assert_eq!(runtime.last_error, 0);

        write_u32(&mut memory, info + 12, 22640);
        let result = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            thunk,
            &[
                info as u32,
                type_mask,
                condition_mask as u32,
                (condition_mask >> 32) as u32,
            ],
        );
        assert_eq!(result, 0);
        assert_eq!(runtime.last_error, ERROR_OLD_WIN_VERSION);
    })
}

#[test]
fn crt_vsnprintf_s_truncation_returns_required_and_terminates() {
    with_big_stack(|| {
        let (_temp, mut runtime, mut memory) = setup_crt_test_runtime();
        let vsnprintf_s = runtime.alloc_host_thunk(HostThunk::StdioCommonVsnprintfS);
        let format = runtime
            .alloc_utf16_string(&mut memory, "%d")
            .expect("format");
        let va_area = 0x63_000;
        memory.map_bytes(va_area, &[0_u8; 16]);
        write_u32(&mut memory, va_area, 12_345);
        let buffer = 0x62_000;
        memory.map_bytes(buffer, &[0xAA_u8; 16]);

        // Truncation: required size returned, NUL-terminated prefix, ERANGE.
        let ret = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            vsnprintf_s,
            &[0, buffer as u32, 3, format as u32, 0, va_area as u32],
        );
        assert_eq!(ret, 5);
        assert_eq!(
            memory.read_bytes(buffer, 3).expect("buffer"),
            [b'1', b'2', 0]
        );
        assert_eq!(runtime.crt_errno_get(&mut memory), ERANGE);
        // The truncation aborted the guest (no handler installed); clear
        // errno for the success case below.
        let set_errno = runtime.alloc_host_thunk(HostThunk::SetErrno);
        dispatch_x86_thunk(&mut runtime, &mut memory, set_errno, &[0]);

        // Success: full string + NUL, no errno.
        let ret = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            vsnprintf_s,
            &[0, buffer as u32, 16, format as u32, 0, va_area as u32],
        );
        assert_eq!(ret, 5);
        assert_eq!(
            memory.read_bytes(buffer, 6).expect("buffer"),
            [b'1', b'2', b'3', b'4', b'5', 0]
        );
        assert_eq!(runtime.crt_errno_get(&mut memory), 0);
    })
}

#[test]
fn crt_vsnprintf_legacy_returns_minus_one_on_overflow() {
    with_big_stack(|| {
        let (_temp, mut runtime, mut memory) = setup_crt_test_runtime();
        let vsnprintf = runtime.alloc_host_thunk(HostThunk::StdioCommonVsnprintf);
        let format = runtime
            .alloc_utf16_string(&mut memory, "%d")
            .expect("format");
        let va_area = 0x63_000;
        memory.map_bytes(va_area, &[0_u8; 16]);
        write_u32(&mut memory, va_area, 999);
        let buffer = 0x62_000;
        memory.map_bytes(buffer, &[0xAA_u8; 16]);

        // Legacy _vsnprintf: overflow → -1, buffer untouched and unterminated.
        let ret = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            vsnprintf,
            &[0, buffer as u32, 2, format as u32, 0, va_area as u32],
        );
        assert_eq!(ret, (-1_i32) as u32 as u64);
        assert_eq!(memory.read_bytes(buffer, 4).expect("buffer"), [0xAA; 4]);

        // Fits → written + NUL.
        let ret = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            vsnprintf,
            &[0, buffer as u32, 8, format as u32, 0, va_area as u32],
        );
        assert_eq!(ret, 3);
        assert_eq!(
            memory.read_bytes(buffer, 4).expect("buffer"),
            [b'9', b'9', b'9', 0]
        );

        // Query idiom: NULL buffer + 0 count → required size.
        let ret = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            vsnprintf,
            &[0, 0, 0, format as u32, 0, va_area as u32],
        );
        assert_eq!(ret, 3);
    })
}

#[test]
fn crt_invalid_parameter_invokes_guest_handler() {
    with_big_stack(|| {
        let (_temp, mut runtime, mut memory) = setup_crt_test_runtime();
        let marker_addr = 0x70_000;
        // The callback stores the marker through a guest `mov [addr], eax`;
        // the destination must be loader-mapped (guest stores never
        // materialize pages).
        memory.map_zeroed_if_unmapped(marker_addr, 4);
        write_x86_stub(
            &mut memory,
            0x70_100,
            &marker_callback(marker_addr, 0xCAFE_5EED),
        );
        let set_handler = runtime.alloc_host_thunk(HostThunk::SetInvalidParameterHandler);
        let previous = dispatch_x86_thunk_crt(&mut runtime, &mut memory, set_handler, &[0x70_100]);
        assert_eq!(previous, 0);

        let strcpy_s = runtime.alloc_host_thunk(HostThunk::StrcpyS);
        let dst = 0x62_000;
        memory.map_bytes(dst, &[0_u8; 8]);
        let src = runtime.alloc_c_string(&mut memory, "hello").expect("src");
        // dst capacity 4 < 6 (strlen("hello") + 1) → ERANGE, handler
        // invoked, destination reset to the empty string.
        dispatch_x86_thunk_crt(
            &mut runtime,
            &mut memory,
            strcpy_s,
            &[dst as u32, 4, src as u32],
        );
        assert_eq!(read_u32(&memory, marker_addr).expect("marker"), 0xCAFE_5EED);
        assert_eq!(runtime.crt_errno_get(&mut memory), ERANGE);
        assert_eq!(memory.read_u8(dst).expect("dst[0]"), 0);
    })
}

#[test]
fn crt_invalid_parameter_without_handler_aborts() {
    with_big_stack(|| {
        let (_temp, mut runtime, mut memory) = setup_crt_test_runtime();
        let strcpy_s = runtime.alloc_host_thunk(HostThunk::StrcpyS);
        let src = runtime.alloc_c_string(&mut memory, "hello").expect("src");
        // NULL destination with no handler installed → abort (exit code 134).
        let result =
            dispatch_x86_thunk_result(&mut runtime, &mut memory, strcpy_s, &[0, 4, src as u32]);
        assert_eq!(result, Some(134));
    })
}

#[test]
fn crt_strcpy_s_success_and_truncation() {
    with_big_stack(|| {
        let (_temp, mut runtime, mut memory) = setup_crt_test_runtime();
        // Success path (no handler needed — no error).
        let strcpy_s = runtime.alloc_host_thunk(HostThunk::StrcpyS);
        let dst = 0x62_000;
        memory.map_bytes(dst, &[0xAA_u8; 16]);
        let src = runtime.alloc_c_string(&mut memory, "abc").expect("src");
        let ret = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            strcpy_s,
            &[dst as u32, 16, src as u32],
        );
        assert_eq!(ret, 0);
        assert_eq!(
            memory.read_bytes(dst, 4).expect("dst"),
            [b'a', b'b', b'c', 0]
        );

        // Truncation resets the destination and aborts (no handler).
        let result = dispatch_x86_thunk_result(
            &mut runtime,
            &mut memory,
            strcpy_s,
            &[dst as u32, 3, src as u32],
        );
        assert_eq!(result, Some(134));
        assert_eq!(memory.read_u8(dst).expect("dst[0]"), 0);
    })
}

// ── Adversarial-review regressions ───────────────────────────────────────
#[test]
fn crt_strtod_exponent_not_doubled_and_special_strings() {
    with_big_stack(|| {
        let (_temp, mut runtime, mut memory) = setup_crt_test_runtime();
        let atof = runtime.alloc_host_thunk(HostThunk::Atof);
        let check =
            |runtime: &mut PeHostRuntime, memory: &mut MemoryImage, text: &str, expected: f64| {
                let ptr = runtime.alloc_c_string(memory, text).expect("string");
                let mut state = CpuState::new(GuestArch::X86);
                state.set(Register::Rsp, 0x50_000);
                memory.map_bytes(0x50_000, &[0_u8; 0x1000]);
                write_u32(memory, 0x50_000, 0);
                write_u32(memory, 0x50_004, ptr as u32);
                runtime
                    .dispatch_import(atof, &mut state, memory)
                    .expect("atof");
                let got = state.x87.stack.last().copied().unwrap_or(0.0);
                let ok = if expected.is_nan() {
                    got.is_nan()
                } else {
                    got == expected || (got - expected).abs() <= expected.abs().max(1.0) * 1e-12
                };
                assert!(ok, "atof({text:?}) = {got}, expected {expected}");
            };
        check(&mut runtime, &mut memory, "1.5e3", 1500.0);
        check(&mut runtime, &mut memory, "1e10", 1e10);
        check(&mut runtime, &mut memory, "1.5e-3", 0.0015);
        check(&mut runtime, &mut memory, "0x1p4", 16.0);
        check(&mut runtime, &mut memory, "inf", f64::INFINITY);
        check(&mut runtime, &mut memory, "-inf", f64::NEG_INFINITY);
        check(&mut runtime, &mut memory, "nan", f64::NAN);
        check(&mut runtime, &mut memory, "42", 42.0);
    })
}

#[test]
fn crt_strtol_negative_overflow_and_base_validation() {
    with_big_stack(|| {
        let (_temp, mut runtime, mut memory) = setup_crt_test_runtime();
        let strtol = runtime.alloc_host_thunk(HostThunk::Strtol);
        let strtoul = runtime.alloc_host_thunk(HostThunk::Strtoul);
        let strtoi64 = runtime.alloc_host_thunk(HostThunk::Strtoi64);
        let strtoui64 = runtime.alloc_host_thunk(HostThunk::Strtoui64);
        let end = 0x61_000;
        memory.map_bytes(end, &[0_u8; 4]);

        // strtoul("-1") → 0xFFFFFFFF (no ERANGE — the magnitude fits).
        let s = runtime.alloc_c_string(&mut memory, "-1").expect("s");
        let ret = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            strtoul,
            &[s as u32, end as u32, 10],
        );
        assert_eq!(ret, u32::MAX as u64);
        assert_eq!(runtime.crt_errno_get(&mut memory), 0);

        // strtoul negative magnitude overflow → 0xFFFFFFFF + ERANGE.
        let big = runtime
            .alloc_c_string(&mut memory, "-999999999999999999999")
            .expect("big");
        let ret = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            strtoul,
            &[big as u32, end as u32, 10],
        );
        assert_eq!(ret, u32::MAX as u64);
        assert_eq!(runtime.crt_errno_get(&mut memory), ERANGE);

        // _strtoui64("-1") → u64::MAX (EAX:EDX); negative overflow → same + ERANGE.
        let dispatch_64 =
            |runtime: &mut PeHostRuntime, memory: &mut MemoryImage, thunk: u64, arg: u32| -> u64 {
                let mut state = CpuState::new(GuestArch::X86);
                state.set(Register::Rsp, 0x50_000);
                write_u32(memory, 0x50_000, 0);
                write_u32(memory, 0x50_004, arg);
                write_u32(memory, 0x50_008, end as u32);
                write_u32(memory, 0x50_00C, 10);
                runtime
                    .dispatch_import(thunk, &mut state, memory)
                    .expect("dispatch 64-bit strtoi64 family");
                let low = state.get(Register::Rax);
                let high = state.get(Register::Rdx);
                low | (high << 32)
            };
        assert_eq!(
            dispatch_64(&mut runtime, &mut memory, strtoui64, s as u32),
            u64::MAX
        );
        assert_eq!(
            dispatch_64(&mut runtime, &mut memory, strtoui64, big as u32),
            u64::MAX
        );
        assert_eq!(runtime.crt_errno_get(&mut memory), ERANGE);
        // _strtoi64("-1") stays i64 -1.
        assert_eq!(
            dispatch_64(&mut runtime, &mut memory, strtoi64, s as u32),
            (-1_i64) as u64
        );

        // strtoul("5") still parses; errno reset by a successful call.
        let set_errno = runtime.alloc_host_thunk(HostThunk::SetErrno);
        dispatch_x86_thunk(&mut runtime, &mut memory, set_errno, &[0]);
        let five = runtime.alloc_c_string(&mut memory, "5").expect("5");
        let ret = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            strtoul,
            &[five as u32, end as u32, 10],
        );
        assert_eq!(ret, 5);
        assert_eq!(runtime.crt_errno_get(&mut memory), 0);

        // Invalid bases: 1 and 37 → EINVAL, *endptr = nptr, value 0.
        for base in [1_i32, 37] {
            let s = runtime.alloc_c_string(&mut memory, "123").expect("s");
            let ret = dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                strtol,
                &[s as u32, end as u32, base as u32],
            );
            assert_eq!(ret, 0);
            assert_eq!(runtime.crt_errno_get(&mut memory), EINVAL);
            assert_eq!(read_u32(&memory, end).expect("end"), s as u32);
        }

        // No conversion with whitespace: *endptr = nptr (the ORIGINAL ptr).
        dispatch_x86_thunk(&mut runtime, &mut memory, set_errno, &[0]);
        let ws = runtime.alloc_c_string(&mut memory, "  xyz").expect("ws");
        let ret = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            strtol,
            &[ws as u32, end as u32, 10],
        );
        assert_eq!(ret, 0);
        assert_eq!(runtime.crt_errno_get(&mut memory), 0);
        assert_eq!(read_u32(&memory, end).expect("end"), ws as u32);

        // _strtoi64_s with invalid base: *value = 0 + EINVAL.
        let strtoi64_s = runtime.alloc_host_thunk(HostThunk::Strtoi64S);
        let out = 0x61_008;
        memory.map_bytes(out, &[0_u8; 8]);
        let s = runtime.alloc_c_string(&mut memory, "123").expect("s");
        let status = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            strtoi64_s,
            &[s as u32, end as u32, 1, out as u32],
        );
        assert_eq!(status, EINVAL as u64);
        assert_eq!(memory.read_u64(out).expect("value"), 0);
        assert_eq!(runtime.crt_errno_get(&mut memory), EINVAL);
    })
}

#[test]
fn crt_strtoi64_s_null_value_aborts_with_einval() {
    with_big_stack(|| {
        let (_temp, mut runtime, mut memory) = setup_crt_test_runtime();
        let strtoi64_s = runtime.alloc_host_thunk(HostThunk::Strtoi64S);
        let s = runtime.alloc_c_string(&mut memory, "123").expect("s");
        let result =
            dispatch_x86_thunk_result(&mut runtime, &mut memory, strtoi64_s, &[s as u32, 0, 10, 0]);
        assert_eq!(result, Some(134));
        assert_eq!(runtime.crt_errno_get(&mut memory), EINVAL);
    })
}

#[test]
fn evidence_math_crt_math() {
    with_big_stack(|| {
        // Every msvcrt math export round-trips against host f64 math on both
        // guest ABIs: x86 cdecl (doubles on the stack, result in ST(0)) and
        // x64 (XMM0+ args, XMM0 result).
        let (_temp, mut runtime, mut memory) = setup_crt_test_runtime();
        let cos = runtime.alloc_host_thunk(HostThunk::CrtCos);
        let sin = runtime.alloc_host_thunk(HostThunk::CrtSin);
        let tan = runtime.alloc_host_thunk(HostThunk::CrtTan);
        let exp = runtime.alloc_host_thunk(HostThunk::CrtExp);
        let log = runtime.alloc_host_thunk(HostThunk::CrtLog);
        let sqrt = runtime.alloc_host_thunk(HostThunk::CrtSqrt);
        let fabs = runtime.alloc_host_thunk(HostThunk::CrtFabs);
        let ceil = runtime.alloc_host_thunk(HostThunk::CrtCeil);
        let floor = runtime.alloc_host_thunk(HostThunk::CrtFloor);
        let atan2 = runtime.alloc_host_thunk(HostThunk::CrtAtan2);
        let pow = runtime.alloc_host_thunk(HostThunk::CrtPow);

        let close = |actual: f64, expected: f64| {
            let ok = actual == expected
                || (actual.is_nan() && expected.is_nan())
                || (actual - expected).abs() <= expected.abs().max(1.0) * 1e-12;
            assert!(ok, "expected {expected}, got {actual}");
        };
        close(
            dispatch_math_x86(&mut runtime, &mut memory, cos, &[0.0]),
            1.0,
        );
        close(
            dispatch_math_x86(&mut runtime, &mut memory, sin, &[0.0]),
            0.0,
        );
        close(
            dispatch_math_x86(&mut runtime, &mut memory, tan, &[0.0]),
            0.0,
        );
        close(
            dispatch_math_x86(&mut runtime, &mut memory, exp, &[1.0]),
            std::f64::consts::E,
        );
        close(
            dispatch_math_x86(&mut runtime, &mut memory, log, &[std::f64::consts::E]),
            1.0,
        );
        close(
            dispatch_math_x86(&mut runtime, &mut memory, sqrt, &[4.0]),
            2.0,
        );
        close(
            dispatch_math_x86(&mut runtime, &mut memory, fabs, &[-3.5]),
            3.5,
        );
        close(
            dispatch_math_x86(&mut runtime, &mut memory, ceil, &[2.3]),
            3.0,
        );
        close(
            dispatch_math_x86(&mut runtime, &mut memory, floor, &[2.7]),
            2.0,
        );
        close(
            dispatch_math_x86(&mut runtime, &mut memory, atan2, &[1.0, 1.0]),
            std::f64::consts::FRAC_PI_4,
        );
        close(
            dispatch_math_x86(&mut runtime, &mut memory, pow, &[2.0, 10.0]),
            1024.0,
        );

        // C domain/range plumbing: sqrt(-1) → NaN + EDOM; log(0) → -inf +
        // ERANGE; log(-1) → NaN + EDOM; pow(negative, fractional) → NaN + EDOM.
        assert!(dispatch_math_x86(&mut runtime, &mut memory, sqrt, &[-1.0]).is_nan());
        assert_eq!(runtime.crt_errno_get(&mut memory), EDOM);
        close(
            dispatch_math_x86(&mut runtime, &mut memory, log, &[0.0]),
            f64::NEG_INFINITY,
        );
        assert_eq!(runtime.crt_errno_get(&mut memory), ERANGE);
        assert!(dispatch_math_x86(&mut runtime, &mut memory, log, &[-1.0]).is_nan());
        assert_eq!(runtime.crt_errno_get(&mut memory), EDOM);
        assert!(dispatch_math_x86(&mut runtime, &mut memory, pow, &[-2.0, 0.5]).is_nan());
        assert_eq!(runtime.crt_errno_get(&mut memory), EDOM);
        // exp overflow → +inf + ERANGE.
        assert_eq!(
            dispatch_math_x86(&mut runtime, &mut memory, exp, &[1000.0]),
            f64::INFINITY
        );
        assert_eq!(runtime.crt_errno_get(&mut memory), ERANGE);

        // x64 ABI: same values through XMM0.
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X64);
        close(
            dispatch_math_x64(&mut runtime, &mut memory, cos, &[0.0]),
            1.0,
        );
        close(
            dispatch_math_x64(&mut runtime, &mut memory, sqrt, &[16.0]),
            4.0,
        );
        close(
            dispatch_math_x64(&mut runtime, &mut memory, fabs, &[-2.5]),
            2.5,
        );
        close(
            dispatch_math_x64(&mut runtime, &mut memory, atan2, &[1.0, 1.0]),
            std::f64::consts::FRAC_PI_4,
        );
        close(
            dispatch_math_x64(&mut runtime, &mut memory, pow, &[2.0, 10.0]),
            1024.0,
        );
    })
}

#[test]
fn evidence_math_crt_stdio() {
    with_big_stack(|| {
        // printf/sprintf/vsprintf render through the shared UCRT format
        // engine (narrow formats widened); sscanf scans back through the
        // shared strtol/strtod cores.  printf delivers to the guest stdout.
        let (_temp, mut runtime, mut memory) = setup_crt_test_runtime();
        let printf = runtime.alloc_host_thunk(HostThunk::CrtPrintf);
        let sprintf = runtime.alloc_host_thunk(HostThunk::CrtSprintf);
        let vsprintf = runtime.alloc_host_thunk(HostThunk::CrtVsprintf);
        let sscanf = runtime.alloc_host_thunk(HostThunk::CrtSscanf);

        // printf("count=%d name=%s pi=%.2f\n", ...) → guest stdout.
        let format = runtime
            .alloc_c_string(&mut memory, "count=%d name=%s pi=%.2f\n")
            .expect("format");
        let name = runtime.alloc_c_string(&mut memory, "casa1").expect("name");
        let pi_bits = std::f64::consts::PI.to_bits();
        dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            printf,
            &[
                format as u32,
                42,
                name as u32,
                pi_bits as u32,
                (pi_bits >> 32) as u32,
            ],
        );
        assert_eq!(runtime.stdout, "count=42 name=casa1 pi=3.14\n");

        // sprintf(buffer, "%x-%d-%s", ...) → NUL-terminated bytes; the return
        // value is the length excluding the NUL.
        let buffer = 0x61_000;
        memory.map_bytes(buffer, &[0_u8; 64]);
        let fmt = runtime
            .alloc_c_string(&mut memory, "%x-%d-%s")
            .expect("fmt");
        let ret = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            sprintf,
            &[buffer as u32, fmt as u32, 0xCAFE, 7, name as u32],
        );
        assert_eq!(ret, b"cafe-7-casa1".len() as u64);
        let mut rendered = memory
            .read_bytes(buffer, b"cafe-7-casa1".len() + 1)
            .expect("read buffer");
        let nul = rendered.pop().expect("nul");
        assert_eq!(nul, 0);
        assert_eq!(rendered, b"cafe-7-casa1");

        // vsprintf(buffer, format, va_list) with a caller-built va list.
        let va_area = 0x62_000;
        memory.map_bytes(va_area, &[0_u8; 64]);
        let long_value = 1_000_000_000_i64;
        let long_bits = long_value as u64;
        write_u32(&mut memory, va_area, long_bits as u32);
        write_u32(&mut memory, va_area + 4, (long_bits >> 32) as u32);
        let fmt = runtime.alloc_c_string(&mut memory, "%lld").expect("fmt");
        let ret = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            vsprintf,
            &[buffer as u32, fmt as u32, va_area as u32],
        );
        assert_eq!(ret, b"1000000000".len() as u64);
        let rendered = memory
            .read_bytes(buffer, b"1000000000".len())
            .expect("read buffer");
        assert_eq!(rendered, b"1000000000");

        // sscanf("42 casa1 3.5", "%d %s %f", &i, str, &f) → 3 assignments.
        let input = runtime
            .alloc_c_string(&mut memory, "42 casa1 3.5")
            .expect("input");
        let fmt = runtime
            .alloc_c_string(&mut memory, "%d %s %f")
            .expect("fmt");
        let i_out = 0x63_000;
        let s_out = 0x63_004;
        let f_out = 0x63_100;
        memory.map_bytes(i_out, &[0_u8; 4]);
        memory.map_bytes(s_out, &[0_u8; 32]);
        memory.map_bytes(f_out, &[0_u8; 4]);
        let ret = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            sscanf,
            &[
                input as u32,
                fmt as u32,
                i_out as u32,
                s_out as u32,
                f_out as u32,
            ],
        );
        assert_eq!(ret, 3);
        assert_eq!(read_u32(&memory, i_out).expect("int"), 42);
        assert_eq!(read_c_string(&memory, s_out).expect("str"), "casa1");
        let f_bits = read_u32(&memory, f_out).expect("float");
        assert_eq!(f32::from_bits(f_bits), 3.5);

        // sscanf width/hex/%n: "ff 9" with "%2x %d %n" → 2 assignments and the
        // consumed count through %n.
        let input = runtime.alloc_c_string(&mut memory, "ff 9").expect("input");
        let fmt = runtime
            .alloc_c_string(&mut memory, "%2x %d %n")
            .expect("fmt");
        let x_out = 0x63_200;
        let d_out = 0x63_204;
        let n_out = 0x63_208;
        memory.map_bytes(x_out, &[0_u8; 12]);
        let ret = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            sscanf,
            &[
                input as u32,
                fmt as u32,
                x_out as u32,
                d_out as u32,
                n_out as u32,
            ],
        );
        assert_eq!(ret, 2);
        assert_eq!(read_u32(&memory, x_out).expect("hex"), 0xFF);
        assert_eq!(read_u32(&memory, d_out).expect("dec"), 9);
        // %n reports the characters consumed so far ("ff" + space + "9" = 4).
        assert_eq!(read_u32(&memory, n_out).expect("n"), 4);

        // sscanf scanset + literal: "alice;x" with "%[a-z];%c" → 2.
        let input = runtime
            .alloc_c_string(&mut memory, "alice;x")
            .expect("input");
        let fmt = runtime
            .alloc_c_string(&mut memory, "%[a-z];%c")
            .expect("fmt");
        let str_out = 0x63_210;
        let c_out = 0x63_230;
        memory.map_bytes(str_out, &[0_u8; 16]);
        memory.map_bytes(c_out, &[0_u8; 4]);
        let ret = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            sscanf,
            &[input as u32, fmt as u32, str_out as u32, c_out as u32],
        );
        assert_eq!(ret, 2);
        assert_eq!(read_c_string(&memory, str_out).expect("str"), "alice");
        assert_eq!(read_u32(&memory, c_out).expect("char"), u32::from(b'x'));

        // Matching failure: "%d" against "abc" → 0; empty input → EOF (-1).
        let abc = runtime.alloc_c_string(&mut memory, "abc").expect("abc");
        let fmt = runtime.alloc_c_string(&mut memory, "%d").expect("fmt");
        let d_out = 0x63_220;
        memory.map_bytes(d_out, &[0_u8; 4]);
        let ret = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            sscanf,
            &[abc as u32, fmt as u32, d_out as u32],
        );
        assert_eq!(ret, 0);
        let empty = runtime.alloc_c_string(&mut memory, "").expect("empty");
        let ret = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            sscanf,
            &[empty as u32, fmt as u32, d_out as u32],
        );
        // EOF is -1; on x86 RAX carries the truncated 32-bit value.
        assert_eq!(ret, u64::from(u32::MAX));
    })
}

#[test]
fn evidence_math_crt_vcruntime() {
    with_big_stack(|| {
        // Every vcruntime140.dll export resolves through the import-name
        // tables to a concrete thunk and behaves like its CRT counterpart.
        let (_temp, mut runtime, mut memory) = setup_crt_test_runtime();
        let import = |name: &str| ResolvedImport {
            requested_module: "vcruntime140.dll".to_string(),
            resolved_module: "vcruntime140.dll".to_string(),
            symbol: ImportSymbol::ByName {
                hint: 0,
                name: name.to_string(),
            },
            iat_rva: 0x1000,
            export: ExportSymbol {
                ordinal: 1,
                name: Some(name.to_string()),
                target: ExportTarget::Rva(0x2000),
            },
        };
        for name in [
            "memcpy", "memmove", "memset", "strchr", "strlen", "strncmp", "strncpy", "strrchr",
            "strstr", "wcschr", "wcslen", "wcsncmp", "wcsncpy", "wcsrchr", "wcsstr",
        ] {
            assert!(
                !matches!(
                    HostThunk::from_import(&import(name)),
                    HostThunk::Unsupported { .. }
                ),
                "vcruntime140.dll!{name} must map to a concrete thunk"
            );
        }

        // strlen / strchr / strrchr / strstr / strncmp / strncpy.
        let strlen = runtime.alloc_host_thunk(HostThunk::from_import(&import("strlen")));
        let s = runtime.alloc_c_string(&mut memory, "hello").expect("s");
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, strlen, &[s as u32]),
            5
        );
        let strchr = runtime.alloc_host_thunk(HostThunk::from_import(&import("strchr")));
        let found = dispatch_x86_thunk(&mut runtime, &mut memory, strchr, &[s as u32, b'l' as u32]);
        assert_eq!(found, s + 2);
        let strrchr = runtime.alloc_host_thunk(HostThunk::from_import(&import("strrchr")));
        let found =
            dispatch_x86_thunk(&mut runtime, &mut memory, strrchr, &[s as u32, b'l' as u32]);
        assert_eq!(found, s + 3);
        let strstr = runtime.alloc_host_thunk(HostThunk::from_import(&import("strstr")));
        let needle = runtime.alloc_c_string(&mut memory, "ll").expect("needle");
        let found = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            strstr,
            &[s as u32, needle as u32],
        );
        assert_eq!(found, s + 2);
        let strncmp = runtime.alloc_host_thunk(HostThunk::from_import(&import("strncmp")));
        let other = runtime.alloc_c_string(&mut memory, "help").expect("other");
        let cmp = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            strncmp,
            &[s as u32, other as u32, 4],
        );
        assert_eq!(cmp as i32, i32::from(b'l' as i8) - i32::from(b'p' as i8));
        let strncpy = runtime.alloc_host_thunk(HostThunk::from_import(&import("strncpy")));
        let dest = 0x61_000;
        memory.map_bytes(dest, &[0_u8; 16]);
        let copied = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            strncpy,
            &[dest as u32, s as u32, 8],
        );
        assert_eq!(copied, dest);
        let bytes = memory.read_bytes(dest, 8).expect("copy");
        assert_eq!(&bytes[..5], b"hello");
        assert_eq!(&bytes[5..], &[0, 0, 0]);

        // memcpy / memmove / memset.
        let memcpy = runtime.alloc_host_thunk(HostThunk::from_import(&import("memcpy")));
        let src = 0x61_100;
        memory.map_bytes(src, &[1, 2, 3, 4]);
        let dst = 0x61_110;
        memory.map_bytes(dst, &[0_u8; 4]);
        let ret = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            memcpy,
            &[dst as u32, src as u32, 4],
        );
        assert_eq!(ret, dst);
        assert_eq!(memory.read_bytes(dst, 4).expect("memcpy"), vec![1, 2, 3, 4]);
        let memmove = runtime.alloc_host_thunk(HostThunk::from_import(&import("memmove")));
        let overlap = 0x61_200;
        memory.map_bytes(overlap, &[1, 2, 3, 4, 5]);
        dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            memmove,
            &[(overlap + 1) as u32, overlap as u32, 4],
        );
        assert_eq!(
            memory.read_bytes(overlap, 5).expect("memmove"),
            vec![1, 1, 2, 3, 4]
        );
        let memset = runtime.alloc_host_thunk(HostThunk::from_import(&import("memset")));
        let area = 0x61_300;
        memory.map_bytes(area, &[0_u8; 4]);
        dispatch_x86_thunk(&mut runtime, &mut memory, memset, &[area as u32, 0xAB, 4]);
        assert_eq!(
            memory.read_bytes(area, 4).expect("memset"),
            vec![0xAB, 0xAB, 0xAB, 0xAB]
        );

        // Wide family: wcslen / wcschr / wcsrchr / wcsstr / wcsncmp / wcsncpy.
        let wcslen = runtime.alloc_host_thunk(HostThunk::from_import(&import("wcslen")));
        let wide = runtime
            .alloc_utf16_string(&mut memory, "abba")
            .expect("wide");
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, wcslen, &[wide as u32]),
            4
        );
        let wcschr = runtime.alloc_host_thunk(HostThunk::from_import(&import("wcschr")));
        let found = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            wcschr,
            &[wide as u32, b'b' as u32],
        );
        assert_eq!(found, wide + 2);
        let wcsrchr = runtime.alloc_host_thunk(HostThunk::from_import(&import("wcsrchr")));
        let found = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            wcsrchr,
            &[wide as u32, b'b' as u32],
        );
        assert_eq!(found, wide + 4);
        let wcsstr = runtime.alloc_host_thunk(HostThunk::from_import(&import("wcsstr")));
        let wneedle = runtime
            .alloc_utf16_string(&mut memory, "bb")
            .expect("wneedle");
        let found = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            wcsstr,
            &[wide as u32, wneedle as u32],
        );
        assert_eq!(found, wide + 2);
        let wcsncmp = runtime.alloc_host_thunk(HostThunk::from_import(&import("wcsncmp")));
        let wother = runtime
            .alloc_utf16_string(&mut memory, "abca")
            .expect("wother");
        let cmp = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            wcsncmp,
            &[wide as u32, wother as u32, 4],
        );
        assert_eq!(cmp as i32, i32::from(b'b') - i32::from(b'c'));
        let wcsncpy = runtime.alloc_host_thunk(HostThunk::from_import(&import("wcsncpy")));
        let wdest = 0x61_400;
        memory.map_bytes(wdest, &[0_u8; 16]);
        let copied = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            wcsncpy,
            &[wdest as u32, wide as u32, 3],
        );
        assert_eq!(copied, wdest);
        assert_eq!(read_guest_utf16_string(&memory, wdest, 4), "abb");
    })
}

#[test]
fn evidence_math_crt_msvcp() {
    with_big_stack(|| {
        // msvcp140.dll: the _Mtx_* / _Cnd_* C11-threads wrappers, the _X*
        // throw helpers and the random_device entropy pair.
        let (_temp, mut runtime, mut memory) = setup_crt_test_runtime();
        let mtx_init = runtime.alloc_host_thunk(HostThunk::MsvcpMtxInit);
        let mtx_lock = runtime.alloc_host_thunk(HostThunk::MsvcpMtxLock);
        let mtx_unlock = runtime.alloc_host_thunk(HostThunk::MsvcpMtxUnlock);
        let mtx_current = runtime.alloc_host_thunk(HostThunk::MsvcpMtxCurrent);
        let mtx_reset = runtime.alloc_host_thunk(HostThunk::MsvcpMtxReset);
        let mtx_destroy = runtime.alloc_host_thunk(HostThunk::MsvcpMtxDestroy);
        let cnd_init = runtime.alloc_host_thunk(HostThunk::MsvcpCndInit);
        let cnd_signal = runtime.alloc_host_thunk(HostThunk::MsvcpCndSignal);
        let cnd_broadcast = runtime.alloc_host_thunk(HostThunk::MsvcpCndBroadcast);
        let cnd_wait = runtime.alloc_host_thunk(HostThunk::MsvcpCndWait);
        let cnd_destroy = runtime.alloc_host_thunk(HostThunk::MsvcpCndDestroy);
        let rd_get = runtime.alloc_host_thunk(HostThunk::MsvcpRandomDeviceGet);
        let rd_init = runtime.alloc_host_thunk(HostThunk::MsvcpRandomDeviceInit);

        // _Mtx_init writes an opaque handle through the out-param.
        let mtx_slot = 0x61_000;
        memory.map_bytes(mtx_slot, &[0_u8; 8]);
        let status = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            mtx_init,
            &[mtx_slot as u32, 0x10000],
        );
        assert_eq!(status, 0);
        let handle = read_guest_pointer(&memory, mtx_slot, GuestArch::X86).expect("mtx handle");
        assert_ne!(handle, 0);

        // Unlocked: _Mtx_current → 0; lock → owner is the current thread.
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, mtx_current, &[handle as u32]),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, mtx_lock, &[handle as u32]),
            0
        );
        let tid = u64::from(runtime.win32.current_thread_id());
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, mtx_current, &[handle as u32]),
            tid
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, mtx_unlock, &[handle as u32]),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, mtx_current, &[handle as u32]),
            0
        );

        // Recursive mutex: double-lock bumps the depth; reset clears it.
        let rec_slot = 0x61_008;
        memory.map_bytes(rec_slot, &[0_u8; 8]);
        dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            mtx_init,
            &[rec_slot as u32, 0x10001],
        );
        let rec_handle = read_guest_pointer(&memory, rec_slot, GuestArch::X86).expect("rec handle");
        dispatch_x86_thunk(&mut runtime, &mut memory, mtx_lock, &[rec_handle as u32]);
        dispatch_x86_thunk(&mut runtime, &mut memory, mtx_lock, &[rec_handle as u32]);
        assert_eq!(
            runtime.msvcp_mtxes.get(&rec_handle).expect("rec mtx").depth,
            2
        );
        dispatch_x86_thunk(&mut runtime, &mut memory, mtx_unlock, &[rec_handle as u32]);
        assert_eq!(
            runtime.msvcp_mtxes.get(&rec_handle).expect("rec mtx").depth,
            1
        );
        dispatch_x86_thunk(&mut runtime, &mut memory, mtx_reset, &[rec_handle as u32]);
        let rec = runtime.msvcp_mtxes.get(&rec_handle).expect("rec mtx");
        assert_eq!(rec.owner, 0);
        assert_eq!(rec.depth, 0);

        // _Mtx_destroy removes the host state.
        dispatch_x86_thunk(&mut runtime, &mut memory, mtx_destroy, &[handle as u32]);
        assert!(!runtime.msvcp_mtxes.contains_key(&handle));

        // _Cnd_init writes an opaque handle; wait without pending threads is a
        // legal spurious wakeup that re-acquires the mutex; signal/broadcast
        // are no-ops without waiters; destroy removes the state.
        let cnd_slot = 0x61_010;
        memory.map_bytes(cnd_slot, &[0_u8; 8]);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, cnd_init, &[cnd_slot as u32]),
            0
        );
        let cnd_handle = read_guest_pointer(&memory, cnd_slot, GuestArch::X86).expect("cnd handle");
        assert_ne!(cnd_handle, 0);
        dispatch_x86_thunk(&mut runtime, &mut memory, mtx_lock, &[rec_handle as u32]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                cnd_wait,
                &[cnd_handle as u32, rec_handle as u32],
            ),
            0
        );
        assert_eq!(
            runtime.msvcp_mtxes.get(&rec_handle).expect("rec mtx").owner,
            runtime.win32.current_thread_id()
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, cnd_signal, &[cnd_handle as u32]),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                cnd_broadcast,
                &[cnd_handle as u32]
            ),
            0
        );
        dispatch_x86_thunk(&mut runtime, &mut memory, cnd_destroy, &[cnd_handle as u32]);
        assert!(!runtime.msvcp_cnds.contains_key(&cnd_handle));

        // std::random_device::_Init returns 0; _Get returns real entropy
        // (16 draws are never all equal — a 2^-480 failure bound).
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, rd_init, &[]),
            0
        );
        let draws: Vec<u64> = (0..16)
            .map(|_| dispatch_x86_thunk(&mut runtime, &mut memory, rd_get, &[]))
            .collect();
        assert!(
            draws.iter().any(|draw| *draw != draws[0]),
            "random_device::_Get must produce varying entropy"
        );

        // The _X* throw helpers raise the MSVC C++ exception and terminate
        // the process when nothing catches (Windows semantics).
        let xout = runtime.alloc_host_thunk(HostThunk::MsvcpXoutOfRange);
        let msg = runtime
            .alloc_c_string(&mut memory, "vector::_M_range_check")
            .expect("msg");
        let result = dispatch_x86_thunk_result(&mut runtime, &mut memory, xout, &[msg as u32]);
        assert_eq!(result, Some(-0x1F92_8C9D));
        assert_eq!(runtime.unhandled_guest_exception, Some(0xE06D_7363));
        let xbad = runtime.alloc_host_thunk(HostThunk::MsvcpXbadAlloc);
        let result = dispatch_x86_thunk_result(&mut runtime, &mut memory, xbad, &[]);
        assert_eq!(result, Some(-0x1F92_8C9D));
        let throw_c = runtime.alloc_host_thunk(HostThunk::MsvcpThrowCError);
        let result = dispatch_x86_thunk_result(&mut runtime, &mut memory, throw_c, &[1]);
        assert_eq!(result, Some(-0x1F92_8C9D));
    })
}

#[test]
fn crt_vsnprintf_s_null_buffer_with_count_aborts() {
    with_big_stack(|| {
        let (_temp, mut runtime, mut memory) = setup_crt_test_runtime();
        let vsnprintf_s = runtime.alloc_host_thunk(HostThunk::StdioCommonVsnprintfS);
        let format = runtime
            .alloc_utf16_string(&mut memory, "%d")
            .expect("format");
        let va_area = 0x63_000;
        memory.map_bytes(va_area, &[0_u8; 16]);
        write_u32(&mut memory, va_area, 12);
        let result = dispatch_x86_thunk_result(
            &mut runtime,
            &mut memory,
            vsnprintf_s,
            &[0, 0, 4, format as u32, 0, va_area as u32],
        );
        assert_eq!(result, Some(134));
        assert_eq!(runtime.crt_errno_get(&mut memory), EINVAL);
    })
}

#[test]
fn crt_get_errno_null_aborts_with_einval() {
    with_big_stack(|| {
        let (_temp, mut runtime, mut memory) = setup_crt_test_runtime();
        let get_errno = runtime.alloc_host_thunk(HostThunk::GetErrno);
        let result = dispatch_x86_thunk_result(&mut runtime, &mut memory, get_errno, &[0]);
        assert_eq!(result, Some(134));
        assert_eq!(runtime.crt_errno_get(&mut memory), EINVAL);
    })
}

#[test]
fn crt_fwrite_overflow_returns_zero_with_einval() {
    with_big_stack(|| {
        let (_temp, mut runtime, mut memory) = setup_crt_test_runtime();
        let fwrite = runtime.alloc_host_thunk(HostThunk::Fwrite);
        let buf = 0x64_000;
        memory.map_bytes(buf, &[0_u8; 16]);
        let stream = runtime.globals.iob_streams[1];
        // size * count overflows u64.
        let ret = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            fwrite,
            &[buf as u32, u32::MAX, u32::MAX, stream as u32],
        );
        assert_eq!(ret, 0);
        assert_eq!(runtime.crt_errno_get(&mut memory), EINVAL);
    })
}

#[test]
fn crt_putenv_empty_value_removes_variable() {
    with_big_stack(|| {
        let (_temp, mut runtime, mut memory) = setup_crt_test_runtime();
        runtime
            .process_environment
            .insert("DEL_ME".to_string(), "value".to_string());
        let putenv = runtime.alloc_host_thunk(HostThunk::Putenv);
        let s = runtime.alloc_c_string(&mut memory, "DEL_ME=").expect("s");
        let ret = dispatch_x86_thunk(&mut runtime, &mut memory, putenv, &[s as u32]);
        assert_eq!(ret, 0);
        assert!(
            !runtime
                .process_environment
                .iter()
                .any(|(key, _)| key.eq_ignore_ascii_case("DEL_ME"))
        );
    })
}

#[test]
fn crt_fgetc_and_fgets_set_errno_eio_on_read_error() {
    with_big_stack(|| {
        let (_temp, mut runtime, mut memory) = setup_crt_test_runtime();
        runtime
            .win32
            .create_directory_w("C:\\game")
            .expect("create guest dir");
        let path = "C:\\game\\eio.txt";
        fs::write(
            runtime
                .win32
                .guest_path_to_host_path(path)
                .expect("host path"),
            b"data",
        )
        .expect("write");
        let fopen = runtime.alloc_host_thunk(HostThunk::Fopen);
        let fgetc = runtime.alloc_host_thunk(HostThunk::Fgetc);
        let fgets = runtime.alloc_host_thunk(HostThunk::Fgets);
        let path_ptr = runtime.alloc_c_string(&mut memory, path).expect("path");
        let mode_ptr = runtime.alloc_c_string(&mut memory, "r").expect("mode");
        let fp = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            fopen,
            &[path_ptr as u32, mode_ptr as u32],
        );
        assert_ne!(fp, 0);

        // Break the backing handle behind the stream's back.
        let handle = runtime.crt_stream_state(fp).expect("state").handle;
        runtime.win32.close_handle(handle).expect("close handle");

        // fgetc → EOF with errno EIO.
        let ret = dispatch_x86_thunk(&mut runtime, &mut memory, fgetc, &[fp as u32]);
        assert_eq!(ret, EOF as u32 as u64);
        assert_eq!(runtime.crt_errno_get(&mut memory), EIO);

        // fgets → NULL with errno EIO.
        let set_errno = runtime.alloc_host_thunk(HostThunk::SetErrno);
        dispatch_x86_thunk(&mut runtime, &mut memory, set_errno, &[0]);
        let buf = 0x62_000;
        memory.map_bytes(buf, &[0_u8; 16]);
        let ret = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            fgets,
            &[buf as u32, 16, fp as u32],
        );
        assert_eq!(ret, 0);
        assert_eq!(runtime.crt_errno_get(&mut memory), EIO);
    })
}

#[test]
fn crt_vfprintf_write_error_returns_negative() {
    with_big_stack(|| {
        let (_temp, mut runtime, mut memory) = setup_crt_test_runtime();
        runtime
            .win32
            .create_directory_w("C:\\game")
            .expect("create guest dir");
        let path = "C:\\game\\ro.txt";
        fs::write(
            runtime
                .win32
                .guest_path_to_host_path(path)
                .expect("host path"),
            b"x",
        )
        .expect("write");
        let fopen = runtime.alloc_host_thunk(HostThunk::Fopen);
        let vfprintf = runtime.alloc_host_thunk(HostThunk::StdioCommonVfprintf);
        let path_ptr = runtime.alloc_c_string(&mut memory, path).expect("path");
        let mode_ptr = runtime.alloc_c_string(&mut memory, "w").expect("mode");
        let fp = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            fopen,
            &[path_ptr as u32, mode_ptr as u32],
        );
        assert_ne!(fp, 0);
        // Break the backing handle behind the stream's back.
        let handle = runtime.crt_stream_state(fp).expect("state").handle;
        runtime.win32.close_handle(handle).expect("close handle");
        let format = runtime
            .alloc_utf16_string(&mut memory, "hi")
            .expect("format");
        let va_area = 0x63_000;
        memory.map_bytes(va_area, &[0_u8; 16]);
        let written = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            vfprintf,
            &[0, fp as u32, format as u32, 0, va_area as u32],
        );
        assert_eq!(written, u32::MAX as u64, "write error → EOF (32-bit RAX)");
        assert_eq!(runtime.crt_errno_get(&mut memory), EIO);
    })
}

#[test]
fn crt_exit_abort_cexit_codes() {
    with_big_stack(|| {
        let (_temp, mut runtime, mut memory) = setup_crt_test_runtime();

        // _exit(code) records the process-exit request and returns the code.
        let crt_exit = runtime.alloc_host_thunk(HostThunk::CrtExit);
        let result = dispatch_x86_thunk_result(&mut runtime, &mut memory, crt_exit, &[7]);
        assert_eq!(result, Some(7));
        assert_eq!(runtime.process_exit_requested, Some(7));
        runtime.process_exit_requested = None;

        // exit(code) behaves the same way.
        let exit = runtime.alloc_host_thunk(HostThunk::Exit);
        let result = dispatch_x86_thunk_result(&mut runtime, &mut memory, exit, &[9]);
        assert_eq!(result, Some(9));
        assert_eq!(runtime.process_exit_requested, Some(9));
        runtime.process_exit_requested = None;

        // abort() terminates with the documented 134 (SIGABRT + 128).
        let abort = runtime.alloc_host_thunk(HostThunk::Abort);
        let result = dispatch_x86_thunk_result(&mut runtime, &mut memory, abort, &[]);
        assert_eq!(result, Some(134));
        assert_eq!(runtime.process_exit_requested, Some(134));
        runtime.process_exit_requested = None;

        // _cexit() is a plain return that does not request a process exit.
        let cexit = runtime.alloc_host_thunk(HostThunk::Cexit);
        assert_eq!(dispatch_x86_thunk(&mut runtime, &mut memory, cexit, &[]), 0);
        assert_eq!(runtime.process_exit_requested, None);
    })
}

#[test]
fn winspool_open_close_and_enum_dispatch() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge =
            GameEnvironment::create_in(temp_dir.path(), "winspool-enum", GeArch::X86, "win11-23h2")
                .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();

        let handle_out = 0x30_000_u64;
        write_guest_pointer(&mut memory, handle_out, 0, GuestArch::X86).expect("handle slot");
        let open = runtime.alloc_host_thunk(HostThunk::OpenPrinterW);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, open, &[0, handle_out as u32, 0]),
            1,
            "OpenPrinterW(NULL name) opens the default printer"
        );
        let handle = read_guest_pointer(&memory, handle_out, GuestArch::X86).expect("handle");
        assert_ne!(handle, 0, "OpenPrinterW writes a printer handle");

        let needed = 0x30_100_u64;
        let returned = 0x30_104_u64;
        let enum_thunk = runtime.alloc_host_thunk(HostThunk::EnumPrintersW);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                enum_thunk,
                &[0, 0, 2, 0, 0, needed as u32, returned as u32]
            ),
            0,
            "EnumPrintersW with no buffer reports the needed size"
        );
        assert_eq!(runtime.last_error, 122, "ERROR_INSUFFICIENT_BUFFER");
        let total_needed = memory.read_u32(needed).expect("needed");
        let count = memory.read_u32(returned).expect("returned");
        assert!(count >= 1, "at least the default printer is enumerated");
        assert!(total_needed > 0);

        let buffer = 0x40_000_u64;
        memory.map_bytes(buffer, &[0_u8; 8192]);
        write_u32(&mut memory, needed, 0);
        write_u32(&mut memory, returned, 0);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                enum_thunk,
                &[0, 0, 2, buffer as u32, 8192, needed as u32, returned as u32]
            ),
            1,
            "EnumPrintersW fills the PRINTER_INFO_2W buffer"
        );
        assert_eq!(memory.read_u32(returned).expect("returned"), count);
        assert_eq!(
            memory.read_u32(buffer + 64).expect("attributes"),
            runtime
                .print_subsystem
                .get_printer(handle)
                .expect("printer")
                .attributes,
            "the first PRINTER_INFO_2W carries the printer attributes"
        );

        // A too-small buffer reports ERROR_INSUFFICIENT_BUFFER.
        let small = 0x40_800_u64;
        memory.map_bytes(small, &[0_u8; 64]);
        write_u32(&mut memory, needed, 0);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                enum_thunk,
                &[0, 0, 2, small as u32, 64, needed as u32, returned as u32]
            ),
            0,
            "EnumPrintersW fails on a small buffer"
        );
        assert_eq!(runtime.last_error, 122, "ERROR_INSUFFICIENT_BUFFER");

        let close = runtime.alloc_host_thunk(HostThunk::ClosePrinter);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, close, &[handle as u32]),
            1,
            "ClosePrinter returns TRUE"
        );
    })
}

#[test]
fn version_dll_query_roundtrip_dispatch() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge =
            GameEnvironment::create_in(temp_dir.path(), "version-dll", GeArch::X86, "win11-23h2")
                .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();

        // Stage a PE with an RT_VERSION resource into the guest filesystem.
        let pe_bytes = version_pe_for_test();
        let host_src = temp_dir.path().join("versioned.exe");
        std::fs::write(&host_src, &pe_bytes).expect("write host pe");
        runtime
            .win32
            .stage_host_file_w(&host_src, "C:\\versioned.exe")
            .expect("stage guest pe");

        let filename = runtime
            .alloc_utf16_string(&mut memory, "C:\\versioned.exe")
            .expect("filename");
        let handle_slot = 0x30_000_u64;
        write_u32(&mut memory, handle_slot, 0xFF);

        let size_thunk = runtime.alloc_host_thunk(HostThunk::GetFileVersionInfoSizeW);
        let blob_len = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            size_thunk,
            &[filename as u32, handle_slot as u32],
        );
        assert!(
            blob_len > 0,
            "GetFileVersionInfoSizeW returns the blob size"
        );
        assert_eq!(
            memory.read_u32(handle_slot).expect("reserved handle"),
            0,
            "the reserved handle slot is zeroed"
        );

        let data_ptr = 0x40_000_u64;
        memory.map_bytes(data_ptr, &[0_u8; 4096]);
        let info_thunk = runtime.alloc_host_thunk(HostThunk::GetFileVersionInfoW);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                info_thunk,
                &[filename as u32, 0, blob_len as u32, data_ptr as u32]
            ),
            1,
            "GetFileVersionInfoW copies the version blob"
        );
        let copied = memory
            .read_bytes(data_ptr, blob_len as usize)
            .expect("blob bytes");
        let expected = version_resource_blob_for_test();
        assert_eq!(copied, expected, "the blob bytes are intact");

        // VerQueryValueW("\\") → VS_FIXEDFILEINFO.
        let buffer_ptr = 0x30_100_u64;
        let len_ptr = 0x30_104_u64;
        let fixed_sub = runtime
            .alloc_utf16_string(&mut memory, "\\")
            .expect("fixed subblock");
        let query = runtime.alloc_host_thunk(HostThunk::VerQueryValueW);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                query,
                &[
                    data_ptr as u32,
                    fixed_sub as u32,
                    buffer_ptr as u32,
                    len_ptr as u32
                ]
            ),
            1,
            "VerQueryValueW(\\) finds the fixed file info"
        );
        assert_eq!(
            memory.read_u32(len_ptr).expect("fixed len"),
            52,
            "sizeof(VS_FIXEDFILEINFO)"
        );
        let fixed_addr =
            read_guest_pointer(&memory, buffer_ptr, GuestArch::X86).expect("fixed addr");
        let signature = memory.read_u32(fixed_addr).expect("signature");
        assert_eq!(signature, 0xfeef_04bd, "VS_FIXEDFILEINFO signature");
        let file_version_ms = memory.read_u32(fixed_addr + 8).expect("ms");
        assert_eq!(
            file_version_ms,
            (1 << 16) | 2,
            "dwFileVersionMS encodes 1.2"
        );

        // VerQueryValueW("\StringFileInfo\040904b0\FileVersion") → "1.2.3.4".
        let string_sub = runtime
            .alloc_utf16_string(&mut memory, "\\StringFileInfo\\040904b0\\FileVersion")
            .expect("string subblock");
        let value_ptr = 0x30_200_u64;
        let value_len_ptr = 0x30_204_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                query,
                &[
                    data_ptr as u32,
                    string_sub as u32,
                    value_ptr as u32,
                    value_len_ptr as u32
                ]
            ),
            1,
            "VerQueryValueW(StringFileInfo) finds the string value"
        );
        let value_addr =
            read_guest_pointer(&memory, value_ptr, GuestArch::X86).expect("value addr");
        let value_bytes = memory
            .read_bytes(
                value_addr,
                memory.read_u32(value_len_ptr).expect("len") as usize,
            )
            .expect("value bytes");
        let value = String::from_utf16_lossy(
            &value_bytes
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect::<Vec<_>>(),
        );
        assert_eq!(
            value.trim_end_matches('\0'),
            "1.2.3.4",
            "the StringFileInfo value is the file version"
        );

        // Unknown sub-blocks fail with ERROR_INVALID_PARAMETER.
        let unknown_sub = runtime
            .alloc_utf16_string(&mut memory, "\\NoSuchBlock")
            .expect("unknown subblock");
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                query,
                &[
                    data_ptr as u32,
                    unknown_sub as u32,
                    value_ptr as u32,
                    value_len_ptr as u32
                ]
            ),
            0,
            "unknown sub-blocks fail"
        );
        assert_eq!(runtime.last_error, 87, "ERROR_INVALID_PARAMETER");
    })
}

#[test]
fn evidence_d3d8thk_esent_wsp_wininet_dinput_surfaces() {
    crate::runtime::dispatch::d3d8thk::reset_test_facade();
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("evidence-mixed");
        let mut memory = MemoryImage::default();

        // ── d3d8thk: the adapter/device/swapchain lifecycle ──
        let enum_adapters: u64 = runtime.alloc_host_thunk(HostThunk::D3DKMTEnumAdapters);
        let open_adapter: u64 = runtime.alloc_host_thunk(HostThunk::D3DKMTOpenAdapterFromLuid);
        let create_device: u64 = runtime.alloc_host_thunk(HostThunk::D3DKMTCreateDevice);
        let create_swapchain: u64 = runtime.alloc_host_thunk(HostThunk::D3DKMTCreateSwapChain);
        let present: u64 = runtime.alloc_host_thunk(HostThunk::D3DKMTPresent);
        let destroy_swapchain: u64 = runtime.alloc_host_thunk(HostThunk::D3DKMTDestroySwapchain);
        let destroy_device: u64 = runtime.alloc_host_thunk(HostThunk::D3DKMTDestroyDevice);
        let close_adapter: u64 = runtime.alloc_host_thunk(HostThunk::D3DKMTCloseAdapter);
        let enum_info = 0x41_000_u64;
        let adapter_list = 0x41_008_u64;
        write_guest_u32(&mut memory, enum_info, 0).ok();
        write_guest_u32(&mut memory, enum_info + 4, 0).ok();
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                enum_adapters,
                &[enum_info as u32]
            ),
            0
        );
        assert_eq!(
            read_guest_u32(&memory, enum_info).unwrap(),
            1,
            "one adapter"
        );
        write_guest_u32(&mut memory, enum_info, 1).ok();
        write_guest_pointer(&mut memory, enum_info + 4, adapter_list, GuestArch::X86).ok();
        memory.map_bytes(adapter_list, &[0_u8; 20]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                enum_adapters,
                &[enum_info as u32]
            ),
            0
        );
        let open_info = 0x41_020_u64;
        memory.map_bytes(open_info, &[0_u8; 12]);
        let adapter_luid_low = read_guest_u32(&memory, adapter_list + 4).unwrap();
        let adapter_luid_high = read_guest_u32(&memory, adapter_list + 8).unwrap();
        write_guest_u32(&mut memory, open_info, adapter_luid_low).ok();
        write_guest_u32(&mut memory, open_info + 4, adapter_luid_high).ok();
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, open_adapter, &[open_info as u32]),
            0
        );
        let adapter = read_guest_u32(&memory, open_info + 8).unwrap();
        assert_ne!(adapter, 0);
        let device_info = 0x41_030_u64;
        memory.map_bytes(device_info, &[0_u8; 12]);
        write_guest_u32(&mut memory, device_info, adapter).ok();
        write_guest_u32(&mut memory, device_info + 4, 0).ok();
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                create_device,
                &[device_info as u32]
            ),
            0
        );
        let device = read_guest_u32(&memory, device_info + 8).unwrap();
        assert_ne!(device, 0);
        let swap_info = 0x41_040_u64;
        memory.map_bytes(swap_info, &[0_u8; 28]);
        write_guest_u32(&mut memory, swap_info, device).ok();
        write_guest_u32(&mut memory, swap_info + 4, 8).ok();
        write_guest_u32(&mut memory, swap_info + 8, 8).ok();
        write_guest_u32(&mut memory, swap_info + 12, 87).ok();
        write_guest_u32(&mut memory, swap_info + 16, 2).ok();
        write_guest_u32(&mut memory, swap_info + 20, 0).ok();
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                create_swapchain,
                &[swap_info as u32]
            ),
            0
        );
        let swapchain = read_guest_u32(&memory, swap_info + 24).unwrap();
        assert_ne!(swapchain, 0);
        let present_info = 0x41_060_u64;
        memory.map_bytes(present_info, &[0_u8; 56]);
        write_guest_u32(&mut memory, present_info, device).ok();
        write_guest_u32(&mut memory, present_info + 4, swapchain).ok();
        write_guest_u32(&mut memory, present_info + 8, 1).ok();
        write_guest_u32(&mut memory, present_info + 12, 0).ok();
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, present, &[present_info as u32]),
            0
        );
        assert_eq!(
            read_guest_u64(&memory, present_info + 16).unwrap(),
            1,
            "one present"
        );
        assert_eq!(
            read_guest_u64(&memory, present_info + 24).unwrap(),
            1,
            "one refresh"
        );
        let swap_close = 0x41_0A0_u64;
        write_guest_u32(&mut memory, swap_close, swapchain).ok();
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                destroy_swapchain,
                &[swap_close as u32]
            ),
            0
        );
        let device_close = 0x41_0A8_u64;
        write_guest_u32(&mut memory, device_close, device).ok();
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                destroy_device,
                &[device_close as u32]
            ),
            0
        );
        let close_info = 0x41_0B0_u64;
        write_guest_u32(&mut memory, close_info, adapter).ok();
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                close_adapter,
                &[close_info as u32]
            ),
            0
        );

        // ── esent: the engine lifecycle ──
        let jet_init: u64 = runtime.alloc_host_thunk(HostThunk::JetInit);
        let jet_create: u64 = runtime.alloc_host_thunk(HostThunk::JetCreateDatabase);
        let jet_open_table: u64 = runtime.alloc_host_thunk(HostThunk::JetOpenTable);
        let jet_close: u64 = runtime.alloc_host_thunk(HostThunk::JetCloseDatabase);
        let jet_term: u64 = runtime.alloc_host_thunk(HostThunk::JetTerm);
        let instance = 0x7000_0001_u64;
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, jet_init, &[instance as u32]),
            0
        );
        let db_path = 0x41_100_u64;
        let db_wide: Vec<u16> = std::env::temp_dir()
            .join("casa1-evidence.edb")
            .to_string_lossy()
            .encode_utf16()
            .chain([0])
            .collect();
        for (i, unit) in db_wide.iter().enumerate() {
            write_guest_u16(&mut memory, db_path + (i as u64 * 2), *unit).ok();
        }
        let db_out = 0x41_200_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                jet_create,
                &[instance as u32, 0, db_path as u32, 0, 0, db_out as u32]
            ),
            0
        );
        let db = read_guest_pointer(&memory, db_out, GuestArch::X86).unwrap();
        assert_ne!(db, 0);
        let table_ptr = 0x41_210_u64;
        let table_wide: Vec<u16> = "Table1".encode_utf16().chain([0]).collect();
        for (i, unit) in table_wide.iter().enumerate() {
            write_guest_u16(&mut memory, table_ptr + (i as u64 * 2), *unit).ok();
        }
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                jet_open_table,
                &[instance as u32, 0, db as u32, table_ptr as u32, 0x41_220, 0]
            ),
            0xffff_fa8d,
            "JET_errObjectNotFound"
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                jet_close,
                &[instance as u32, db as u32, 0]
            ),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, jet_term, &[instance as u32, 0]),
            0
        );

        // ── msafd: the provider socket ──
        let wsp_startup: u64 = runtime.alloc_host_thunk(HostThunk::WSPStartup);
        let wsp_socket: u64 = runtime.alloc_host_thunk(HostThunk::WSPSocket);
        let wsp_cleanup: u64 = runtime.alloc_host_thunk(HostThunk::WSPCleanup);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, wsp_startup, &[0x0202, 0x41_300]),
            0
        );
        let socket = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            wsp_socket,
            &[2, 1, 6, 0, 0, 0, 0, 0],
        );
        assert_ne!(socket, 0xffff_ffff, "the provider socket");
        assert!(
            runtime.win32_is_socket(socket),
            "socket {socket:#x} is a winsock handle"
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, wsp_cleanup, &[]),
            0
        );

        // ── wininet: the request object ──
        let attempt_connect: u64 = runtime.alloc_host_thunk(HostThunk::InternetAttemptConnect);
        let open_url: u64 = runtime.alloc_host_thunk(HostThunk::InternetOpenUrlW);
        let read_file: u64 = runtime.alloc_host_thunk(HostThunk::InternetReadFileExW);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, attempt_connect, &[]),
            0
        );
        let url_ptr = 0x41_400_u64;
        let url_wide: Vec<u16> = "https://example.com/".encode_utf16().chain([0]).collect();
        for (i, unit) in url_wide.iter().enumerate() {
            write_guest_u16(&mut memory, url_ptr + (i as u64 * 2), *unit).ok();
        }
        let request = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            open_url,
            &[0, url_ptr as u32, 0, 0, 0, 0],
        );
        assert_ne!(request, 0);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                read_file,
                &[request as u32, 0, 0, 0]
            ),
            0
        );
        assert_eq!(runtime.last_error, 12029, "ERROR_INTERNET_CANNOT_CONNECT");

        // ── dinput: the object + no devices ──
        let di_create: u64 = runtime.alloc_host_thunk(HostThunk::DirectInputCreateW);
        let di_device: u64 = runtime.alloc_host_thunk(HostThunk::DirectInputCreateDevice);
        let di_out = 0x41_500_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                di_create,
                &[0, 0x0800, di_out as u32, 0]
            ),
            0
        );
        let di = read_guest_pointer(&memory, di_out, GuestArch::X86).unwrap();
        assert_ne!(di, 0);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                di_device,
                &[di as u32, 0x41_510, 0x41_520]
            ),
            0x8007_0012,
            "DIERR_DEVICENOTREG"
        );
    })
}

#[test]
fn evidence_system_sweep_surfaces() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("evidence-sweep");
        let mut memory = MemoryImage::default();

        // ── comctl32: the image-list metrics ──
        let icon_size: u64 = runtime.alloc_host_thunk(HostThunk::ImageListGetIconSize);
        let width_out = 0x41_000_u64;
        let height_out = 0x41_010_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                icon_size,
                &[0x2000, width_out as u32, height_out as u32]
            ),
            1
        );
        assert_eq!(read_guest_u32(&memory, width_out).unwrap(), 16);
        assert_eq!(read_guest_u32(&memory, height_out).unwrap(), 16);

        // ── cfgmgr32: the device list ──
        let device_list: u64 = runtime.alloc_host_thunk(HostThunk::CmGetDeviceIdListW);
        let buffer = 0x41_100_u64;
        let size_out = 0x41_110_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                device_list,
                &[0, buffer as u32, size_out as u32, 0]
            ),
            0
        );
        assert_eq!(
            read_guest_u32(&memory, size_out).unwrap(),
            2,
            "empty device list"
        );

        // ── powrprof: the active scheme ──
        let active_scheme: u64 = runtime.alloc_host_thunk(HostThunk::PowerGetActiveScheme);
        let scheme_out = 0x41_200_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                active_scheme,
                &[0, scheme_out as u32]
            ),
            0
        );
        let scheme = read_guest_pointer(&memory, scheme_out, GuestArch::X86).unwrap();
        assert_ne!(scheme, 0);

        // ── wintypes ──
        let ro_init: u64 = runtime.alloc_host_thunk(HostThunk::RoInitialize);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, ro_init, &[0]),
            0
        );

        // ── winhttp: the time format round trip ──
        let time_from: u64 = runtime.alloc_host_thunk(HostThunk::WinHttpTimeFromSystemTime);
        let system_time = 0x41_300_u64;
        write_guest_u16(&mut memory, system_time, 2026).ok();
        write_guest_u16(&mut memory, system_time + 2, 1).ok();
        write_guest_u16(&mut memory, system_time + 6, 15).ok();
        write_guest_u16(&mut memory, system_time + 8, 10).ok();
        write_guest_u16(&mut memory, system_time + 10, 30).ok();
        write_guest_u16(&mut memory, system_time + 12, 45).ok();
        let time_buffer = 0x41_400_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                time_from,
                &[system_time as u32, time_buffer as u32, 64]
            ),
            1
        );
        let text = memory.read_bytes(time_buffer, 23).unwrap();
        let text = String::from_utf8_lossy(&text).to_string();
        assert!(
            text.contains("15, 01 2026 10:30:45"),
            "the HTTP time format: {text}"
        );

        // ── urlmon: the user agent ──
        let user_agent: u64 = runtime.alloc_host_thunk(HostThunk::ObtainUserAgentString);
        let agent_buffer = 0x41_500_u64;
        let agent_size = 0x41_520_u64;
        write_guest_u32(&mut memory, agent_size, 64).ok();
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                user_agent,
                &[0, agent_buffer as u32, agent_size as u32]
            ),
            0
        );
        let len = read_guest_u32(&memory, agent_size).unwrap() as usize;
        let agent_bytes = memory
            .read_bytes(agent_buffer, len.saturating_sub(1))
            .unwrap();
        let agent = String::from_utf8_lossy(&agent_bytes).to_string();
        assert!(agent.contains("Casa1"), "the user agent: {agent}");

        // ── rasapi32: the honest no-connections ──
        let ras_enum: u64 = runtime.alloc_host_thunk(HostThunk::RasEnumConnections);
        let count_out = 0x41_600_u64;
        let hr = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            ras_enum,
            &[0, 0x41_610, count_out as u32],
        );
        assert_eq!(hr, 0x60b, "ERROR_BUFFER_TOO_SMALL (no connections)");

        // ── wbemprox: the WMI session ──
        let wmi_connect: u64 = runtime.alloc_host_thunk(HostThunk::WmiConnect);
        let wmi_query: u64 = runtime.alloc_host_thunk(HostThunk::WmiQuery);
        let wmi_close: u64 = runtime.alloc_host_thunk(HostThunk::WmiClose);
        let handle = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            wmi_connect,
            &[0, 0x41_620, 0, 0, 0, 0],
        );
        assert_ne!(handle, 0);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                wmi_query,
                &[handle as u32, 0x41_630, 0, 0, 0x41_640]
            ),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, wmi_close, &[handle as u32]),
            0
        );

        // ── dsound: the no-driver answer ──
        let ds_create: u64 = runtime.alloc_host_thunk(HostThunk::DirectSoundCreate8);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, ds_create, &[0, 0x41_700, 0]),
            0x8878_0007,
            "DSERR_NODRIVER"
        );
    })
}

#[test]
fn evidence_long_tail_surfaces() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("evidence-tail");
        let mut memory = MemoryImage::default();

        // ── ATL module server ──
        let atl_register: u64 = runtime.alloc_host_thunk(HostThunk::AtlModuleRegisterServer);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, atl_register, &[0]),
            0
        );

        // ── the CRT sync primitives ──
        let mtx_init: u64 = runtime.alloc_host_thunk(HostThunk::MtxInit);
        let mtx_lock: u64 = runtime.alloc_host_thunk(HostThunk::MtxLock);
        let mtx_unlock: u64 = runtime.alloc_host_thunk(HostThunk::MtxUnlock);
        let mtx_destroy: u64 = runtime.alloc_host_thunk(HostThunk::MtxDestroy);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, mtx_init, &[0x41_000]),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, mtx_lock, &[0x41_000]),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, mtx_unlock, &[0x41_000]),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, mtx_destroy, &[0x41_000]),
            0
        );

        // ── steam session ──
        let steam_logged: u64 = runtime.alloc_host_thunk(HostThunk::SteamBLoggedOn);
        let steam_id: u64 = runtime.alloc_host_thunk(HostThunk::SteamBGetSteamId);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, steam_logged, &[]),
            1
        );
        let id_out = 0x41_100_u64;
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, steam_id, &[id_out as u32]),
            1
        );
        assert_eq!(
            read_guest_u64(&memory, id_out).unwrap(),
            0x1100_0001_0000_0001
        );

        // ── mscorwks: the CLR-absent answers ──
        let clr_managed: u64 = runtime.alloc_host_thunk(HostThunk::ClrCreateManagedInstance);
        let out = 0x41_200_u64;
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, clr_managed, &[0, 0, out as u32]),
            0x8013_1013
        );
        assert_eq!(read_guest_pointer(&memory, out, GuestArch::X86).unwrap(), 0);

        // ── ntdsapi: the no-domain answers ──
        let ds_bind: u64 = runtime.alloc_host_thunk(HostThunk::DsBind);
        let bind_out = 0x41_300_u64;
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, ds_bind, &[0, bind_out as u32]),
            0x8007_0e8d,
            "ERROR_DS_NOT_AVAILABLE"
        );
        assert_eq!(
            read_guest_pointer(&memory, bind_out, GuestArch::X86).unwrap(),
            0
        );

        // ── xinput9_1_0: the no-device answers ──
        let xi_state: u64 = runtime.alloc_host_thunk(HostThunk::XInputGetState);
        let xi_hr = dispatch_x86_thunk(&mut runtime, &mut memory, xi_state, &[0, 0x41_400]);
        assert!(xi_hr != 0, "the xinput surface answers an honest failure");

        // ── the WIC extensions: the no-codec answer ──
        let wic_webp: u64 = runtime.alloc_host_thunk(HostThunk::WicCreateWebpDecoder);
        let codec_out = 0x41_500_u64;
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, wic_webp, &[0, codec_out as u32]),
            0x8898_2f02,
            "WIC_E_CODECNOTFOUND"
        );
        assert_eq!(
            read_guest_pointer(&memory, codec_out, GuestArch::X86).unwrap(),
            0
        );
    })
}

#[test]
fn evidence_final_scraps_surfaces() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("evidence-scraps");
        let mut memory = MemoryImage::default();

        let x3da_init: u64 = runtime.alloc_host_thunk(HostThunk::X3dAudioInitialize);
        let x3da_calc: u64 = runtime.alloc_host_thunk(HostThunk::X3dAudioCalculate);
        let handle_out = 0x41_000_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                x3da_init,
                &[0x3, 343.5f32.to_bits(), handle_out as u32]
            ),
            0
        );
        // The initialize call writes a real opaque instance handle: our
        // magic prefix + the instance's speaker mask + speed of sound.
        assert_eq!(
            read_u32(&memory, handle_out).unwrap(),
            0x3144_3358,
            "the X3DAudio instance handle carries the runtime magic"
        );
        assert_eq!(read_u32(&memory, handle_out + 4).unwrap(), 0x3);
        assert_eq!(
            f32::from_bits(read_u32(&memory, handle_out + 8).unwrap()),
            343.5
        );
        // A calculate with no listener/emitter/DSP settings is an
        // invalid call (deterministic error, not a silent zero).
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                x3da_calc,
                &[handle_out as u32, 0, 0, 0x7f, 0x41_010]
            ),
            1,
            "null listener/emitter must not be a silent success"
        );

        let persist: u64 = runtime.alloc_host_thunk(HostThunk::IPersistFile);
        let iid_ptr = dispatch_x86_thunk(&mut runtime, &mut memory, persist, &[]);
        assert_ne!(iid_ptr, 0);
        assert_eq!(
            memory.read_bytes(iid_ptr, 16).unwrap()[0],
            0x0b,
            "IID_IPersistFile data"
        );
        let d3d12_heap: u64 = runtime.alloc_host_thunk(HostThunk::ID3d12Heap);
        assert_ne!(
            dispatch_x86_thunk(&mut runtime, &mut memory, d3d12_heap, &[]),
            0
        );

        let net_dc: u64 = runtime.alloc_host_thunk(HostThunk::NetGetDcName);
        let dc_out = 0x41_100_u64;
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, net_dc, &[0, 0, dc_out as u32]),
            0x54b,
            "NERR_DCNotFound"
        );
        assert_eq!(
            read_guest_pointer(&memory, dc_out, GuestArch::X86).unwrap(),
            0
        );

        let dp_create: u64 = runtime.alloc_host_thunk(HostThunk::DirectPlayCreate);
        let dp_out = 0x41_200_u64;
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, dp_create, &[0, dp_out as u32, 0]),
            0,
            "the legacy DirectPlay object is real"
        );
        assert_ne!(
            read_guest_pointer(&memory, dp_out, GuestArch::X86).unwrap(),
            0
        );

        let gdip: u64 = runtime.alloc_host_thunk(HostThunk::GdipCreateGraphics);
        let g_out = 0x41_300_u64;
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, gdip, &[0, g_out as u32]),
            0
        );
        assert_ne!(
            read_guest_pointer(&memory, g_out, GuestArch::X86).unwrap(),
            0
        );

        let nt_map: u64 = runtime.alloc_host_thunk(HostThunk::NtCreateFileMapping);
        let section_out = 0x41_400_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                nt_map,
                &[0xffff_ffff, 0, 0, 0, 0x1000, section_out as u32]
            ),
            0
        );
        assert_ne!(
            read_guest_pointer(&memory, section_out, GuestArch::X86).unwrap(),
            0
        );
    })
}
