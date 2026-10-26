use super::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IrInstruction {
    Cpuid,
    Xgetbv,
    MovImm {
        dst: Register,
        value: u64,
    },
    MovImm8 {
        dst: ByteRegister,
        value: u8,
    },
    MovReg {
        dst: Register,
        src: Register,
        width: usize,
    },
    MovReg8 {
        dst: ByteRegister,
        src: ByteRegister,
    },
    MovdFromXmm {
        dst: Register,
        src: u8,
    },
    NotMemory {
        address: MemoryOperand,
        width: usize,
    },
    AddImm {
        dst: Register,
        value: u64,
        width: usize,
    },
    AddReg8 {
        dst: ByteRegister,
        src: ByteRegister,
    },
    AddReg8Op {
        dst: ByteRegister,
        src: CompareOperand,
    },
    AddMemory8 {
        address: MemoryOperand,
        src: ByteRegister,
    },
    AddOperand {
        dst: Register,
        src: CompareOperand,
        width: usize,
    },
    AddMemory {
        address: MemoryOperand,
        src: Register,
        width: usize,
    },
    AddImmMemory {
        address: MemoryOperand,
        value: u64,
        width: usize,
    },
    AdcOperand {
        dst: Register,
        src: CompareOperand,
        width: usize,
    },
    AdcReg8Op {
        dst: ByteRegister,
        src: CompareOperand,
    },
    AdcMemory {
        address: MemoryOperand,
        src: Register,
        width: usize,
    },
    AdcMemory8 {
        address: MemoryOperand,
        src: ByteRegister,
    },
    AdcImm {
        dst: Register,
        value: u64,
        width: usize,
    },
    AdcImm8 {
        dst: ByteRegister,
        value: u8,
    },
    AddImm8 {
        dst: ByteRegister,
        value: u8,
    },
    AdcImmMemory {
        address: MemoryOperand,
        value: u64,
        width: usize,
    },
    OrImm {
        dst: Register,
        value: u64,
        width: usize,
    },
    OrImm8 {
        dst: ByteRegister,
        value: u8,
    },
    AndImm8 {
        dst: ByteRegister,
        value: u8,
    },
    OrImmMemory {
        address: MemoryOperand,
        value: u64,
        width: usize,
    },
    SubImm {
        dst: Register,
        value: u64,
        width: usize,
    },
    SubImm8 {
        dst: ByteRegister,
        value: u8,
    },
    SubImmMemory {
        address: MemoryOperand,
        value: u64,
        width: usize,
    },
    AndImm {
        dst: Register,
        value: u64,
        width: usize,
    },
    AndImmMemory {
        address: MemoryOperand,
        value: u64,
        width: usize,
    },
    AndReg {
        dst: Register,
        src: CompareOperand,
        width: usize,
    },
    AndMemory {
        address: MemoryOperand,
        src: Register,
        width: usize,
    },
    RolImm {
        dst: Register,
        count: u8,
        width: usize,
    },
    RorImm {
        dst: Register,
        count: u8,
        width: usize,
    },
    RclImm {
        dst: Register,
        count: u8,
        width: usize,
    },
    RcrImm {
        dst: Register,
        count: u8,
        width: usize,
    },
    RolImmMemory {
        address: MemoryOperand,
        count: u8,
        width: usize,
    },
    RorImmMemory {
        address: MemoryOperand,
        count: u8,
        width: usize,
    },
    RclImmMemory {
        address: MemoryOperand,
        count: u8,
        width: usize,
    },
    RcrImmMemory {
        address: MemoryOperand,
        count: u8,
        width: usize,
    },
    ShlImm {
        dst: Register,
        count: u8,
        width: usize,
    },
    ShrImm {
        dst: Register,
        count: u8,
        width: usize,
    },
    SarImm {
        dst: Register,
        count: u8,
        width: usize,
    },
    ShlImmMemory {
        address: MemoryOperand,
        count: u8,
        width: usize,
    },
    ShrImmMemory {
        address: MemoryOperand,
        count: u8,
        width: usize,
    },
    SarImmMemory {
        address: MemoryOperand,
        count: u8,
        width: usize,
    },
    RolCl {
        dst: Register,
        width: usize,
    },
    RclCl {
        dst: Register,
        width: usize,
    },
    RcrCl {
        dst: Register,
        width: usize,
    },
    RolClMemory {
        address: MemoryOperand,
        width: usize,
    },
    RorClMemory {
        address: MemoryOperand,
        width: usize,
    },
    RclClMemory {
        address: MemoryOperand,
        width: usize,
    },
    RcrClMemory {
        address: MemoryOperand,
        width: usize,
    },
    ShlClMemory {
        address: MemoryOperand,
        width: usize,
    },
    ShrClMemory {
        address: MemoryOperand,
        width: usize,
    },
    SarClMemory {
        address: MemoryOperand,
        width: usize,
    },
    ShlCl {
        dst: Register,
        width: usize,
    },
    RorCl {
        dst: Register,
        width: usize,
    },
    ShrCl {
        dst: Register,
        width: usize,
    },
    SarCl {
        dst: Register,
        width: usize,
    },
    ShldImm {
        dst: Register,
        src: Register,
        count: u8,
        width: usize,
    },
    ShldCl {
        dst: Register,
        src: Register,
        width: usize,
    },
    ShrdImm {
        dst: Register,
        src: Register,
        count: u8,
        width: usize,
    },
    ImulImm {
        dst: Register,
        src: CompareOperand,
        imm: u64,
        width: usize,
    },
    ImulReg {
        dst: Register,
        src: CompareOperand,
        width: usize,
    },
    MulAcc {
        src: CompareOperand,
        width: usize,
    },
    ImulAcc {
        src: CompareOperand,
        width: usize,
    },
    Div {
        src: CompareOperand,
        width: usize,
    },
    Idiv {
        src: CompareOperand,
        width: usize,
    },
    SubReg8 {
        dst: ByteRegister,
        src: CompareOperand,
    },
    SbbReg8 {
        dst: ByteRegister,
        src: CompareOperand,
    },
    NegReg {
        dst: Register,
        width: usize,
    },
    NegReg8 {
        dst: ByteRegister,
    },
    NotReg {
        dst: Register,
        width: usize,
    },
    NotReg8 {
        dst: ByteRegister,
    },
    Cdq {
        width: usize,
    },
    Movs {
        width: usize,
        repeat: bool,
    },
    Stos {
        width: usize,
        repeat: bool,
    },
    Lods {
        width: usize,
        repeat: bool,
    },
    Cmps {
        width: usize,
        repeat: bool,
        repne: bool,
    },
    Scas {
        width: usize,
        repeat: bool,
        repne: bool,
    },
    /// BOUND instruction: check if register value is within bounds specified
    /// by a memory operand (pair of signed values). Raises #BR (INT 5) if
    /// the register value is out of range. Only valid in 32-bit mode.
    Bound {
        reg: Register,
        address: MemoryOperand,
        width: usize,
    },
    Hlt,
    Cli,
    Sti,
    Std,
    Ud2,
    Sahf,
    Lahf,
    SetCarryFlag {
        value: bool,
    },
    ComplementCarryFlag,
    PushAll,
    PopAll,
    LoadSegment {
        segment: u8,
        src: CompareOperand,
    },
    PortIn {
        port: Option<u16>,
        width: usize,
    },
    PortOut {
        port: Option<u16>,
        width: usize,
    },
    MovFromDr {
        dst: Register,
        index: u8,
    },
    MovToDr {
        index: u8,
        src: Register,
    },
    Fxsave {
        address: MemoryOperand,
    },
    Fxrstor {
        address: MemoryOperand,
    },
    Xsave {
        address: MemoryOperand,
    },
    Xsaveopt {
        address: MemoryOperand,
    },
    Xrstor {
        address: MemoryOperand,
    },
    SubOperand {
        dst: Register,
        src: CompareOperand,
        width: usize,
    },
    SubMemory {
        address: MemoryOperand,
        src: Register,
        width: usize,
    },
    SubMemory8 {
        address: MemoryOperand,
        src: ByteRegister,
    },
    SbbMemory {
        address: MemoryOperand,
        src: Register,
        width: usize,
    },
    SbbMemory8 {
        address: MemoryOperand,
        src: ByteRegister,
    },
    SbbImm8 {
        dst: ByteRegister,
        value: u8,
    },
    SbbImm {
        dst: Register,
        value: u64,
        width: usize,
    },
    SbbOperand {
        dst: Register,
        src: CompareOperand,
        width: usize,
    },
    Compare {
        lhs: CompareOperand,
        rhs: CompareOperand,
        width: usize,
    },
    Test {
        lhs: CompareOperand,
        rhs: CompareOperand,
        width: usize,
    },
    ExchangeRegisters {
        left: Register,
        right: Register,
        width: usize,
    },
    ExchangeMemory {
        address: MemoryOperand,
        register: Register,
        width: usize,
    },
    ExchangeRegisters8 {
        left: ByteRegister,
        right: ByteRegister,
    },
    ExchangeMemory8 {
        address: MemoryOperand,
        reg: ByteRegister,
    },
    SignExtendTo64 {
        dst: Register,
        src: CompareOperand,
        width: usize,
    },
    SignExtend {
        dst: Register,
        src: CompareOperand,
        src_width: usize,
        dst_width: usize,
    },
    ZeroExtendTo64 {
        dst: Register,
        src: CompareOperand,
        width: usize,
    },
    XorImm {
        dst: Register,
        value: u64,
        width: usize,
    },
    XorImm8 {
        dst: ByteRegister,
        value: u8,
    },
    XorImmMemory {
        address: MemoryOperand,
        value: u64,
        width: usize,
    },
    XorReg {
        dst: Register,
        src: CompareOperand,
        width: usize,
    },
    XorReg8 {
        dst: ByteRegister,
        src: ByteRegister,
    },
    XorReg8Op {
        dst: ByteRegister,
        src: CompareOperand,
    },
    XorMemory8 {
        address: MemoryOperand,
        src: ByteRegister,
    },
    XorMemory {
        address: MemoryOperand,
        src: Register,
        width: usize,
    },
    OrReg {
        dst: Register,
        src: CompareOperand,
        width: usize,
    },
    OrMemory {
        address: MemoryOperand,
        src: Register,
        width: usize,
    },
    OrMemory8 {
        address: MemoryOperand,
        src: ByteRegister,
    },
    AndReg8 {
        dst: ByteRegister,
        src: ByteRegister,
    },
    AndReg8Op {
        dst: ByteRegister,
        src: CompareOperand,
    },
    AndMemory8 {
        address: MemoryOperand,
        src: ByteRegister,
    },
    BitTest {
        base: Register,
        bit: Register,
        width: usize,
    },
    BitTestImm {
        src: CompareOperand,
        bit: u64,
        width: usize,
    },
    OrReg8 {
        dst: ByteRegister,
        src: ByteRegister,
    },
    OrReg8Op {
        dst: ByteRegister,
        src: CompareOperand,
    },
    IncReg {
        dst: Register,
        width: usize,
    },
    DecReg {
        dst: Register,
        width: usize,
    },
    IncReg8 {
        dst: ByteRegister,
    },
    DecReg8 {
        dst: ByteRegister,
    },
    IncMemory {
        address: MemoryOperand,
        width: usize,
    },
    DecMemory {
        address: MemoryOperand,
        width: usize,
    },
    Cmov {
        condition: ConditionCode,
        dst: Register,
        src: CompareOperand,
        width: usize,
    },
    LoadMemory8 {
        dst: ByteRegister,
        address: MemoryOperand,
    },
    LoadMemory {
        dst: Register,
        address: MemoryOperand,
        width: usize,
    },
    StoreMemory8 {
        src: ByteRegister,
        address: MemoryOperand,
    },
    StoreMemory {
        src: Register,
        address: MemoryOperand,
        width: usize,
    },
    StoreImmediate {
        address: MemoryOperand,
        value: u64,
        width: usize,
    },
    Call {
        target: u64,
        return_address: u64,
    },
    CallRegister {
        src: Register,
        return_address: u64,
    },
    CallMemory {
        address: MemoryOperand,
        return_address: u64,
    },
    JumpRegister {
        src: Register,
    },
    JumpMemory {
        address: MemoryOperand,
    },
    Setcc {
        condition: ConditionCode,
        dst: ByteRegister,
    },
    SetccMemory {
        condition: ConditionCode,
        address: MemoryOperand,
    },
    JumpIf {
        condition: ConditionCode,
        target: u64,
        fallthrough: u64,
    },
    Jump {
        target: u64,
    },
    Nop,
    LoadEffectiveAddress {
        dst: Register,
        address: MemoryOperand,
        width: usize,
    },
    PushReg {
        src: Register,
    },
    PushMemory {
        address: MemoryOperand,
        width: usize,
    },
    PushImm {
        value: u64,
        width: usize,
    },
    PushFlags {
        width: usize,
    },
    PopReg {
        dst: Register,
    },
    PopMemory {
        address: MemoryOperand,
        width: usize,
    },
    PopFlags {
        width: usize,
    },
    Cld,
    Leave,
    Return {
        stack_adjust: u64,
    },
    Popcnt {
        dst: Register,
        src: Register,
    },
    Lzcnt {
        dst: Register,
        src: Register,
    },
    Bsf {
        dst: Register,
        src: Register,
    },
    Bswap {
        dst: Register,
        width: usize,
    },
    Rdtsc,
    MovdToXmm {
        dst: u8,
        src: Register,
    },
    Pshufd {
        dst: u8,
        src: u8,
        imm: u8,
    },
    Pshuflw {
        dst: u8,
        src: u8,
        imm: u8,
    },
    Psrldq {
        dst: u8,
        imm: u8,
    },
    Pslldq {
        dst: u8,
        imm: u8,
    },
    Movlhps {
        dst: u8,
        src: u8,
    },
    StoreDwordFromXmm {
        address: MemoryOperand,
        src: u8,
    },
    MoveXmm {
        dst: u8,
        src: u8,
    },
    LoadXmm {
        dst: u8,
        address: MemoryOperand,
    },
    StoreXmm {
        src: u8,
        address: MemoryOperand,
    },
    MoveVector {
        dst: u8,
        src: u8,
        width: usize,
    },
    LoadVector {
        dst: u8,
        address: MemoryOperand,
        width: usize,
    },
    StoreVector {
        src: u8,
        address: MemoryOperand,
        width: usize,
    },
    Pxor {
        dst: u8,
        src: u8,
    },
    VectorOr {
        dst: u8,
        lhs: u8,
        rhs: VectorOperand,
        width: usize,
    },
    VectorAnd {
        dst: u8,
        lhs: u8,
        rhs: VectorOperand,
        width: usize,
    },
    VectorAndNot {
        dst: u8,
        lhs: u8,
        rhs: VectorOperand,
        width: usize,
    },
    VectorXor {
        dst: u8,
        lhs: u8,
        rhs: VectorOperand,
        width: usize,
    },
    Paddd {
        dst: u8,
        src: u8,
    },
    Paddq {
        dst: u8,
        src: u8,
    },
    Psubd {
        dst: u8,
        src: u8,
    },
    Pmulld {
        dst: u8,
        src: u8,
    },
    VectorAddQ {
        dst: u8,
        lhs: u8,
        rhs: VectorOperand,
        width: usize,
    },
    VectorIntOp {
        kind: VectorIntKind,
        dst: u8,
        lhs: u8,
        rhs: VectorOperand,
        width: usize,
    },
    VectorCompareEqBytes {
        dst: u8,
        lhs: u8,
        rhs: VectorOperand,
        width: usize,
    },
    VectorMoveMaskBytes {
        dst: Register,
        src: u8,
        width: usize,
    },
    VzeroUpper,
    X87ClearExceptions,
    X87LoadInt32 {
        address: MemoryOperand,
    },
    X87LoadInt64 {
        address: MemoryOperand,
    },
    X87Load {
        address: MemoryOperand,
        width: usize,
    },
    X87LoadControlWord {
        address: MemoryOperand,
    },
    X87NegateTop,
    X87AddMemory {
        address: MemoryOperand,
        width: usize,
    },
    X87MulMemory {
        address: MemoryOperand,
        width: usize,
    },
    X87DivMemory {
        address: MemoryOperand,
        width: usize,
    },
    X87Swap {
        index: usize,
    },
    X87StoreControlWord {
        address: MemoryOperand,
    },
    X87Store {
        address: MemoryOperand,
        width: usize,
        pop: bool,
    },
    X87StorePopRegister {
        index: usize,
    },
    X87StorePop {
        address: MemoryOperand,
    },
    X87Compare {
        index: usize,
        pop: bool,
    },
    X87Init,
    LoadMxcsr {
        address: MemoryOperand,
    },
    StoreMxcsr {
        address: MemoryOperand,
    },
    Cvtpd2ps {
        dst: u8,
        src: VectorOperand,
    },
    Cvtdq2pd {
        dst: u8,
        src: VectorOperand,
    },
    Addsd {
        dst: u8,
        src: VectorOperand,
    },
    Divss {
        dst: u8,
        src: VectorOperand,
    },
    SseArith {
        op: SseArithOp,
        kind: SseFloatKind,
        dst: u8,
        src: VectorOperand,
    },
    SseSqrt {
        kind: SseFloatKind,
        dst: u8,
        src: VectorOperand,
    },
    SseRcp {
        scalar: bool,
        dst: u8,
        src: VectorOperand,
    },
    SseRsqrt {
        scalar: bool,
        dst: u8,
        src: VectorOperand,
    },
    CvtIntToFloat {
        to_double: bool,
        dst: u8,
        src: CompareOperand,
    },
    CvtFloatToInt {
        truncate: bool,
        is_double: bool,
        dst: Register,
        src: VectorOperand,
    },
    Ucomi {
        is_double: bool,
        lhs: u8,
        rhs: VectorOperand,
    },
    Comiss {
        lhs: u8,
        rhs: VectorOperand,
    },
    Pcmpistri {
        lhs: u8,
        rhs: VectorOperand,
        imm: u8,
    },
    HaddPs {
        dst: u8,
        src: u8,
    },
    Pshufb {
        dst: u8,
        mask: u8,
    },
    BlendD {
        dst: u8,
        src: u8,
        mask: u8,
    },
    Crc32 {
        dst: Register,
        src: Register,
    },
    Rdrand {
        dst: Register,
    },
    Rdseed {
        dst: Register,
    },
    Rdpmc {
        counter: u8,
    },
    Clflush {
        address: u64,
    },
    Clflushopt {
        address: u64,
    },
    Clwb {
        address: u64,
    },
    Pcommit,
    // TSX/RTM
    Xbegin {
        target: u64,
    },
    Xend,
    Xabort {
        imm: u8,
    },
    Xtest,
    // SGX stubs (detection only)
    Encls,
    Enclu,
    // CET shadow stack
    SaveSsP {
        address: u64,
    },
    Rstorssp {
        address: MemoryOperand,
    },
    Incssp {
        src: Register,
    },
    Wrss {
        dst: MemoryOperand,
        src: Register,
    },
    Wruss {
        dst: MemoryOperand,
        src: Register,
    },
    // MPX bounds
    BndmkReg {
        dst: u8,
        src: u8,
    },
    BndmkMem {
        dst: u8,
        address: MemoryOperand,
    },
    BndclReg {
        bnd: u8,
        src: u8,
    },
    BndclMem {
        bnd: u8,
        address: MemoryOperand,
    },
    BndcuReg {
        bnd: u8,
        src: u8,
    },
    BndcuMem {
        bnd: u8,
        address: MemoryOperand,
    },
    BndcnReg {
        bnd: u8,
        src: u8,
    },
    BndcnMem {
        bnd: u8,
        address: MemoryOperand,
    },
    BndmovReg {
        dst: u8,
        src: u8,
    },
    BndmovMemLoad {
        dst: u8,
        address: MemoryOperand,
    },
    BndmovMemStore {
        src: u8,
        address: MemoryOperand,
    },
    Andn {
        dst: Register,
        lhs: Register,
        rhs: Register,
    },
    Bextr {
        dst: Register,
        src: Register,
        range: Register,
    },
    Blsi {
        dst: Register,
        src: Register,
    },
    Blsmsk {
        dst: Register,
        src: Register,
    },
    Blsr {
        dst: Register,
        src: Register,
    },
    Bzhi {
        dst: Register,
        src: Register,
        index: Register,
    },
    Mulx {
        dst_lo: Register,
        dst_hi: Register,
        src: Register,
    },
    Pdep {
        dst: Register,
        src: Register,
        mask: Register,
    },
    Pext {
        dst: Register,
        src: Register,
        mask: Register,
    },
    Rorx {
        dst: Register,
        src: Register,
        imm: u8,
    },
    Sarx {
        dst: Register,
        src: Register,
        shift: Register,
    },
    Shrx {
        dst: Register,
        src: Register,
        shift: Register,
    },
    Shlx {
        dst: Register,
        src: Register,
        shift: Register,
    },
    LockCmpxchg {
        address: MemoryOperand,
        src: Register,
        width: usize,
    },
    CmpxchgRegisters {
        dst: Register,
        src: Register,
        width: usize,
    },
    LockCmpxchg8b {
        address: MemoryOperand,
    },
    LockXadd {
        address: MemoryOperand,
        src: Register,
        width: usize,
    },
    XaddRegisters {
        dst: Register,
        src: Register,
        width: usize,
    },
    Mfence,
    X87LoadConst {
        value: f64,
    },
    X87AddPop {
        index: usize,
    },
    X87Mul {
        index: usize,
    },
    X87DivRegister {
        index: usize,
    },
    X87DivPop {
        index: usize,
    },
    X87Add,
    X87Div,
    AdcReg8 {
        dst: ByteRegister,
        src: ByteRegister,
    },
    // ADX instructions (0x66/F3 0x0F 0x38 0xF6)
    // ADCX: dst += src + CF (uses carry flag)
    Adcx {
        dst: Register,
        src: CompareOperand,
        width: usize,
    },
    // ADOX: dst += src + OF (uses overflow flag)
    Adox {
        dst: Register,
        src: CompareOperand,
        width: usize,
    },
    PopSeg {
        width: usize,
    },
    // FMA fused multiply-add variants
    // element_kind: 0=PS (f32), 1=PD (f64)
    // width: 16=128-bit, 32=256-bit, 64=512-bit
    FmaVector {
        kind: FmaKind,
        dst: u8,
        src1: u8,
        src2: VectorOperand,
        element_kind: u8,
        width: usize,
    },
    // AVX-512 shuffle/permute
    ShuffleF32 {
        dst: u8,
        src1: u8,
        src2: VectorOperand,
        mask: u8,
        width: usize,
        evex: EvexInfo,
    },
    ShuffleF64 {
        dst: u8,
        src1: u8,
        src2: VectorOperand,
        mask: u8,
        width: usize,
        evex: EvexInfo,
    },
    AlignD {
        dst: u8,
        src1: u8,
        src2: VectorOperand,
        imm: u8,
        width: usize,
        evex: EvexInfo,
    },
    AlignQ {
        dst: u8,
        src1: u8,
        src2: VectorOperand,
        imm: u8,
        width: usize,
        evex: EvexInfo,
    },
    InsertSubVector {
        dst: u8,
        src: u8,
        sub_src: VectorOperand,
        index: u8,
        element_size: u8,
        width: usize,
        evex: EvexInfo,
    },
    ExtractSubVector {
        dst: VectorOperand,
        src: VectorOperand,
        index: u8,
        element_size: u8,
        width: usize,
        evex: EvexInfo,
    },
    BroadcastSubVector {
        dst: u8,
        src: VectorOperand,
        element_size: u8,
        width: usize,
        evex: EvexInfo,
    },
    BroadcastMask {
        dst: u8,
        src: u8,
        width: usize,
    },
    PermuteVarDq {
        dst: u8,
        src: u8,
        indices: VectorOperand,
        element_size: u8,
        width: usize,
        evex: EvexInfo,
    },
    PermuteVarPsPd {
        dst: u8,
        src: VectorOperand,
        indices: u8,
        element_size: u8,
        width: usize,
        evex: EvexInfo,
    },
    PermuteI2 {
        dst: u8,
        src1: u8,
        src2: VectorOperand,
        indices: u8,
        element_size: u8,
        width: usize,
        evex: EvexInfo,
    },
    PermuteT2 {
        dst: u8,
        src1: u8,
        src2: VectorOperand,
        indices: u8,
        element_size: u8,
        width: usize,
        evex: EvexInfo,
    },
    PermuteImm {
        dst: u8,
        src: VectorOperand,
        imm: u8,
        element_size: u8,
        width: usize,
        evex: EvexInfo,
    },
    PermuteImm2Src {
        dst: u8,
        src1: u8,
        src2: VectorOperand,
        imm: u8,
        element_size: u8,
        width: usize,
        evex: EvexInfo,
    },
    // AVX-512 arithmetic (masked)
    AddPacked {
        dst: u8,
        src1: u8,
        src2: VectorOperand,
        element_size: u8,
        width: usize,
        evex: EvexInfo,
    },
    SubPacked {
        dst: u8,
        src1: u8,
        src2: VectorOperand,
        element_size: u8,
        width: usize,
        evex: EvexInfo,
    },
    MulPacked {
        dst: u8,
        src1: u8,
        src2: VectorOperand,
        element_size: u8,
        width: usize,
        evex: EvexInfo,
    },
    DivPacked {
        dst: u8,
        src1: u8,
        src2: VectorOperand,
        element_size: u8,
        width: usize,
        evex: EvexInfo,
    },
    MinPacked {
        dst: u8,
        src1: u8,
        src2: VectorOperand,
        element_size: u8,
        width: usize,
        evex: EvexInfo,
    },
    MaxPacked {
        dst: u8,
        src1: u8,
        src2: VectorOperand,
        element_size: u8,
        width: usize,
        evex: EvexInfo,
    },
    SqrtPacked {
        dst: u8,
        src: VectorOperand,
        element_size: u8,
        width: usize,
        evex: EvexInfo,
    },
    // AVX-512 conversion
    ConvertPacked {
        dst: u8,
        src: VectorOperand,
        from_size: u8,
        to_size: u8,
        width: usize,
        evex: EvexInfo,
    },
    ConvertToInt {
        dst: u8,
        src: VectorOperand,
        from_size: u8,
        to_int_size: u8,
        truncate: bool,
        width: usize,
        evex: EvexInfo,
    },
    ConvertFromInt {
        dst: u8,
        src: VectorOperand,
        from_int_size: u8,
        to_size: u8,
        unsigned: bool,
        width: usize,
        evex: EvexInfo,
    },
    // AVX-512 compare
    ComparePacked {
        dst_mask: u8,
        src1: u8,
        src2: VectorOperand,
        element_size: u8,
        predicate: u8,
        width: usize,
        evex: EvexInfo,
    },
    // AVX-512 special
    FixupSpecial {
        dst: u8,
        src1: u8,
        src2: VectorOperand,
        table: u8,
        element_size: u8,
        width: usize,
        evex: EvexInfo,
    },
    ExtractExponent {
        dst: u8,
        src: VectorOperand,
        element_size: u8,
        width: usize,
        evex: EvexInfo,
    },
    ExtractMantissa {
        dst: u8,
        src: VectorOperand,
        element_size: u8,
        norm: u8,
        sign: u8,
        width: usize,
        evex: EvexInfo,
    },
    ReducePrecision {
        dst: u8,
        src: VectorOperand,
        element_size: u8,
        reduce_op: u8,
        width: usize,
        evex: EvexInfo,
    },
    RangePacked {
        dst: u8,
        src1: u8,
        src2: VectorOperand,
        element_size: u8,
        predicate: u8,
        width: usize,
        evex: EvexInfo,
    },
    ScaleByPower2 {
        dst: u8,
        src1: u8,
        src2: VectorOperand,
        element_size: u8,
        width: usize,
        evex: EvexInfo,
    },
    FloatClass {
        dst_mask: u8,
        src: VectorOperand,
        element_size: u8,
        class_mask: u8,
        width: usize,
        evex: EvexInfo,
    },
    // VPTERNLOG
    Pternlog {
        dst: u8,
        src1: u8,
        src2: VectorOperand,
        truth_table: u8,
        element_size: u8,
        width: usize,
        evex: EvexInfo,
    },
    // VPCONFLICT
    ConflictDetect {
        dst: u8,
        src: VectorOperand,
        element_size: u8,
        width: usize,
        evex: EvexInfo,
    },
    // VCOMPRESS / VEXPAND
    CompressVector {
        dst: VectorOperand,
        src: u8,
        element_size: u8,
        width: usize,
        evex: EvexInfo,
    },
    ExpandVector {
        dst: u8,
        src: VectorOperand,
        element_size: u8,
        width: usize,
        evex: EvexInfo,
    },
    // Gather/Scatter
    GatherVector {
        dst: u8,
        base_addr: VectorOperand,
        indices: u8,
        scale: u8,
        element_size: u8,
        width: usize,
        evex: EvexInfo,
    },
    ScatterVector {
        base_addr: VectorOperand,
        indices: u8,
        src: u8,
        scale: u8,
        element_size: u8,
        width: usize,
        evex: EvexInfo,
    },
    // Mask register operations
    Kand {
        dst: u8,
        src1: u8,
        src2: u8,
        size: u8,
    },
    Kor {
        dst: u8,
        src1: u8,
        src2: u8,
        size: u8,
    },
    Kxor {
        dst: u8,
        src1: u8,
        src2: u8,
        size: u8,
    },
    Knot {
        dst: u8,
        src: u8,
        size: u8,
    },
    Kshiftl {
        dst: u8,
        src: u8,
        count: u8,
        size: u8,
    },
    Kshiftr {
        dst: u8,
        src: u8,
        count: u8,
        size: u8,
    },
    Kadd {
        dst: u8,
        src1: u8,
        src2: u8,
        size: u8,
    },
    Ktest {
        src1: u8,
        src2: u8,
        size: u8,
    },
    Kunpck {
        dst: u8,
        src1: u8,
        src2: u8,
        size: u8,
    },
    // AES-NI software implementations
    AesEnc {
        dst: u8,
        src: u8,
    },
    AesEncLast {
        dst: u8,
        src: u8,
    },
    AesDec {
        dst: u8,
        src: u8,
    },
    AesDecLast {
        dst: u8,
        src: u8,
    },
    AesImc {
        dst: u8,
        src: u8,
    },
    AesKeyGenAssist {
        dst: u8,
        src: u8,
        imm: u8,
    },
    // PCLMULQDQ
    Pclmulqdq {
        dst: u8,
        src: u8,
        imm: u8,
    },
    // SHA software implementations
    Sha1Rnds4 {
        dst: u8,
        src: u8,
        imm: u8,
    },
    Sha1NextE {
        dst: u8,
        src: u8,
    },
    Sha1Msg1 {
        dst: u8,
        src: u8,
    },
    Sha1Msg2 {
        dst: u8,
        src: u8,
    },
    Sha256Rnds2 {
        dst: u8,
        src: u8,
    },
    Sha256Msg1 {
        dst: u8,
        src: u8,
    },
    Sha256Msg2 {
        dst: u8,
        src: u8,
    },
    // ── Phase P5: Breakpoint / int 0x2d ──────────────────────────────────
    /// Triggers STATUS_BREAKPOINT through the SEH subsystem.
    /// Raised by `Int3` (0xCC), `int 0x2d` (0xCD 0x2D), and `int 0x03`.
    Breakpoint,
    /// Tier-2 register-allocation spill: store a guest register into the
    /// per-CPU spill area (transparent to the guest register file).
    SpillStore {
        slot: u16,
        src: Register,
    },
    /// Tier-2 register-allocation fill: reload a spilled value into a guest
    /// register from the per-CPU spill area.
    SpillLoad {
        slot: u16,
        dst: Register,
    },
    /// Tier-2 explicit x86 flag materialisation for an ALU operation whose
    /// result is not a CMP/TEST.  `op`: 0=add, 1=sub, 2=logic.
    ExplicitFlags {
        op: u8,
        lhs: Register,
        rhs: Register,
        result: Register,
        width: usize,
    },
}

/// Masking/broadcast/rounding info for EVEX-encoded instructions.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvexInfo {
    pub mask: Option<u8>, // k0-k7 mask register (None or 0 = no masking)
    pub zm: bool,         // zero-mask (EVEX.z)
    pub bcast: bool,      // broadcast/embedded rounding
    pub er: Option<u8>,   // embedded rounding mode (0=RN,1=RD,2=RU,3=RZ)
}

impl EvexInfo {
    pub fn from_evex(evex: &EvexPrefix) -> Self {
        let mask = if evex.aaa != 0 { Some(evex.aaa) } else { None };
        let er = if evex.bcast && (evex.ll & 0x2) != 0 {
            // When b=1 and ll has the high bit set, ll encodes rounding mode
            Some(evex.ll & 0x3)
        } else {
            None
        };
        EvexInfo {
            mask,
            zm: evex.z,
            bcast: evex.bcast,
            er,
        }
    }
    pub fn no_mask() -> Self {
        EvexInfo {
            mask: None,
            zm: false,
            bcast: false,
            er: None,
        }
    }
}

impl Default for EvexInfo {
    fn default() -> Self {
        EvexInfo::no_mask()
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum FmaKind {
    Vfmadd132,
    Vfmadd213,
    Vfmadd231,
    Vfmsub132,
    Vfmsub213,
    Vfmsub231,
    Vfnmadd132,
    Vfnmadd213,
    Vfnmadd231,
}

/// Legacy SSE floating-point element kind: PS (packed single), SS (scalar
/// single), PD (packed double), SD (scalar double).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SseFloatKind {
    Ps,
    Ss,
    Pd,
    Sd,
}

/// Legacy SSE floating-point arithmetic operation kind.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SseArithOp {
    Add,
    Sub,
    Mul,
    Div,
    Max,
    Min,
}

/// Element-wise vector integer operation kind (AVX2 VEX.256 encoded).
/// Each variant specifies the element size and operation type.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum VectorIntKind {
    Paddb,
    Paddw,
    Paddd,
    Psubb,
    Psubw,
    Psubd,
    Psubq,
    Psllw,
    Pslld,
    Psllq,
    Psrlw,
    Psrld,
    Psrlq,
    Psraw,
    Psrad,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionSummary {
    pub flags: Flags,
    pub memory_hash: String,
    pub ordering_log: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct BlockCacheKey {
    pub start_address: u64,
    pub source_hash: String,
    pub os_build: String,
    pub macwin_version: String,
    pub cpu_profile: String,
    pub arch: GuestArch,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TranslationTier {
    Tier0,
    Tier1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JitPolicy {
    pub map_jit_preferred: bool,
    pub uses_wx_toggle: bool,
    pub rwx_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnwindInfo {
    pub begin: u64,
    pub end: u64,
    pub stack_allocation: u32,
    pub saved_registers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Arm64Block {
    pub instructions: Vec<String>,
    pub policy: JitPolicy,
    pub unwind: UnwindInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TranslatedBlock {
    pub key: BlockCacheKey,
    pub decoded: Vec<DecodedInstruction>,
    pub ir: Vec<IrInstruction>,
    pub arm64: Arm64Block,
    pub touched_pages: BTreeSet<u64>,
    pub tier: TranslationTier,
    pub persistent: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct TranslationCache {
    pub blocks: BTreeMap<BlockCacheKey, TranslatedBlock>,
    pub unwind_registry: BTreeMap<BlockCacheKey, UnwindInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CpuEngineConfig {
    pub arch: GuestArch,
    pub os_build: String,
    pub macwin_version: String,
    pub virtualization: CpuVirtualization,
}

impl CpuEngineConfig {
    pub fn from_profile(
        arch: GuestArch,
        os_build: impl Into<String>,
        macwin_version: impl Into<String>,
        profile: Option<&CpuProfile>,
    ) -> AppResult<Self> {
        Ok(Self {
            arch,
            os_build: os_build.into(),
            macwin_version: macwin_version.into(),
            virtualization: CpuVirtualization::from_profile(arch, profile)?,
        })
    }
}

impl TranslationCache {
    pub fn translate(
        &mut self,
        bytes: &[u8],
        start_address: u64,
        config: &CpuEngineConfig,
    ) -> AppResult<TranslatedBlock> {
        let key = build_cache_key(bytes, start_address, config);
        if let Some(existing) = self.blocks.get(&key) {
            return Ok(existing.clone());
        }
        let decoded = decode_block(bytes, start_address, config.arch)?;
        let ir = lower_to_ir(&decoded)?;
        let touched_pages = touched_pages(start_address, bytes.len());
        let unwind = UnwindInfo {
            begin: start_address,
            end: start_address + bytes.len() as u64,
            stack_allocation: 32,
            saved_registers: vec!["fp".to_string(), "lr".to_string()],
        };
        let block = TranslatedBlock {
            key: key.clone(),
            decoded,
            ir: ir.clone(),
            arm64: Arm64Block {
                instructions: Vec::new(), // Skip lower_to_arm64 — JIT can't execute anyway
                policy: JitPolicy {
                    map_jit_preferred: true,
                    uses_wx_toggle: true,
                    rwx_enabled: false,
                },
                unwind: unwind.clone(),
            },
            touched_pages,
            tier: TranslationTier::Tier0,
            persistent: false,
        };
        self.unwind_registry.insert(key.clone(), unwind);
        self.blocks.insert(key, block.clone());
        Ok(block)
    }

    pub fn promote(&mut self, key: &BlockCacheKey) -> AppResult<()> {
        let block = self.blocks.get_mut(key).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("missing translated block {}", key.source_hash),
            )
        })?;
        block.tier = TranslationTier::Tier1;
        block.persistent = true;
        Ok(())
    }

    pub fn invalidate_code_write(&mut self, address: u64, length: usize) -> Vec<BlockCacheKey> {
        let dirty_pages = touched_pages(address, length);
        let keys = self
            .blocks
            .iter()
            .filter(|(_, block)| !block.touched_pages.is_disjoint(&dirty_pages))
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        for key in &keys {
            self.blocks.remove(key);
            self.unwind_registry.remove(key);
        }
        keys
    }
}
