const std = @import("../std.zig");
const testing = std.testing;
const valgrind = std.valgrind;

pub const MemCheckClientRequest = enum(usize) {
    MakeMemNoAccess = valgrind.ToolBase("MC".*),
    MakeMemUndefined,
    MakeMemDefined,
    Discard,
    CheckMemIsAddressable,
    CheckMemIsDefined,
    DoLeakCheck,
    CountLeaks,
    GetVbits,
    SetVbits,
    CreateBlock,
    MakeMemDefinedIfAddressable,
    CountLeakBlocks,
    EnableAddrErrorReportingInRange,
    DisableAddrErrorReportingInRange,
};

fn do_mem_check_client_request_expr(default: usize, request: MemCheckClientRequest, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) usize {
    return valgrind.do_client_request(default, @as(usize, @int_cast(@int_from_enum(request))), a1, a2, a3, a4, a5);
}

fn do_mem_check_client_request_stmt(request: MemCheckClientRequest, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) void {
    _ = do_mem_check_client_request_expr(0, request, a1, a2, a3, a4, a5);
}

/// Mark memory at qzz.ptr as unaddressable for qzz.len bytes.
pub fn make_mem_no_access(qzz: []const u8) void {
    _ = do_mem_check_client_request_expr(0, // default return
        .MakeMemNoAccess, @int_from_ptr(qzz.ptr), qzz.len, 0, 0, 0);
}

/// Mark memory at qzz.ptr as addressable but undefined for qzz.len bytes.
pub fn make_mem_undefined(qzz: []const u8) void {
    _ = do_mem_check_client_request_expr(0, // default return
        .MakeMemUndefined, @int_from_ptr(qzz.ptr), qzz.len, 0, 0, 0);
}

/// Mark memory at qzz.ptr as addressable and defined or qzz.len bytes.
pub fn make_mem_defined(qzz: []const u8) void {
    _ = do_mem_check_client_request_expr(0, // default return
        .MakeMemDefined, @int_from_ptr(qzz.ptr), qzz.len, 0, 0, 0);
}

/// Similar to make_mem_defined except that addressability is
/// not altered: bytes which are addressable are marked as defined,
/// but those which are not addressable are left unchanged.
pub fn make_mem_defined_if_addressable(qzz: []const u8) void {
    _ = do_mem_check_client_request_expr(0, // default return
        .MakeMemDefinedIfAddressable, @int_from_ptr(qzz.ptr), qzz.len, 0, 0, 0);
}

/// Create a block-description handle.  The description is an ascii
/// string which is included in any messages pertaining to addresses
/// within the specified memory range.  Has no other effect on the
/// properties of the memory range.
pub fn create_block(qzz: []const u8, desc: [*:0]const u8) usize {
    return do_mem_check_client_request_expr(0, // default return
        .CreateBlock, @int_from_ptr(qzz.ptr), qzz.len, @int_from_ptr(desc), 0, 0);
}

/// Discard a block-description-handle. Returns 1 for an
/// invalid handle, 0 for a valid handle.
pub fn discard(blkindex: usize) bool {
    return do_mem_check_client_request_expr(0, // default return
        .Discard, 0, blkindex, 0, 0, 0) != 0;
}

/// Check that memory at qzz.ptr is addressable for qzz.len bytes.
/// If suitable addressability is not established, Valgrind prints an
/// error message and returns the address of the first offending byte.
/// Otherwise it returns zero.
pub fn check_mem_is_addressable(qzz: []const u8) usize {
    return do_mem_check_client_request_expr(0, .CheckMemIsAddressable, @int_from_ptr(qzz.ptr), qzz.len, 0, 0, 0);
}

/// Check that memory at qzz.ptr is addressable and defined for
/// qzz.len bytes.  If suitable addressability and definedness are not
/// established, Valgrind prints an error message and returns the
/// address of the first offending byte.  Otherwise it returns zero.
pub fn check_mem_is_defined(qzz: []const u8) usize {
    return do_mem_check_client_request_expr(0, .CheckMemIsDefined, @int_from_ptr(qzz.ptr), qzz.len, 0, 0, 0);
}

/// Do a full memory leak check (like --leak-check=full) mid-execution.
pub fn do_leak_check() void {
    do_mem_check_client_request_stmt(.DO_LEAK_CHECK, 0, 0, 0, 0, 0);
}

/// Same as do_leak_check() but only showing the entries for
/// which there was an increase in leaked bytes or leaked nr of blocks
/// since the previous leak search.
pub fn do_added_leak_check() void {
    do_mem_check_client_request_stmt(.DO_LEAK_CHECK, 0, 1, 0, 0, 0);
}

/// Same as do_added_leak_check() but showing entries with
/// increased or decreased leaked bytes/blocks since previous leak
/// search.
pub fn do_changed_leak_check() void {
    do_mem_check_client_request_stmt(.DO_LEAK_CHECK, 0, 2, 0, 0, 0);
}

/// Do a summary memory leak check (like --leak-check=summary) mid-execution.
pub fn do_quick_leak_check() void {
    do_mem_check_client_request_stmt(.DO_LEAK_CHECK, 1, 0, 0, 0, 0);
}

/// Return number of leaked, dubious, reachable and suppressed bytes found by
/// all previous leak checks.
const CountResult = struct {
    leaked: usize,
    dubious: usize,
    reachable: usize,
    suppressed: usize,
};

pub fn count_leaks() CountResult {
    var res: CountResult = .{
        .leaked = 0,
        .dubious = 0,
        .reachable = 0,
        .suppressed = 0,
    };
    do_mem_check_client_request_stmt(
        .CountLeaks,
        @int_from_ptr(&res.leaked),
        @int_from_ptr(&res.dubious),
        @int_from_ptr(&res.reachable),
        @int_from_ptr(&res.suppressed),
        0,
    );
    return res;
}

test count_leaks {
    try testing.expect_equal(
        @as(CountResult, .{
            .leaked = 0,
            .dubious = 0,
            .reachable = 0,
            .suppressed = 0,
        }),
        count_leaks(),
    );
}

pub fn count_leak_blocks() CountResult {
    var res: CountResult = .{
        .leaked = 0,
        .dubious = 0,
        .reachable = 0,
        .suppressed = 0,
    };
    do_mem_check_client_request_stmt(
        .CountLeakBlocks,
        @int_from_ptr(&res.leaked),
        @int_from_ptr(&res.dubious),
        @int_from_ptr(&res.reachable),
        @int_from_ptr(&res.suppressed),
        0,
    );
    return res;
}

test count_leak_blocks {
    try testing.expect_equal(
        @as(CountResult, .{
            .leaked = 0,
            .dubious = 0,
            .reachable = 0,
            .suppressed = 0,
        }),
        count_leak_blocks(),
    );
}

/// Get the validity data for addresses zza and copy it
/// into the provided zzvbits array.  Return values:
///    0   if not running on valgrind
///    1   success
///    2   [previously indicated unaligned arrays;  these are now allowed]
///    3   if any parts of zzsrc/zzvbits are not addressable.
/// The metadata is not copied in cases 0, 2 or 3 so it should be
/// impossible to segfault your system by using this call.
pub fn get_vbits(zza: []u8, zzvbits: []u8) u2 {
    std.debug.assert(zzvbits.len >= zza.len / 8);
    return @as(u2, @int_cast(do_mem_check_client_request_expr(0, .GetVbits, @int_from_ptr(zza.ptr), @int_from_ptr(zzvbits), zza.len, 0, 0)));
}

/// Set the validity data for addresses zza, copying it
/// from the provided zzvbits array.  Return values:
///    0   if not running on valgrind
///    1   success
///    2   [previously indicated unaligned arrays;  these are now allowed]
///    3   if any parts of zza/zzvbits are not addressable.
/// The metadata is not copied in cases 0, 2 or 3 so it should be
/// impossible to segfault your system by using this call.
pub fn set_vbits(zzvbits: []u8, zza: []u8) u2 {
    std.debug.assert(zzvbits.len >= zza.len / 8);
    return @as(u2, @int_cast(do_mem_check_client_request_expr(0, .SetVbits, @int_from_ptr(zza.ptr), @int_from_ptr(zzvbits), zza.len, 0, 0)));
}

/// Disable and re-enable reporting of addressing errors in the
/// specified address range.
pub fn disable_addr_error_reporting_in_range(qzz: []u8) usize {
    return do_mem_check_client_request_expr(0, // default return
        .DisableAddrErrorReportingInRange, @int_from_ptr(qzz.ptr), qzz.len, 0, 0, 0);
}

pub fn enable_addr_error_reporting_in_range(qzz: []u8) usize {
    return do_mem_check_client_request_expr(0, // default return
        .EnableAddrErrorReportingInRange, @int_from_ptr(qzz.ptr), qzz.len, 0, 0, 0);
}
