const std = @import("../std.zig");
const valgrind = std.valgrind;

pub const CallgrindClientRequest = enum(usize) {
    DumpStats = valgrind.ToolBase("CT".*),
    ZeroStats,
    ToggleCollect,
    DumpStatsAt,
    StartInstrumentation,
    StopInstrumentation,
};

fn do_callgrind_client_request_expr(default: usize, request: CallgrindClientRequest, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) usize {
    return valgrind.do_client_request(default, @as(usize, @int_cast(@int_from_enum(request))), a1, a2, a3, a4, a5);
}

fn do_callgrind_client_request_stmt(request: CallgrindClientRequest, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) void {
    _ = do_callgrind_client_request_expr(0, request, a1, a2, a3, a4, a5);
}

/// Dump current state of cost centers, and zero them afterwards
pub fn dump_stats() void {
    do_callgrind_client_request_stmt(.DumpStats, 0, 0, 0, 0, 0);
}

/// Dump current state of cost centers, and zero them afterwards.
/// The argument is appended to a string stating the reason which triggered
/// the dump. This string is written as a description field into the
/// profile data dump.
pub fn dump_stats_at(pos_str: [*:0]const u8) void {
    do_callgrind_client_request_stmt(.DumpStatsAt, @int_from_ptr(pos_str), 0, 0, 0, 0);
}

/// Zero cost centers
pub fn zero_stats() void {
    do_callgrind_client_request_stmt(.ZeroStats, 0, 0, 0, 0, 0);
}

/// Toggles collection state.
/// The collection state specifies whether the happening of events
/// should be noted or if they are to be ignored. Events are noted
/// by increment of counters in a cost center
pub fn toggle_collect() void {
    do_callgrind_client_request_stmt(.ToggleCollect, 0, 0, 0, 0, 0);
}

/// Start full callgrind instrumentation if not already switched on.
/// When cache simulation is done, it will flush the simulated cache;
/// this will lead to an artificial cache warmup phase afterwards with
/// cache misses which would not have happened in reality.
pub fn start_instrumentation() void {
    do_callgrind_client_request_stmt(.StartInstrumentation, 0, 0, 0, 0, 0);
}

/// Stop full callgrind instrumentation if not already switched off.
/// This flushes Valgrinds translation cache, and does no additional
/// instrumentation afterwards, which effectivly will run at the same
/// speed as the "none" tool (ie. at minimal slowdown).
/// Use this to bypass Callgrind aggregation for uninteresting code parts.
/// To start Callgrind in this mode to ignore the setup phase, use
/// the option "--instr-atstart=no".
pub fn stop_instrumentation() void {
    do_callgrind_client_request_stmt(.StopInstrumentation, 0, 0, 0, 0, 0);
}
