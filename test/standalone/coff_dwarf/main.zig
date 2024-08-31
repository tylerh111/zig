const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

extern fn add(a: u32, b: u32, addr: *usize) u32;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer assert(gpa.deinit() == .ok);
    const allocator = gpa.allocator();

    var debug_info = try std.debug.open_self_debug_info(allocator);
    defer debug_info.deinit();

    var add_addr: usize = undefined;
    _ = add(1, 2, &add_addr);

    const module = try debug_info.get_module_for_address(add_addr);
    const symbol = try module.get_symbol_at_address(allocator, add_addr);
    defer symbol.deinit(allocator);

    try testing.expect_equal_strings("add", symbol.symbol_name);
    try testing.expect(symbol.line_info != null);
    try testing.expect_equal_strings("shared_lib.c", std.fs.path.basename(symbol.line_info.?.file_name));
    try testing.expect_equal(@as(u64, 3), symbol.line_info.?.line);
    try testing.expect_equal(@as(u64, 0), symbol.line_info.?.column);
}
