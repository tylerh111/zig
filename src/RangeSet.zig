const std = @import("std");
const assert = std.debug.assert;
const Order = std.math.Order;

const InternPool = @import("InternPool.zig");
const Type = @import("type.zig").Type;
const Value = @import("Value.zig");
const Module = @import("Module.zig");
const RangeSet = @This();
const SwitchProngSrc = @import("Module.zig").SwitchProngSrc;

ranges: std.ArrayList(Range),
module: *Module,

pub const Range = struct {
    first: InternPool.Index,
    last: InternPool.Index,
    src: SwitchProngSrc,
};

pub fn init(allocator: std.mem.Allocator, module: *Module) RangeSet {
    return .{
        .ranges = std.ArrayList(Range).init(allocator),
        .module = module,
    };
}

pub fn deinit(self: *RangeSet) void {
    self.ranges.deinit();
}

pub fn add(
    self: *RangeSet,
    first: InternPool.Index,
    last: InternPool.Index,
    src: SwitchProngSrc,
) !?SwitchProngSrc {
    const mod = self.module;
    const ip = &mod.intern_pool;

    const ty = ip.type_of(first);
    assert(ty == ip.type_of(last));

    for (self.ranges.items) |range| {
        assert(ty == ip.type_of(range.first));
        assert(ty == ip.type_of(range.last));

        if (Value.from_interned(last).compare_scalar(.gte, Value.from_interned(range.first), Type.from_interned(ty), mod) and
            Value.from_interned(first).compare_scalar(.lte, Value.from_interned(range.last), Type.from_interned(ty), mod))
        {
            return range.src; // They overlap.
        }
    }

    try self.ranges.append(.{
        .first = first,
        .last = last,
        .src = src,
    });
    return null;
}

/// Assumes a and b do not overlap
fn less_than(mod: *Module, a: Range, b: Range) bool {
    const ty = Type.from_interned(mod.intern_pool.type_of(a.first));
    return Value.from_interned(a.first).compare_scalar(.lt, Value.from_interned(b.first), ty, mod);
}

pub fn spans(self: *RangeSet, first: InternPool.Index, last: InternPool.Index) !bool {
    const mod = self.module;
    const ip = &mod.intern_pool;
    assert(ip.type_of(first) == ip.type_of(last));

    if (self.ranges.items.len == 0)
        return false;

    std.mem.sort(Range, self.ranges.items, mod, less_than);

    if (self.ranges.items[0].first != first or
        self.ranges.items[self.ranges.items.len - 1].last != last)
    {
        return false;
    }

    var space: InternPool.Key.Int.Storage.BigIntSpace = undefined;

    var counter = try std.math.big.int.Managed.init(self.ranges.allocator);
    defer counter.deinit();

    // look for gaps
    for (self.ranges.items[1..], 0..) |cur, i| {
        // i starts counting from the second item.
        const prev = self.ranges.items[i];

        // prev.last + 1 == cur.first
        try counter.copy(Value.from_interned(prev.last).to_big_int(&space, mod));
        try counter.add_scalar(&counter, 1);

        const cur_start_int = Value.from_interned(cur.first).to_big_int(&space, mod);
        if (!cur_start_int.eql(counter.to_const())) {
            return false;
        }
    }

    return true;
}
