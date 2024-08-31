const std = @import("std");

pub export fn entry() void {
    var ohnoes: *usize = undefined;
    _ = slice_as_bytes(ohnoes);
    _ = &ohnoes;
}
fn slice_as_bytes(slice: anytype) is_ptr_to(.Array)(@TypeOf(slice)) {}

pub const TraitFn = fn (type) bool;

pub fn is_ptr_to(comptime id: std.builtin.TypeId) TraitFn {
    const Closure = struct {
        pub fn trait(comptime T: type) bool {
            if (!comptime is_single_item_ptr(T)) return false;
            return id == @typeInfo(std.meta.Child(T));
        }
    };
    return Closure.trait;
}

pub fn is_single_item_ptr(comptime T: type) bool {
    if (comptime is(.Pointer)(T)) {
        return @typeInfo(T).Pointer.size == .One;
    }
    return false;
}

pub fn is(comptime id: std.builtin.TypeId) TraitFn {
    const Closure = struct {
        pub fn trait(comptime T: type) bool {
            return id == @typeInfo(T);
        }
    };
    return Closure.trait;
}

// error
// backend=llvm
// target=native
//
// :8:48: error: expected type 'type', found 'bool'
