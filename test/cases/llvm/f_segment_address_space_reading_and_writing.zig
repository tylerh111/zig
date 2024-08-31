fn assert(ok: bool) void {
    if (!ok) unreachable;
}

fn set_fs(value: c_ulong) void {
    asm volatile (
        \\syscall
        :
        : [number] "{rax}" (158),
          [code] "{rdi}" (0x1002),
          [val] "{rsi}" (value),
        : "rcx", "r11", "memory"
    );
}

fn get_fs() c_ulong {
    var result: c_ulong = undefined;
    asm volatile (
        \\syscall
        :
        : [number] "{rax}" (158),
          [code] "{rdi}" (0x1003),
          [ptr] "{rsi}" (@int_from_ptr(&result)),
        : "rcx", "r11", "memory"
    );
    return result;
}

var test_value: u64 = 12345;

pub fn main() void {
    const orig_fs = get_fs();

    set_fs(@int_from_ptr(&test_value));
    assert(get_fs() == @int_from_ptr(&test_value));

    var test_ptr: *allowzero addrspace(.fs) u64 = @ptrFromInt(0);
    _ = &test_ptr;
    assert(test_ptr.* == 12345);
    test_ptr.* = 98765;
    assert(test_value == 98765);

    set_fs(orig_fs);
}

// run
// backend=llvm
// target=x86_64-linux
//
