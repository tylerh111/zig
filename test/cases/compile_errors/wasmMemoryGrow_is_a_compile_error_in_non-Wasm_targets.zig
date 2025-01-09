export fn foo() void {
    _ = @wasmmemorygrow(0, 1);
    return;
}

// error
// backend=stage2
// target=x86_64-native
//
// :2:9: error: builtin @wasmmemorygrow is available when targeting WebAssembly; targeted CPU architecture is x86_64
