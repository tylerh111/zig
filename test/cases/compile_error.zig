export fn foo() void {
    @compile_error("this is an error");
}

// error
//
// :2:5: error: this is an error
