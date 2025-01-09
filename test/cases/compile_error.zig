export fn foo() void {
    @compileerror("this is an error");
}

// error
//
// :2:5: error: this is an error
