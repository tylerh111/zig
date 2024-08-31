// purposefully conflicting function with main source file
// but it's private so it should be OK
fn private_function() bool {
    return false;
}

pub fn print_text() bool {
    return private_function();
}

pub var saw_foo_function = false;
pub fn foo_function() void {
    saw_foo_function = true;
}
