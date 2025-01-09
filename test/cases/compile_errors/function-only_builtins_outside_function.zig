comptime {
    @setAlignStack(1);
}

comptime {
    @setCold(true);
}

comptime {
    @src();
}

comptime {
    @returnaddress();
}

comptime {
    @frameaddress();
}

comptime {
    @breakpoint();
}

comptime {
    @cvaarg(1, 2);
}

comptime {
    @cvacopy(1);
}

comptime {
    @cvaend(1);
}

comptime {
    @cvastart();
}

comptime {
    @workItemId(42);
}

comptime {
    @workgroupsize(42);
}

comptime {
    @workgroupid(42);
}

// error
// backend=stage2
// target=native
//
// :2:5: error: '@setAlignStack' outside function scope
// :6:5: error: '@setCold' outside function scope
// :10:5: error: '@src' outside function scope
// :14:5: error: '@returnaddress' outside function scope
// :18:5: error: '@frameaddress' outside function scope
// :22:5: error: '@breakpoint' outside function scope
// :26:5: error: '@cvaarg' outside function scope
// :30:5: error: '@cvacopy' outside function scope
// :34:5: error: '@cvaend' outside function scope
// :38:5: error: '@cvastart' outside function scope
// :42:5: error: '@workItemId' outside function scope
// :46:5: error: '@workgroupsize' outside function scope
// :50:5: error: '@workgroupid' outside function scope
