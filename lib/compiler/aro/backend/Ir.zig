const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const Interner = @import("Interner.zig");
const Object = @import("Object.zig");

const Ir = @This();

interner: *Interner,
decls: std.StringArrayHashMapUnmanaged(Decl),

pub const Decl = struct {
    instructions: std.MultiArrayList(Inst),
    body: std.ArrayListUnmanaged(Ref),
    arena: std.heap.ArenaAllocator.State,

    pub fn deinit(decl: *Decl, gpa: Allocator) void {
        decl.instructions.deinit(gpa);
        decl.body.deinit(gpa);
        decl.arena.promote(gpa).deinit();
    }
};

pub const Builder = struct {
    gpa: Allocator,
    arena: std.heap.ArenaAllocator,
    interner: *Interner,

    decls: std.StringArrayHashMapUnmanaged(Decl) = .{},
    instructions: std.MultiArrayList(Ir.Inst) = .{},
    body: std.ArrayListUnmanaged(Ref) = .{},
    alloc_count: u32 = 0,
    arg_count: u32 = 0,
    current_label: Ref = undefined,

    pub fn deinit(b: *Builder) void {
        for (b.decls.values()) |*decl| {
            decl.deinit(b.gpa);
        }
        b.arena.deinit();
        b.instructions.deinit(b.gpa);
        b.body.deinit(b.gpa);
        b.* = undefined;
    }

    pub fn finish(b: *Builder) Ir {
        return .{
            .interner = b.interner,
            .decls = b.decls.move(),
        };
    }

    pub fn start_fn(b: *Builder) Allocator.Error!void {
        const entry = try b.make_label("entry");
        try b.body.append(b.gpa, entry);
        b.current_label = entry;
    }

    pub fn finish_fn(b: *Builder, name: []const u8) !void {
        var duped_instructions = try b.instructions.clone(b.gpa);
        errdefer duped_instructions.deinit(b.gpa);
        var duped_body = try b.body.clone(b.gpa);
        errdefer duped_body.deinit(b.gpa);

        try b.decls.put(b.gpa, name, .{
            .instructions = duped_instructions,
            .body = duped_body,
            .arena = b.arena.state,
        });
        b.instructions.shrink_retaining_capacity(0);
        b.body.shrink_retaining_capacity(0);
        b.arena = std.heap.ArenaAllocator.init(b.gpa);
        b.alloc_count = 0;
        b.arg_count = 0;
    }

    pub fn start_block(b: *Builder, label: Ref) !void {
        try b.body.append(b.gpa, label);
        b.current_label = label;
    }

    pub fn add_arg(b: *Builder, ty: Interner.Ref) Allocator.Error!Ref {
        const ref: Ref = @enumFromInt(b.instructions.len);
        try b.instructions.append(b.gpa, .{ .tag = .arg, .data = .{ .none = {} }, .ty = ty });
        try b.body.insert(b.gpa, b.arg_count, ref);
        b.arg_count += 1;
        return ref;
    }

    pub fn add_alloc(b: *Builder, size: u32, @"align": u32) Allocator.Error!Ref {
        const ref: Ref = @enumFromInt(b.instructions.len);
        try b.instructions.append(b.gpa, .{
            .tag = .alloc,
            .data = .{ .alloc = .{ .size = size, .@"align" = @"align" } },
            .ty = .ptr,
        });
        try b.body.insert(b.gpa, b.alloc_count + b.arg_count + 1, ref);
        b.alloc_count += 1;
        return ref;
    }

    pub fn add_inst(b: *Builder, tag: Ir.Inst.Tag, data: Ir.Inst.Data, ty: Interner.Ref) Allocator.Error!Ref {
        const ref: Ref = @enumFromInt(b.instructions.len);
        try b.instructions.append(b.gpa, .{ .tag = tag, .data = data, .ty = ty });
        try b.body.append(b.gpa, ref);
        return ref;
    }

    pub fn make_label(b: *Builder, name: [*:0]const u8) Allocator.Error!Ref {
        const ref: Ref = @enumFromInt(b.instructions.len);
        try b.instructions.append(b.gpa, .{ .tag = .label, .data = .{ .label = name }, .ty = .void });
        return ref;
    }

    pub fn add_jump(b: *Builder, label: Ref) Allocator.Error!void {
        _ = try b.add_inst(.jmp, .{ .un = label }, .noreturn);
    }

    pub fn add_branch(b: *Builder, cond: Ref, true_label: Ref, false_label: Ref) Allocator.Error!void {
        const branch = try b.arena.allocator().create(Ir.Inst.Branch);
        branch.* = .{
            .cond = cond,
            .then = true_label,
            .@"else" = false_label,
        };
        _ = try b.add_inst(.branch, .{ .branch = branch }, .noreturn);
    }

    pub fn add_switch(b: *Builder, target: Ref, values: []Interner.Ref, labels: []Ref, default: Ref) Allocator.Error!void {
        assert(values.len == labels.len);
        const a = b.arena.allocator();
        const @"switch" = try a.create(Ir.Inst.Switch);
        @"switch".* = .{
            .target = target,
            .cases_len = @int_cast(values.len),
            .case_vals = (try a.dupe(Interner.Ref, values)).ptr,
            .case_labels = (try a.dupe(Ref, labels)).ptr,
            .default = default,
        };
        _ = try b.add_inst(.@"switch", .{ .@"switch" = @"switch" }, .noreturn);
    }

    pub fn add_store(b: *Builder, ptr: Ref, val: Ref) Allocator.Error!void {
        _ = try b.add_inst(.store, .{ .bin = .{ .lhs = ptr, .rhs = val } }, .void);
    }

    pub fn add_constant(b: *Builder, val: Interner.Ref, ty: Interner.Ref) Allocator.Error!Ref {
        const ref: Ref = @enumFromInt(b.instructions.len);
        try b.instructions.append(b.gpa, .{
            .tag = .constant,
            .data = .{ .constant = val },
            .ty = ty,
        });
        return ref;
    }

    pub fn add_phi(b: *Builder, inputs: []const Inst.Phi.Input, ty: Interner.Ref) Allocator.Error!Ref {
        const a = b.arena.allocator();
        const input_refs = try a.alloc(Ref, inputs.len * 2 + 1);
        input_refs[0] = @enumFromInt(inputs.len);
        @memcpy(input_refs[1..], std.mem.bytes_as_slice(Ref, std.mem.slice_as_bytes(inputs)));

        return b.add_inst(.phi, .{ .phi = .{ .ptr = input_refs.ptr } }, ty);
    }

    pub fn add_select(b: *Builder, cond: Ref, then: Ref, @"else": Ref, ty: Interner.Ref) Allocator.Error!Ref {
        const branch = try b.arena.allocator().create(Ir.Inst.Branch);
        branch.* = .{
            .cond = cond,
            .then = then,
            .@"else" = @"else",
        };
        return b.add_inst(.select, .{ .branch = branch }, ty);
    }
};

pub const Renderer = struct {
    gpa: Allocator,
    obj: *Object,
    ir: *const Ir,
    errors: ErrorList = .{},

    pub const ErrorList = std.StringArrayHashMapUnmanaged([]const u8);

    pub const Error = Allocator.Error || error{LowerFail};

    pub fn deinit(r: *Renderer) void {
        for (r.errors.values()) |msg| r.gpa.free(msg);
        r.errors.deinit(r.gpa);
    }

    pub fn render(r: *Renderer) !void {
        switch (r.obj.target.cpu.arch) {
            .x86, .x86_64 => return @import("Ir/x86/Renderer.zig").render(r),
            else => unreachable,
        }
    }

    pub fn fail(
        r: *Renderer,
        name: []const u8,
        comptime format: []const u8,
        args: anytype,
    ) Error {
        try r.errors.ensure_unused_capacity(r.gpa, 1);
        r.errors.put_assume_capacity(name, try std.fmt.alloc_print(r.gpa, format, args));
        return error.LowerFail;
    }
};

pub fn render(
    ir: *const Ir,
    gpa: Allocator,
    target: std.Target,
    errors: ?*Renderer.ErrorList,
) !*Object {
    const obj = try Object.create(gpa, target);
    errdefer obj.deinit();

    var renderer: Renderer = .{
        .gpa = gpa,
        .obj = obj,
        .ir = ir,
    };
    defer {
        if (errors) |some| {
            some.* = renderer.errors.move();
        }
        renderer.deinit();
    }

    try renderer.render();
    return obj;
}

pub const Ref = enum(u32) { none = std.math.max_int(u32), _ };

pub const Inst = struct {
    tag: Tag,
    data: Data,
    ty: Interner.Ref,

    pub const Tag = enum {
        // data.constant
        // not included in blocks
        constant,

        // data.arg
        // not included in blocks
        arg,
        symbol,

        // data.label
        label,

        // data.block
        label_addr,
        jmp,

        // data.switch
        @"switch",

        // data.branch
        branch,
        select,

        // data.un
        jmp_val,

        // data.call
        call,

        // data.alloc
        alloc,

        // data.phi
        phi,

        // data.bin
        store,
        bit_or,
        bit_xor,
        bit_and,
        bit_shl,
        bit_shr,
        cmp_eq,
        cmp_ne,
        cmp_lt,
        cmp_lte,
        cmp_gt,
        cmp_gte,
        add,
        sub,
        mul,
        div,
        mod,

        // data.un
        ret,
        load,
        bit_not,
        negate,
        trunc,
        zext,
        sext,
    };

    pub const Data = union {
        constant: Interner.Ref,
        none: void,
        bin: struct {
            lhs: Ref,
            rhs: Ref,
        },
        un: Ref,
        arg: u32,
        alloc: struct {
            size: u32,
            @"align": u32,
        },
        @"switch": *Switch,
        call: *Call,
        label: [*:0]const u8,
        branch: *Branch,
        phi: Phi,
    };

    pub const Branch = struct {
        cond: Ref,
        then: Ref,
        @"else": Ref,
    };

    pub const Switch = struct {
        target: Ref,
        cases_len: u32,
        default: Ref,
        case_vals: [*]Interner.Ref,
        case_labels: [*]Ref,
    };

    pub const Call = struct {
        func: Ref,
        args_len: u32,
        args_ptr: [*]Ref,

        pub fn args(c: Call) []Ref {
            return c.args_ptr[0..c.args_len];
        }
    };

    pub const Phi = struct {
        ptr: [*]Ir.Ref,

        pub const Input = struct {
            label: Ir.Ref,
            value: Ir.Ref,
        };

        pub fn inputs(p: Phi) []Input {
            const len = @int_from_enum(p.ptr[0]) * 2;
            const slice = (p.ptr + 1)[0..len];
            return std.mem.bytes_as_slice(Input, std.mem.slice_as_bytes(slice));
        }
    };
};

pub fn deinit(ir: *Ir, gpa: std.mem.Allocator) void {
    for (ir.decls.values()) |*decl| {
        decl.deinit(gpa);
    }
    ir.decls.deinit(gpa);
    ir.* = undefined;
}

const TYPE = std.io.tty.Color.bright_magenta;
const INST = std.io.tty.Color.bright_cyan;
const REF = std.io.tty.Color.bright_blue;
const LITERAL = std.io.tty.Color.bright_green;
const ATTRIBUTE = std.io.tty.Color.bright_yellow;

const RefMap = std.AutoArrayHashMap(Ref, void);

pub fn dump(ir: *const Ir, gpa: Allocator, config: std.io.tty.Config, w: anytype) !void {
    for (ir.decls.keys(), ir.decls.values()) |name, *decl| {
        try ir.dump_decl(decl, gpa, name, config, w);
    }
}

fn dump_decl(ir: *const Ir, decl: *const Decl, gpa: Allocator, name: []const u8, config: std.io.tty.Config, w: anytype) !void {
    const tags = decl.instructions.items(.tag);
    const data = decl.instructions.items(.data);

    var ref_map = RefMap.init(gpa);
    defer ref_map.deinit();

    var label_map = RefMap.init(gpa);
    defer label_map.deinit();

    const ret_inst = decl.body.items[decl.body.items.len - 1];
    const ret_operand = data[@int_from_enum(ret_inst)].un;
    const ret_ty = decl.instructions.items(.ty)[@int_from_enum(ret_operand)];
    try ir.write_type(ret_ty, config, w);
    try config.set_color(w, REF);
    try w.print(" @{s}", .{name});
    try config.set_color(w, .reset);
    try w.write_all("(");

    var arg_count: u32 = 0;
    while (true) : (arg_count += 1) {
        const ref = decl.body.items[arg_count];
        if (tags[@int_from_enum(ref)] != .arg) break;
        if (arg_count != 0) try w.write_all(", ");
        try ref_map.put(ref, {});
        try ir.write_ref(decl, &ref_map, ref, config, w);
        try config.set_color(w, .reset);
    }
    try w.write_all(") {\n");
    for (decl.body.items[arg_count..]) |ref| {
        switch (tags[@int_from_enum(ref)]) {
            .label => try label_map.put(ref, {}),
            else => {},
        }
    }

    for (decl.body.items[arg_count..]) |ref| {
        const i = @int_from_enum(ref);
        const tag = tags[i];
        switch (tag) {
            .arg, .constant, .symbol => unreachable,
            .label => {
                const label_index = label_map.get_index(ref).?;
                try config.set_color(w, REF);
                try w.print("{s}.{d}:\n", .{ data[i].label, label_index });
            },
            // .label_val => {
            //     const un = data[i].un;
            //     try w.print("    %{d} = label.{d}\n", .{ i, @int_from_enum(un) });
            // },
            .jmp => {
                const un = data[i].un;
                try config.set_color(w, INST);
                try w.write_all("    jmp ");
                try write_label(decl, &label_map, un, config, w);
                try w.write_byte('\n');
            },
            .branch => {
                const br = data[i].branch;
                try config.set_color(w, INST);
                try w.write_all("    branch ");
                try ir.write_ref(decl, &ref_map, br.cond, config, w);
                try config.set_color(w, .reset);
                try w.write_all(", ");
                try write_label(decl, &label_map, br.then, config, w);
                try config.set_color(w, .reset);
                try w.write_all(", ");
                try write_label(decl, &label_map, br.@"else", config, w);
                try w.write_byte('\n');
            },
            .select => {
                const br = data[i].branch;
                try ir.write_new_ref(decl, &ref_map, ref, config, w);
                try w.write_all("select ");
                try ir.write_ref(decl, &ref_map, br.cond, config, w);
                try config.set_color(w, .reset);
                try w.write_all(", ");
                try ir.write_ref(decl, &ref_map, br.then, config, w);
                try config.set_color(w, .reset);
                try w.write_all(", ");
                try ir.write_ref(decl, &ref_map, br.@"else", config, w);
                try w.write_byte('\n');
            },
            // .jmp_val => {
            //     const bin = data[i].bin;
            //     try w.print("    %{s} %{d} label.{d}\n", .{ @tag_name(tag), @int_from_enum(bin.lhs), @int_from_enum(bin.rhs) });
            // },
            .@"switch" => {
                const @"switch" = data[i].@"switch";
                try config.set_color(w, INST);
                try w.write_all("    switch ");
                try ir.write_ref(decl, &ref_map, @"switch".target, config, w);
                try config.set_color(w, .reset);
                try w.write_all(" {");
                for (@"switch".case_vals[0..@"switch".cases_len], @"switch".case_labels) |val_ref, label_ref| {
                    try w.write_all("\n        ");
                    try ir.write_value(val_ref, config, w);
                    try config.set_color(w, .reset);
                    try w.write_all(" => ");
                    try write_label(decl, &label_map, label_ref, config, w);
                    try config.set_color(w, .reset);
                }
                try config.set_color(w, LITERAL);
                try w.write_all("\n        default ");
                try config.set_color(w, .reset);
                try w.write_all("=> ");
                try write_label(decl, &label_map, @"switch".default, config, w);
                try config.set_color(w, .reset);
                try w.write_all("\n    }\n");
            },
            .call => {
                const call = data[i].call;
                try ir.write_new_ref(decl, &ref_map, ref, config, w);
                try w.write_all("call ");
                try ir.write_ref(decl, &ref_map, call.func, config, w);
                try config.set_color(w, .reset);
                try w.write_all("(");
                for (call.args(), 0..) |arg, arg_i| {
                    if (arg_i != 0) try w.write_all(", ");
                    try ir.write_ref(decl, &ref_map, arg, config, w);
                    try config.set_color(w, .reset);
                }
                try w.write_all(")\n");
            },
            .alloc => {
                const alloc = data[i].alloc;
                try ir.write_new_ref(decl, &ref_map, ref, config, w);
                try w.write_all("alloc ");
                try config.set_color(w, ATTRIBUTE);
                try w.write_all("size ");
                try config.set_color(w, LITERAL);
                try w.print("{d}", .{alloc.size});
                try config.set_color(w, ATTRIBUTE);
                try w.write_all(" align ");
                try config.set_color(w, LITERAL);
                try w.print("{d}", .{alloc.@"align"});
                try w.write_byte('\n');
            },
            .phi => {
                try ir.write_new_ref(decl, &ref_map, ref, config, w);
                try w.write_all("phi");
                try config.set_color(w, .reset);
                try w.write_all(" {");
                for (data[i].phi.inputs()) |input| {
                    try w.write_all("\n        ");
                    try write_label(decl, &label_map, input.label, config, w);
                    try config.set_color(w, .reset);
                    try w.write_all(" => ");
                    try ir.write_ref(decl, &ref_map, input.value, config, w);
                    try config.set_color(w, .reset);
                }
                try config.set_color(w, .reset);
                try w.write_all("\n    }\n");
            },
            .store => {
                const bin = data[i].bin;
                try config.set_color(w, INST);
                try w.write_all("    store ");
                try ir.write_ref(decl, &ref_map, bin.lhs, config, w);
                try config.set_color(w, .reset);
                try w.write_all(", ");
                try ir.write_ref(decl, &ref_map, bin.rhs, config, w);
                try w.write_byte('\n');
            },
            .ret => {
                try config.set_color(w, INST);
                try w.write_all("    ret ");
                if (data[i].un != .none) try ir.write_ref(decl, &ref_map, data[i].un, config, w);
                try w.write_byte('\n');
            },
            .load => {
                try ir.write_new_ref(decl, &ref_map, ref, config, w);
                try w.write_all("load ");
                try ir.write_ref(decl, &ref_map, data[i].un, config, w);
                try w.write_byte('\n');
            },
            .bit_or,
            .bit_xor,
            .bit_and,
            .bit_shl,
            .bit_shr,
            .cmp_eq,
            .cmp_ne,
            .cmp_lt,
            .cmp_lte,
            .cmp_gt,
            .cmp_gte,
            .add,
            .sub,
            .mul,
            .div,
            .mod,
            => {
                const bin = data[i].bin;
                try ir.write_new_ref(decl, &ref_map, ref, config, w);
                try w.print("{s} ", .{@tag_name(tag)});
                try ir.write_ref(decl, &ref_map, bin.lhs, config, w);
                try config.set_color(w, .reset);
                try w.write_all(", ");
                try ir.write_ref(decl, &ref_map, bin.rhs, config, w);
                try w.write_byte('\n');
            },
            .bit_not,
            .negate,
            .trunc,
            .zext,
            .sext,
            => {
                const un = data[i].un;
                try ir.write_new_ref(decl, &ref_map, ref, config, w);
                try w.print("{s} ", .{@tag_name(tag)});
                try ir.write_ref(decl, &ref_map, un, config, w);
                try w.write_byte('\n');
            },
            .label_addr, .jmp_val => {},
        }
    }
    try config.set_color(w, .reset);
    try w.write_all("}\n\n");
}

fn write_type(ir: Ir, ty_ref: Interner.Ref, config: std.io.tty.Config, w: anytype) !void {
    const ty = ir.interner.get(ty_ref);
    try config.set_color(w, TYPE);
    switch (ty) {
        .ptr_ty, .noreturn_ty, .void_ty, .func_ty => try w.write_all(@tag_name(ty)),
        .int_ty => |bits| try w.print("i{d}", .{bits}),
        .float_ty => |bits| try w.print("f{d}", .{bits}),
        .array_ty => |info| {
            try w.print("[{d} * ", .{info.len});
            try ir.write_type(info.child, .no_color, w);
            try w.write_byte(']');
        },
        .vector_ty => |info| {
            try w.print("<{d} * ", .{info.len});
            try ir.write_type(info.child, .no_color, w);
            try w.write_byte('>');
        },
        .record_ty => |elems| {
            // TODO collect into buffer and only print once
            try w.write_all("{ ");
            for (elems, 0..) |elem, i| {
                if (i != 0) try w.write_all(", ");
                try ir.write_type(elem, config, w);
            }
            try w.write_all(" }");
        },
        else => unreachable, // not a type
    }
}

fn write_value(ir: Ir, val: Interner.Ref, config: std.io.tty.Config, w: anytype) !void {
    try config.set_color(w, LITERAL);
    const key = ir.interner.get(val);
    switch (key) {
        .null => return w.write_all("nullptr_t"),
        .int => |repr| switch (repr) {
            inline else => |x| return w.print("{d}", .{x}),
        },
        .float => |repr| switch (repr) {
            inline else => |x| return w.print("{d}", .{@as(f64, @float_cast(x))}),
        },
        .bytes => |b| return std.zig.string_escape(b, "", .{}, w),
        else => unreachable, // not a value
    }
}

fn write_ref(ir: Ir, decl: *const Decl, ref_map: *RefMap, ref: Ref, config: std.io.tty.Config, w: anytype) !void {
    assert(ref != .none);
    const index = @int_from_enum(ref);
    const ty_ref = decl.instructions.items(.ty)[index];
    if (decl.instructions.items(.tag)[index] == .constant) {
        try ir.write_type(ty_ref, config, w);
        const v_ref = decl.instructions.items(.data)[index].constant;
        try w.write_byte(' ');
        try ir.write_value(v_ref, config, w);
        return;
    } else if (decl.instructions.items(.tag)[index] == .symbol) {
        const name = decl.instructions.items(.data)[index].label;
        try ir.write_type(ty_ref, config, w);
        try config.set_color(w, REF);
        try w.print(" @{s}", .{name});
        return;
    }
    try ir.write_type(ty_ref, config, w);
    try config.set_color(w, REF);
    const ref_index = ref_map.get_index(ref).?;
    try w.print(" %{d}", .{ref_index});
}

fn write_new_ref(ir: Ir, decl: *const Decl, ref_map: *RefMap, ref: Ref, config: std.io.tty.Config, w: anytype) !void {
    try ref_map.put(ref, {});
    try w.write_all("    ");
    try ir.write_ref(decl, ref_map, ref, config, w);
    try config.set_color(w, .reset);
    try w.write_all(" = ");
    try config.set_color(w, INST);
}

fn write_label(decl: *const Decl, label_map: *RefMap, ref: Ref, config: std.io.tty.Config, w: anytype) !void {
    assert(ref != .none);
    const index = @int_from_enum(ref);
    const label = decl.instructions.items(.data)[index].label;
    try config.set_color(w, REF);
    const label_index = label_map.get_index(ref).?;
    try w.print("{s}.{d}", .{ label, label_index });
}
