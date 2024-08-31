const std = @import("std");

pub const AbbrevOp = union(enum) {
    literal: u32, // 0
    fixed: u16, // 1
    fixed_runtime: type, // 1
    vbr: u16, // 2
    char6: void, // 4
    blob: void, // 5
    array_fixed: u16, // 3, 1
    array_fixed_runtime: type, // 3, 1
    array_vbr: u16, // 3, 2
    array_char6: void, // 3, 4
};

pub const Error = error{OutOfMemory};

pub fn BitcodeWriter(comptime types: []const type) type {
    return struct {
        const BcWriter = @This();

        buffer: std.ArrayList(u32),
        bit_buffer: u32 = 0,
        bit_count: u5 = 0,

        widths: [types.len]u16,

        pub fn get_type_width(self: BcWriter, comptime Type: type) u16 {
            return self.widths[comptime std.mem.index_of_scalar(type, types, Type).?];
        }

        pub fn init(allocator: std.mem.Allocator, widths: [types.len]u16) BcWriter {
            return .{
                .buffer = std.ArrayList(u32).init(allocator),
                .widths = widths,
            };
        }

        pub fn deinit(self: BcWriter) void {
            self.buffer.deinit();
        }

        pub fn to_owned_slice(self: *BcWriter) Error![]const u32 {
            std.debug.assert(self.bit_count == 0);
            return self.buffer.to_owned_slice();
        }

        pub fn length(self: BcWriter) usize {
            std.debug.assert(self.bit_count == 0);
            return self.buffer.items.len;
        }

        pub fn write_bits(self: *BcWriter, value: anytype, bits: u16) Error!void {
            if (bits == 0) return;

            var in_buffer = buf_value(value, 32);
            var in_bits = bits;

            // Store input bits in buffer if they fit otherwise store as many as possible and flush
            if (self.bit_count > 0) {
                const bits_remaining = 31 - self.bit_count + 1;
                const n: u5 = @int_cast(@min(bits_remaining, in_bits));
                const v = @as(u32, @truncate(in_buffer)) << self.bit_count;
                self.bit_buffer |= v;
                in_buffer >>= n;

                self.bit_count +%= n;
                in_bits -= n;

                if (self.bit_count != 0) return;
                try self.buffer.append(self.bit_buffer);
                self.bit_buffer = 0;
            }

            // Write 32-bit chunks of input bits
            while (in_bits >= 32) {
                try self.buffer.append(@truncate(in_buffer));

                in_buffer >>= 31;
                in_buffer >>= 1;
                in_bits -= 32;
            }

            // Store remaining input bits in buffer
            if (in_bits > 0) {
                self.bit_count = @int_cast(in_bits);
                self.bit_buffer = @truncate(in_buffer);
            }
        }

        pub fn write_vbr(self: *BcWriter, value: anytype, comptime vbr_bits: usize) Error!void {
            comptime {
                std.debug.assert(vbr_bits > 1);
                if (@bitSizeOf(@TypeOf(value)) > 64) @compile_error("Unsupported VBR block type: " ++ @type_name(@TypeOf(value)));
            }

            var in_buffer = buf_value(value, vbr_bits);

            const continue_bit = @as(@TypeOf(in_buffer), 1) << @int_cast(vbr_bits - 1);
            const mask = continue_bit - 1;

            // If input is larger than one VBR block can store
            // then store vbr_bits - 1 bits and a continue bit
            while (in_buffer > mask) {
                try self.write_bits(in_buffer & mask | continue_bit, vbr_bits);
                in_buffer >>= @int_cast(vbr_bits - 1);
            }

            // Store remaining bits
            try self.write_bits(in_buffer, vbr_bits);
        }

        pub fn bits_vbr(_: *const BcWriter, value: anytype, comptime vbr_bits: usize) u16 {
            comptime {
                std.debug.assert(vbr_bits > 1);
                if (@bitSizeOf(@TypeOf(value)) > 64) @compile_error("Unsupported VBR block type: " ++ @type_name(@TypeOf(value)));
            }

            var bits: u16 = 0;

            var in_buffer = buf_value(value, vbr_bits);

            const continue_bit = @as(@TypeOf(in_buffer), 1) << @int_cast(vbr_bits - 1);
            const mask = continue_bit - 1;

            // If input is larger than one VBR block can store
            // then store vbr_bits - 1 bits and a continue bit
            while (in_buffer > mask) {
                bits += @int_cast(vbr_bits);
                in_buffer >>= @int_cast(vbr_bits - 1);
            }

            // Store remaining bits
            bits += @int_cast(vbr_bits);
            return bits;
        }

        pub fn write6_bit_char(self: *BcWriter, c: u8) Error!void {
            try self.write_bits(char_to6_bit(c), 6);
        }

        pub fn write_blob(self: *BcWriter, blob: []const u8) Error!void {
            const blob_word_size = std.mem.align_forward(usize, blob.len, 4);
            try self.buffer.ensure_unused_capacity(blob_word_size + 1);
            self.align_to32() catch unreachable;

            const slice = self.buffer.add_many_as_slice_assume_capacity(blob_word_size / 4);
            const slice_bytes = std.mem.slice_as_bytes(slice);
            @memcpy(slice_bytes[0..blob.len], blob);
            @memset(slice_bytes[blob.len..], 0);
        }

        pub fn align_to32(self: *BcWriter) Error!void {
            if (self.bit_count == 0) return;

            try self.buffer.append(self.bit_buffer);
            self.bit_buffer = 0;
            self.bit_count = 0;
        }

        pub fn enter_top_block(self: *BcWriter, comptime SubBlock: type) Error!BlockWriter(SubBlock) {
            return BlockWriter(SubBlock).init(self, 2, true);
        }

        fn BlockWriter(comptime Block: type) type {
            return struct {
                const Self = @This();

                // The minimum abbrev id length based on the number of abbrevs present in the block
                pub const abbrev_len = std.math.log2_int_ceil(
                    u6,
                    4 + (if (@hasDecl(Block, "abbrevs")) Block.abbrevs.len else 0),
                );

                start: usize,
                bitcode: *BcWriter,

                pub fn init(bitcode: *BcWriter, comptime parent_abbrev_len: u6, comptime define_abbrevs: bool) Error!Self {
                    try bitcode.write_bits(1, parent_abbrev_len);
                    try bitcode.write_vbr(Block.id, 8);
                    try bitcode.write_vbr(abbrev_len, 4);
                    try bitcode.align_to32();

                    // We store the index of the block size and store a dummy value as the number of words in the block
                    const start = bitcode.length();
                    try bitcode.write_bits(0, 32);

                    var self = Self{
                        .start = start,
                        .bitcode = bitcode,
                    };

                    // Predefine all block abbrevs
                    if (define_abbrevs) {
                        inline for (Block.abbrevs) |Abbrev| {
                            try self.define_abbrev(&Abbrev.ops);
                        }
                    }

                    return self;
                }

                pub fn enter_sub_block(self: Self, comptime SubBlock: type, comptime define_abbrevs: bool) Error!BlockWriter(SubBlock) {
                    return BlockWriter(SubBlock).init(self.bitcode, abbrev_len, define_abbrevs);
                }

                pub fn end(self: *Self) Error!void {
                    try self.bitcode.write_bits(0, abbrev_len);
                    try self.bitcode.align_to32();

                    // Set the number of words in the block at the start of the block
                    self.bitcode.buffer.items[self.start] = @truncate(self.bitcode.length() - self.start - 1);
                }

                pub fn write_unabbrev(self: *Self, code: u32, values: []const u64) Error!void {
                    try self.bitcode.write_bits(3, abbrev_len);
                    try self.bitcode.write_vbr(code, 6);
                    try self.bitcode.write_vbr(values.len, 6);
                    for (values) |val| {
                        try self.bitcode.write_vbr(val, 6);
                    }
                }

                pub fn write_abbrev(self: *Self, params: anytype) Error!void {
                    return self.write_abbrev_adapted(params, struct {
                        pub fn get(_: @This(), param: anytype, comptime _: []const u8) @TypeOf(param) {
                            return param;
                        }
                    }{});
                }

                pub fn abbrev_id(comptime Abbrev: type) u32 {
                    inline for (Block.abbrevs, 0..) |abbrev, i| {
                        if (Abbrev == abbrev) return i + 4;
                    }

                    @compile_error("Unknown abbrev: " ++ @type_name(Abbrev));
                }

                pub fn write_abbrev_adapted(
                    self: *Self,
                    params: anytype,
                    adapter: anytype,
                ) Error!void {
                    const Abbrev = @TypeOf(params);

                    try self.bitcode.write_bits(comptime abbrev_id(Abbrev), abbrev_len);

                    const fields = std.meta.fields(Abbrev);

                    // This abbreviation might only contain literals
                    if (fields.len == 0) return;

                    comptime var field_index: usize = 0;
                    inline for (Abbrev.ops) |ty| {
                        const field_name = fields[field_index].name;
                        const param = @field(params, field_name);

                        switch (ty) {
                            .literal => continue,
                            .fixed => |len| try self.bitcode.write_bits(adapter.get(param, field_name), len),
                            .fixed_runtime => |width_ty| try self.bitcode.write_bits(
                                adapter.get(param, field_name),
                                self.bitcode.get_type_width(width_ty),
                            ),
                            .vbr => |len| try self.bitcode.write_vbr(adapter.get(param, field_name), len),
                            .char6 => try self.bitcode.write6_bit_char(adapter.get(param, field_name)),
                            .blob => {
                                try self.bitcode.write_vbr(param.len, 6);
                                try self.bitcode.write_blob(param);
                            },
                            .array_fixed => |len| {
                                try self.bitcode.write_vbr(param.len, 6);
                                for (param) |x| {
                                    try self.bitcode.write_bits(adapter.get(x, field_name), len);
                                }
                            },
                            .array_fixed_runtime => |width_ty| {
                                try self.bitcode.write_vbr(param.len, 6);
                                for (param) |x| {
                                    try self.bitcode.write_bits(
                                        adapter.get(x, field_name),
                                        self.bitcode.get_type_width(width_ty),
                                    );
                                }
                            },
                            .array_vbr => |len| {
                                try self.bitcode.write_vbr(param.len, 6);
                                for (param) |x| {
                                    try self.bitcode.write_vbr(adapter.get(x, field_name), len);
                                }
                            },
                            .array_char6 => {
                                try self.bitcode.write_vbr(param.len, 6);
                                for (param) |x| {
                                    try self.bitcode.write6_bit_char(adapter.get(x, field_name));
                                }
                            },
                        }
                        field_index += 1;
                        if (field_index == fields.len) break;
                    }
                }

                pub fn define_abbrev(self: *Self, comptime ops: []const AbbrevOp) Error!void {
                    const bitcode = self.bitcode;
                    try bitcode.write_bits(2, abbrev_len);

                    // ops.len is not accurate because arrays are actually two ops
                    try bitcode.write_vbr(blk: {
                        var count: usize = 0;
                        inline for (ops) |op| {
                            count += switch (op) {
                                .literal, .fixed, .fixed_runtime, .vbr, .char6, .blob => 1,
                                .array_fixed, .array_fixed_runtime, .array_vbr, .array_char6 => 2,
                            };
                        }
                        break :blk count;
                    }, 5);

                    inline for (ops) |op| {
                        switch (op) {
                            .literal => |value| {
                                try bitcode.write_bits(1, 1);
                                try bitcode.write_vbr(value, 8);
                            },
                            .fixed => |width| {
                                try bitcode.write_bits(0, 1);
                                try bitcode.write_bits(1, 3);
                                try bitcode.write_vbr(width, 5);
                            },
                            .fixed_runtime => |width_ty| {
                                try bitcode.write_bits(0, 1);
                                try bitcode.write_bits(1, 3);
                                try bitcode.write_vbr(bitcode.get_type_width(width_ty), 5);
                            },
                            .vbr => |width| {
                                try bitcode.write_bits(0, 1);
                                try bitcode.write_bits(2, 3);
                                try bitcode.write_vbr(width, 5);
                            },
                            .char6 => {
                                try bitcode.write_bits(0, 1);
                                try bitcode.write_bits(4, 3);
                            },
                            .blob => {
                                try bitcode.write_bits(0, 1);
                                try bitcode.write_bits(5, 3);
                            },
                            .array_fixed => |width| {
                                // Array op
                                try bitcode.write_bits(0, 1);
                                try bitcode.write_bits(3, 3);

                                // Fixed or VBR op
                                try bitcode.write_bits(0, 1);
                                try bitcode.write_bits(1, 3);
                                try bitcode.write_vbr(width, 5);
                            },
                            .array_fixed_runtime => |width_ty| {
                                // Array op
                                try bitcode.write_bits(0, 1);
                                try bitcode.write_bits(3, 3);

                                // Fixed or VBR op
                                try bitcode.write_bits(0, 1);
                                try bitcode.write_bits(1, 3);
                                try bitcode.write_vbr(bitcode.get_type_width(width_ty), 5);
                            },
                            .array_vbr => |width| {
                                // Array op
                                try bitcode.write_bits(0, 1);
                                try bitcode.write_bits(3, 3);

                                // Fixed or VBR op
                                try bitcode.write_bits(0, 1);
                                try bitcode.write_bits(2, 3);
                                try bitcode.write_vbr(width, 5);
                            },
                            .array_char6 => {
                                // Array op
                                try bitcode.write_bits(0, 1);
                                try bitcode.write_bits(3, 3);

                                // Char6 op
                                try bitcode.write_bits(0, 1);
                                try bitcode.write_bits(4, 3);
                            },
                        }
                    }
                }
            };
        }
    };
}

fn char_to6_bit(c: u8) u8 {
    return switch (c) {
        'a'...'z' => c - 'a',
        'A'...'Z' => c - 'A' + 26,
        '0'...'9' => c - '0' + 52,
        '.' => 62,
        '_' => 63,
        else => @panic("Failed to encode byte as 6-bit char"),
    };
}

fn BufType(comptime T: type, comptime min_len: usize) type {
    return std.meta.Int(.unsigned, @max(min_len, @bitSizeOf(switch (@typeInfo(T)) {
        .ComptimeInt => u32,
        .Int => |info| if (info.signedness == .unsigned)
            T
        else
            @compile_error("Unsupported type: " ++ @type_name(T)),
        .Enum => |info| info.tag_type,
        .Bool => u1,
        .Struct => |info| switch (info.layout) {
            .auto, .@"extern" => @compile_error("Unsupported type: " ++ @type_name(T)),
            .@"packed" => std.meta.Int(.unsigned, @bitSizeOf(T)),
        },
        else => @compile_error("Unsupported type: " ++ @type_name(T)),
    })));
}

fn buf_value(value: anytype, comptime min_len: usize) BufType(@TypeOf(value), min_len) {
    return switch (@typeInfo(@TypeOf(value))) {
        .ComptimeInt, .Int => @int_cast(value),
        .Enum => @int_from_enum(value),
        .Bool => @int_from_bool(value),
        .Struct => @int_cast(@as(std.meta.Int(.unsigned, @bitSizeOf(@TypeOf(value))), @bit_cast(value))),
        else => unreachable,
    };
}
