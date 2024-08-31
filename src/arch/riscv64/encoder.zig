pub const Instruction = struct {
    encoding: Encoding,
    ops: [3]Operand = .{.none} ** 3,

    pub const Operand = union(enum) {
        none,
        reg: Register,
        mem: Memory,
        imm: Immediate,
    };

    pub fn new(mnemonic: Encoding.Mnemonic, ops: []const Operand) !Instruction {
        const encoding = (try Encoding.find_by_mnemonic(mnemonic, ops)) orelse {
            std.log.err("no encoding found for:  {s} {s} {s} {s} {s}", .{
                @tag_name(mnemonic),
                @tag_name(if (ops.len > 0) ops[0] else .none),
                @tag_name(if (ops.len > 1) ops[1] else .none),
                @tag_name(if (ops.len > 2) ops[2] else .none),
                @tag_name(if (ops.len > 3) ops[3] else .none),
            });
            return error.InvalidInstruction;
        };

        var result_ops: [3]Operand = .{.none} ** 3;
        @memcpy(result_ops[0..ops.len], ops);

        return .{
            .encoding = encoding,
            .ops = result_ops,
        };
    }

    pub fn encode(inst: Instruction, writer: anytype) !void {
        try writer.write_int(u32, inst.encoding.data.to_u32(), .little);
    }
};

const std = @import("std");

const Lower = @import("Lower.zig");
const Mir = @import("Mir.zig");
const bits = @import("bits.zig");
const Encoding = @import("Encoding.zig");

const Register = bits.Register;
const Memory = bits.Memory;
const Immediate = bits.Immediate;

const log = std.log.scoped(.encode);
