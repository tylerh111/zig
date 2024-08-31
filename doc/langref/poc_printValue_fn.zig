const Writer = struct {
    pub fn print_value(self: *Writer, value: anytype) !void {
        switch (@typeInfo(@TypeOf(value))) {
            .Int => {
                return self.writeInt(value);
            },
            .Float => {
                return self.writeFloat(value);
            },
            .Pointer => {
                return self.write(value);
            },
            else => {
                @compileError("Unable to print type '" ++ @typeName(@TypeOf(value)) ++ "'");
            },
        }
    }

    fn write(self: *Writer, value: []const u8) !void {
        _ = self;
        _ = value;
    }
    fn write_int(self: *Writer, value: anytype) !void {
        _ = self;
        _ = value;
    }
    fn write_float(self: *Writer, value: anytype) !void {
        _ = self;
        _ = value;
    }
};

// syntax
