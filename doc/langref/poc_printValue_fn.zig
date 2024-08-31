const Writer = struct {
    pub fn print_value(self: *Writer, value: anytype) !void {
        switch (@typeInfo(@TypeOf(value))) {
            .Int => {
                return self.write_int(value);
            },
            .Float => {
                return self.write_float(value);
            },
            .Pointer => {
                return self.write(value);
            },
            else => {
                @compile_error("Unable to print type '" ++ @type_name(@TypeOf(value)) ++ "'");
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
