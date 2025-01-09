const Writer = struct {
    pub fn printValue(self: *Writer, value: anytype) !void {
        switch (@typeinfo(@TypeOf(value))) {
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
                @compileerror("Unable to print type '" ++ @typename(@TypeOf(value)) ++ "'");
            },
        }
    }

    fn write(self: *Writer, value: []const u8) !void {
        _ = self;
        _ = value;
    }
    fn writeInt(self: *Writer, value: anytype) !void {
        _ = self;
        _ = value;
    }
    fn writeFloat(self: *Writer, value: anytype) !void {
        _ = self;
        _ = value;
    }
};

// syntax
