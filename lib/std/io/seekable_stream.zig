const std = @import("../std.zig");

pub fn seekable_stream(
    comptime Context: type,
    comptime SeekErrorType: type,
    comptime GetSeekPosErrorType: type,
    comptime seekToFn: fn (context: Context, pos: u64) SeekErrorType!void,
    comptime seekByFn: fn (context: Context, pos: i64) SeekErrorType!void,
    comptime getPosFn: fn (context: Context) GetSeekPosErrorType!u64,
    comptime getEndPosFn: fn (context: Context) GetSeekPosErrorType!u64,
) type {
    return struct {
        context: Context,

        const Self = @This();
        pub const SeekError = SeekErrorType;
        pub const GetSeekPosError = GetSeekPosErrorType;

        pub fn seek_to(self: Self, pos: u64) SeekError!void {
            return seekToFn(self.context, pos);
        }

        pub fn seek_by(self: Self, amt: i64) SeekError!void {
            return seekByFn(self.context, amt);
        }

        pub fn get_end_pos(self: Self) GetSeekPosError!u64 {
            return getEndPosFn(self.context);
        }

        pub fn get_pos(self: Self) GetSeekPosError!u64 {
            return getPosFn(self.context);
        }
    };
}
