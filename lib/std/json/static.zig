const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;
const ArrayList = std.ArrayList;

const Scanner = @import("./scanner.zig").Scanner;
const Token = @import("./scanner.zig").Token;
const AllocWhen = @import("./scanner.zig").AllocWhen;
const default_max_value_len = @import("./scanner.zig").default_max_value_len;
const is_number_formatted_like_an_integer = @import("./scanner.zig").is_number_formatted_like_an_integer;

const Value = @import("./dynamic.zig").Value;
const Array = @import("./dynamic.zig").Array;

/// Controls how to deal with various inconsistencies between the JSON document and the Zig struct type passed in.
/// For duplicate fields or unknown fields, set options in this struct.
/// For missing fields, give the Zig struct fields default values.
pub const ParseOptions = struct {
    /// Behaviour when a duplicate field is encountered.
    /// The default is to return `error.DuplicateField`.
    duplicate_field_behavior: enum {
        use_first,
        @"error",
        use_last,
    } = .@"error",

    /// If false, finding an unknown field returns `error.UnknownField`.
    ignore_unknown_fields: bool = false,

    /// Passed to `std.json.Scanner.next_alloc_max` or `std.json.Reader.next_alloc_max`.
    /// The default for `parse_from_slice` or `parse_from_token_source` with a `*std.json.Scanner` input
    /// is the length of the input slice, which means `error.ValueTooLong` will never be returned.
    /// The default for `parse_from_token_source` with a `*std.json.Reader` is `std.json.default_max_value_len`.
    /// Ignored for `parse_from_value` and `parse_from_value_leaky`.
    max_value_len: ?usize = null,

    /// This determines whether strings should always be copied,
    /// or if a reference to the given buffer should be preferred if possible.
    /// The default for `parse_from_slice` or `parse_from_token_source` with a `*std.json.Scanner` input
    /// is `.alloc_if_needed`.
    /// The default with a `*std.json.Reader` input is `.alloc_always`.
    /// Ignored for `parse_from_value` and `parse_from_value_leaky`.
    allocate: ?AllocWhen = null,
};

pub fn Parsed(comptime T: type) type {
    return struct {
        arena: *ArenaAllocator,
        value: T,

        pub fn deinit(self: @This()) void {
            const allocator = self.arena.child_allocator;
            self.arena.deinit();
            allocator.destroy(self.arena);
        }
    };
}

/// Parses the json document from `s` and returns the result packaged in a `std.json.Parsed`.
/// You must call `deinit()` of the returned object to clean up allocated resources.
/// If you are using a `std.heap.ArenaAllocator` or similar, consider calling `parse_from_slice_leaky` instead.
/// Note that `error.BufferUnderrun` is not actually possible to return from this function.
pub fn parse_from_slice(
    comptime T: type,
    allocator: Allocator,
    s: []const u8,
    options: ParseOptions,
) ParseError(Scanner)!Parsed(T) {
    var scanner = Scanner.init_complete_input(allocator, s);
    defer scanner.deinit();

    return parse_from_token_source(T, allocator, &scanner, options);
}

/// Parses the json document from `s` and returns the result.
/// Allocations made during this operation are not carefully tracked and may not be possible to individually clean up.
/// It is recommended to use a `std.heap.ArenaAllocator` or similar.
pub fn parse_from_slice_leaky(
    comptime T: type,
    allocator: Allocator,
    s: []const u8,
    options: ParseOptions,
) ParseError(Scanner)!T {
    var scanner = Scanner.init_complete_input(allocator, s);
    defer scanner.deinit();

    return parse_from_token_source_leaky(T, allocator, &scanner, options);
}

/// `scanner_or_reader` must be either a `*std.json.Scanner` with complete input or a `*std.json.Reader`.
/// Note that `error.BufferUnderrun` is not actually possible to return from this function.
pub fn parse_from_token_source(
    comptime T: type,
    allocator: Allocator,
    scanner_or_reader: anytype,
    options: ParseOptions,
) ParseError(@TypeOf(scanner_or_reader.*))!Parsed(T) {
    var parsed = Parsed(T){
        .arena = try allocator.create(ArenaAllocator),
        .value = undefined,
    };
    errdefer allocator.destroy(parsed.arena);
    parsed.arena.* = ArenaAllocator.init(allocator);
    errdefer parsed.arena.deinit();

    parsed.value = try parse_from_token_source_leaky(T, parsed.arena.allocator(), scanner_or_reader, options);

    return parsed;
}

/// `scanner_or_reader` must be either a `*std.json.Scanner` with complete input or a `*std.json.Reader`.
/// Allocations made during this operation are not carefully tracked and may not be possible to individually clean up.
/// It is recommended to use a `std.heap.ArenaAllocator` or similar.
pub fn parse_from_token_source_leaky(
    comptime T: type,
    allocator: Allocator,
    scanner_or_reader: anytype,
    options: ParseOptions,
) ParseError(@TypeOf(scanner_or_reader.*))!T {
    if (@TypeOf(scanner_or_reader.*) == Scanner) {
        assert(scanner_or_reader.is_end_of_input);
    }
    var resolved_options = options;
    if (resolved_options.max_value_len == null) {
        if (@TypeOf(scanner_or_reader.*) == Scanner) {
            resolved_options.max_value_len = scanner_or_reader.input.len;
        } else {
            resolved_options.max_value_len = default_max_value_len;
        }
    }
    if (resolved_options.allocate == null) {
        if (@TypeOf(scanner_or_reader.*) == Scanner) {
            resolved_options.allocate = .alloc_if_needed;
        } else {
            resolved_options.allocate = .alloc_always;
        }
    }

    const value = try inner_parse(T, allocator, scanner_or_reader, resolved_options);

    assert(.end_of_document == try scanner_or_reader.next());

    return value;
}

/// Like `parse_from_slice`, but the input is an already-parsed `std.json.Value` object.
/// Only `options.ignore_unknown_fields` is used from `options`.
pub fn parse_from_value(
    comptime T: type,
    allocator: Allocator,
    source: Value,
    options: ParseOptions,
) ParseFromValueError!Parsed(T) {
    var parsed = Parsed(T){
        .arena = try allocator.create(ArenaAllocator),
        .value = undefined,
    };
    errdefer allocator.destroy(parsed.arena);
    parsed.arena.* = ArenaAllocator.init(allocator);
    errdefer parsed.arena.deinit();

    parsed.value = try parse_from_value_leaky(T, parsed.arena.allocator(), source, options);

    return parsed;
}

pub fn parse_from_value_leaky(
    comptime T: type,
    allocator: Allocator,
    source: Value,
    options: ParseOptions,
) ParseFromValueError!T {
    // I guess this function doesn't need to exist,
    // but the flow of the sourcecode is easy to follow and grouped nicely with
    // this pub redirect function near the top and the implementation near the bottom.
    return inner_parse_from_value(T, allocator, source, options);
}

/// The error set that will be returned when parsing from `*Source`.
/// Note that this may contain `error.BufferUnderrun`, but that error will never actually be returned.
pub fn ParseError(comptime Source: type) type {
    // A few of these will either always be present or present enough of the time that
    // omitting them is more confusing than always including them.
    return ParseFromValueError || Source.NextError || Source.PeekError || Source.AllocError;
}

pub const ParseFromValueError = std.fmt.ParseIntError || std.fmt.ParseFloatError || Allocator.Error || error{
    UnexpectedToken,
    InvalidNumber,
    Overflow,
    InvalidEnumTag,
    DuplicateField,
    UnknownField,
    MissingField,
    LengthMismatch,
};

/// This is an internal function called recursively
/// during the implementation of `parse_from_token_source_leaky` and similar.
/// It is exposed primarily to enable custom `json_parse()` methods to call back into the `parseFrom*` system,
/// such as if you're implementing a custom container of type `T`;
/// you can call `inner_parse(T, ...)` for each of the container's items.
/// Note that `null` fields are not allowed on the `options` when calling this function.
/// (The `options` you get in your `json_parse` method has no `null` fields.)
pub fn inner_parse(
    comptime T: type,
    allocator: Allocator,
    source: anytype,
    options: ParseOptions,
) ParseError(@TypeOf(source.*))!T {
    switch (@typeInfo(T)) {
        .Bool => {
            return switch (try source.next()) {
                .true => true,
                .false => false,
                else => error.UnexpectedToken,
            };
        },
        .Float, .ComptimeFloat => {
            const token = try source.next_alloc_max(allocator, .alloc_if_needed, options.max_value_len.?);
            defer free_allocated(allocator, token);
            const slice = switch (token) {
                inline .number, .allocated_number, .string, .allocated_string => |slice| slice,
                else => return error.UnexpectedToken,
            };
            return try std.fmt.parse_float(T, slice);
        },
        .Int, .ComptimeInt => {
            const token = try source.next_alloc_max(allocator, .alloc_if_needed, options.max_value_len.?);
            defer free_allocated(allocator, token);
            const slice = switch (token) {
                inline .number, .allocated_number, .string, .allocated_string => |slice| slice,
                else => return error.UnexpectedToken,
            };
            return slice_to_int(T, slice);
        },
        .Optional => |optionalInfo| {
            switch (try source.peek_next_token_type()) {
                .null => {
                    _ = try source.next();
                    return null;
                },
                else => {
                    return try inner_parse(optionalInfo.child, allocator, source, options);
                },
            }
        },
        .Enum => {
            if (std.meta.has_fn(T, "json_parse")) {
                return T.json_parse(allocator, source, options);
            }

            const token = try source.next_alloc_max(allocator, .alloc_if_needed, options.max_value_len.?);
            defer free_allocated(allocator, token);
            const slice = switch (token) {
                inline .number, .allocated_number, .string, .allocated_string => |slice| slice,
                else => return error.UnexpectedToken,
            };
            return slice_to_enum(T, slice);
        },
        .Union => |unionInfo| {
            if (std.meta.has_fn(T, "json_parse")) {
                return T.json_parse(allocator, source, options);
            }

            if (unionInfo.tag_type == null) @compile_error("Unable to parse into untagged union '" ++ @type_name(T) ++ "'");

            if (.object_begin != try source.next()) return error.UnexpectedToken;

            var result: ?T = null;
            var name_token: ?Token = try source.next_alloc_max(allocator, .alloc_if_needed, options.max_value_len.?);
            const field_name = switch (name_token.?) {
                inline .string, .allocated_string => |slice| slice,
                else => {
                    return error.UnexpectedToken;
                },
            };

            inline for (unionInfo.fields) |u_field| {
                if (std.mem.eql(u8, u_field.name, field_name)) {
                    // Free the name token now in case we're using an allocator that optimizes freeing the last allocated object.
                    // (Recursing into inner_parse() might trigger more allocations.)
                    free_allocated(allocator, name_token.?);
                    name_token = null;
                    if (u_field.type == void) {
                        // void isn't really a json type, but we can support void payload union tags with {} as a value.
                        if (.object_begin != try source.next()) return error.UnexpectedToken;
                        if (.object_end != try source.next()) return error.UnexpectedToken;
                        result = @union_init(T, u_field.name, {});
                    } else {
                        // Recurse.
                        result = @union_init(T, u_field.name, try inner_parse(u_field.type, allocator, source, options));
                    }
                    break;
                }
            } else {
                // Didn't match anything.
                return error.UnknownField;
            }

            if (.object_end != try source.next()) return error.UnexpectedToken;

            return result.?;
        },

        .Struct => |structInfo| {
            if (structInfo.is_tuple) {
                if (.array_begin != try source.next()) return error.UnexpectedToken;

                var r: T = undefined;
                inline for (0..structInfo.fields.len) |i| {
                    r[i] = try inner_parse(structInfo.fields[i].type, allocator, source, options);
                }

                if (.array_end != try source.next()) return error.UnexpectedToken;

                return r;
            }

            if (std.meta.has_fn(T, "json_parse")) {
                return T.json_parse(allocator, source, options);
            }

            if (.object_begin != try source.next()) return error.UnexpectedToken;

            var r: T = undefined;
            var fields_seen = [_]bool{false} ** structInfo.fields.len;

            while (true) {
                var name_token: ?Token = try source.next_alloc_max(allocator, .alloc_if_needed, options.max_value_len.?);
                const field_name = switch (name_token.?) {
                    inline .string, .allocated_string => |slice| slice,
                    .object_end => { // No more fields.
                        break;
                    },
                    else => {
                        return error.UnexpectedToken;
                    },
                };

                inline for (structInfo.fields, 0..) |field, i| {
                    if (field.is_comptime) @compile_error("comptime fields are not supported: " ++ @type_name(T) ++ "." ++ field.name);
                    if (std.mem.eql(u8, field.name, field_name)) {
                        // Free the name token now in case we're using an allocator that optimizes freeing the last allocated object.
                        // (Recursing into inner_parse() might trigger more allocations.)
                        free_allocated(allocator, name_token.?);
                        name_token = null;
                        if (fields_seen[i]) {
                            switch (options.duplicate_field_behavior) {
                                .use_first => {
                                    // Parse and ignore the redundant value.
                                    // We don't want to skip the value, because we want type checking.
                                    _ = try inner_parse(field.type, allocator, source, options);
                                    break;
                                },
                                .@"error" => return error.DuplicateField,
                                .use_last => {},
                            }
                        }
                        @field(r, field.name) = try inner_parse(field.type, allocator, source, options);
                        fields_seen[i] = true;
                        break;
                    }
                } else {
                    // Didn't match anything.
                    free_allocated(allocator, name_token.?);
                    if (options.ignore_unknown_fields) {
                        try source.skip_value();
                    } else {
                        return error.UnknownField;
                    }
                }
            }
            try fill_default_struct_values(T, &r, &fields_seen);
            return r;
        },

        .Array => |array_info| {
            switch (try source.peek_next_token_type()) {
                .array_begin => {
                    // Typical array.
                    return internal_parse_array(T, array_info.child, array_info.len, allocator, source, options);
                },
                .string => {
                    if (array_info.child != u8) return error.UnexpectedToken;
                    // Fixed-length string.

                    var r: T = undefined;
                    var i: usize = 0;
                    while (true) {
                        switch (try source.next()) {
                            .string => |slice| {
                                if (i + slice.len != r.len) return error.LengthMismatch;
                                @memcpy(r[i..][0..slice.len], slice);
                                break;
                            },
                            .partial_string => |slice| {
                                if (i + slice.len > r.len) return error.LengthMismatch;
                                @memcpy(r[i..][0..slice.len], slice);
                                i += slice.len;
                            },
                            .partial_string_escaped_1 => |arr| {
                                if (i + arr.len > r.len) return error.LengthMismatch;
                                @memcpy(r[i..][0..arr.len], arr[0..]);
                                i += arr.len;
                            },
                            .partial_string_escaped_2 => |arr| {
                                if (i + arr.len > r.len) return error.LengthMismatch;
                                @memcpy(r[i..][0..arr.len], arr[0..]);
                                i += arr.len;
                            },
                            .partial_string_escaped_3 => |arr| {
                                if (i + arr.len > r.len) return error.LengthMismatch;
                                @memcpy(r[i..][0..arr.len], arr[0..]);
                                i += arr.len;
                            },
                            .partial_string_escaped_4 => |arr| {
                                if (i + arr.len > r.len) return error.LengthMismatch;
                                @memcpy(r[i..][0..arr.len], arr[0..]);
                                i += arr.len;
                            },
                            else => unreachable,
                        }
                    }

                    return r;
                },

                else => return error.UnexpectedToken,
            }
        },

        .Vector => |vecInfo| {
            switch (try source.peek_next_token_type()) {
                .array_begin => {
                    return internal_parse_array(T, vecInfo.child, vecInfo.len, allocator, source, options);
                },
                else => return error.UnexpectedToken,
            }
        },

        .Pointer => |ptr_info| {
            switch (ptr_info.size) {
                .One => {
                    const r: *ptr_info.child = try allocator.create(ptr_info.child);
                    r.* = try inner_parse(ptr_info.child, allocator, source, options);
                    return r;
                },
                .Slice => {
                    switch (try source.peek_next_token_type()) {
                        .array_begin => {
                            _ = try source.next();

                            // Typical array.
                            var arraylist = ArrayList(ptr_info.child).init(allocator);
                            while (true) {
                                switch (try source.peek_next_token_type()) {
                                    .array_end => {
                                        _ = try source.next();
                                        break;
                                    },
                                    else => {},
                                }

                                try arraylist.ensure_unused_capacity(1);
                                arraylist.append_assume_capacity(try inner_parse(ptr_info.child, allocator, source, options));
                            }

                            if (ptr_info.sentinel) |some| {
                                const sentinel_value = @as(*align(1) const ptr_info.child, @ptr_cast(some)).*;
                                return try arraylist.to_owned_slice_sentinel(sentinel_value);
                            }

                            return try arraylist.to_owned_slice();
                        },
                        .string => {
                            if (ptr_info.child != u8) return error.UnexpectedToken;

                            // Dynamic length string.
                            if (ptr_info.sentinel) |sentinel_ptr| {
                                // Use our own array list so we can append the sentinel.
                                var value_list = ArrayList(u8).init(allocator);
                                _ = try source.alloc_next_into_array_list(&value_list, .alloc_always);
                                return try value_list.to_owned_slice_sentinel(@as(*const u8, @ptr_cast(sentinel_ptr)).*);
                            }
                            if (ptr_info.is_const) {
                                switch (try source.next_alloc_max(allocator, options.allocate.?, options.max_value_len.?)) {
                                    inline .string, .allocated_string => |slice| return slice,
                                    else => unreachable,
                                }
                            } else {
                                // Have to allocate to get a mutable copy.
                                switch (try source.next_alloc_max(allocator, .alloc_always, options.max_value_len.?)) {
                                    .allocated_string => |slice| return slice,
                                    else => unreachable,
                                }
                            }
                        },
                        else => return error.UnexpectedToken,
                    }
                },
                else => @compile_error("Unable to parse into type '" ++ @type_name(T) ++ "'"),
            }
        },
        else => @compile_error("Unable to parse into type '" ++ @type_name(T) ++ "'"),
    }
    unreachable;
}

fn internal_parse_array(
    comptime T: type,
    comptime Child: type,
    comptime len: comptime_int,
    allocator: Allocator,
    source: anytype,
    options: ParseOptions,
) !T {
    assert(.array_begin == try source.next());

    var r: T = undefined;
    var i: usize = 0;
    while (i < len) : (i += 1) {
        r[i] = try inner_parse(Child, allocator, source, options);
    }

    if (.array_end != try source.next()) return error.UnexpectedToken;

    return r;
}

/// This is an internal function called recursively
/// during the implementation of `parse_from_value_leaky`.
/// It is exposed primarily to enable custom `json_parse_from_value()` methods to call back into the `parse_from_value*` system,
/// such as if you're implementing a custom container of type `T`;
/// you can call `inner_parse_from_value(T, ...)` for each of the container's items.
pub fn inner_parse_from_value(
    comptime T: type,
    allocator: Allocator,
    source: Value,
    options: ParseOptions,
) ParseFromValueError!T {
    switch (@typeInfo(T)) {
        .Bool => {
            switch (source) {
                .bool => |b| return b,
                else => return error.UnexpectedToken,
            }
        },
        .Float, .ComptimeFloat => {
            switch (source) {
                .float => |f| return @as(T, @float_cast(f)),
                .integer => |i| return @as(T, @float_from_int(i)),
                .number_string, .string => |s| return std.fmt.parse_float(T, s),
                else => return error.UnexpectedToken,
            }
        },
        .Int, .ComptimeInt => {
            switch (source) {
                .float => |f| {
                    if (@round(f) != f) return error.InvalidNumber;
                    if (f > std.math.max_int(T)) return error.Overflow;
                    if (f < std.math.min_int(T)) return error.Overflow;
                    return @as(T, @int_from_float(f));
                },
                .integer => |i| {
                    if (i > std.math.max_int(T)) return error.Overflow;
                    if (i < std.math.min_int(T)) return error.Overflow;
                    return @as(T, @int_cast(i));
                },
                .number_string, .string => |s| {
                    return slice_to_int(T, s);
                },
                else => return error.UnexpectedToken,
            }
        },
        .Optional => |optionalInfo| {
            switch (source) {
                .null => return null,
                else => return try inner_parse_from_value(optionalInfo.child, allocator, source, options),
            }
        },
        .Enum => {
            if (std.meta.has_fn(T, "json_parse_from_value")) {
                return T.json_parse_from_value(allocator, source, options);
            }

            switch (source) {
                .float => return error.InvalidEnumTag,
                .integer => |i| return std.meta.int_to_enum(T, i),
                .number_string, .string => |s| return slice_to_enum(T, s),
                else => return error.UnexpectedToken,
            }
        },
        .Union => |unionInfo| {
            if (std.meta.has_fn(T, "json_parse_from_value")) {
                return T.json_parse_from_value(allocator, source, options);
            }

            if (unionInfo.tag_type == null) @compile_error("Unable to parse into untagged union '" ++ @type_name(T) ++ "'");

            if (source != .object) return error.UnexpectedToken;
            if (source.object.count() != 1) return error.UnexpectedToken;

            var it = source.object.iterator();
            const kv = it.next().?;
            const field_name = kv.key_ptr.*;

            inline for (unionInfo.fields) |u_field| {
                if (std.mem.eql(u8, u_field.name, field_name)) {
                    if (u_field.type == void) {
                        // void isn't really a json type, but we can support void payload union tags with {} as a value.
                        if (kv.value_ptr.* != .object) return error.UnexpectedToken;
                        if (kv.value_ptr.*.object.count() != 0) return error.UnexpectedToken;
                        return @union_init(T, u_field.name, {});
                    }
                    // Recurse.
                    return @union_init(T, u_field.name, try inner_parse_from_value(u_field.type, allocator, kv.value_ptr.*, options));
                }
            }
            // Didn't match anything.
            return error.UnknownField;
        },

        .Struct => |structInfo| {
            if (structInfo.is_tuple) {
                if (source != .array) return error.UnexpectedToken;
                if (source.array.items.len != structInfo.fields.len) return error.UnexpectedToken;

                var r: T = undefined;
                inline for (0..structInfo.fields.len, source.array.items) |i, item| {
                    r[i] = try inner_parse_from_value(structInfo.fields[i].type, allocator, item, options);
                }

                return r;
            }

            if (std.meta.has_fn(T, "json_parse_from_value")) {
                return T.json_parse_from_value(allocator, source, options);
            }

            if (source != .object) return error.UnexpectedToken;

            var r: T = undefined;
            var fields_seen = [_]bool{false} ** structInfo.fields.len;

            var it = source.object.iterator();
            while (it.next()) |kv| {
                const field_name = kv.key_ptr.*;

                inline for (structInfo.fields, 0..) |field, i| {
                    if (field.is_comptime) @compile_error("comptime fields are not supported: " ++ @type_name(T) ++ "." ++ field.name);
                    if (std.mem.eql(u8, field.name, field_name)) {
                        assert(!fields_seen[i]); // Can't have duplicate keys in a Value.object.
                        @field(r, field.name) = try inner_parse_from_value(field.type, allocator, kv.value_ptr.*, options);
                        fields_seen[i] = true;
                        break;
                    }
                } else {
                    // Didn't match anything.
                    if (!options.ignore_unknown_fields) return error.UnknownField;
                }
            }
            try fill_default_struct_values(T, &r, &fields_seen);
            return r;
        },

        .Array => |array_info| {
            switch (source) {
                .array => |array| {
                    // Typical array.
                    return inner_parse_array_from_array_value(T, array_info.child, array_info.len, allocator, array, options);
                },
                .string => |s| {
                    if (array_info.child != u8) return error.UnexpectedToken;
                    // Fixed-length string.

                    if (s.len != array_info.len) return error.LengthMismatch;

                    var r: T = undefined;
                    @memcpy(r[0..], s);
                    return r;
                },

                else => return error.UnexpectedToken,
            }
        },

        .Vector => |vecInfo| {
            switch (source) {
                .array => |array| {
                    return inner_parse_array_from_array_value(T, vecInfo.child, vecInfo.len, allocator, array, options);
                },
                else => return error.UnexpectedToken,
            }
        },

        .Pointer => |ptr_info| {
            switch (ptr_info.size) {
                .One => {
                    const r: *ptr_info.child = try allocator.create(ptr_info.child);
                    r.* = try inner_parse_from_value(ptr_info.child, allocator, source, options);
                    return r;
                },
                .Slice => {
                    switch (source) {
                        .array => |array| {
                            const r = if (ptr_info.sentinel) |sentinel_ptr|
                                try allocator.alloc_sentinel(ptr_info.child, array.items.len, @as(*align(1) const ptr_info.child, @ptr_cast(sentinel_ptr)).*)
                            else
                                try allocator.alloc(ptr_info.child, array.items.len);

                            for (array.items, r) |item, *dest| {
                                dest.* = try inner_parse_from_value(ptr_info.child, allocator, item, options);
                            }

                            return r;
                        },
                        .string => |s| {
                            if (ptr_info.child != u8) return error.UnexpectedToken;
                            // Dynamic length string.

                            const r = if (ptr_info.sentinel) |sentinel_ptr|
                                try allocator.alloc_sentinel(ptr_info.child, s.len, @as(*align(1) const ptr_info.child, @ptr_cast(sentinel_ptr)).*)
                            else
                                try allocator.alloc(ptr_info.child, s.len);
                            @memcpy(r[0..], s);

                            return r;
                        },
                        else => return error.UnexpectedToken,
                    }
                },
                else => @compile_error("Unable to parse into type '" ++ @type_name(T) ++ "'"),
            }
        },
        else => @compile_error("Unable to parse into type '" ++ @type_name(T) ++ "'"),
    }
}

fn inner_parse_array_from_array_value(
    comptime T: type,
    comptime Child: type,
    comptime len: comptime_int,
    allocator: Allocator,
    array: Array,
    options: ParseOptions,
) !T {
    if (array.items.len != len) return error.LengthMismatch;

    var r: T = undefined;
    for (array.items, 0..) |item, i| {
        r[i] = try inner_parse_from_value(Child, allocator, item, options);
    }

    return r;
}

fn slice_to_int(comptime T: type, slice: []const u8) !T {
    if (is_number_formatted_like_an_integer(slice))
        return std.fmt.parse_int(T, slice, 10);
    // Try to coerce a float to an integer.
    const float = try std.fmt.parse_float(f128, slice);
    if (@round(float) != float) return error.InvalidNumber;
    if (float > std.math.max_int(T) or float < std.math.min_int(T)) return error.Overflow;
    return @as(T, @int_cast(@as(i128, @int_from_float(float))));
}

fn slice_to_enum(comptime T: type, slice: []const u8) !T {
    // Check for a named value.
    if (std.meta.string_to_enum(T, slice)) |value| return value;
    // Check for a numeric value.
    if (!is_number_formatted_like_an_integer(slice)) return error.InvalidEnumTag;
    const n = std.fmt.parse_int(@typeInfo(T).Enum.tag_type, slice, 10) catch return error.InvalidEnumTag;
    return std.meta.int_to_enum(T, n);
}

fn fill_default_struct_values(comptime T: type, r: *T, fields_seen: *[@typeInfo(T).Struct.fields.len]bool) !void {
    inline for (@typeInfo(T).Struct.fields, 0..) |field, i| {
        if (!fields_seen[i]) {
            if (field.default_value) |default_ptr| {
                const default = @as(*align(1) const field.type, @ptr_cast(default_ptr)).*;
                @field(r, field.name) = default;
            } else {
                return error.MissingField;
            }
        }
    }
}

fn free_allocated(allocator: Allocator, token: Token) void {
    switch (token) {
        .allocated_number, .allocated_string => |slice| {
            allocator.free(slice);
        },
        else => {},
    }
}

test {
    _ = @import("./static_test.zig");
}
