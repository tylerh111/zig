const std = @import("std");

const types = @import("../types.zig");
const LiteralsSection = types.compressed_block.LiteralsSection;
const Table = types.compressed_block.Table;

const readers = @import("../readers.zig");

const decode_fse_table = @import("fse.zig").decode_fse_table;

pub const Error = error{
    MalformedHuffmanTree,
    MalformedFseTable,
    MalformedAccuracyLog,
    EndOfStream,
};

fn decode_fse_huffman_tree(
    source: anytype,
    compressed_size: usize,
    buffer: []u8,
    weights: *[256]u4,
) !usize {
    var stream = std.io.limited_reader(source, compressed_size);
    var bit_reader = readers.bit_reader(stream.reader());

    var entries: [1 << 6]Table.Fse = undefined;
    const table_size = decode_fse_table(&bit_reader, 256, 6, &entries) catch |err| switch (err) {
        error.MalformedAccuracyLog, error.MalformedFseTable => |e| return e,
        error.EndOfStream => return error.MalformedFseTable,
        else => |e| return e,
    };
    const accuracy_log = std.math.log2_int_ceil(usize, table_size);

    const amount = try stream.reader().read_all(buffer);
    var huff_bits: readers.ReverseBitReader = undefined;
    huff_bits.init(buffer[0..amount]) catch return error.MalformedHuffmanTree;

    return assign_weights(&huff_bits, accuracy_log, &entries, weights);
}

fn decode_fse_huffman_tree_slice(src: []const u8, compressed_size: usize, weights: *[256]u4) !usize {
    if (src.len < compressed_size) return error.MalformedHuffmanTree;
    var stream = std.io.fixed_buffer_stream(src[0..compressed_size]);
    var counting_reader = std.io.counting_reader(stream.reader());
    var bit_reader = readers.bit_reader(counting_reader.reader());

    var entries: [1 << 6]Table.Fse = undefined;
    const table_size = decode_fse_table(&bit_reader, 256, 6, &entries) catch |err| switch (err) {
        error.MalformedAccuracyLog, error.MalformedFseTable => |e| return e,
        error.EndOfStream => return error.MalformedFseTable,
    };
    const accuracy_log = std.math.log2_int_ceil(usize, table_size);

    const start_index = std.math.cast(usize, counting_reader.bytes_read) orelse
        return error.MalformedHuffmanTree;
    const huff_data = src[start_index..compressed_size];
    var huff_bits: readers.ReverseBitReader = undefined;
    huff_bits.init(huff_data) catch return error.MalformedHuffmanTree;

    return assign_weights(&huff_bits, accuracy_log, &entries, weights);
}

fn assign_weights(
    huff_bits: *readers.ReverseBitReader,
    accuracy_log: usize,
    entries: *[1 << 6]Table.Fse,
    weights: *[256]u4,
) !usize {
    var i: usize = 0;
    var even_state: u32 = huff_bits.read_bits_no_eof(u32, accuracy_log) catch return error.MalformedHuffmanTree;
    var odd_state: u32 = huff_bits.read_bits_no_eof(u32, accuracy_log) catch return error.MalformedHuffmanTree;

    while (i < 254) {
        const even_data = entries[even_state];
        var read_bits: usize = 0;
        const even_bits = huff_bits.read_bits(u32, even_data.bits, &read_bits) catch unreachable;
        weights[i] = std.math.cast(u4, even_data.symbol) orelse return error.MalformedHuffmanTree;
        i += 1;
        if (read_bits < even_data.bits) {
            weights[i] = std.math.cast(u4, entries[odd_state].symbol) orelse return error.MalformedHuffmanTree;
            i += 1;
            break;
        }
        even_state = even_data.baseline + even_bits;

        read_bits = 0;
        const odd_data = entries[odd_state];
        const odd_bits = huff_bits.read_bits(u32, odd_data.bits, &read_bits) catch unreachable;
        weights[i] = std.math.cast(u4, odd_data.symbol) orelse return error.MalformedHuffmanTree;
        i += 1;
        if (read_bits < odd_data.bits) {
            if (i == 255) return error.MalformedHuffmanTree;
            weights[i] = std.math.cast(u4, entries[even_state].symbol) orelse return error.MalformedHuffmanTree;
            i += 1;
            break;
        }
        odd_state = odd_data.baseline + odd_bits;
    } else return error.MalformedHuffmanTree;

    if (!huff_bits.is_empty()) {
        return error.MalformedHuffmanTree;
    }

    return i + 1; // stream contains all but the last symbol
}

fn decode_direct_huffman_tree(source: anytype, encoded_symbol_count: usize, weights: *[256]u4) !usize {
    const weights_byte_count = (encoded_symbol_count + 1) / 2;
    for (0..weights_byte_count) |i| {
        const byte = try source.read_byte();
        weights[2 * i] = @as(u4, @int_cast(byte >> 4));
        weights[2 * i + 1] = @as(u4, @int_cast(byte & 0xF));
    }
    return encoded_symbol_count + 1;
}

fn assign_symbols(weight_sorted_prefixed_symbols: []LiteralsSection.HuffmanTree.PrefixedSymbol, weights: [256]u4) usize {
    for (0..weight_sorted_prefixed_symbols.len) |i| {
        weight_sorted_prefixed_symbols[i] = .{
            .symbol = @as(u8, @int_cast(i)),
            .weight = undefined,
            .prefix = undefined,
        };
    }

    std.mem.sort(
        LiteralsSection.HuffmanTree.PrefixedSymbol,
        weight_sorted_prefixed_symbols,
        weights,
        less_than_by_weight,
    );

    var prefix: u16 = 0;
    var prefixed_symbol_count: usize = 0;
    var sorted_index: usize = 0;
    const symbol_count = weight_sorted_prefixed_symbols.len;
    while (sorted_index < symbol_count) {
        var symbol = weight_sorted_prefixed_symbols[sorted_index].symbol;
        const weight = weights[symbol];
        if (weight == 0) {
            sorted_index += 1;
            continue;
        }

        while (sorted_index < symbol_count) : ({
            sorted_index += 1;
            prefixed_symbol_count += 1;
            prefix += 1;
        }) {
            symbol = weight_sorted_prefixed_symbols[sorted_index].symbol;
            if (weights[symbol] != weight) {
                prefix = ((prefix - 1) >> (weights[symbol] - weight)) + 1;
                break;
            }
            weight_sorted_prefixed_symbols[prefixed_symbol_count].symbol = symbol;
            weight_sorted_prefixed_symbols[prefixed_symbol_count].prefix = prefix;
            weight_sorted_prefixed_symbols[prefixed_symbol_count].weight = weight;
        }
    }
    return prefixed_symbol_count;
}

fn build_huffman_tree(weights: *[256]u4, symbol_count: usize) error{MalformedHuffmanTree}!LiteralsSection.HuffmanTree {
    var weight_power_sum_big: u32 = 0;
    for (weights[0 .. symbol_count - 1]) |value| {
        weight_power_sum_big += (@as(u16, 1) << value) >> 1;
    }
    if (weight_power_sum_big >= 1 << 11) return error.MalformedHuffmanTree;
    const weight_power_sum = @as(u16, @int_cast(weight_power_sum_big));

    // advance to next power of two (even if weight_power_sum is a power of 2)
    // TODO: is it valid to have weight_power_sum == 0?
    const max_number_of_bits = if (weight_power_sum == 0) 1 else std.math.log2_int(u16, weight_power_sum) + 1;
    const next_power_of_two = @as(u16, 1) << max_number_of_bits;
    weights[symbol_count - 1] = std.math.log2_int(u16, next_power_of_two - weight_power_sum) + 1;

    var weight_sorted_prefixed_symbols: [256]LiteralsSection.HuffmanTree.PrefixedSymbol = undefined;
    const prefixed_symbol_count = assign_symbols(weight_sorted_prefixed_symbols[0..symbol_count], weights.*);
    const tree = LiteralsSection.HuffmanTree{
        .max_bit_count = max_number_of_bits,
        .symbol_count_minus_one = @as(u8, @int_cast(prefixed_symbol_count - 1)),
        .nodes = weight_sorted_prefixed_symbols,
    };
    return tree;
}

pub fn decode_huffman_tree(
    source: anytype,
    buffer: []u8,
) (@TypeOf(source).Error || Error)!LiteralsSection.HuffmanTree {
    const header = try source.read_byte();
    var weights: [256]u4 = undefined;
    const symbol_count = if (header < 128)
        // FSE compressed weights
        try decode_fse_huffman_tree(source, header, buffer, &weights)
    else
        try decode_direct_huffman_tree(source, header - 127, &weights);

    return build_huffman_tree(&weights, symbol_count);
}

pub fn decode_huffman_tree_slice(
    src: []const u8,
    consumed_count: *usize,
) Error!LiteralsSection.HuffmanTree {
    if (src.len == 0) return error.MalformedHuffmanTree;
    const header = src[0];
    var bytes_read: usize = 1;
    var weights: [256]u4 = undefined;
    const symbol_count = if (header < 128) count: {
        // FSE compressed weights
        bytes_read += header;
        break :count try decode_fse_huffman_tree_slice(src[1..], header, &weights);
    } else count: {
        var fbs = std.io.fixed_buffer_stream(src[1..]);
        defer bytes_read += fbs.pos;
        break :count try decode_direct_huffman_tree(fbs.reader(), header - 127, &weights);
    };

    consumed_count.* += bytes_read;
    return build_huffman_tree(&weights, symbol_count);
}

fn less_than_by_weight(
    weights: [256]u4,
    lhs: LiteralsSection.HuffmanTree.PrefixedSymbol,
    rhs: LiteralsSection.HuffmanTree.PrefixedSymbol,
) bool {
    // NOTE: this function relies on the use of a stable sorting algorithm,
    //       otherwise a special case of if (weights[lhs] == weights[rhs]) return lhs < rhs;
    //       should be added
    return weights[lhs.symbol] < weights[rhs.symbol];
}
