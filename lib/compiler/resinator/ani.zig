//! https://en.wikipedia.org/wiki/Resource_Interchange_File_Format
//! https://www.moon-soft.com/program/format/windows/ani.htm
//! https://www.gdgsoft.com/anituner/help/aniformat.htm
//! https://www.lomont.org/software/aniexploit/ExploitANI.pdf
//!
//! RIFF( 'ACON'
//!   [LIST( 'INFO' <info_data> )]
//!   [<DISP_ck>]
//!   anih( <ani_header> )
//!   [rate( <rate_info> )]
//!   ['seq '( <sequence_info> )]
//!   LIST( 'fram' icon( <icon_file> ) ... )
//! )

const std = @import("std");

const AF_ICON: u32 = 1;

pub fn is_animated_icon(reader: anytype) bool {
    const flags = get_aniheader_flags(reader) catch return false;
    return flags & AF_ICON == AF_ICON;
}

fn get_aniheader_flags(reader: anytype) !u32 {
    const riff_header = try reader.read_bytes_no_eof(4);
    if (!std.mem.eql(u8, &riff_header, "RIFF")) return error.InvalidFormat;

    _ = try reader.read_int(u32, .little); // size of RIFF chunk

    const form_type = try reader.read_bytes_no_eof(4);
    if (!std.mem.eql(u8, &form_type, "ACON")) return error.InvalidFormat;

    while (true) {
        const chunk_id = try reader.read_bytes_no_eof(4);
        const chunk_len = try reader.read_int(u32, .little);
        if (!std.mem.eql(u8, &chunk_id, "anih")) {
            // TODO: Move file cursor instead of skip_bytes
            try reader.skip_bytes(chunk_len, .{});
            continue;
        }

        const aniheader = try reader.read_struct(ANIHEADER);
        return std.mem.native_to_little(u32, aniheader.flags);
    }
}

/// From Microsoft Multimedia Data Standards Update April 15, 1994
const ANIHEADER = extern struct {
    cbSizeof: u32,
    cFrames: u32,
    cSteps: u32,
    cx: u32,
    cy: u32,
    cBitCount: u32,
    cPlanes: u32,
    jifRate: u32,
    flags: u32,
};
