//! Epoch reference times in terms of their difference from
//! UTC 1970-01-01 in seconds.
const std = @import("../std.zig");
const testing = std.testing;
const math = std.math;

/// Jan 01, 1970 AD
pub const posix = 0;
/// Jan 01, 1980 AD
pub const dos = 315532800;
/// Jan 01, 2001 AD
pub const ios = 978307200;
/// Nov 17, 1858 AD
pub const openvms = -3506716800;
/// Jan 01, 1900 AD
pub const zos = -2208988800;
/// Jan 01, 1601 AD
pub const windows = -11644473600;
/// Jan 01, 1978 AD
pub const amiga = 252460800;
/// Dec 31, 1967 AD
pub const pickos = -63244800;
/// Jan 06, 1980 AD
pub const gps = 315964800;
/// Jan 01, 0001 AD
pub const clr = -62135769600;

pub const unix = posix;
pub const android = posix;
pub const os2 = dos;
pub const bios = dos;
pub const vfat = dos;
pub const ntfs = windows;
pub const ntp = zos;
pub const jbase = pickos;
pub const aros = amiga;
pub const morphos = amiga;
pub const brew = gps;
pub const atsc = gps;
pub const go = clr;

/// The type that holds the current year, i.e. 2016
pub const Year = u16;

pub const epoch_year = 1970;
pub const secs_per_day: u17 = 24 * 60 * 60;

pub fn is_leap_year(year: Year) bool {
    if (@mod(year, 4) != 0)
        return false;
    if (@mod(year, 100) != 0)
        return true;
    return (0 == @mod(year, 400));
}

test is_leap_year {
    try testing.expect_equal(false, is_leap_year(2095));
    try testing.expect_equal(true, is_leap_year(2096));
    try testing.expect_equal(false, is_leap_year(2100));
    try testing.expect_equal(true, is_leap_year(2400));
}

pub fn get_days_in_year(year: Year) u9 {
    return if (is_leap_year(year)) 366 else 365;
}

pub const YearLeapKind = enum(u1) { not_leap, leap };

pub const Month = enum(u4) {
    jan = 1,
    feb,
    mar,
    apr,
    may,
    jun,
    jul,
    aug,
    sep,
    oct,
    nov,
    dec,

    /// return the numeric calendar value for the given month
    /// i.e. jan=1, feb=2, etc
    pub fn numeric(self: Month) u4 {
        return @int_from_enum(self);
    }
};

/// Get the number of days in the given month
pub fn get_days_in_month(leap_year: YearLeapKind, month: Month) u5 {
    return switch (month) {
        .jan => 31,
        .feb => @as(u5, switch (leap_year) {
            .leap => 29,
            .not_leap => 28,
        }),
        .mar => 31,
        .apr => 30,
        .may => 31,
        .jun => 30,
        .jul => 31,
        .aug => 31,
        .sep => 30,
        .oct => 31,
        .nov => 30,
        .dec => 31,
    };
}

pub const YearAndDay = struct {
    year: Year,
    /// The number of days into the year (0 to 365)
    day: u9,

    pub fn calculate_month_day(self: YearAndDay) MonthAndDay {
        var month: Month = .jan;
        var days_left = self.day;
        const leap_kind: YearLeapKind = if (is_leap_year(self.year)) .leap else .not_leap;
        while (true) {
            const days_in_month = get_days_in_month(leap_kind, month);
            if (days_left < days_in_month)
                break;
            days_left -= days_in_month;
            month = @as(Month, @enumFromInt(@int_from_enum(month) + 1));
        }
        return .{ .month = month, .day_index = @as(u5, @int_cast(days_left)) };
    }
};

pub const MonthAndDay = struct {
    month: Month,
    day_index: u5, // days into the month (0 to 30)
};

// days since epoch Oct 1, 1970
pub const EpochDay = struct {
    day: u47, // u47 = u64 - u17 (because day = sec(u64) / secs_per_day(u17)
    pub fn calculate_year_day(self: EpochDay) YearAndDay {
        var year_day = self.day;
        var year: Year = epoch_year;
        while (true) {
            const year_size = get_days_in_year(year);
            if (year_day < year_size)
                break;
            year_day -= year_size;
            year += 1;
        }
        return .{ .year = year, .day = @as(u9, @int_cast(year_day)) };
    }
};

/// seconds since start of day
pub const DaySeconds = struct {
    secs: u17, // max is 24*60*60 = 86400

    /// the number of hours past the start of the day (0 to 23)
    pub fn get_hours_into_day(self: DaySeconds) u5 {
        return @as(u5, @int_cast(@div_trunc(self.secs, 3600)));
    }
    /// the number of minutes past the hour (0 to 59)
    pub fn get_minutes_into_hour(self: DaySeconds) u6 {
        return @as(u6, @int_cast(@div_trunc(@mod(self.secs, 3600), 60)));
    }
    /// the number of seconds past the start of the minute (0 to 59)
    pub fn get_seconds_into_minute(self: DaySeconds) u6 {
        return math.comptime_mod(self.secs, 60);
    }
};

/// seconds since epoch Oct 1, 1970 at 12:00 AM
pub const EpochSeconds = struct {
    secs: u64,

    /// Returns the number of days since the epoch as an EpochDay.
    /// Use EpochDay to get information about the day of this time.
    pub fn get_epoch_day(self: EpochSeconds) EpochDay {
        return EpochDay{ .day = @as(u47, @int_cast(@div_trunc(self.secs, secs_per_day))) };
    }

    /// Returns the number of seconds into the day as DaySeconds.
    /// Use DaySeconds to get information about the time.
    pub fn get_day_seconds(self: EpochSeconds) DaySeconds {
        return DaySeconds{ .secs = math.comptime_mod(self.secs, secs_per_day) };
    }
};

fn test_epoch(secs: u64, expected_year_day: YearAndDay, expected_month_day: MonthAndDay, expected_day_seconds: struct {
    /// 0 to 23
    hours_into_day: u5,
    /// 0 to 59
    minutes_into_hour: u6,
    /// 0 to 59
    seconds_into_minute: u6,
}) !void {
    const epoch_seconds = EpochSeconds{ .secs = secs };
    const epoch_day = epoch_seconds.get_epoch_day();
    const day_seconds = epoch_seconds.get_day_seconds();
    const year_day = epoch_day.calculate_year_day();
    try testing.expect_equal(expected_year_day, year_day);
    try testing.expect_equal(expected_month_day, year_day.calculate_month_day());
    try testing.expect_equal(expected_day_seconds.hours_into_day, day_seconds.get_hours_into_day());
    try testing.expect_equal(expected_day_seconds.minutes_into_hour, day_seconds.get_minutes_into_hour());
    try testing.expect_equal(expected_day_seconds.seconds_into_minute, day_seconds.get_seconds_into_minute());
}

test "epoch decoding" {
    try test_epoch(0, .{ .year = 1970, .day = 0 }, .{
        .month = .jan,
        .day_index = 0,
    }, .{ .hours_into_day = 0, .minutes_into_hour = 0, .seconds_into_minute = 0 });

    try test_epoch(31535999, .{ .year = 1970, .day = 364 }, .{
        .month = .dec,
        .day_index = 30,
    }, .{ .hours_into_day = 23, .minutes_into_hour = 59, .seconds_into_minute = 59 });

    try test_epoch(1622924906, .{ .year = 2021, .day = 31 + 28 + 31 + 30 + 31 + 4 }, .{
        .month = .jun,
        .day_index = 4,
    }, .{ .hours_into_day = 20, .minutes_into_hour = 28, .seconds_into_minute = 26 });

    try test_epoch(1625159473, .{ .year = 2021, .day = 31 + 28 + 31 + 30 + 31 + 30 }, .{
        .month = .jul,
        .day_index = 0,
    }, .{ .hours_into_day = 17, .minutes_into_hour = 11, .seconds_into_minute = 13 });
}
