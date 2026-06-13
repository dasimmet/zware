// vendored from: https://codeberg.org/ziglang/zig/src/tag/0.16.0/lib/std/Io/Reader.zig#L1292

const std = @import("std");
const Reader = std.Io.Reader;
const TakeLeb128Error = Reader.TakeLeb128Error;
const assert = std.debug.assert;

/// Read a single LEB128 value as type T, or `error.Overflow` if the value cannot fit.
pub fn takeLeb128(r: *Reader, comptime T: type) TakeLeb128Error!T {
    const info = switch (@typeInfo(T)) {
        .int => |info| info,
        else => @compileError(@typeName(T) ++ " not supported"),
    };
    const Byte = packed struct { bits: u7, more: bool };

    if (info.bits <= 7) {
        var byte: Byte = undefined;
        const Bits = @Int(info.signedness, 7);

        byte = @bitCast(try r.takeByte());
        const val = std.math.cast(T, @as(Bits, @bitCast(byte.bits))) orelse error.Overflow;

        const allowed_bits: u7 = switch (info.signedness) {
            .unsigned => 0,
            .signed => @bitCast(@as(i7, @bitCast(byte.bits)) >> 6),
        };

        var fits = true;
        while (byte.more) {
            byte = @bitCast(try r.takeByte());

            if (byte.bits != allowed_bits) fits = false;
        }

        return if (fits) blk: {
            @branchHint(.likely);
            break :blk val;
        } else error.Overflow;
    }

    const Unsigned = @Int(.unsigned, info.bits);
    const UInt = std.math.ByteAlignedInt(Unsigned);
    const Int = std.math.ByteAlignedInt(T);

    const uint_bits = @typeInfo(UInt).int.bits;

    var byte: Byte = undefined;
    var val: UInt = 0;
    const max_bytes = @divFloor(info.bits - 1, 7) + 1;
    inline for (0..max_bytes) |iteration| {
        const shift = iteration * 7;

        byte = @bitCast(try r.takeByte());

        const extended: UInt = byte.bits;
        val |= extended << shift;

        const bits_written = shift + 7;

        if (bits_written >= info.bits) {
            const bits_overflowed = bits_written - info.bits;
            const bits_remaining = @mod(info.bits, 7);

            const allowed_bits: u7, const fits: bool = switch (info.signedness) {
                .unsigned => blk: {
                    const fits = bits_remaining == 0 or byte.bits >> bits_remaining == 0;

                    break :blk .{ 0, fits };
                },
                .signed => blk: {
                    const bits: i7 = @bitCast(byte.bits);

                    // Move the sign bit into the MSB
                    const shifted_bits: i7 = bits << bits_overflowed;

                    const value_sign: i7 = shifted_bits >> 6; // sign extends
                    const bits_sign: i7 = bits >> bits_remaining; // sign extends

                    const fits = bits_remaining == 0 or bits_sign == value_sign;

                    if (uint_bits != info.bits and value_sign != 0) {
                        const sign_extend_mask = @as(UInt, std.math.maxInt(UInt)) << info.bits;
                        val |= sign_extend_mask;
                    }

                    break :blk .{ @bitCast(value_sign), fits };
                },
            };

            switch (info.signedness) {
                .signed => assert(allowed_bits == 0 or allowed_bits == 0x7F),
                .unsigned => comptime assert(allowed_bits == 0),
            }

            if (!fits or byte.more) return error.Overflow;
            return std.math.cast(T, @as(Int, @bitCast(val))) orelse error.Overflow;
        }

        comptime assert(bits_written < info.bits);
        if (!byte.more) {
            if (info.signedness == .signed and // can be negative
                byte.bits & 0x40 != 0) // is negative
            {
                const sign_extend_mask = @as(UInt, std.math.maxInt(UInt)) << bits_written;
                val |= sign_extend_mask;
            }
            return std.math.cast(T, @as(Int, @bitCast(val))) orelse error.Overflow;
        }
    }
}
