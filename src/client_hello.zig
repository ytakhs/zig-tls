const std = @import("std");
const testing = std.testing;

const HandshakeType = enum(u8) {
    client_hello = 1,
};

pub const ClientHelloHandshake = struct {
    const Self = @This();

    handshake_type: HandshakeType,
    protocol_version: u16,
    random: []const u8,
    session_id_length: u8,
    session_id: []const u8,
    cipher_suites_length: u16,
    cipher_suites: []const u8,
    compression_methods_length: u8,
    compression_methods: []const u8,

    pub fn length(self: *ClientHelloHandshake) u24 {
        var len: u24 = 0;

        len += (16 + 32 * 8 + 8 + 16 + 8) / 8;
        len += @intCast(u24, self.session_id.len);
        len += @intCast(u24, self.cipher_suites.len);
        len += @intCast(u24, self.compression_methods.len);

        return len;
    }

    pub fn encode(self: *Self, alloc: std.mem.Allocator) ![]const u8 {
        var buf = std.ArrayList(u8).init(alloc);
        // handshake_type
        try buf.append(@enumToInt(self.handshake_type));
        // dummy length
        var dummy_length_buf: [3]u8 = [3]u8{ 0x00, 0x00, 0x00 };
        try buf.appendSlice(dummy_length_buf[0..]);
        // protocol_version
        var protocol_version_buf: [2]u8 = undefined;
        std.mem.writeIntSlice(u16, &protocol_version_buf, self.protocol_version, .Big);
        try buf.appendSlice(protocol_version_buf[0..]);
        // random
        try buf.appendSlice(self.random[0..32]);
        // session_id
        try buf.append(self.session_id_length);
        try buf.appendSlice(self.session_id[0..self.session_id_length]);
        // cipher_suites
        var cipher_suites_length_buf: [2]u8 = undefined;
        std.mem.writeIntSlice(u16, &cipher_suites_length_buf, self.cipher_suites_length, .Big);
        try buf.appendSlice(cipher_suites_length_buf[0..]);
        try buf.appendSlice(self.cipher_suites[0..self.cipher_suites_length]);
        // compression_methods
        try buf.append(self.compression_methods_length);
        try buf.appendSlice(self.compression_methods[0..self.compression_methods_length]);

        const l: u24 = @intCast(u24, buf.items.len) - 4;
        var length_buf: [3]u8 = undefined;
        std.mem.writeIntSlice(u24, &length_buf, l, .Big);
        try buf.replaceRange(1, 3, length_buf[0..]);

        return buf.items;
    }
};

pub const Decoder = struct {
    cur: usize,
    raw: []const u8,

    pub fn init(raw: []const u8) Decoder {
        return .{
            .cur = 0,
            .raw = raw,
        };
    }

    pub fn decode(self: *Decoder) ClientHelloHandshake {
        const handshake_type = @intToEnum(HandshakeType, self.readIntBig(u8, 1));
        const length = self.readIntBig(u24, 3);
        const protocol_version = self.readIntBig(u16, 2);
        const random = self.readSlice(32);
        const session_id_length = self.readIntBig(u8, 1);
        const session_id = self.readSlice(session_id_length);
        const cipher_suites_length = self.readIntBig(u16, 2);
        const cipher_suites = self.readSlice(cipher_suites_length);
        const compression_methods_length = self.readIntBig(u8, 1);
        const compression_methods = self.readSlice(compression_methods_length);

        var handshake = ClientHelloHandshake{
            .handshake_type = handshake_type,
            .protocol_version = protocol_version,
            .random = random,
            .session_id_length = session_id_length,
            .session_id = session_id,
            .cipher_suites_length = cipher_suites_length,
            .cipher_suites = cipher_suites,
            .compression_methods_length = compression_methods_length,
            .compression_methods = compression_methods,
        };

        std.debug.print("0x{x}\n", .{handshake.length()});
        std.debug.assert(handshake.length() == length);

        return handshake;
    }

    fn readIntBig(self: *Decoder, comptime T: type, len: usize) T {
        const v = std.mem.readIntSliceBig(T, self.raw[self.cur .. self.cur + len]);

        self.cur += len;

        return v;
    }

    fn readSlice(self: *Decoder, len: usize) []const u8 {
        const v = self.raw[self.cur .. self.cur + len];

        self.cur += len;

        return v;
    }
};

test "ClientHello" {
    const handshake_type = &[_]u8{
        @enumToInt(HandshakeType.client_hello),
    };
    const length = &[_]u8{
        0x00, 0x00, 0x49,
    };
    const protocol_version = &[_]u8{
        0x03, 0x03,
    };
    const random = &[_]u8{0x00} ** 0x20;
    const session_id_length = &[_]u8{
        0x20,
    };
    const sesion_id = &[_]u8{0x00} ** 0x20;
    const cipher_suites_length = &[_]u8{
        0x00, 0x02,
    };
    const cipher_suites = &[_]u8{
        0x00, 0x9c,
    };
    const compression_methods_length = &[_]u8{
        0x01,
    };
    const compression_methods = &[_]u8{
        0x00,
    };
    const raw =
        handshake_type ++
        length ++
        protocol_version ++
        random ++
        session_id_length ++
        sesion_id ++
        cipher_suites_length ++
        cipher_suites ++
        compression_methods_length ++
        compression_methods;

    var decoder = Decoder.init(raw);
    var handshake = decoder.decode();

    try testing.expectEqual(HandshakeType.client_hello, handshake.handshake_type);
    try testing.expectEqual(@as(u24, 73), handshake.length());
    try testing.expectEqual(@as(u16, 0x0303), handshake.protocol_version);
    try testing.expectEqualSlices(u8, &[_]u8{0x00} ** 32, handshake.random);
    try testing.expectEqual(@as(u8, 32), handshake.session_id_length);
    try testing.expectEqualSlices(u8, &[_]u8{0x00} ** 32, handshake.session_id);
    try testing.expectEqual(@as(u16, 2), handshake.cipher_suites_length);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x9c }, handshake.cipher_suites);
    try testing.expectEqual(@as(u8, 1), handshake.compression_methods_length);
    try testing.expectEqualSlices(u8, &[_]u8{0x00}, handshake.compression_methods);

    const encoded = try handshake.encode(testing.allocator);
    defer testing.allocator.free(encoded);

    try testing.expectEqualSlices(u8, raw, encoded);
}
