const std = @import("std");
const testing = std.testing;

const HandshakeType = enum(u8) {
    client_hello = 1,
};

const ClientHelloHandshake = struct {
    handshake_type: HandshakeType,
    protocol_version: u16,
    random: u32,
    session_id_length: u8,
    session_id: []const u8,
    cipher_suites_length: u16,
    cipher_suites: []const u8,
    compression_methods_length: u8,
    compression_methods: []const u8,

    pub fn length(self: *ClientHelloHandshake) u24 {
        var len: u24 = 0;

        len += (16 + 32 + 8 + 16 + 8) / 8;
        len += @intCast(u24, self.session_id.len);
        len += @intCast(u24, self.cipher_suites.len);
        len += @intCast(u24, self.compression_methods.len);

        return len;
    }
};

const ClientHello = struct {
    const Self = @This();

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
            const random = self.readIntBig(u32, 4);
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

    pub const Encoder = struct {
        buf: std.ArrayList(u8),
        handshake: ClientHelloHandshake,

        pub fn init(alloc: std.mem.Allocator, handshake: ClientHelloHandshake) Encoder {
            return .{
                .buf = std.ArrayList(u8).init(alloc),
                .handshake = handshake,
            };
        }

        pub fn deinit(self: *Encoder) void {
            self.buf.deinit();
        }

        pub fn encode(self: *Encoder) ![]const u8 {
            // handshake_type
            try self.buf.append(@enumToInt(self.handshake.handshake_type));
            // dummy length
            var dummy_length_buf: [3]u8 = [3]u8{ 0x00, 0x00, 0x00 };
            try self.buf.appendSlice(dummy_length_buf[0..]);
            // protocol_version
            var protocol_version_buf: [2]u8 = undefined;
            std.mem.writeIntSlice(u16, &protocol_version_buf, self.handshake.protocol_version, .Big);
            try self.buf.appendSlice(protocol_version_buf[0..]);
            // random
            var random_buf: [4]u8 = undefined;
            std.mem.writeIntSlice(u32, &random_buf, self.handshake.random, .Big);
            try self.buf.appendSlice(random_buf[0..]);
            // session_id
            try self.buf.append(self.handshake.session_id_length);
            try self.buf.appendSlice(self.handshake.session_id[0..self.handshake.session_id_length]);
            // cipher_suites
            var cipher_suites_length_buf: [2]u8 = undefined;
            std.mem.writeIntSlice(u16, &cipher_suites_length_buf, self.handshake.cipher_suites_length, .Big);
            try self.buf.appendSlice(cipher_suites_length_buf[0..]);
            try self.buf.appendSlice(self.handshake.cipher_suites[0..self.handshake.cipher_suites_length]);
            // compression_methods
            try self.buf.append(self.handshake.compression_methods_length);
            try self.buf.appendSlice(self.handshake.compression_methods[0..self.handshake.compression_methods_length]);

            const length: u24 = @intCast(u24, self.buf.items.len) - 4;
            var length_buf: [3]u8 = undefined;
            std.mem.writeIntSlice(u24, &length_buf, length, .Big);
            try self.buf.replaceRange(1, 3, length_buf[0..]);

            return self.buf.items;
        }
    };
};

test "ClientHello" {
    const handshake_type = &[_]u8{
        @enumToInt(HandshakeType.client_hello),
    };
    const length = &[_]u8{
        0x00, 0x00, 0x2d,
    };
    const protocol_version = &[_]u8{
        0x03, 0x03,
    };
    const random = &[_]u8{
        0x00, 0x00, 0x00, 0x00,
    };
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

    var decoder = ClientHello.Decoder.init(raw);
    var handshake = decoder.decode();

    try testing.expectEqual(HandshakeType.client_hello, handshake.handshake_type);
    try testing.expectEqual(@as(u24, 45), handshake.length());
    try testing.expectEqual(@as(u16, 0x0303), handshake.protocol_version);
    try testing.expectEqual(@as(u32, 0x00), handshake.random);
    try testing.expectEqual(@as(u8, 32), handshake.session_id_length);
    try testing.expectEqualSlices(u8, &[_]u8{0x00} ** 32, handshake.session_id);
    try testing.expectEqual(@as(u16, 2), handshake.cipher_suites_length);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x9c }, handshake.cipher_suites);
    try testing.expectEqual(@as(u8, 1), handshake.compression_methods_length);
    try testing.expectEqualSlices(u8, &[_]u8{0x00}, handshake.compression_methods);

    var encoder = ClientHello.Encoder.init(testing.allocator, handshake);
    defer encoder.deinit();
    const encoded = try encoder.encode();

    try testing.expectEqualSlices(u8, raw, encoded);
}
