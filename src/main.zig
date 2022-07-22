const std = @import("std");
const testing = std.testing;

const HandshakeType = enum(u8) {
    client_hello = 1,
};

const ClientHelloHandshake = struct {
    handshake_type: HandshakeType,
    length: u24,
    protocol_version: u16,
    random: u32,
    session_id_length: u8,
    session_id: u32,
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
            const session_id = self.readIntBig(u32, 4); // TODO

            return .{
                .handshake_type = handshake_type,
                .length = length,
                .protocol_version = protocol_version,
                .random = random,
                .session_id_length = session_id_length,
                .session_id = session_id,
            };
        }

        fn readIntBig(self: *Decoder, comptime T: type, len: usize) T {
            const v = std.mem.readIntSliceBig(T, self.raw[self.cur .. self.cur + len]);

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
            try self.buf.append(@enumToInt(self.handshake.handshake_type));

            var length_buf: [3]u8 = undefined;
            std.mem.writeIntSlice(u24, &length_buf, self.handshake.length, .Big);
            try self.buf.appendSlice(length_buf[0..]);

            var protocol_version_buf: [2]u8 = undefined;
            std.mem.writeIntSlice(u16, &protocol_version_buf, self.handshake.protocol_version, .Big);
            try self.buf.appendSlice(protocol_version_buf[0..]);

            var random_buf: [4]u8 = undefined;
            std.mem.writeIntSlice(u32, &random_buf, self.handshake.random, .Big);
            try self.buf.appendSlice(random_buf[0..]);

            try self.buf.append(self.handshake.session_id_length);

            var session_id_buf: [4]u8 = undefined;
            std.mem.writeIntSlice(u32, &session_id_buf, self.handshake.session_id, .Big);
            try self.buf.appendSlice(session_id_buf[0 .. self.handshake.session_id_length / 8]);

            return self.buf.items;
        }
    };
};

test "ClientHello" {
    const raw = &[_]u8{
        @enumToInt(HandshakeType.client_hello),
        // length
        0x10,
        0x00,
        0x00,
        // protocol version
        0x03,
        0x03,
        // random
        0x00,
        0x00,
        0x00,
        0x00,
        // session_id_length
        0x20,
        // session_id
        0x00,
        0x00,
        0x00,
        0x00,
    };

    var decoder = ClientHello.Decoder.init(raw);
    const handshake = decoder.decode();

    try testing.expectEqual(handshake.handshake_type, .client_hello);
    try testing.expectEqual(handshake.length, 1048576);
    try testing.expectEqual(handshake.protocol_version, 0x0303);
    try testing.expectEqual(handshake.random, 0x00);
    try testing.expectEqual(handshake.session_id_length, 32);
    try testing.expectEqual(handshake.session_id, 0x00);

    var encoder = ClientHello.Encoder.init(testing.allocator, handshake);
    defer encoder.deinit();
    const encoded = try encoder.encode();

    try testing.expectEqualSlices(u8, encoded, raw);
}
